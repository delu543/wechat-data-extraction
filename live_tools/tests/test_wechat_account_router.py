from __future__ import annotations

import json
import os
import plistlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Callable, Optional, Sequence

from live_tools import wechat_account_router as router
from live_tools import wechat_key_init as key_init


class ScriptedRunner:
    def __init__(
        self,
        *,
        pgrep_results: Sequence[tuple[int, str]],
        lsof_results: Sequence[tuple[int, str, str]],
        on_lsof: Optional[Callable[[int], None]] = None,
    ) -> None:
        self.pgrep_results = list(pgrep_results)
        self.lsof_results = list(lsof_results)
        self.on_lsof = on_lsof
        self.pgrep_calls = 0
        self.lsof_calls = 0

    def __call__(self, command: Sequence[str], **_kwargs: object) -> subprocess.CompletedProcess:
        executable = command[0]
        if executable == "/usr/bin/pgrep":
            if self.pgrep_calls >= len(self.pgrep_results):
                raise AssertionError("unexpected pgrep call")
            code, stdout = self.pgrep_results[self.pgrep_calls]
            self.pgrep_calls += 1
            return subprocess.CompletedProcess(command, code, stdout=stdout, stderr="")
        if executable == "/usr/sbin/lsof":
            if self.lsof_calls >= len(self.lsof_results):
                raise AssertionError("unexpected lsof call")
            if self.on_lsof is not None:
                self.on_lsof(self.lsof_calls)
            code, stdout, stderr = self.lsof_results[self.lsof_calls]
            self.lsof_calls += 1
            return subprocess.CompletedProcess(command, code, stdout=stdout, stderr=stderr)
        raise AssertionError("unexpected command: %r" % (command,))


class RouterFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / "xwechat_files"
        self.root.mkdir()
        self.app = self._make_app()
        self.main_executable = self.app / "Contents/MacOS/WeChat"
        self.helper_executable = (
            self.app / "Contents/Frameworks/WeChatAppEx.framework/WeChatAppEx"
        )
        self.helper_executable.parent.mkdir(parents=True)
        self.helper_executable.write_bytes(b"helper")
        self.helper_executable.chmod(0o755)
        self.pid_paths = {101: self.main_executable, 102: self.helper_executable}

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _make_app(self) -> Path:
        app = self.base / "official-wechat.app"
        macos = app / "Contents/MacOS"
        macos.mkdir(parents=True)
        with (app / "Contents/Info.plist").open("wb") as handle:
            plistlib.dump(
                {
                    "CFBundleIdentifier": key_init.EXPECTED_BUNDLE_ID,
                    "CFBundleExecutable": "WeChat",
                    "CFBundleShortVersionString": "4.1.11",
                },
                handle,
            )
        executable = macos / "WeChat"
        executable.write_bytes(b"#!/bin/sh\nexit 0\n")
        executable.chmod(0o755)
        return app

    def _write_db(self, path: Path, salt: bytes, *, mtime_ns: int) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(salt + bytes(key_init.PAGE_SIZE - len(salt)))
        os.utime(path, ns=(mtime_ns, mtime_ns))

    def make_account(
        self,
        name: str,
        seed: int,
        *,
        mtime_ns: int,
        optional_targets: bool = True,
    ) -> key_init.AccountCandidate:
        db_base = self.root / name / "db_storage"
        self._write_db(
            db_base / "contact/contact.db",
            bytes([seed]) * 16,
            mtime_ns=mtime_ns,
        )
        self._write_db(
            db_base / "message/message_0.db",
            bytes([seed + 1]) * 16,
            mtime_ns=mtime_ns,
        )
        if optional_targets:
            self._write_db(
                db_base / "message/media_0.db",
                bytes([seed + 2]) * 16,
                mtime_ns=mtime_ns,
            )
            self._write_db(
                db_base / "message/message_resource.db",
                bytes([seed + 3]) * 16,
                mtime_ns=mtime_ns,
            )
        candidates = key_init.discover_account_candidates(self.root)
        return next(item for item in candidates if item.db_base.parent.name == name)

    def pid_path_probe(self, pid: int) -> Path:
        return self.pid_paths[pid]

    @staticmethod
    def lsof_output(mapping: dict[int, Sequence[tuple[str, str]]]) -> str:
        lines: list[str] = []
        for pid, items in mapping.items():
            lines.extend(("p%d" % pid, "cWeChat"))
            for fd, path in items:
                lines.extend(("f" + fd, "n" + path))
        return "\n".join(lines) + "\n"

    def target_path(self, candidate: key_init.AccountCandidate, alias: str) -> str:
        return str(candidate.targets[alias].path.resolve())

    def bind(
        self,
        runner: ScriptedRunner,
        *,
        pid_path_probe: Optional[Callable[[int], Path]] = None,
    ) -> router.ActiveAccountBinding:
        return router.bind_active_account(
            app_path=self.app,
            xwechat_root=self.root,
            sample_interval_seconds=0,
            runner=runner,
            pid_path_probe=pid_path_probe or self.pid_path_probe,
            signature_verifier=lambda _app: True,
            sleep_function=lambda _seconds: None,
        )


class ActiveAccountRouterTests(RouterFixture):
    def test_unique_binding_uses_open_handles_and_never_newest_mtime(self) -> None:
        active = self.make_account(
            "wxid_private_active", 10, mtime_ns=1_000_000_000
        )
        newest = self.make_account(
            "wxid_private_newest", 30, mtime_ns=9_000_000_000
        )
        self.assertEqual(
            key_init.discover_account_candidates(self.root)[0].account_ref,
            newest.account_ref,
            "the fixture must put the inactive account first by mtime",
        )
        held = [
            ("10u", self.target_path(active, "contact")),
            ("11u", self.target_path(active, "message_0")),
            ("12u", self.target_path(active, "media_0")),
            ("13u", self.target_path(active, "message_resource")),
        ]
        output = self.lsof_output(
            {101: held, 102: [("txt", str(self.helper_executable))]}
        )
        scripted = ScriptedRunner(
            pgrep_results=[(0, "101\n102\n"), (0, "101\n102\n")],
            lsof_results=[(0, output, ""), (0, output, "")],
        )
        binding = self.bind(scripted)
        self.assertEqual(binding.account_ref, active.account_ref)
        self.assertEqual(
            binding.held_categories,
            ("contact", "media", "message", "message_resource"),
        )

        public = binding.public_report()
        serialized = json.dumps(public, sort_keys=True)
        self.assertEqual(public["status"], "unique")
        self.assertNotIn(active.account_ref, serialized)
        self.assertNotIn("wxid_private", serialized)
        self.assertNotIn(str(self.base), serialized)
        self.assertNotIn("101", serialized)
        self.assertNotIn(active.account_ref, repr(binding))

    def test_no_open_database_handles_fails_closed(self) -> None:
        self.make_account("wxid_private_a", 10, mtime_ns=1_000_000_000)
        output = self.lsof_output(
            {
                101: [("9u", str(self.base / "unrelated"))],
                102: [("txt", str(self.helper_executable))],
            }
        )
        scripted = ScriptedRunner(
            pgrep_results=[(0, "101\n102\n"), (0, "101\n102\n")],
            lsof_results=[(0, output, ""), (0, output, "")],
        )
        with self.assertRaises(router.AccountRoutingError) as caught:
            self.bind(scripted)
        self.assertEqual(caught.exception.code, "no-active-account")
        self.assertFalse(caught.exception.public_report()["selected"])

    def test_multiple_accounts_with_any_database_handles_is_ambiguous(self) -> None:
        first = self.make_account("wxid_private_a", 10, mtime_ns=1_000_000_000)
        second = self.make_account("wxid_private_b", 30, mtime_ns=2_000_000_000)
        held = [
            ("10u", self.target_path(first, "contact")),
            ("11u", self.target_path(first, "message_0")),
            ("12u", self.target_path(second, "contact")),
        ]
        output = self.lsof_output(
            {101: held, 102: [("txt", str(self.helper_executable))]}
        )
        scripted = ScriptedRunner(
            pgrep_results=[(0, "101\n102\n"), (0, "101\n102\n")],
            lsof_results=[(0, output, ""), (0, output, "")],
        )
        with self.assertRaises(router.AccountRoutingError) as caught:
            self.bind(scripted)
        self.assertEqual(caught.exception.code, "multiple-active-accounts")

    def test_account_switch_between_samples_is_unstable(self) -> None:
        first = self.make_account("wxid_private_a", 10, mtime_ns=1_000_000_000)
        second = self.make_account("wxid_private_b", 30, mtime_ns=2_000_000_000)
        output_a = self.lsof_output(
            {
                101: [
                    ("10u", self.target_path(first, "contact")),
                    ("11u", self.target_path(first, "message_0")),
                ],
                102: [("txt", str(self.helper_executable))],
            }
        )
        output_b = self.lsof_output(
            {
                101: [
                    ("10u", self.target_path(second, "contact")),
                    ("11u", self.target_path(second, "message_0")),
                ],
                102: [("txt", str(self.helper_executable))],
            }
        )
        scripted = ScriptedRunner(
            pgrep_results=[(0, "101\n102\n"), (0, "101\n102\n")],
            lsof_results=[(0, output_a, ""), (0, output_b, "")],
        )
        with self.assertRaises(router.AccountRoutingError) as caught:
            self.bind(scripted)
        self.assertEqual(caught.exception.code, "unstable")

    def test_contact_without_main_message_database_is_insufficient(self) -> None:
        candidate = self.make_account(
            "wxid_private_a", 10, mtime_ns=1_000_000_000
        )
        output = self.lsof_output(
            {
                101: [("10u", self.target_path(candidate, "contact"))],
                102: [("txt", str(self.helper_executable))],
            }
        )
        scripted = ScriptedRunner(
            pgrep_results=[(0, "101\n102\n"), (0, "101\n102\n")],
            lsof_results=[(0, output, ""), (0, output, "")],
        )
        with self.assertRaises(router.AccountRoutingError) as caught:
            self.bind(scripted)
        self.assertEqual(caught.exception.code, "no-active-account")

    def test_sidecars_alone_are_not_core_evidence(self) -> None:
        candidate = self.make_account(
            "wxid_private_a", 10, mtime_ns=1_000_000_000
        )
        output = self.lsof_output(
            {
                101: [
                    ("10u", self.target_path(candidate, "contact") + "-wal"),
                    ("11u", self.target_path(candidate, "message_0") + "-shm"),
                ],
                102: [("txt", str(self.helper_executable))],
            }
        )
        scripted = ScriptedRunner(
            pgrep_results=[(0, "101\n102\n"), (0, "101\n102\n")],
            lsof_results=[(0, output, ""), (0, output, "")],
        )
        with self.assertRaises(router.AccountRoutingError) as caught:
            self.bind(scripted)
        self.assertEqual(caught.exception.code, "no-active-account")

    def test_only_numeric_file_descriptors_are_evidence(self) -> None:
        candidate = self.make_account(
            "wxid_private_a", 10, mtime_ns=1_000_000_000
        )
        output = self.lsof_output(
            {
                101: [
                    ("txt", self.target_path(candidate, "contact")),
                    ("mem", self.target_path(candidate, "message_0")),
                ],
                102: [("txt", str(self.helper_executable))],
            }
        )
        scripted = ScriptedRunner(
            pgrep_results=[(0, "101\n102\n"), (0, "101\n102\n")],
            lsof_results=[(0, output, ""), (0, output, "")],
        )
        with self.assertRaises(router.AccountRoutingError) as caught:
            self.bind(scripted)
        self.assertEqual(caught.exception.code, "no-active-account")

    def test_path_lookalikes_are_not_exact_matches(self) -> None:
        candidate = self.make_account(
            "wxid_private_a", 10, mtime_ns=1_000_000_000
        )
        output = self.lsof_output(
            {
                101: [
                    ("10u", self.target_path(candidate, "contact") + ".copy"),
                    ("11u", self.target_path(candidate, "message_0") + ".copy"),
                ],
                102: [("txt", str(self.helper_executable))],
            }
        )
        scripted = ScriptedRunner(
            pgrep_results=[(0, "101\n102\n"), (0, "101\n102\n")],
            lsof_results=[(0, output, ""), (0, output, "")],
        )
        with self.assertRaises(router.AccountRoutingError) as caught:
            self.bind(scripted)
        self.assertEqual(caught.exception.code, "no-active-account")

    def test_lsof_partial_or_error_result_is_unavailable(self) -> None:
        candidate = self.make_account(
            "wxid_private_a", 10, mtime_ns=1_000_000_000
        )
        partial = self.lsof_output(
            {
                101: [
                    ("10u", self.target_path(candidate, "contact")),
                    ("11u", self.target_path(candidate, "message_0")),
                ],
                102: [("txt", str(self.helper_executable))],
            }
        )
        scripted = ScriptedRunner(
            pgrep_results=[(0, "101\n102\n")],
            lsof_results=[(1, partial, "")],
        )
        with self.assertRaises(router.AccountRoutingError) as caught:
            self.bind(scripted)
        self.assertEqual(caught.exception.code, "unavailable")
        self.assertEqual(caught.exception.samples_completed, 0)

    def test_unexpected_lsof_pid_is_unavailable_and_report_is_redacted(self) -> None:
        self.make_account("wxid_private_a", 10, mtime_ns=1_000_000_000)
        output = self.lsof_output(
            {999: [("10u", str(self.base / "private-secret"))]}
        )
        scripted = ScriptedRunner(
            pgrep_results=[(0, "101\n102\n")],
            lsof_results=[(0, output, "")],
        )
        with self.assertRaises(router.AccountRoutingError) as caught:
            self.bind(scripted)
        report = json.dumps(caught.exception.public_report(), sort_keys=True)
        self.assertEqual(caught.exception.code, "unavailable")
        self.assertNotIn("999", report)
        self.assertNotIn("private-secret", report)
        self.assertNotIn(str(self.base), report)

    def test_process_executable_outside_official_bundle_fails_closed(self) -> None:
        self.make_account("wxid_private_a", 10, mtime_ns=1_000_000_000)
        outside = self.base / "self-signed-copy/WeChat"
        outside.parent.mkdir()
        outside.write_bytes(b"copy")
        outside.chmod(0o755)

        def outside_probe(_pid: int) -> Path:
            return outside

        scripted = ScriptedRunner(
            pgrep_results=[(0, "101\n")],
            lsof_results=[],
        )
        with self.assertRaises(router.AccountRoutingError) as caught:
            self.bind(scripted, pid_path_probe=outside_probe)
        self.assertEqual(caught.exception.code, "unstable")

    def test_process_path_change_during_lsof_is_unstable(self) -> None:
        candidate = self.make_account(
            "wxid_private_a", 10, mtime_ns=1_000_000_000
        )
        output = self.lsof_output(
            {
                101: [
                    ("10u", self.target_path(candidate, "contact")),
                    ("11u", self.target_path(candidate, "message_0")),
                ]
            }
        )
        outside = self.base / "replacement/WeChat"
        outside.parent.mkdir()
        outside.write_bytes(b"copy")
        outside.chmod(0o755)
        calls = 0

        def changing_probe(_pid: int) -> Path:
            nonlocal calls
            calls += 1
            return self.main_executable if calls == 1 else outside

        scripted = ScriptedRunner(
            pgrep_results=[(0, "101\n")],
            lsof_results=[(0, output, "")],
        )
        with self.assertRaises(router.AccountRoutingError) as caught:
            self.bind(scripted, pid_path_probe=changing_probe)
        self.assertEqual(caught.exception.code, "unstable")

    def test_database_inode_change_during_lsof_is_unstable(self) -> None:
        candidate = self.make_account(
            "wxid_private_a", 10, mtime_ns=1_000_000_000
        )
        contact = candidate.targets["contact"].path
        output = self.lsof_output(
            {
                101: [
                    ("10u", str(contact.resolve())),
                    ("11u", self.target_path(candidate, "message_0")),
                ],
                102: [("txt", str(self.helper_executable))],
            }
        )

        def replace_contact(index: int) -> None:
            if index != 0:
                return
            replacement = contact.with_suffix(".replacement")
            replacement.write_bytes(b"R" * key_init.PAGE_SIZE)
            os.replace(replacement, contact)

        scripted = ScriptedRunner(
            pgrep_results=[(0, "101\n102\n")],
            lsof_results=[(0, output, "")],
            on_lsof=replace_contact,
        )
        with self.assertRaises(router.AccountRoutingError) as caught:
            self.bind(scripted)
        self.assertEqual(caught.exception.code, "unstable")

    def test_no_official_process_is_not_replaced_by_directory_guessing(self) -> None:
        self.make_account("wxid_private_a", 10, mtime_ns=9_000_000_000)
        scripted = ScriptedRunner(
            pgrep_results=[(1, ""), (1, "")],
            lsof_results=[],
        )
        with self.assertRaises(router.AccountRoutingError) as caught:
            self.bind(scripted)
        self.assertEqual(caught.exception.code, "no-active-account")

    def test_optional_handle_changes_do_not_break_same_core_binding(self) -> None:
        candidate = self.make_account(
            "wxid_private_a", 10, mtime_ns=1_000_000_000
        )
        core = [
            ("10u", self.target_path(candidate, "contact")),
            ("11u", self.target_path(candidate, "message_0")),
        ]
        first = self.lsof_output(
            {
                101: core + [("12u", self.target_path(candidate, "media_0"))],
                102: [("txt", str(self.helper_executable))],
            }
        )
        second = self.lsof_output(
            {101: core, 102: [("txt", str(self.helper_executable))]}
        )
        scripted = ScriptedRunner(
            pgrep_results=[(0, "101\n102\n"), (0, "101\n102\n")],
            lsof_results=[(0, first, ""), (0, second, "")],
        )
        binding = self.bind(scripted)
        self.assertEqual(binding.account_ref, candidate.account_ref)
        self.assertEqual(binding.held_categories, ("contact", "message"))

    def test_official_helper_process_churn_does_not_change_account_binding(self) -> None:
        candidate = self.make_account(
            "wxid_private_a", 10, mtime_ns=1_000_000_000
        )
        second_helper = self.app / "Contents/Frameworks/OtherHelper"
        second_helper.write_bytes(b"helper")
        second_helper.chmod(0o755)
        self.pid_paths[103] = second_helper
        core = [
            ("10u", self.target_path(candidate, "contact")),
            ("11u", self.target_path(candidate, "message_0")),
        ]
        first = self.lsof_output(
            {101: core, 102: [("txt", str(self.helper_executable))]}
        )
        second = self.lsof_output(
            {101: core, 103: [("txt", str(second_helper))]}
        )
        scripted = ScriptedRunner(
            pgrep_results=[(0, "101\n102\n"), (0, "101\n103\n")],
            lsof_results=[(0, first, ""), (0, second, "")],
        )
        binding = self.bind(scripted)
        self.assertEqual(binding.account_ref, candidate.account_ref)
        self.assertEqual(binding.official_process_count, 2)

    def test_invalid_official_signature_fails_before_process_inspection(self) -> None:
        self.make_account("wxid_private_a", 10, mtime_ns=1_000_000_000)
        scripted = ScriptedRunner(pgrep_results=[], lsof_results=[])
        with self.assertRaises(router.AccountRoutingError) as caught:
            router.bind_active_account(
                app_path=self.app,
                xwechat_root=self.root,
                runner=scripted,
                signature_verifier=lambda _app: False,
                pid_path_probe=self.pid_path_probe,
                sleep_function=lambda _seconds: None,
            )
        self.assertEqual(caught.exception.code, "unavailable")
        self.assertEqual(scripted.pgrep_calls, 0)


if __name__ == "__main__":
    unittest.main()
