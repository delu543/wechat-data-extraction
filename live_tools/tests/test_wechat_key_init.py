from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import plistlib
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from live_tools import wechat_key_init as key_init


class FixtureMixin:
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def make_db_tree(self) -> tuple[Path, Path]:
        root = self.base / "xwechat_files"
        db_base = root / "wxid_fixture" / "db_storage"
        (db_base / "contact").mkdir(parents=True)
        (db_base / "message").mkdir()
        return root, db_base

    def write_db(self, path: Path, salt: bytes, *, size: int = key_init.PAGE_SIZE) -> None:
        path.write_bytes(salt + bytes(size - len(salt)))

    def write_encrypted_first_page(self, path: Path, salt: bytes, key: bytes) -> None:
        from Crypto.Cipher import AES

        plaintext = bytearray(key_init.PAGE_SIZE)
        plaintext[:16] = key_init.SQLITE_HEADER
        plaintext[16:18] = struct_pack_u16(key_init.PAGE_SIZE)
        plaintext[18] = 2
        plaintext[19] = 2
        plaintext[20] = key_init.RESERVE_SIZE
        plaintext[21] = 64
        plaintext[22] = 32
        plaintext[23] = 32
        iv = bytes(range(16))
        encrypted_end = key_init.PAGE_SIZE - key_init.RESERVE_SIZE
        ciphertext = AES.new(key, AES.MODE_CBC, iv).encrypt(
            plaintext[16:encrypted_end]
        )
        page = bytearray(key_init.PAGE_SIZE)
        page[:16] = salt
        page[16:encrypted_end] = ciphertext
        page[encrypted_end : encrypted_end + 16] = iv
        path.write_bytes(page)

    def make_app(
        self,
        bundle_id: str = key_init.EXPECTED_BUNDLE_ID,
        version: str = "4.1.11",
        app_name: str = "微信.app",
    ) -> Path:
        app = self.base / app_name
        contents = app / "Contents"
        macos = contents / "MacOS"
        macos.mkdir(parents=True)
        with (contents / "Info.plist").open("wb") as handle:
            plistlib.dump(
                {
                    "CFBundleIdentifier": bundle_id,
                    "CFBundleExecutable": "WeChat",
                    "CFBundleShortVersionString": version,
                },
                handle,
            )
        executable = macos / "WeChat"
        executable.write_bytes(b"#!/bin/sh\nexit 0\n")
        executable.chmod(0o755)
        return app

    def make_private_dir(self) -> Path:
        private = self.base / "private"
        private.mkdir(mode=0o700)
        private.chmod(0o700)
        return private

    @staticmethod
    def routed_unique(account_ref: str) -> tuple[str, dict[str, object], None]:
        return (
            account_ref,
            {
                "status": "unique",
                "selected": True,
                "method": "official-process-numeric-fd-exact-match",
                "samples_completed": 2,
                "official_process_count": 2,
                "held_categories": ["contact", "message"],
                "core_evidence": {"contact": True, "message": True},
                "writes_performed": False,
            },
            None,
        )

    @staticmethod
    def routed_failure(code: str) -> tuple[None, dict[str, object], str]:
        return (
            None,
            {
                "status": code,
                "selected": False,
                "method": "official-process-numeric-fd-exact-match",
                "samples_completed": 2,
                "writes_performed": False,
            },
            code,
        )


class PathValidationTests(FixtureMixin, unittest.TestCase):
    def test_accepts_exact_one_account_db_storage(self) -> None:
        root, db_base = self.make_db_tree()
        self.assertEqual(key_init.validate_db_base(db_base, root), db_base.resolve())

    def test_rejects_nested_or_outside_db_storage(self) -> None:
        root, db_base = self.make_db_tree()
        nested = db_base / "nested" / "db_storage"
        nested.mkdir(parents=True)
        with self.assertRaises(key_init.SafeInitError):
            key_init.validate_db_base(nested, root)
        outside = self.base / "elsewhere" / "db_storage"
        outside.mkdir(parents=True)
        with self.assertRaises(key_init.SafeInitError):
            key_init.validate_db_base(outside, root)

    def test_rejects_symlink_db_base(self) -> None:
        root, db_base = self.make_db_tree()
        link = root / "linked-db"
        link.symlink_to(db_base, target_is_directory=True)
        with self.assertRaises(key_init.SafeInitError):
            key_init.validate_db_base(link, root)

    def test_targets_are_exact_and_never_broad(self) -> None:
        self.assertEqual(
            key_init.parse_targets("contact,message_0,media_12,message_resource"),
            ("contact", "message_0", "media_12", "message_resource"),
        )
        self.assertEqual(
            key_init.target_relative_path("message_resource"),
            "message/message_resource.db",
        )
        for unsafe in (
            "all",
            "message",
            "message_*",
            "message_00",
            "../contact",
            "contact.db",
            "contact,contact",
            "contact,",
        ):
            with self.subTest(unsafe=unsafe), self.assertRaises(key_init.SafeInitError):
                key_init.parse_targets(unsafe)

    def test_inspect_targets_accepts_only_regular_non_symlink_files(self) -> None:
        _root, db_base = self.make_db_tree()
        self.write_db(db_base / "contact/contact.db", b"A" * 16)
        self.write_db(db_base / "message/message_0.db", b"B" * 16)
        targets = key_init.inspect_targets(db_base, ("contact", "message_0"))
        self.assertEqual(set(targets), {"contact", "message_0"})
        self.assertEqual(targets["message_0"].salt, b"B" * 16)

        target = db_base / "message/media_0.db"
        real = db_base / "message/real-media.db"
        self.write_db(real, b"C" * 16)
        target.symlink_to(real)
        with self.assertRaises(key_init.SafeInitError):
            key_init.inspect_targets(db_base, ("media_0",))

    def test_rejects_duplicate_target_salts(self) -> None:
        _root, db_base = self.make_db_tree()
        self.write_db(db_base / "message/message_0.db", b"S" * 16)
        self.write_db(db_base / "message/media_0.db", b"S" * 16)
        with self.assertRaises(key_init.SafeInitError):
            key_init.inspect_targets(db_base, ("message_0", "media_0"))

    def test_rejects_partial_database_page(self) -> None:
        _root, db_base = self.make_db_tree()
        self.write_db(
            db_base / "message/message_0.db",
            b"P" * 16,
            size=key_init.PAGE_SIZE + 1,
        )
        with self.assertRaises(key_init.SafeInitError):
            key_init.inspect_targets(db_base, ("message_0",))


class AccountDiscoveryAndDoctorTests(FixtureMixin, unittest.TestCase):
    def make_discoverable_account(self) -> tuple[Path, Path, bytes]:
        root, db_base = self.make_db_tree()
        salt = b"A" * 16
        self.write_db(db_base / "contact/contact.db", salt)
        self.write_db(db_base / "message/message_0.db", b"B" * 16)
        self.write_db(db_base / "message/media_0.db", b"C" * 16)
        self.write_db(db_base / "message/message_resource.db", b"D" * 16)
        self.write_db(db_base / "message/message_fts.db", b"E" * 16)
        self.write_db(
            db_base / "message/message_1.db",
            b"F" * 16,
            size=key_init.PAGE_SIZE + 1,
        )
        external = self.base / "external.db"
        self.write_db(external, b"G" * 16)
        (db_base / "message/media_1.db").symlink_to(external)
        return root, db_base, salt

    def test_discovers_only_safe_exact_targets_and_resolves_reference(self) -> None:
        root, db_base, _salt = self.make_discoverable_account()
        candidates = key_init.discover_account_candidates(root)
        self.assertEqual(len(candidates), 1)
        candidate = candidates[0]
        self.assertRegex(candidate.account_ref, r"^account-[0-9a-f]{12}$")
        self.assertEqual(
            set(candidate.targets),
            {"contact", "message_0", "media_0", "message_resource"},
        )
        self.assertEqual(key_init.resolve_account_ref(candidate.account_ref, root), db_base.resolve())
        with self.assertRaises(key_init.SafeInitError):
            key_init.resolve_account_ref("account-000000000000", root)

        args = argparse.Namespace(account_ref=candidate.account_ref, db_base=None)
        self.assertEqual(key_init.requested_db_base(args, xwechat_root=root), db_base.resolve())

        renamed = root / "different-private-account-name"
        db_base.parent.rename(renamed)
        self.assertEqual(
            key_init.discover_account_candidates(root)[0].account_ref,
            candidate.account_ref,
            "the public reference must derive from database identity, not the account name",
        )

    def test_more_than_twenty_valid_accounts_fails_closed_without_a_path(self) -> None:
        root = self.base / "xwechat_files"
        root.mkdir()
        for index in range(key_init.MAX_ACCOUNT_CANDIDATES + 1):
            db_base = root / ("private-account-%02d" % index) / "db_storage"
            (db_base / "contact").mkdir(parents=True)
            (db_base / "message").mkdir()
            self.write_db(db_base / "contact/contact.db", bytes([index + 1]) * 16)
            self.write_db(db_base / "message/message_0.db", bytes([index + 101]) * 16)
        with self.assertRaises(key_init.SafeInitError) as caught:
            key_init.discover_account_candidates(root)
        self.assertNotIn(str(root), str(caught.exception))
        self.assertNotIn("private-account", str(caught.exception))

    def test_account_parser_requires_exactly_one_reference_or_path(self) -> None:
        parser = key_init.build_parser()
        parsed = parser.parse_args(
            ["dry-scan", "--account-ref", "account-0123456789ab", "--targets", "contact"]
        )
        self.assertEqual(parsed.account_ref, "account-0123456789ab")
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                parser.parse_args(["dry-scan", "--targets", "contact"])
            with self.assertRaises(SystemExit):
                parser.parse_args(
                    [
                        "dry-scan",
                        "--account-ref",
                        "account-0123456789ab",
                        "--db-base",
                        "/tmp/db_storage",
                        "--targets",
                        "contact",
                    ]
                )
            with self.assertRaises(SystemExit):
                parser.parse_args(
                    [
                        "capture",
                        "--account-ref",
                        "account-0123456789ab",
                        "--targets",
                        "contact",
                    ]
                )
        capture = parser.parse_args(
            [
                "capture",
                "--account-ref",
                "account-0123456789ab",
                "--targets",
                "contact",
                "--approve-digest",
                "A" * 64,
            ]
        )
        self.assertEqual(capture.approve_digest, "a" * 64)

    def test_setup_doctor_is_read_only_and_does_not_expose_paths_or_account_names(self) -> None:
        root, _db_base, raw_salt = self.make_discoverable_account()
        candidate = key_init.discover_account_candidates(root)[0]
        app = self.make_app()
        private = self.base / "private-does-not-exist"
        before = set(self.base.rglob("*"))

        def fake_runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess:
            if command[0] == "/usr/bin/codesign":
                return subprocess.CompletedProcess(command, 0, "", "")
            if command[0] == "/usr/bin/pgrep":
                return subprocess.CompletedProcess(command, 0, "123\n", "")
            return subprocess.CompletedProcess(command, 2, "", "")

        with mock.patch.object(
            key_init,
            "_route_current_account",
            return_value=self.routed_unique(candidate.account_ref),
        ):
            report = key_init.build_setup_doctor_report(
                app_path=app,
                xwechat_root=root,
                private_dir=private,
                runner=fake_runner,
            )
        after = set(self.base.rglob("*"))
        serialized = json.dumps(report, ensure_ascii=False)
        self.assertEqual(before, after)
        self.assertFalse(report["writes_performed"])
        self.assertEqual(report["mode"], "read-only")
        self.assertEqual(report["application"]["bundle_id"], key_init.EXPECTED_BUNDLE_ID)
        self.assertEqual(report["local_storage"]["status"], "readable")
        self.assertEqual(report["account_ref"], candidate.account_ref)
        self.assertEqual(report["current_account"]["status"], "unique")
        self.assertNotIn("accounts", report)
        self.assertNotIn("candidate_number", serialized)
        self.assertNotIn("last_database_update", serialized)
        self.assertNotIn("total_bytes", serialized)
        self.assertNotIn("wxid_fixture", serialized)
        self.assertNotIn(str(self.base), serialized)
        self.assertNotIn(raw_salt.hex(), serialized)

    def test_doctor_multiple_current_accounts_fails_without_candidate_list(self) -> None:
        root, db_base, _raw_salt = self.make_discoverable_account()
        second = root / "second-private-account" / "db_storage"
        (second / "contact").mkdir(parents=True)
        (second / "message").mkdir()
        self.write_db(second / "contact/contact.db", b"H" * 16)
        self.write_db(second / "message/message_0.db", b"I" * 16)
        app = self.make_app()

        def running_and_signed(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess:
            if command[0] == "/usr/bin/codesign":
                return subprocess.CompletedProcess(command, 0, "", "")
            if command[0] == "/usr/bin/pgrep":
                return subprocess.CompletedProcess(command, 0, "123\n", "")
            return subprocess.CompletedProcess(command, 2, "", "")

        with mock.patch.object(
            key_init, "_route_current_account", return_value=self.routed_failure(
                "multiple-active-accounts"
            )
        ), mock.patch.object(
            key_init, "dependency_status", return_value={"frida": False, "pycryptodome": True}
        ):
            report = key_init.build_setup_doctor_report(
                app_path=app,
                xwechat_root=root,
                private_dir=self.base / "absent-private",
                runner=running_and_signed,
            )
        codes = [item["code"] for item in report["blockers"]]
        self.assertIn("missing-frida", codes)
        self.assertIn("multiple-active-accounts", codes)
        self.assertEqual(report["next_action"], "resolve-reported-prerequisites")
        self.assertFalse(report["prerequisites_ready"])
        self.assertNotIn("accounts", report)
        self.assertIsNone(report["account_ref"])

    def test_doctor_keeps_app_validation_separate_from_process_inspection(self) -> None:
        root, _db_base, _raw_salt = self.make_discoverable_account()
        app = self.make_app()

        def process_unavailable(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess:
            if command[0] == "/usr/bin/codesign":
                return subprocess.CompletedProcess(command, 0, "", "")
            if command[0] == "/usr/bin/pgrep":
                return subprocess.CompletedProcess(command, 2, "", "")
            return subprocess.CompletedProcess(command, 2, "", "")

        with mock.patch.object(
            key_init,
            "dependency_status",
            return_value={"frida": True, "pycryptodome": True},
        ):
            report = key_init.build_setup_doctor_report(
                app_path=app,
                xwechat_root=root,
                private_dir=self.base / "absent-private",
                runner=process_unavailable,
            )
        codes = [item["code"] for item in report["blockers"]]
        self.assertEqual(report["application"]["status"], "validated")
        self.assertEqual(report["application"]["process_state"], "unavailable")
        self.assertIn("unavailable", codes)
        self.assertNotIn("wechat-4x-validation-failed", codes)

    def test_doctor_fails_closed_for_every_non_unique_route_result(self) -> None:
        root, _db_base, _raw_salt = self.make_discoverable_account()
        app = self.make_app()

        def signed_and_running(
            command: list[str], **_kwargs: object
        ) -> subprocess.CompletedProcess:
            if command[0] == "/usr/bin/codesign":
                return subprocess.CompletedProcess(command, 0, "", "")
            if command[0] == "/usr/bin/pgrep":
                return subprocess.CompletedProcess(command, 0, "123\n", "")
            return subprocess.CompletedProcess(command, 2, "", "")

        for code in (
            "no-active-account",
            "multiple-active-accounts",
            "unstable",
            "unavailable",
        ):
            with self.subTest(code=code), mock.patch.object(
                key_init,
                "_route_current_account",
                return_value=self.routed_failure(code),
            ), mock.patch.object(
                key_init,
                "dependency_status",
                return_value={"frida": True, "pycryptodome": True},
            ):
                report = key_init.build_setup_doctor_report(
                    app_path=app,
                    xwechat_root=root,
                    private_dir=self.base / "absent-private",
                    runner=signed_and_running,
                )
            self.assertIn(code, [item["code"] for item in report["blockers"]])
            self.assertFalse(report["prerequisites_ready"])
            self.assertFalse(report["ready_for_dry_scan"])
            self.assertIsNone(report["account_ref"])
            self.assertEqual(report["targets"], [])
            serialized = json.dumps(report, sort_keys=True)
            self.assertNotIn("wxid_fixture", serialized)
            self.assertNotIn(str(self.base), serialized)
            self.assertNotIn('"accounts"', serialized)

    def test_existing_initialization_does_not_require_capture_process_probe_or_frida(self) -> None:
        root, _db_base, _raw_salt = self.make_discoverable_account()
        candidate = key_init.discover_account_candidates(root)[0]
        private = self.make_private_dir()
        key_init.write_success_files(
            private,
            candidate.db_base,
            candidate.targets,
            {name: "0" * 64 for name in candidate.targets},
        )
        app = self.make_app()

        def signed_and_running(
            command: list[str], **_kwargs: object
        ) -> subprocess.CompletedProcess:
            if command[0] == "/usr/bin/codesign":
                return subprocess.CompletedProcess(command, 0, "", "")
            if command[0] == "/usr/bin/pgrep":
                return subprocess.CompletedProcess(command, 0, "123\n", "")
            return subprocess.CompletedProcess(command, 2, "", "")

        with mock.patch.object(
            key_init,
            "_route_current_account",
            return_value=self.routed_unique(candidate.account_ref),
        ), mock.patch.object(
            key_init, "dependency_status", return_value={"frida": False, "pycryptodome": True}
        ):
            report = key_init.build_setup_doctor_report(
                app_path=app,
                xwechat_root=root,
                private_dir=private,
                runner=signed_and_running,
            )
        codes = [item["code"] for item in report["blockers"]]
        self.assertTrue(report["existing_initialization_ready"])
        self.assertNotIn("missing-frida", codes)
        self.assertNotIn("unavailable", codes)
        self.assertEqual(report["next_action"], "use-existing-initialization")

    def test_doctor_accepts_exact_legacy_state_after_read_only_page_validation(self) -> None:
        root, db_base = self.make_db_tree()
        contact_key = bytes.fromhex("51" * 32)
        message_key = bytes.fromhex("52" * 32)
        self.write_encrypted_first_page(
            db_base / "contact/contact.db", b"A" * 16, contact_key
        )
        self.write_encrypted_first_page(
            db_base / "message/message_0.db", b"B" * 16, message_key
        )
        candidate = key_init.discover_account_candidates(root)[0]
        private = self.make_private_dir()
        key_init.atomic_write_json(
            private / key_init.KEYS_FILENAME,
            {"contact": contact_key.hex(), "message_0": message_key.hex()},
        )
        key_init.atomic_write_json(
            private / key_init.CONFIG_FILENAME,
            {
                "schema_version": 1,
                "db_base_path": str(candidate.db_base),
                "keys_file": str(private / key_init.KEYS_FILENAME),
                "target_count": 2,
                "targets": {
                    "contact": "contact/contact.db",
                    "message_0": "message/message_0.db",
                },
            },
        )
        app = self.make_app()

        def signed_and_running(
            command: list[str], **_kwargs: object
        ) -> subprocess.CompletedProcess:
            if command[0] == "/usr/bin/codesign":
                return subprocess.CompletedProcess(command, 0, "", "")
            if command[0] == "/usr/bin/pgrep":
                return subprocess.CompletedProcess(command, 0, "123\n", "")
            return subprocess.CompletedProcess(command, 2, "", "")

        before = {
            path.name: path.read_bytes()
            for path in (private / key_init.KEYS_FILENAME, private / key_init.CONFIG_FILENAME)
        }
        with mock.patch.object(
            key_init,
            "_route_current_account",
            return_value=self.routed_unique(candidate.account_ref),
        ), mock.patch.object(
            key_init, "dependency_status", return_value={"frida": False, "pycryptodome": True}
        ):
            report = key_init.build_setup_doctor_report(
                app_path=app,
                xwechat_root=root,
                private_dir=private,
                runner=signed_and_running,
            )
        self.assertTrue(report["existing_initialization_ready"])
        self.assertTrue(report["private_state"]["legacy_exact_validated"])
        self.assertEqual(report["private_state"]["salt_state"], "validated-legacy")
        self.assertEqual(
            before,
            {
                path.name: path.read_bytes()
                for path in (
                    private / key_init.KEYS_FILENAME,
                    private / key_init.CONFIG_FILENAME,
                )
            },
        )

    def test_setup_doctor_exit_code_requires_ready_or_existing_initialization(self) -> None:
        blocked = {"ready_for_capture": False, "existing_initialization_ready": False}
        ready = {"ready_for_capture": True, "existing_initialization_ready": False}
        args = argparse.Namespace(app=str(self.make_app()))
        with mock.patch.object(key_init, "build_setup_doctor_report", return_value=blocked):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(key_init.run_setup_doctor(args), 2)
        with mock.patch.object(key_init, "build_setup_doctor_report", return_value=ready):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(key_init.run_setup_doctor(args), 0)

    def test_private_state_reports_salt_match_then_change_without_exposing_key(self) -> None:
        root, _db_base, _salt = self.make_discoverable_account()
        candidate = key_init.discover_account_candidates(root)[0]
        private = self.make_private_dir()
        keys = {name: ("0" * 64) for name in candidate.targets}
        key_init.write_success_files(private, candidate.db_base, candidate.targets, keys)

        matching = key_init.inspect_existing_private_state(private, (candidate,))
        self.assertTrue(matching["initialized"])
        self.assertEqual(matching["salt_state"], "match")
        self.assertEqual(matching["matching_account_ref"], candidate.account_ref)
        self.assertEqual(
            matching["initialized_targets"], sorted(candidate.targets)
        )

        self.write_db(candidate.db_base / "message/message_0.db", b"Z" * 16)
        changed_candidate = key_init.discover_account_candidates(root)[0]
        changed = key_init.inspect_existing_private_state(private, (changed_candidate,))
        self.assertEqual(changed["salt_state"], "changed")

    def test_account_scoped_state_is_schema_two_and_root_legacy_is_exact_only(self) -> None:
        root, _db_base, _salt = self.make_discoverable_account()
        current = key_init.discover_account_candidates(root)[0]
        private = self.make_private_dir()
        keys = {name: "1" * 64 for name in current.targets}

        key_init.write_success_files(
            private,
            current.db_base,
            current.targets,
            keys,
            account_ref=current.account_ref,
        )
        scoped = private / key_init.ACCOUNTS_DIRNAME / current.account_ref
        config = json.loads((scoped / key_init.CONFIG_FILENAME).read_text())
        self.assertEqual(config["schema_version"], 2)
        self.assertEqual(config["account_ref"], current.account_ref)
        self.assertEqual(config["keys_file"], str(scoped / key_init.KEYS_FILENAME))
        self.assertFalse((private / key_init.KEYS_FILENAME).exists())
        state = key_init.inspect_existing_private_state(
            private, (current,), account_ref=current.account_ref
        )
        self.assertEqual(state["state_scope"], "account-scoped")
        self.assertEqual(state["salt_state"], "match")

        other_private = self.base / "legacy-private"
        other_private.mkdir(mode=0o700)
        key_init.write_success_files(
            other_private, current.db_base, current.targets, keys
        )
        other_db = root / "other-private-account" / "db_storage"
        (other_db / "contact").mkdir(parents=True)
        (other_db / "message").mkdir()
        self.write_db(other_db / "contact/contact.db", b"Y" * 16)
        self.write_db(other_db / "message/message_0.db", b"Z" * 16)
        other = next(
            item
            for item in key_init.discover_account_candidates(root)
            if item.account_ref != current.account_ref
        )
        before = {
            path.name: path.read_bytes()
            for path in (
                other_private / key_init.KEYS_FILENAME,
                other_private / key_init.CONFIG_FILENAME,
            )
        }
        ignored = key_init.inspect_existing_private_state(
            other_private, (other,), account_ref=other.account_ref
        )
        self.assertFalse(ignored["initialized"])
        self.assertEqual(ignored["legacy_state"], "different-account-ignored")
        self.assertEqual(ignored["salt_state"], "not-initialized")
        self.assertEqual(
            before,
            {
                path.name: path.read_bytes()
                for path in (
                    other_private / key_init.KEYS_FILENAME,
                    other_private / key_init.CONFIG_FILENAME,
                )
            },
        )

    def test_legacy_without_fingerprints_is_ready_only_after_exact_page_validation(self) -> None:
        root, db_base = self.make_db_tree()
        contact_key = bytes.fromhex("11" * 32)
        message_key = bytes.fromhex("22" * 32)
        self.write_encrypted_first_page(
            db_base / "contact/contact.db", b"C" * 16, contact_key
        )
        self.write_encrypted_first_page(
            db_base / "message/message_0.db", b"M" * 16, message_key
        )
        candidate = key_init.discover_account_candidates(root)[0]
        private = self.make_private_dir()
        key_init.atomic_write_json(
            private / key_init.KEYS_FILENAME,
            {"contact": contact_key.hex(), "message_0": message_key.hex()},
        )
        key_init.atomic_write_json(
            private / key_init.CONFIG_FILENAME,
            {
                "schema_version": 1,
                "db_base_path": str(candidate.db_base),
                "keys_file": str(private / key_init.KEYS_FILENAME),
                "target_count": 2,
                "targets": {
                    "contact": "contact/contact.db",
                    "message_0": "message/message_0.db",
                },
            },
        )
        before = (private / key_init.CONFIG_FILENAME).read_bytes()
        validated = key_init.inspect_existing_private_state(
            private, (candidate,), account_ref=candidate.account_ref
        )
        self.assertTrue(validated["initialized"])
        self.assertTrue(validated["legacy_exact_validated"])
        self.assertEqual(validated["salt_state"], "validated-legacy")
        self.assertEqual((private / key_init.CONFIG_FILENAME).read_bytes(), before)

        key_init.atomic_write_json(
            private / key_init.KEYS_FILENAME,
            {"contact": contact_key.hex(), "message_0": "33" * 32},
        )
        failed = key_init.inspect_existing_private_state(
            private, (candidate,), account_ref=candidate.account_ref
        )
        self.assertFalse(failed["legacy_exact_validated"])
        self.assertEqual(failed["salt_state"], "legacy-validation-failed")

        key_init.atomic_write_json(
            private / key_init.KEYS_FILENAME,
            {
                "contact": contact_key.hex(),
                "message_0": message_key.hex(),
                "media_0": "44" * 32,
            },
        )
        legacy_config = json.loads((private / key_init.CONFIG_FILENAME).read_text())
        legacy_config["target_count"] = 3
        legacy_config["targets"]["media_0"] = "message/media_0.db"
        key_init.atomic_write_json(private / key_init.CONFIG_FILENAME, legacy_config)
        missing = key_init.inspect_existing_private_state(
            private, (candidate,), account_ref=candidate.account_ref
        )
        self.assertTrue(missing["initialized"])
        self.assertEqual(missing["salt_state"], "legacy-validation-failed")


class ApplicationAndRuntimeTests(FixtureMixin, unittest.TestCase):
    def test_validates_bundle_id_and_plist_executable(self) -> None:
        app = self.make_app()
        validated = key_init.validate_wechat_app(app)
        self.assertEqual(validated.bundle_id, key_init.EXPECTED_BUNDLE_ID)
        self.assertEqual(validated.version, "4.1.11")
        self.assertEqual(validated.executable_path.name, "WeChat")

        wrong = self.base / "wrong"
        app.rename(wrong)
        replacement = self.make_app(bundle_id="example.invalid")
        with self.assertRaises(key_init.SafeInitError):
            key_init.validate_wechat_app(replacement)

        for index, unsupported in enumerate(("3.9.12", "5.0.0", "40.1")):
            app = self.make_app(version=unsupported, app_name="unsupported-%d.app" % index)
            with self.subTest(version=unsupported), self.assertRaises(key_init.SafeInitError):
                key_init.validate_wechat_app(app)

    def test_rejects_symlink_declared_executable(self) -> None:
        app = self.make_app()
        executable = app / "Contents/MacOS/WeChat"
        executable.unlink()
        external = self.base / "external-executable"
        external.write_text("#!/bin/sh\n")
        external.chmod(0o755)
        executable.symlink_to(external)
        with self.assertRaises(key_init.SafeInitError):
            key_init.validate_wechat_app(app)

    def test_runtime_copy_is_random_private_and_only_copy_is_signed(self) -> None:
        app_path = self.make_app()
        app = key_init.validate_wechat_app(app_path)
        private = self.make_private_dir()
        original_plist = app_path / "Contents/Info.plist"
        before = (original_plist.stat().st_ino, original_plist.read_bytes())
        calls: list[list[str]] = []
        source_cdhash = "a" * 40

        def fake_runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess:
            calls.append(command)
            if "--display" in command:
                return subprocess.CompletedProcess(
                    command, 0, "", "CDHash=%s\n" % source_cdhash
                )
            return subprocess.CompletedProcess(command, 0, "", "")

        quiescence_checks: list[bool] = []
        runtime = key_init.prepare_runtime_copy(
            app,
            private,
            source_cdhash,
            runner=fake_runner,
            quiescence_check=lambda: quiescence_checks.append(True),
        )
        self.assertTrue(runtime.runtime_dir.is_dir())
        self.assertEqual(stat.S_IMODE(runtime.runtime_dir.stat().st_mode), 0o700)
        self.assertEqual(runtime.runtime_dir.parent, private / key_init.RUNTIME_DIRNAME)
        self.assertTrue((runtime.runtime_dir / key_init.RUNTIME_OWNER_FILENAME).is_file())
        self.assertEqual(len(calls), 4)
        self.assertEqual(Path(calls[0][-1]), runtime.app_copy_path)
        self.assertIn("-R=" + key_init.OFFICIAL_WECHAT_REQUIREMENT, calls[0])
        self.assertIn("--display", calls[1])
        self.assertIn("--force", calls[2])
        self.assertIn("--verify", calls[3])
        self.assertIn("--strict", calls[3])
        self.assertEqual(quiescence_checks, [True, True])
        self.assertNotEqual(Path(calls[0][-1]), app.app_path)
        after = (original_plist.stat().st_ino, original_plist.read_bytes())
        self.assertEqual(before, after)

    def test_runtime_copy_is_removed_if_strict_signature_verify_fails(self) -> None:
        app = key_init.validate_wechat_app(self.make_app())
        private = self.make_private_dir()
        source_cdhash = "b" * 40

        def fake_runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess:
            if "--display" in command:
                return subprocess.CompletedProcess(
                    command, 0, "", "CDHash=%s\n" % source_cdhash
                )
            if "--verify" in command and not any(
                item.startswith("-R=") for item in command
            ):
                return subprocess.CompletedProcess(command, 1, "", "")
            return subprocess.CompletedProcess(command, 0, "", "")

        with self.assertRaises(key_init.SafeInitError):
            key_init.prepare_runtime_copy(
                app, private, source_cdhash, runner=fake_runner
            )
        runtime_root = private / key_init.RUNTIME_DIRNAME
        self.assertEqual(list(runtime_root.iterdir()), [])

    def test_runtime_copy_is_removed_before_resigning_if_cdhash_changes(self) -> None:
        app = key_init.validate_wechat_app(self.make_app())
        private = self.make_private_dir()
        calls: list[list[str]] = []

        def changed_copy(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess:
            calls.append(command)
            if "--display" in command:
                return subprocess.CompletedProcess(
                    command, 0, "", "CDHash=%s\n" % ("f" * 40)
                )
            return subprocess.CompletedProcess(command, 0, "", "")

        with self.assertRaises(key_init.SafeInitError):
            key_init.prepare_runtime_copy(
                app, private, "a" * 40, runner=changed_copy
            )
        self.assertFalse(any("--force" in command for command in calls))
        self.assertEqual(list((private / key_init.RUNTIME_DIRNAME).iterdir()), [])

    def test_runtime_is_removed_if_prepared_recovery_metadata_cannot_be_written(self) -> None:
        app = key_init.validate_wechat_app(self.make_app())
        private = self.make_private_dir()
        source_cdhash = "1" * 40

        def signed(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess:
            if "--display" in command:
                return subprocess.CompletedProcess(
                    command, 0, "", "CDHash=%s\n" % source_cdhash
                )
            return subprocess.CompletedProcess(command, 0, "", "")

        real_atomic_write = key_init.atomic_write_json

        def fail_top_level_runtime(path: Path, data: object) -> None:
            if path.name == key_init.RUNTIME_FILENAME:
                raise key_init.SafeInitError("synthetic metadata failure")
            real_atomic_write(path, data)  # type: ignore[arg-type]

        with mock.patch.object(
            key_init, "atomic_write_json", side_effect=fail_top_level_runtime
        ):
            with self.assertRaises(key_init.SafeInitError):
                key_init.prepare_runtime_copy(
                    app, private, source_cdhash, runner=signed
                )
        self.assertEqual(list((private / key_init.RUNTIME_DIRNAME).iterdir()), [])
        self.assertFalse((private / key_init.RUNTIME_FILENAME).exists())

    def test_capture_guard_fails_closed_when_original_process_is_running(self) -> None:
        app = key_init.validate_wechat_app(self.make_app())
        calls: list[list[str]] = []

        def running(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess:
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, "123\n", "")

        with self.assertRaises(key_init.SafeInitError):
            key_init.assert_original_wechat_stopped(app, runner=running)
        self.assertEqual(calls[0][0:2], ["/usr/bin/pgrep", "-f"])
        self.assertIn("Contents", calls[0][2])
        self.assertNotIn("123", str(calls), "PID output must not be propagated")

        def stopped(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess:
            return subprocess.CompletedProcess(command, 1, "", "")

        key_init.assert_original_wechat_stopped(app, runner=stopped)

        def inspection_failed(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess:
            return subprocess.CompletedProcess(command, 2, "", "")

        with self.assertRaises(key_init.SafeInitError):
            key_init.assert_original_wechat_stopped(app, runner=inspection_failed)

    def test_target_holder_check_covers_existing_sidecars_and_redacts_failure(self) -> None:
        _root, db_base = self.make_db_tree()
        self.write_db(db_base / "message/message_0.db", b"J" * 16)
        Path(str(db_base / "message/message_0.db") + "-wal").write_bytes(b"wal")
        targets = key_init.inspect_targets(db_base, ("message_0",))
        observed: list[Path] = []

        def clear(paths: object) -> list[object]:
            observed.extend(paths)  # type: ignore[arg-type]
            return []

        report = key_init.inspect_target_database_holders(targets, holder_probe=clear)
        self.assertEqual(report, {"status": "clear", "holder_count": 0})
        self.assertEqual(len(observed), 2)
        self.assertTrue(str(observed[1]).endswith("-wal"))

        def broken(_paths: object) -> list[object]:
            raise RuntimeError(str(db_base / "private-path"))

        with self.assertRaises(key_init.SafeInitError) as caught:
            key_init.inspect_target_database_holders(targets, holder_probe=broken)
        self.assertNotIn(str(db_base), str(caught.exception))

    def test_dry_scan_is_structured_and_missing_dependency_is_not_success(self) -> None:
        root, db_base = self.make_db_tree()
        self.write_db(db_base / "contact/contact.db", b"K" * 16)
        self.write_db(db_base / "message/message_0.db", b"L" * 16)
        account_ref = key_init.discover_account_candidates(root)[0].account_ref
        app = self.make_app()
        args = argparse.Namespace(
            account_ref=account_ref,
            db_base=None,
            targets="contact,message_0",
            app=str(app),
        )

        def signed_and_running(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess:
            if command[0] == "/usr/bin/codesign":
                if "--display" in command:
                    return subprocess.CompletedProcess(
                        command, 0, "", "CDHash=%s\n" % ("c" * 40)
                    )
                return subprocess.CompletedProcess(command, 0, "", "")
            if command[0] == "/usr/bin/pgrep":
                return subprocess.CompletedProcess(command, 0, "321\n", "")
            return subprocess.CompletedProcess(command, 2, "", "")

        with mock.patch.object(
            key_init,
            "_route_current_account",
            return_value=self.routed_unique(account_ref),
        ), mock.patch.object(
            key_init, "dependency_status", return_value={"frida": False, "pycryptodome": True}
        ):
            report = key_init.build_dry_scan_report(
                args,
                xwechat_root=root,
                runner=signed_and_running,
                holder_probe=lambda _paths: [object()],
            )
        self.assertFalse(report["writes_performed"])
        self.assertFalse(report["prerequisites_ready"])
        self.assertFalse(report["ready_for_capture"])
        self.assertEqual(report["database_holders"]["holder_count"], 1)
        self.assertRegex(report["approval_digest"], r"^[0-9a-f]{64}$")
        self.assertEqual(
            [item["alias"] for item in report["targets"]], ["contact", "message_0"]
        )
        self.assertIn("missing-frida", [item["code"] for item in report["blockers"]])

    def test_dry_scan_account_mismatch_has_no_usable_authorization_summary(self) -> None:
        root, db_base = self.make_db_tree()
        self.write_db(db_base / "contact/contact.db", b"K" * 16)
        self.write_db(db_base / "message/message_0.db", b"L" * 16)
        requested = key_init.discover_account_candidates(root)[0].account_ref
        app = self.make_app()
        args = argparse.Namespace(
            account_ref=requested,
            db_base=None,
            targets="contact,message_0",
            app=str(app),
        )
        different = "account-0123456789ab"
        if different == requested:
            different = "account-fedcba987654"
        with mock.patch.object(
            key_init, "require_official_wechat_signature"
        ), mock.patch.object(
            key_init,
            "_route_current_account",
            return_value=self.routed_unique(different),
        ), mock.patch.object(
            key_init, "dependency_status", return_value={"frida": True, "pycryptodome": True}
        ), mock.patch.object(
            key_init, "official_app_cdhash"
        ) as cdhash, mock.patch.object(
            key_init, "inspect_target_database_holders"
        ) as holders:
            report = key_init.build_dry_scan_report(args, xwechat_root=root)
        self.assertFalse(report["authorization_summary_usable"])
        self.assertIsNone(report["approval_digest"])
        self.assertFalse(report["prerequisites_ready"])
        self.assertEqual(report["targets"], [])
        self.assertIn(
            "account-ref-mismatch", [item["code"] for item in report["blockers"]]
        )
        cdhash.assert_not_called()
        holders.assert_not_called()

    def test_capture_digest_binds_scope_before_any_write(self) -> None:
        _root, db_base = self.make_db_tree()
        self.write_db(db_base / "contact/contact.db", b"M" * 16)
        app_path = self.make_app()
        app = key_init.validate_wechat_app(app_path)
        targets = key_init.inspect_targets(db_base, ("contact",))
        private = self.base / "must-remain-absent"
        base_args = argparse.Namespace(
            duration=5,
            account_ref=None,
            db_base=str(db_base),
            targets="contact",
            app=str(app_path),
            private_dir=str(private),
            approve_digest="0" * 64,
        )
        correct = key_init.capture_approval_digest(
            base_args, db_base, targets, app, "d" * 40
        )
        changed_code_identity = key_init.capture_approval_digest(
            base_args, db_base, targets, app, "e" * 40
        )
        self.assertNotEqual(correct, base_args.approve_digest)
        self.assertNotEqual(correct, changed_code_identity)
        with mock.patch.object(key_init, "requested_db_base", return_value=db_base.resolve()), mock.patch.object(
            key_init, "require_official_wechat_signature"
        ), mock.patch.object(key_init, "official_app_cdhash", return_value="d" * 40), mock.patch.object(
            key_init, "assert_original_wechat_stopped"
        ), mock.patch.object(
            key_init, "assert_no_target_database_holders"
        ), mock.patch.object(key_init, "require_capture_dependencies") as dependencies:
            with self.assertRaises(key_init.SafeInitError):
                key_init.run_capture(base_args)
        self.assertFalse(private.exists())
        dependencies.assert_not_called()

    def test_capture_writes_account_scoped_schema_two_and_shared_runtime(self) -> None:
        root, db_base = self.make_db_tree()
        self.write_db(db_base / "contact/contact.db", b"N" * 16)
        self.write_db(db_base / "message/message_0.db", b"O" * 16)
        candidate = key_init.discover_account_candidates(root)[0]
        app_path = self.make_app()
        app = key_init.validate_wechat_app(app_path)
        targets = key_init.inspect_targets(db_base, ("contact", "message_0"))
        private = self.base / "capture-private"
        args = argparse.Namespace(
            duration=5,
            account_ref=candidate.account_ref,
            db_base=None,
            targets="contact,message_0",
            app=str(app_path),
            private_dir=str(private),
            approve_digest="",
        )
        args.approve_digest = key_init.capture_approval_digest(
            args, db_base, targets, app, "d" * 40
        )
        runtime = key_init.PreparedRuntime(
            run_id="a" * 32,
            runtime_dir=private / key_init.RUNTIME_DIRNAME / "init-fixture",
            app_copy_path=private / key_init.RUNTIME_DIRNAME / "init-fixture/copy.app",
            executable_path=private
            / key_init.RUNTIME_DIRNAME
            / "init-fixture/copy.app/Contents/MacOS/WeChat",
        )
        capture_result = key_init.CaptureResult(
            pid=4242,
            matched_keys={"contact": "1" * 64, "message_0": "2" * 64},
            missing_targets=(),
        )
        with mock.patch.object(
            key_init, "requested_db_base", return_value=db_base.resolve()
        ), mock.patch.object(
            key_init, "require_official_wechat_signature"
        ), mock.patch.object(
            key_init, "official_app_cdhash", return_value="d" * 40
        ), mock.patch.object(
            key_init, "assert_original_wechat_stopped"
        ), mock.patch.object(
            key_init, "assert_no_target_database_holders"
        ), mock.patch.object(
            key_init, "require_capture_dependencies", return_value=object()
        ), mock.patch.object(
            key_init, "ensure_no_owned_runtime"
        ), mock.patch.object(
            key_init, "prepare_runtime_copy", return_value=runtime
        ), mock.patch.object(
            key_init, "capture_keys", return_value=capture_result
        ):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(key_init.run_capture(args), 0)

        scoped = private / key_init.ACCOUNTS_DIRNAME / candidate.account_ref
        config = json.loads((scoped / key_init.CONFIG_FILENAME).read_text())
        self.assertEqual(config["schema_version"], 2)
        self.assertEqual(config["account_ref"], candidate.account_ref)
        self.assertTrue((scoped / key_init.KEYS_FILENAME).exists())
        self.assertFalse((private / key_init.KEYS_FILENAME).exists())
        self.assertTrue((private / key_init.RUNTIME_FILENAME).exists())

    def test_official_signature_requirement_is_pinned_and_capture_checks_before_writing(self) -> None:
        app_path = self.make_app()
        app = key_init.validate_wechat_app(app_path)
        calls: list[list[str]] = []

        def rejected(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess:
            calls.append(command)
            return subprocess.CompletedProcess(command, 3, "", "")

        with self.assertRaises(key_init.SafeInitError):
            key_init.require_official_wechat_signature(app, runner=rejected)
        self.assertIn("-R=" + key_init.OFFICIAL_WECHAT_REQUIREMENT, calls[0])
        self.assertIn(key_init.EXPECTED_TEAM_ID, calls[0][4])

        root, db_base = self.make_db_tree()
        self.write_db(db_base / "contact/contact.db", b"Q" * 16)
        private = self.base / "must-not-be-created"
        args = argparse.Namespace(
            duration=5,
            account_ref=None,
            db_base=str(db_base),
            targets="contact",
            app=str(app_path),
            private_dir=str(private),
        )
        with mock.patch.object(key_init, "requested_db_base", return_value=db_base.resolve()):
            with mock.patch.object(key_init, "verify_app_signature", return_value=False):
                with self.assertRaises(key_init.SafeInitError):
                    key_init.run_capture(args)
        self.assertFalse(private.exists())
        self.assertTrue(root.exists())

    def test_atomic_json_is_0600_and_leaves_no_temporary_file(self) -> None:
        private = self.make_private_dir()
        output = private / "state.json"
        key_init.atomic_write_json(output, {"secret": "redacted-fixture"})
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertEqual(json.loads(output.read_text()), {"secret": "redacted-fixture"})
        self.assertEqual([path.name for path in private.iterdir()], ["state.json"])


class CryptoAndFridaTests(FixtureMixin, unittest.TestCase):
    def make_encrypted_first_page(self, path: Path, salt: bytes, key: bytes) -> None:
        from Crypto.Cipher import AES

        plaintext = bytearray(key_init.PAGE_SIZE)
        plaintext[:16] = key_init.SQLITE_HEADER
        plaintext[16:18] = struct_pack_u16(key_init.PAGE_SIZE)
        plaintext[18] = 2
        plaintext[19] = 2
        plaintext[20] = key_init.RESERVE_SIZE
        plaintext[21] = 64
        plaintext[22] = 32
        plaintext[23] = 32
        iv = bytes(range(16))
        encrypted_end = key_init.PAGE_SIZE - key_init.RESERVE_SIZE
        ciphertext = AES.new(key, AES.MODE_CBC, iv).encrypt(plaintext[16:encrypted_end])
        page = salt + ciphertext + iv + bytes(key_init.RESERVE_SIZE - len(iv))
        self.assertEqual(len(page), key_init.PAGE_SIZE)
        path.write_bytes(page)

    def make_target(self) -> tuple[key_init.TargetDB, bytes]:
        path = self.base / "message_0.db"
        salt = bytes(range(16, 32))
        key = bytes(range(32))
        self.make_encrypted_first_page(path, salt, key)
        return (
            key_init.TargetDB("message_0", "message/message_0.db", path, path.stat().st_size, salt),
            key,
        )

    def test_generated_frida_script_has_exact_salts_and_no_disk_writer(self) -> None:
        target, _key = self.make_target()
        script = key_init.build_frida_script({target.name: target})
        self.assertIn(target.salt.hex(), script)
        self.assertIn("TARGETS_BY_SALT", script)
        self.assertNotIn("new File", script)
        self.assertNotIn("LOG_PATH", script)
        self.assertNotIn("write(JSON", script)
        self.assertIn("Process.attachModuleObserver", script)
        self.assertNotIn("setTimeout(installLoop", script)
        self.assertIn("retval.toInt32() !== 0", script)
        self.assertIn("this.salt = bytesToHex", script)
        self.assertNotIn("this.password =", script)
        self.assertGreater(
            script.index("const password = bytesToHex"),
            script.index("hasOwnProperty.call(TARGETS_BY_SALT"),
            "password bytes must only be read after exact-salt membership succeeds",
        )

    def test_row_matches_only_same_salt_and_valid_first_page(self) -> None:
        target, key = self.make_target()
        targets = {target.name: target}
        matched: dict[str, str] = {}
        wrong_salt_row = {
            "salt": (b"X" * 16).hex(),
            "derived_key": key.hex(),
            "password": None,
        }
        self.assertEqual(key_init.match_pbkdf_row(wrong_salt_row, targets, matched), ())
        self.assertEqual(matched, {})

        wrong_key_row = {
            "salt": target.salt.hex(),
            "derived_key": (b"Z" * 32).hex(),
            "password": None,
        }
        self.assertEqual(key_init.match_pbkdf_row(wrong_key_row, targets, matched), ())
        self.assertEqual(matched, {})

        exact_row = {
            "salt": target.salt.hex(),
            "derived_key": key.hex(),
            "password": None,
        }
        self.assertEqual(
            key_init.match_pbkdf_row(exact_row, targets, matched), ("message_0",)
        )
        self.assertEqual(matched, {"message_0": key.hex()})

    def test_capture_uses_memory_callback_and_returns_pid(self) -> None:
        target, key = self.make_target()
        row = {
            "type": "pbkdf2",
            "salt": target.salt.hex(),
            "derived_key": key.hex(),
            "password": None,
        }

        class FakeScript:
            def __init__(self) -> None:
                self.callback = None

            def on(self, event: str, callback: object) -> None:
                self.callback = callback

            def load(self) -> None:
                assert self.callback is not None
                self.callback({"type": "send", "payload": row}, None)

            def unload(self) -> None:
                pass

        class FakeSession:
            def __init__(self) -> None:
                self.script = FakeScript()

            def create_script(self, _source: str) -> FakeScript:
                return self.script

            def on(self, _event: str, _callback: object) -> None:
                pass

            def detach(self) -> None:
                pass

        class FakeDevice:
            def __init__(self) -> None:
                self.session = FakeSession()
                self.resumed = False

            def spawn(self, program: str) -> int:
                self.program = program
                return 4242

            def attach(self, pid: int) -> FakeSession:
                self.pid = pid
                return self.session

            def resume(self, pid: int) -> None:
                self.resumed = pid == 4242

        class FakeFrida:
            def __init__(self) -> None:
                self.device = FakeDevice()

            def get_local_device(self) -> FakeDevice:
                return self.device

        runtime = key_init.PreparedRuntime(
            run_id="a" * 32,
            runtime_dir=self.base / "runtime",
            app_copy_path=self.base / "runtime/微信-keyinit.app",
            executable_path=self.base / "runtime/微信-keyinit.app/Contents/MacOS/WeChat",
        )
        seen_pids: list[int] = []
        before = set(self.base.rglob("*"))
        fake = FakeFrida()
        result = key_init.capture_keys(
            fake,
            runtime,
            {target.name: target},
            5,
            pre_spawn=lambda: seen_pids.append(-1),
            on_pid=seen_pids.append,
        )
        after = set(self.base.rglob("*"))
        self.assertEqual(result.pid, 4242)
        self.assertEqual(result.matched_keys, {target.name: key.hex()})
        self.assertEqual(result.missing_targets, ())
        self.assertEqual(seen_pids, [-1, 4242])
        self.assertTrue(fake.device.resumed)
        self.assertEqual(before, after, "capture must not write raw rows or host scripts")


class CleanupTests(FixtureMixin, unittest.TestCase):
    def make_owned_runtime(self) -> tuple[Path, Path, int]:
        private = self.make_private_dir()
        runtime_root = private / key_init.RUNTIME_DIRNAME
        runtime_root.mkdir(mode=0o700)
        runtime = runtime_root / "init-fixture"
        runtime.mkdir(mode=0o700)
        run_id = "b" * 32
        key_init.atomic_write_json(
            runtime / key_init.RUNTIME_OWNER_FILENAME,
            {
                "schema_version": 1,
                "owner": "wechat_key_init.py",
                "run_id": run_id,
            },
        )
        pid = 424242
        key_init.atomic_write_json(
            private / key_init.RUNTIME_FILENAME,
            {
                "schema_version": 1,
                "owner": "wechat_key_init.py",
                "run_id": run_id,
                "status": "complete",
                "pid": pid,
                "runtime_dir": str(runtime),
            },
        )
        return private, runtime, pid

    def test_cleanup_requires_pid_gone_and_matching_owner(self) -> None:
        private, runtime, _pid = self.make_owned_runtime()
        with mock.patch.object(key_init, "pid_exists", return_value=True):
            with self.assertRaises(key_init.SafeInitError):
                key_init.cleanup_owned_runtime(private)
        self.assertTrue(runtime.exists())

        with mock.patch.object(key_init, "pid_exists", return_value=False):
            key_init.cleanup_owned_runtime(
                private,
                runner=lambda command, **_kwargs: subprocess.CompletedProcess(
                    command, 1, "", ""
                ),
            )
        self.assertFalse(runtime.exists())
        metadata = json.loads((private / key_init.RUNTIME_FILENAME).read_text())
        self.assertEqual(metadata["status"], "cleaned")
        self.assertIsNone(metadata["runtime_dir"])

    def test_cleanup_refuses_arbitrary_recorded_path(self) -> None:
        private, _runtime, _pid = self.make_owned_runtime()
        arbitrary = self.base / "not-owned"
        arbitrary.mkdir()
        metadata_path = private / key_init.RUNTIME_FILENAME
        metadata = json.loads(metadata_path.read_text())
        metadata["runtime_dir"] = str(arbitrary)
        key_init.atomic_write_json(metadata_path, metadata)
        with mock.patch.object(key_init, "pid_exists", return_value=False):
            with self.assertRaises(key_init.SafeInitError):
                key_init.cleanup_owned_runtime(private)
        self.assertTrue(arbitrary.exists())

    def test_orphaned_marker_owned_runtime_is_detected_and_recoverable(self) -> None:
        private, runtime, _pid = self.make_owned_runtime()
        (private / key_init.RUNTIME_FILENAME).unlink()
        state = key_init.inspect_existing_private_state(private, ())
        self.assertEqual(state["runtime_state"], "orphaned-or-unreconciled")
        self.assertEqual(state["owned_runtime_count"], 1)
        self.assertEqual(state["orphaned_runtime_count"], 1)
        self.assertTrue(state["runtime_cleanup_required"])
        with self.assertRaises(key_init.SafeInitError):
            key_init.ensure_no_owned_runtime(private)

        removed = key_init.cleanup_owned_runtime(
            private,
            runner=lambda command, **_kwargs: subprocess.CompletedProcess(
                command, 1, "", ""
            ),
        )
        self.assertEqual(removed, 1)
        self.assertFalse(runtime.exists())
        metadata = json.loads((private / key_init.RUNTIME_FILENAME).read_text())
        self.assertEqual(metadata["status"], "cleaned")
        self.assertEqual(metadata["recovered_owned_runtime_count"], 1)

    def test_unmarked_runtime_entry_fails_closed_and_is_not_deleted(self) -> None:
        private = self.make_private_dir()
        runtime_root = private / key_init.RUNTIME_DIRNAME
        runtime_root.mkdir(mode=0o700)
        unmarked = runtime_root / "init-interrupted-before-marker"
        unmarked.mkdir(mode=0o700)
        state = key_init.inspect_existing_private_state(private, ())
        self.assertEqual(state["runtime_state"], "unsafe")
        with self.assertRaises(key_init.SafeInitError):
            key_init.cleanup_owned_runtime(private)
        self.assertTrue(unmarked.exists())

    def test_cleanup_reconciles_metadata_after_owned_directory_was_already_removed(self) -> None:
        private, runtime, _pid = self.make_owned_runtime()
        (runtime / key_init.RUNTIME_OWNER_FILENAME).unlink()
        runtime.rmdir()
        with mock.patch.object(key_init, "pid_exists", return_value=False):
            removed = key_init.cleanup_owned_runtime(private)
        self.assertEqual(removed, 0)
        metadata = json.loads((private / key_init.RUNTIME_FILENAME).read_text())
        self.assertEqual(metadata["status"], "cleaned")
        self.assertIsNone(metadata["runtime_dir"])


def struct_pack_u16(value: int) -> bytes:
    return bytes(((value >> 8) & 0xFF, value & 0xFF))


if __name__ == "__main__":
    unittest.main()
