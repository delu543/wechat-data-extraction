from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import hashlib
import sqlite3
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
CLIENT_PATH = (
    PACKAGE_ROOT
    / "skills"
    / "wechat-local-export"
    / "scripts"
    / "wechat_local_export_client.py"
)
VALIDATOR_PATH = PACKAGE_ROOT / "scripts" / "validate_package.py"
DEV_BACKEND_PATH = PACKAGE_ROOT / "scripts" / "dev_backend.py"


def _load_module(name: str, path: Path):
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise AssertionError(f"unable to load {path}")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


class PackageStaticTests(unittest.TestCase):
    def _direct_request_fixture(
        self,
        root: Path,
        *,
        types: list[str] | None = None,
    ) -> tuple[Path, Path, Path]:
        home = root / "home"
        task_root = (
            home
            / "Library"
            / "Application Support"
            / "WeChatLocalExport"
            / "tasks"
        )
        request_dir = task_root / "request-fixture"
        request_dir.mkdir(parents=True)
        task_root.chmod(0o700)
        request_dir.chmod(0o700)
        request = request_dir / "request.json"
        request.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "chat": "精确语音群",
                    "chat_id": None,
                    "start": "2030-01-01 09:00:00",
                    "end": "2030-01-01 10:00:00",
                    "types": types if types is not None else ["voice"],
                }
            ),
            encoding="utf-8",
        )
        request.chmod(0o600)
        return home, request_dir, request

    def _direct_doctor_backend(self, root: Path) -> SimpleNamespace:
        account_ref = "account-0123456789ab"
        binding = SimpleNamespace(
            account_ref=account_ref,
            public_report=lambda: {
                "status": "unique",
                "selected": True,
                "official_process_count": 1,
                "held_categories": ["contact", "message"],
                "core_evidence": {"contact": True, "message": True},
                "writes_performed": False,
            },
        )
        return SimpleNamespace(
            bind_active_account=lambda: binding,
            load_account_profile=lambda requested_ref: {
                "schema_version": 2,
                "account_ref": requested_ref,
                "vault_dir": str(root / "vault"),
                "account_root": str(root / "account"),
                "swift_bin": None,
            },
            doctor=lambda *_args, **_kwargs: {
                "ready_for_scan": True,
                "ready_for_voice_mp4": True,
            },
        )

    def test_validator_passes(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(VALIDATOR_PATH)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        report = json.loads(completed.stdout)
        self.assertEqual(report["status"], "ok")
        self.assertFalse(report["setup_implicit"])
        self.assertTrue(report["export_implicit"])
        self.assertFalse(report["signed_companion_included"])

    def test_client_exposes_only_high_level_commands(self) -> None:
        client = _load_module("portable_client_commands", CLIENT_PATH)
        self.assertEqual(
            client.ALLOWED_COMMANDS,
            {"doctor", "scan", "export", "direct-voice-mp4"},
        )
        parser = client.build_parser()
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                parser.parse_args(["init"])
        self.assertEqual(raised.exception.code, 2)

    def test_client_rejects_credential_like_unknown_arguments_without_echo(self) -> None:
        client = _load_module("portable_client_redaction", CLIENT_PATH)
        parser = client.build_parser()
        captured = io.StringIO()
        private_value = "do-not-echo-this-value"
        with contextlib.redirect_stderr(captured):
            with self.assertRaises(SystemExit):
                parser.parse_args(["doctor", "--credential", private_value])
        self.assertNotIn(private_value, captured.getvalue())

    def test_development_backend_redacts_private_paths_from_expected_errors(
        self,
    ) -> None:
        backend = _load_module(
            "portable_backend_error_redaction",
            DEV_BACKEND_PATH,
        )
        mac_home_prefix = str(Path("/", "Users")) + os.sep
        private_path = str(
            Path("/", "Users", "private-account", "chat", "voice.mp4")
        )
        public = backend._public_error_text(
            backend.DevelopmentBackendError(
                f"ffmpeg failed while reading {private_path}"
            )
        )
        self.assertNotIn(private_path, public)
        self.assertNotIn(mac_home_prefix, public)
        self.assertIn("已隐藏", public)
        self.assertEqual(
            backend._public_error_text(
                backend.DevelopmentBackendError("当前账号发生变化")
            ),
            "当前账号发生变化",
        )

    def test_client_forwards_explicit_voice_mp4_only_mode(self) -> None:
        client = _load_module("portable_client_voice_mp4_only", CLIENT_PATH)
        arguments = [
            "export",
            "--plan",
            "/private/plan.json",
            "--output-dir",
            "/private/output",
            "--confirm-digest",
            "a" * 64,
            "--confirm-count",
            "13",
            "--voice-mp4-only",
        ]
        parsed = client.build_parser().parse_args(arguments)
        forwarded = client.backend_arguments(parsed)
        self.assertIn("--voice-mp4-only", forwarded)
        self.assertNotIn("--allow-partial", forwarded)
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                client.build_parser().parse_args(arguments + ["--allow-partial"])

    def test_client_forwards_single_request_direct_voice_command(self) -> None:
        client = _load_module("portable_client_direct_voice", CLIENT_PATH)
        parsed = client.build_parser().parse_args(
            [
                "direct-voice-mp4",
                "--request",
                "/private/request.json",
                "--output-dir",
                "/private/new-output",
            ]
        )
        self.assertEqual(
            client.backend_arguments(parsed),
            [
                "direct-voice-mp4",
                "--request",
                "/private/request.json",
                "--output-dir",
                "/private/new-output",
            ],
        )
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                client.build_parser().parse_args(
                    [
                        "direct-voice-mp4",
                        "--request",
                        "/private/request.json",
                        "--output-dir",
                        "/private/new-output",
                        "--allow-partial",
                    ]
                )

    def test_direct_voice_command_orchestrates_one_request_and_cleans_plan(
        self,
    ) -> None:
        backend_module = _load_module(
            "portable_backend_direct_voice_success",
            DEV_BACKEND_PATH,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            home, request_dir, request = self._direct_request_fixture(root)
            output = root / "voice-output"
            backend = self._direct_doctor_backend(root)
            scan_digest = "a" * 64
            events: list[str] = []

            def fake_scan(args, received_backend, **kwargs):
                events.append("scan")
                self.assertIs(received_backend, backend)
                self.assertTrue(kwargs["reserved_output"])
                plan = Path(args.output)
                self.assertEqual(plan.parent, request_dir)
                self.assertTrue(plan.is_file())
                self.assertEqual(plan.stat().st_size, 0)
                self.assertEqual(plan.stat().st_mode & 0o777, 0o600)
                plan.write_text("{}\n", encoding="utf-8")
                kwargs["report_sink"](
                    {
                        "status": "dry-scan-complete",
                        "plan_digest": scan_digest,
                        "message_count": 2,
                        "counts_by_kind": {"voice": 2},
                        "selection": {"types": ["voice"]},
                        "chat": {
                            "display_name": "精确语音群",
                            "kind": "group",
                        },
                        "time_range": {
                            "start_input": "2030-01-01 09:00:00",
                            "end_input": "2030-01-01 10:00:00",
                        },
                        "first_create_time": 100,
                        "last_create_time": 200,
                        "requires_user_confirmation": True,
                        "routing_mode": "current-official-session",
                        "snapshot_mode": "online",
                    }
                )
                return 0

            def fake_export(args, _project_root, received_backend, **kwargs):
                events.append("export")
                self.assertIs(received_backend, backend)
                self.assertEqual(args.plan, next(iter(map(str, request_dir.glob(".direct-voice-plan-*.json")))))
                self.assertEqual(args.confirm_digest, scan_digest)
                self.assertEqual(args.confirm_count, 2)
                self.assertFalse(args.allow_partial)
                self.assertTrue(args.voice_mp4_only)
                kwargs["report_sink"](
                    {
                        "status": "complete",
                        "output_mode": "voice-mp4-only",
                        "message_count": 2,
                        "issue_count": 0,
                        "plan_digest": scan_digest,
                        "output_dir": str(output),
                        "verification": {
                            "status": "verified-before-atomic-publish"
                        },
                    }
                )
                return 0

            captured = io.StringIO()
            with (
                mock.patch.dict(os.environ, {"HOME": str(home)}),
                mock.patch.object(backend_module.Path, "home", return_value=home),
                mock.patch.object(backend_module, "run_scan", fake_scan),
                mock.patch.object(backend_module, "run_export", fake_export),
                contextlib.redirect_stdout(captured),
            ):
                result = backend_module.run_direct_voice_mp4(
                    SimpleNamespace(
                        request=str(request),
                        output_dir=str(output),
                    ),
                    PACKAGE_ROOT.parent,
                    backend,
                )

            self.assertEqual(result, 0)
            self.assertEqual(events, ["scan", "export"])
            self.assertTrue(request.is_file())
            self.assertFalse(
                list(request_dir.glob(".direct-voice-plan-*.json"))
            )
            public_text = captured.getvalue()
            public = json.loads(public_text)
            self.assertEqual(public["status"], "complete")
            self.assertEqual(public["message_count"], 2)
            self.assertTrue(public["temporary_plan_cleaned"])
            self.assertNotIn(str(request), public_text)
            self.assertNotIn(str(output), public_text)
            self.assertNotIn(scan_digest, public_text)

    def test_direct_voice_command_stops_on_ambiguity_and_cleans_plan(self) -> None:
        backend_module = _load_module(
            "portable_backend_direct_voice_ambiguous",
            DEV_BACKEND_PATH,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            home, request_dir, request = self._direct_request_fixture(root)
            backend = self._direct_doctor_backend(root)

            def fake_scan(_args, _backend, **kwargs):
                kwargs["report_sink"](
                    {
                        "status": "needs-chat-selection",
                        "candidate_count": 2,
                        "candidates": [
                            {
                                "display_name": "同名群",
                                "kind": "group",
                                "match": "exact",
                            },
                            {
                                "display_name": "同名群",
                                "kind": "group",
                                "match": "exact",
                            },
                        ],
                        "plan_created": False,
                    }
                )
                return 3

            captured = io.StringIO()
            with (
                mock.patch.dict(os.environ, {"HOME": str(home)}),
                mock.patch.object(backend_module.Path, "home", return_value=home),
                mock.patch.object(backend_module, "run_scan", fake_scan),
                mock.patch.object(
                    backend_module,
                    "run_export",
                    side_effect=AssertionError("ambiguous request must not export"),
                ),
                contextlib.redirect_stdout(captured),
            ):
                result = backend_module.run_direct_voice_mp4(
                    SimpleNamespace(
                        request=str(request),
                        output_dir=str(root / "output"),
                    ),
                    PACKAGE_ROOT.parent,
                    backend,
                )

            self.assertEqual(result, 3)
            self.assertFalse(
                list(request_dir.glob(".direct-voice-plan-*.json"))
            )
            report = json.loads(captured.getvalue())
            self.assertEqual(report["status"], "needs-chat-selection")
            self.assertFalse(report["export_performed"])
            self.assertTrue(report["temporary_plan_cleaned"])

    def test_direct_voice_command_zero_result_cleans_plan_without_export(
        self,
    ) -> None:
        backend_module = _load_module(
            "portable_backend_direct_voice_zero",
            DEV_BACKEND_PATH,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            home, request_dir, request = self._direct_request_fixture(root)
            backend = self._direct_doctor_backend(root)

            def fake_scan(_args, _backend, **kwargs):
                kwargs["report_sink"](
                    {
                        "status": "dry-scan-complete",
                        "plan_digest": "b" * 64,
                        "message_count": 0,
                        "counts_by_kind": {"voice": 0},
                        "selection": {"types": ["voice"]},
                        "chat": {
                            "display_name": "精确语音群",
                            "kind": "group",
                        },
                        "time_range": {
                            "start_input": "2030-01-01 09:00:00",
                            "end_input": "2030-01-01 10:00:00",
                        },
                        "routing_mode": "current-official-session",
                        "snapshot_mode": "online",
                    }
                )
                return 0

            captured = io.StringIO()
            with (
                mock.patch.dict(os.environ, {"HOME": str(home)}),
                mock.patch.object(backend_module.Path, "home", return_value=home),
                mock.patch.object(backend_module, "run_scan", fake_scan),
                mock.patch.object(
                    backend_module,
                    "run_export",
                    side_effect=AssertionError("zero result must not export"),
                ),
                contextlib.redirect_stdout(captured),
            ):
                result = backend_module.run_direct_voice_mp4(
                    SimpleNamespace(
                        request=str(request),
                        output_dir=str(root / "output"),
                    ),
                    PACKAGE_ROOT.parent,
                    backend,
                )

            self.assertEqual(result, 3)
            self.assertFalse(
                list(request_dir.glob(".direct-voice-plan-*.json"))
            )
            report = json.loads(captured.getvalue())
            self.assertEqual(report["status"], "no-matching-voices")
            self.assertFalse(report["export_performed"])
            self.assertTrue(report["temporary_plan_cleaned"])

    def test_direct_voice_command_failure_still_cleans_only_internal_plan(
        self,
    ) -> None:
        backend_module = _load_module(
            "portable_backend_direct_voice_failure",
            DEV_BACKEND_PATH,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            home, request_dir, request = self._direct_request_fixture(root)
            unrelated = request_dir / "keep-me.json"
            unrelated.write_text("{}\n", encoding="utf-8")
            unrelated.chmod(0o600)
            backend = self._direct_doctor_backend(root)

            with (
                mock.patch.dict(os.environ, {"HOME": str(home)}),
                mock.patch.object(backend_module.Path, "home", return_value=home),
                mock.patch.object(
                    backend_module,
                    "run_scan",
                    side_effect=backend_module.DevelopmentBackendError(
                        "online scan failed"
                    ),
                ),
                self.assertRaisesRegex(
                    backend_module.DevelopmentBackendError,
                    "online scan failed",
                ),
            ):
                backend_module.run_direct_voice_mp4(
                    SimpleNamespace(
                        request=str(request),
                        output_dir=str(root / "output"),
                    ),
                    PACKAGE_ROOT.parent,
                    backend,
                )

            self.assertTrue(request.is_file())
            self.assertTrue(unrelated.is_file())
            self.assertFalse(
                list(request_dir.glob(".direct-voice-plan-*.json"))
            )

    def test_direct_voice_command_requires_both_doctor_readiness_gates(
        self,
    ) -> None:
        backend_module = _load_module(
            "portable_backend_direct_voice_doctor_gates",
            DEV_BACKEND_PATH,
        )
        for missing_flag in ("ready_for_scan", "ready_for_voice_mp4"):
            with self.subTest(missing_flag=missing_flag):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary).resolve()
                    home, request_dir, request = self._direct_request_fixture(root)
                    backend = self._direct_doctor_backend(root)
                    backend.doctor = lambda *_args, missing_flag=missing_flag, **_kwargs: {
                        "ready_for_scan": missing_flag != "ready_for_scan",
                        "ready_for_voice_mp4": (
                            missing_flag != "ready_for_voice_mp4"
                        ),
                    }
                    with (
                        mock.patch.object(
                            backend_module.Path,
                            "home",
                            return_value=home,
                        ),
                        mock.patch.object(
                            backend_module,
                            "run_scan",
                            side_effect=AssertionError(
                                "failed doctor gate must stop before scan"
                            ),
                        ),
                        self.assertRaises(
                            backend_module.DevelopmentBackendError
                        ),
                    ):
                        backend_module.run_direct_voice_mp4(
                            SimpleNamespace(
                                request=str(request),
                                output_dir=str(root / "output"),
                            ),
                            PACKAGE_ROOT.parent,
                            backend,
                        )
                    self.assertTrue(request.is_file())
                    self.assertFalse(
                        list(request_dir.glob(".direct-voice-plan-*.json"))
                    )

    def test_explicit_helper_is_preferred_without_printing_its_path(self) -> None:
        client = _load_module("portable_client_discovery", CLIENT_PATH)
        with tempfile.TemporaryDirectory() as temporary:
            helper = Path(temporary) / "helper"
            helper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            helper.chmod(0o700)
            previous = os.environ.get(client.HELPER_ENVIRONMENT)
            previous_opt_in = os.environ.get(client.UNVERIFIED_HELPER_OPT_IN)
            os.environ[client.HELPER_ENVIRONMENT] = str(helper)
            os.environ[client.UNVERIFIED_HELPER_OPT_IN] = "1"
            try:
                located = client.locate_backend()
            finally:
                if previous is None:
                    os.environ.pop(client.HELPER_ENVIRONMENT, None)
                else:
                    os.environ[client.HELPER_ENVIRONMENT] = previous
                if previous_opt_in is None:
                    os.environ.pop(client.UNVERIFIED_HELPER_OPT_IN, None)
                else:
                    os.environ[client.UNVERIFIED_HELPER_OPT_IN] = previous_opt_in
            self.assertEqual(located, [str(helper.resolve())])

    def test_development_venv_launcher_keeps_its_symlink_path(self) -> None:
        client = _load_module("portable_client_venv_symlink", CLIENT_PATH)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            adapter = root / "portable_skill" / "scripts" / "dev_backend.py"
            content_backend = root / "content_vault" / "cli.py"
            adapter.parent.mkdir(parents=True)
            content_backend.parent.mkdir(parents=True)
            adapter.write_text("# development adapter\n", encoding="utf-8")
            content_backend.write_text("# content backend\n", encoding="utf-8")

            launcher = root / ".venv" / "bin" / "python"
            launcher.parent.mkdir(parents=True)
            launcher.symlink_to(Path(sys.executable).resolve())
            fake_home = root / "home"
            fake_home.mkdir()

            with (
                mock.patch.object(client, "_candidate_roots", return_value=[root]),
                mock.patch.dict(
                    os.environ,
                    {
                        "HOME": str(fake_home),
                        "WECHAT_LOCAL_EXPORT_TOOLS_DIR": "",
                    },
                ),
            ):
                located = client.locate_backend()

            resolved_root = root.resolve()
            selected_launcher = resolved_root / ".venv" / "bin" / "python"
            selected_adapter = (
                resolved_root
                / "portable_skill"
                / "scripts"
                / "dev_backend.py"
            )
            self.assertTrue(selected_launcher.is_symlink())
            self.assertEqual(
                located,
                [str(selected_launcher), str(selected_adapter)],
            )
            self.assertNotEqual(located[0], str(selected_launcher.resolve()))

    def test_development_python_fallback_keeps_sys_executable_symlink(self) -> None:
        client = _load_module("portable_client_sys_executable_symlink", CLIENT_PATH)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fake_home = root / "home"
            fake_home.mkdir()
            launcher = root / "active-venv" / "bin" / "python"
            launcher.parent.mkdir(parents=True)
            launcher.symlink_to(Path(sys.executable).resolve())

            with (
                mock.patch.object(client.sys, "executable", str(launcher)),
                mock.patch.dict(
                    os.environ,
                    {
                        "HOME": str(fake_home),
                        "WECHAT_LOCAL_EXPORT_TOOLS_DIR": "",
                    },
                ),
            ):
                selected = client._development_python(root)

            self.assertTrue(launcher.is_symlink())
            self.assertEqual(selected, launcher)
            self.assertNotEqual(selected, launcher.resolve())

    def test_setup_policy_is_explicit(self) -> None:
        setup_yaml = (
            PACKAGE_ROOT
            / "skills"
            / "wechat-local-export-setup"
            / "agents"
            / "openai.yaml"
        ).read_text(encoding="utf-8")
        export_yaml = (
            PACKAGE_ROOT
            / "skills"
            / "wechat-local-export"
            / "agents"
            / "openai.yaml"
        ).read_text(encoding="utf-8")
        self.assertIn("allow_implicit_invocation: false", setup_yaml)
        self.assertIn("allow_implicit_invocation: true", export_yaml)

    def test_setup_uses_module_entrypoint_for_initializer(self) -> None:
        setup = (
            PACKAGE_ROOT
            / "skills"
            / "wechat-local-export-setup"
            / "SKILL.md"
        ).read_text(encoding="utf-8")
        for command in ("setup-doctor", "dry-scan", "capture"):
            self.assertIn(
                f"<key-init-python> -m live_tools.wechat_key_init {command}",
                setup,
            )
            self.assertNotIn(
                f"<project_root>/live_tools/wechat_key_init.py {command}",
                setup,
            )
        self.assertIn(
            "working directory set to\n`<project_root>`",
            setup,
        )

    def test_account_setup_docs_bind_only_the_current_official_session(self) -> None:
        project_root = PACKAGE_ROOT.parent
        document_paths = {
            "export_skill": PACKAGE_ROOT
            / "skills"
            / "wechat-local-export"
            / "SKILL.md",
            "setup_skill": PACKAGE_ROOT
            / "skills"
            / "wechat-local-export-setup"
            / "SKILL.md",
            "install": PACKAGE_ROOT / "INSTALL.md",
            "security": PACKAGE_ROOT / "SECURITY.md",
            "privacy": PACKAGE_ROOT / "PRIVACY.md",
            "architecture": project_root / "docs" / "PRODUCT_ARCHITECTURE.md",
            "capabilities": project_root / "docs" / "CAPABILITY_MAP.md",
            "readme": project_root / "README.md",
        }
        documents = {
            name: path.read_text(encoding="utf-8")
            for name, path in document_paths.items()
        }
        normalized = {name: " ".join(text.split()) for name, text in documents.items()}

        for name, text in documents.items():
            for obsolete_account_prompt in (
                "候选账号",
                "选第一个",
                "numbered account choice",
                "report-scoped candidate number",
                "account-selection-required",
                "select-account",
                "candidate N (last database update",
            ):
                self.assertNotIn(obsolete_account_prompt, text, name)

        setup = documents["setup_skill"]
        self.assertIn("current official WeChat session", setup)
        self.assertIn("open any chat", setup)
        self.assertIn("database modification time", setup)
        self.assertIn("stop without dry-scan or capture", setup)
        self.assertIn("Dependency-install approval is not key-capture approval", setup)
        self.assertIn(
            "does **not** authorize creating or retaining a decrypted snapshot",
            setup,
        )

        export = documents["export_skill"]
        self.assertIn("current official WeChat session", export)
        self.assertIn("Never select an account by", export)
        self.assertIn("Do not invoke setup implicitly", export)
        self.assertIn("Never carry a plan across an account switch", export)
        self.assertIn("direct-voice-mp4", export)

        self.assertIn("多账号日常使用", documents["install"])
        self.assertIn("direct-voice-mp4", documents["install"])
        self.assertIn(
            "Automatic account binding is routing evidence, not capture consent",
            normalized["security"],
        )
        self.assertIn("direct-voice-mp4", documents["security"])
        self.assertIn(
            "Switching the current login never silently loads another account's private state",
            normalized["privacy"],
        )
        self.assertIn("direct-voice-mp4", documents["privacy"])
        self.assertIn(
            "read-only current-session binding", documents["architecture"]
        )
        self.assertIn(
            "Current official-session account binding", documents["capabilities"]
        )
        self.assertIn("历史账号目录不会显示为可选项", documents["readme"])

    def test_development_backend_doctor_declares_release_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_home:
            completed = subprocess.run(
                [sys.executable, str(DEV_BACKEND_PATH), "doctor"],
                cwd=PACKAGE_ROOT.parent,
                capture_output=True,
                text=True,
                check=False,
                env=dict(os.environ, HOME=temporary_home),
            )
        self.assertEqual(completed.returncode, 2, completed.stderr)
        report = json.loads(completed.stdout)
        self.assertEqual(report["backend"], "development-source")
        self.assertIn("text", report["supported_types"])
        self.assertIn("voice", report["supported_types"])
        self.assertIn("image", report["supported_types"])
        self.assertFalse(report["signed_companion"])
        self.assertFalse(report["product_ready"])
        self.assertFalse(report["integrity"]["database_page_hmac_verified"])

    def test_no_concrete_home_directory_is_embedded(self) -> None:
        mac_home_prefix = "/" + "Users/"
        linux_home_prefix = "/" + "home/"
        for path in PACKAGE_ROOT.rglob("*"):
            if not path.is_file() or path.suffix == ".pyc":
                continue
            text = path.read_text(encoding="utf-8")
            self.assertNotIn(mac_home_prefix, text, str(path))
            self.assertNotIn(linux_home_prefix, text, str(path))

    def test_development_backend_unified_scan_and_export(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            vault = root / "vault"
            (vault / "contact").mkdir(parents=True)
            (vault / "message").mkdir()
            account = root / "account"
            (account / "msg").mkdir(parents=True)
            fake_home = root / "home"
            fake_home.mkdir()
            subprocess_environment = dict(os.environ, HOME=str(fake_home))
            chat_id = "portable-fixture@chatroom"
            chat_name = "便携测试群"
            table = "Msg_" + hashlib.md5(chat_id.encode()).hexdigest()
            with sqlite3.connect(vault / "contact/contact.db") as connection:
                connection.execute(
                    "CREATE TABLE contact (username TEXT, nick_name TEXT, remark TEXT, alias TEXT)"
                )
                connection.execute(
                    "INSERT INTO contact VALUES (?, ?, '', '')", (chat_id, chat_name)
                )
            with sqlite3.connect(vault / "message/message_0.db") as connection:
                connection.execute(
                    f"CREATE TABLE [{table}] (local_id INTEGER, server_id INTEGER, "
                    "local_type INTEGER, create_time INTEGER, message_content TEXT)"
                )
                connection.execute(
                    f"INSERT INTO [{table}] VALUES (1, 11, 1, 100, 'hello')"
                )
            request = root / "request.json"
            candidate_request = root / "candidate-request.json"
            candidate_request.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "vault_dir": str(vault),
                        "chat": "便携 测试群",
                        "chat_id": None,
                        "start": "99",
                        "end": "101",
                        "types": ["text"],
                    }
                ),
                encoding="utf-8",
            )
            candidate_request.chmod(0o600)
            candidate_plan = root / "candidate-plan.json"
            candidate_scan = subprocess.run(
                [
                    sys.executable,
                    str(DEV_BACKEND_PATH),
                    "scan",
                    "--request",
                    str(candidate_request),
                    "--output",
                    str(candidate_plan),
                ],
                cwd=PACKAGE_ROOT.parent,
                capture_output=True,
                text=True,
                check=False,
                env=subprocess_environment,
            )
            self.assertEqual(candidate_scan.returncode, 3, candidate_scan.stderr)
            candidate_report = json.loads(candidate_scan.stdout)
            self.assertEqual(candidate_report["status"], "needs-chat-selection")
            self.assertEqual(candidate_report["candidate_count"], 1)
            self.assertFalse(candidate_plan.exists())

            request.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "vault_dir": str(vault),
                        "chat": chat_name,
                        "chat_id": None,
                        "start": "99",
                        "end": "101",
                        "types": ["text"],
                    }
                ),
                encoding="utf-8",
            )
            request.chmod(0o600)
            plan = root / "plan.json"
            scanned = subprocess.run(
                [sys.executable, str(DEV_BACKEND_PATH), "scan", "--request", str(request), "--output", str(plan)],
                cwd=PACKAGE_ROOT.parent,
                capture_output=True,
                text=True,
                check=False,
                env=subprocess_environment,
            )
            self.assertEqual(scanned.returncode, 0, scanned.stderr)
            scan_report = json.loads(scanned.stdout)
            self.assertEqual(scan_report["message_count"], 1)
            self.assertEqual(scan_report["selection"]["types"], ["text"])
            output = root / "archive"
            exported = subprocess.run(
                [
                    sys.executable,
                    str(DEV_BACKEND_PATH),
                    "export",
                    "--vault-dir",
                    str(vault),
                    "--account-root",
                    str(account),
                    "--plan",
                    str(plan),
                    "--output-dir",
                    str(output),
                    "--confirm-digest",
                    scan_report["plan_digest"],
                    "--confirm-count",
                    "1",
                ],
                cwd=PACKAGE_ROOT.parent,
                capture_output=True,
                text=True,
                check=False,
                env=subprocess_environment,
            )
            self.assertEqual(exported.returncode, 0, exported.stderr)
            self.assertTrue((output / "index.html").is_file())
            self.assertTrue((output / "manifest.json").is_file())

    def test_implicit_scan_uses_current_account_profile_and_private_routing(self) -> None:
        backend_module = _load_module("portable_backend_current_profile", DEV_BACKEND_PATH)
        account_ref = "account-0123456789ab"
        events: list[str] = []

        def public_report() -> dict[str, object]:
            return {
                "status": "unique",
                "selected": True,
                "official_process_count": 2,
                "held_categories": ["contact", "message"],
                "core_evidence": {"contact": True, "message": True},
                "writes_performed": False,
            }

        binding = SimpleNamespace(
            account_ref=account_ref,
            public_report=public_report,
        )

        def plan_digest(plan: dict[str, object]) -> str:
            unsigned = dict(plan)
            unsigned.pop("plan_digest", None)
            payload = json.dumps(
                unsigned,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            return hashlib.sha256(payload).hexdigest()

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            vault = root / "old-vault"
            vault.mkdir()
            refreshed_vault = root / "refreshed-vault"
            refreshed_vault.mkdir()
            account_root = root / "account"
            account_root.mkdir()
            request_path = root / "request.json"
            request_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "chat": "当前账号群",
                        "chat_id": None,
                        "start": "99",
                        "end": "101",
                        "types": ["text"],
                    }
                ),
                encoding="utf-8",
            )
            request_path.chmod(0o600)
            output_path = root / "plan.json"

            def bind_active_account():
                events.append("bind")
                return binding

            def load_account_profile(requested_ref: str):
                events.append("profile")
                self.assertEqual(requested_ref, account_ref)
                selected_vault = (
                    vault
                    if events.count("profile") == 1
                    else refreshed_vault
                )
                return {
                    "schema_version": 2,
                    "account_ref": account_ref,
                    "vault_dir": str(selected_vault),
                    "account_root": str(account_root),
                    "swift_bin": None,
                }

            def refresh_online_snapshot(
                received_binding,
                received_profile,
                *,
                kinds,
                chat_id,
            ):
                events.append("refresh")
                self.assertIs(received_binding, binding)
                self.assertEqual(received_profile["vault_dir"], str(vault))
                self.assertEqual(kinds, ["text"])
                self.assertEqual(chat_id, "wxid_private@chatroom")
                return {
                    "status": "online-refresh-complete",
                    "profile_updated": True,
                    "run_directory": "/must-not-be-public",
                }

            def find_chat_candidates(received_vault, _chat):
                self.assertEqual(received_vault, vault)
                return [
                    {
                        "chat_id": "wxid_private@chatroom",
                        "display_name": "当前账号群",
                        "kind": "group",
                        "match": "exact",
                    }
                ]

            def build_content_plan(received_vault, *_args, **kwargs):
                events.append("scan")
                self.assertEqual(received_vault, refreshed_vault)
                self.assertEqual(kwargs["chat_id"], "wxid_private@chatroom")
                return {
                    "schema_version": 1,
                    "plan_digest": "0" * 64,
                    "message_count": 0,
                    "counts_by_kind": {},
                    "selection": {
                        "types": ["text"],
                        "all_messages_in_range": False,
                        "unselected_message_count": 0,
                    },
                    "chat": {
                        "display_name": "当前账号群",
                        "chat_id": "wxid_private@chatroom",
                        "kind": "group",
                    },
                    "time_range": {
                        "start_input": "99",
                        "end_input": "101",
                    },
                    "messages": [],
                }

            def write_json(path: Path, plan: dict[str, object], _vault: Path):
                events.append("write")
                path.write_text(json.dumps(plan), encoding="utf-8")

            fake_backend = SimpleNamespace(
                bind_active_account=bind_active_account,
                load_account_profile=load_account_profile,
                refresh_online_snapshot=refresh_online_snapshot,
                resolve_vault=lambda value: Path(value),
                ensure_output=lambda value, _vault: value,
                find_chat_candidates=find_chat_candidates,
                build_content_plan=build_content_plan,
                plan_digest=plan_digest,
                write_json=write_json,
            )
            captured = io.StringIO()
            with contextlib.redirect_stdout(captured):
                result = backend_module.run_scan(
                    SimpleNamespace(request=str(request_path), output=str(output_path)),
                    fake_backend,
                )

            self.assertEqual(result, 0)
            self.assertEqual(
                events,
                ["bind", "profile", "refresh", "profile", "scan", "write"],
            )
            private_plan = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(
                private_plan["routing"],
                {"schema_version": 1, "account_ref": account_ref},
            )
            self.assertEqual(private_plan["plan_digest"], plan_digest(private_plan))
            public_text = captured.getvalue()
            self.assertNotIn(account_ref, public_text)
            self.assertNotIn("wxid_private", public_text)
            self.assertNotIn(str(output_path), public_text)
            public_report = json.loads(public_text)
            self.assertEqual(public_report["routing_mode"], "current-official-session")
            self.assertEqual(public_report["snapshot_mode"], "online")
            self.assertNotIn("run_directory", public_report)

    def test_implicit_scan_does_not_refresh_an_ambiguous_chat(self) -> None:
        backend_module = _load_module("portable_backend_ambiguous_online", DEV_BACKEND_PATH)
        account_ref = "account-0123456789ab"
        binding = SimpleNamespace(account_ref=account_ref)
        events: list[str] = []

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            vault = root / "vault"
            vault.mkdir()
            request_path = root / "request.json"
            request_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "chat": "同名群",
                        "chat_id": None,
                        "start": "99",
                        "end": "101",
                        "types": ["text"],
                    }
                ),
                encoding="utf-8",
            )
            request_path.chmod(0o600)
            output_path = root / "plan.json"
            fake_backend = SimpleNamespace(
                bind_active_account=lambda: events.append("bind") or binding,
                load_account_profile=lambda _ref: events.append("profile")
                or {
                    "schema_version": 2,
                    "account_ref": account_ref,
                    "vault_dir": str(vault),
                    "account_root": str(root / "account"),
                    "swift_bin": None,
                },
                resolve_vault=lambda value: Path(value),
                ensure_output=lambda value, _vault: value,
                find_chat_candidates=lambda _vault, _chat: [
                    {
                        "chat_id": "first@chatroom",
                        "display_name": "同名群",
                        "kind": "group",
                        "match": "exact",
                    },
                    {
                        "chat_id": "second@chatroom",
                        "display_name": "同名群",
                        "kind": "group",
                        "match": "exact",
                    },
                ],
                refresh_online_snapshot=lambda *_args, **_kwargs: self.fail(
                    "ambiguous chat must not refresh"
                ),
                build_content_plan=lambda *_args, **_kwargs: self.fail(
                    "ambiguous chat must not scan"
                ),
            )
            captured = io.StringIO()
            with contextlib.redirect_stdout(captured):
                result = backend_module.run_scan(
                    SimpleNamespace(request=str(request_path), output=str(output_path)),
                    fake_backend,
                )

            self.assertEqual(result, 3)
            self.assertEqual(events, ["bind", "profile"])
            self.assertFalse(output_path.exists())
            report = json.loads(captured.getvalue())
            self.assertEqual(report["status"], "needs-chat-selection")
            self.assertFalse(report["plan_created"])
            self.assertNotIn("snapshot_mode", report)

    def test_online_refresh_error_is_safely_classified(self) -> None:
        backend_module = _load_module("portable_backend_refresh_error", DEV_BACKEND_PATH)
        account_ref = "account-0123456789ab"
        binding = SimpleNamespace(account_ref=account_ref)
        refresh_error = type("OnlineRefreshError", (RuntimeError,), {})

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            vault = root / "vault"
            vault.mkdir()
            request_path = root / "request.json"
            request_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "chat": "当前账号群",
                        "chat_id": None,
                        "start": "99",
                        "end": "101",
                        "types": ["text"],
                    }
                ),
                encoding="utf-8",
            )
            request_path.chmod(0o600)
            fake_backend = SimpleNamespace(
                bind_active_account=lambda: binding,
                load_account_profile=lambda _ref: {
                    "schema_version": 2,
                    "account_ref": account_ref,
                    "vault_dir": str(vault),
                    "account_root": str(root / "account"),
                    "swift_bin": None,
                },
                resolve_vault=lambda value: Path(value),
                ensure_output=lambda value, _vault: value,
                find_chat_candidates=lambda _vault, _chat: [
                    {
                        "chat_id": "selected@chatroom",
                        "display_name": "当前账号群",
                        "kind": "group",
                        "match": "exact",
                    }
                ],
                refresh_online_snapshot=lambda *_args, **_kwargs: (
                    _ for _ in ()
                ).throw(refresh_error("无法协调在线 WAL")),
            )

            with self.assertRaisesRegex(
                backend_module.DevelopmentBackendError,
                "在线快照刷新失败",
            ):
                backend_module.run_scan(
                    SimpleNamespace(
                        request=str(request_path),
                        output=str(root / "plan.json"),
                    ),
                    fake_backend,
                )

    def test_doctor_reports_setup_required_without_using_legacy_profile(self) -> None:
        backend_module = _load_module("portable_backend_missing_profile", DEV_BACKEND_PATH)
        account_ref = "account-111111111111"
        events: list[str] = []
        profile_error = type("ProfileError", (Exception,), {})
        binding = SimpleNamespace(
            account_ref=account_ref,
            public_report=lambda: {
                "status": "unique",
                "selected": True,
                "official_process_count": 1,
                "held_categories": ["contact", "message"],
                "core_evidence": {"contact": True, "message": True},
                "writes_performed": False,
            },
        )

        def load_account_profile(requested_ref: str):
            events.append("profile")
            self.assertEqual(requested_ref, account_ref)
            raise profile_error("missing")

        fake_backend = SimpleNamespace(
            bind_active_account=lambda: events.append("bind") or binding,
            load_account_profile=load_account_profile,
            doctor=lambda *_args, **_kwargs: self.fail("doctor must stop before vault access"),
        )
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            result = backend_module.run_doctor(
                SimpleNamespace(vault_dir=None, account_root=None, swift_bin=None),
                PACKAGE_ROOT.parent,
                fake_backend,
            )
        self.assertEqual(result, 2)
        self.assertEqual(events, ["bind", "profile"])
        report = json.loads(captured.getvalue())
        self.assertEqual(report["current_account"]["status"], "unique")
        self.assertEqual(report["profile"]["status"], "setup-required")
        self.assertIn("$wechat-local-export-setup", report["next_action"])
        self.assertNotIn(account_ref, captured.getvalue())
        source = DEV_BACKEND_PATH.read_text(encoding="utf-8")
        self.assertNotRegex(source, r"\bload_profile\b")

    def test_export_rejects_plan_after_current_account_switch_before_profile_load(self) -> None:
        backend_module = _load_module("portable_backend_account_switch", DEV_BACKEND_PATH)
        planned_ref = "account-aaaaaaaaaaaa"
        current_ref = "account-bbbbbbbbbbbb"
        events: list[str] = []
        binding = SimpleNamespace(account_ref=current_ref)
        plan = {
            "schema_version": 1,
            "routing": {"schema_version": 1, "account_ref": planned_ref},
            "plan_digest": "1" * 64,
            "message_count": 1,
            "counts_by_kind": {"text": 1},
        }
        fake_backend = SimpleNamespace(
            load_content_plan=lambda _path: events.append("plan") or plan,
            bind_active_account=lambda: events.append("bind") or binding,
            load_account_profile=lambda _ref: events.append("profile")
            or self.fail("mismatched account must not load any profile"),
            export_archive=lambda *_args, **_kwargs: self.fail(
                "mismatched account must not export"
            ),
        )
        args = SimpleNamespace(
            vault_dir=None,
            account_root=None,
            swift_bin=None,
            plan="/private/plan.json",
            output_dir="/private/archive",
            confirm_digest=plan["plan_digest"],
            confirm_count=1,
            allow_partial=False,
            voice_mp4_only=False,
        )
        with self.assertRaises(backend_module.DevelopmentBackendError) as raised:
            backend_module.run_export(args, PACKAGE_ROOT.parent, fake_backend)
        self.assertEqual(events, ["plan", "bind"])
        self.assertNotIn(planned_ref, str(raised.exception))
        self.assertNotIn(current_ref, str(raised.exception))

    def test_voice_mp4_only_export_does_not_require_swift_helper(self) -> None:
        backend_module = _load_module(
            "portable_backend_fast_voice_without_swift",
            DEV_BACKEND_PATH,
        )
        account_ref = "account-aaaaaaaaaaaa"
        binding = SimpleNamespace(account_ref=account_ref)
        plan = {
            "schema_version": 1,
            "routing": {"schema_version": 1, "account_ref": account_ref},
            "plan_digest": "7" * 64,
            "message_count": 1,
            "counts_by_kind": {"voice": 1},
        }
        received: dict[str, object] = {}

        def export_archive(*args, **kwargs):
            received["swift_bin"] = kwargs["swift_bin"]
            received["voice_mp4_only"] = kwargs["voice_mp4_only"]
            return {
                "output_mode": "voice-mp4-only",
                "message_count": 1,
                "issue_count": 0,
                "verification": {
                    "status": "verified-before-atomic-publish"
                },
            }

        fake_backend = SimpleNamespace(
            load_content_plan=lambda _path: plan,
            bind_active_account=lambda: binding,
            load_account_profile=lambda _ref: {
                "schema_version": 2,
                "account_ref": account_ref,
                "vault_dir": "/private/vault",
                "account_root": "/private/account",
                "swift_bin": None,
            },
            export_archive=export_archive,
        )
        reports: list[dict] = []
        args = SimpleNamespace(
            vault_dir=None,
            account_root=None,
            swift_bin=None,
            plan="/private/plan.json",
            output_dir="/private/output",
            confirm_digest=plan["plan_digest"],
            confirm_count=1,
            allow_partial=False,
            voice_mp4_only=True,
        )
        with mock.patch.object(
            backend_module,
            "_find_swift_binary",
            side_effect=AssertionError("fast MP4 must not require Swift"),
        ):
            result = backend_module.run_export(
                args,
                PACKAGE_ROOT.parent,
                fake_backend,
                report_sink=reports.append,
            )

        self.assertEqual(result, 0)
        self.assertIsNone(received["swift_bin"])
        self.assertTrue(received["voice_mp4_only"])
        self.assertEqual(reports[0]["status"], "complete")

    def test_explicit_development_paths_bypass_live_routing_without_profile_mix(self) -> None:
        backend_module = _load_module("portable_backend_explicit_paths", DEV_BACKEND_PATH)
        fake_backend = SimpleNamespace(
            bind_active_account=lambda: self.fail("explicit mode must not bind live account"),
            load_account_profile=lambda _ref: self.fail(
                "explicit mode must not load an implicit profile"
            ),
            doctor=lambda vault, *, account_root, swift_bin: {
                "ready_for_scan": True,
                "ready_for_media_export": True,
                "ready_for_voice_mp4": False,
                "received": {
                    "vault_dir": vault,
                    "account_root": account_root,
                    "swift_bin": swift_bin,
                },
            },
        )
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            result = backend_module.run_doctor(
                SimpleNamespace(
                    vault_dir="/private/dev-vault",
                    account_root="/private/dev-account",
                    swift_bin=None,
                ),
                PACKAGE_ROOT.parent,
                fake_backend,
            )
        self.assertEqual(result, 0)
        report = json.loads(captured.getvalue())
        self.assertEqual(report["routing_mode"], "explicit-development-paths")
        self.assertEqual(
            report["current_account"]["status"], "bypassed-development-only"
        )
        self.assertNotIn("/private/dev-vault", captured.getvalue())
        self.assertNotIn("/private/dev-account", captured.getvalue())

    def test_current_account_routing_failures_stop_with_bounded_codes(self) -> None:
        backend_module = _load_module("portable_backend_route_failures", DEV_BACKEND_PATH)
        account_routing_error = type("AccountRoutingError", (Exception,), {})
        for code in (
            "no-active-account",
            "multiple-active-accounts",
            "unstable",
            "unavailable",
        ):
            with self.subTest(code=code):
                failure = account_routing_error("private detail")
                failure.code = code
                failure.samples_completed = 1

                def fail(failure=failure):
                    raise failure

                with self.assertRaises(
                    backend_module.CurrentAccountRoutingError
                ) as raised:
                    backend_module._bind_current_account_or_stop(
                        SimpleNamespace(bind_active_account=fail)
                    )
                self.assertEqual(raised.exception.code, code)
                self.assertEqual(
                    raised.exception.public_report()["status"], code
                )
                self.assertNotIn("private detail", str(raised.exception))

    def test_scan_request_never_defaults_to_all_types(self) -> None:
        backend = _load_module("portable_backend_types", DEV_BACKEND_PATH)
        request = {
            "schema_version": 1,
            "vault_dir": "/private/vault",
            "chat": "示例群",
            "chat_id": None,
            "start": "2030-01-01 09:00:00",
            "end": "2030-01-01 10:00:00",
        }
        with self.assertRaises(backend.DevelopmentBackendError):
            backend._validate_scan_request(request)


if __name__ == "__main__":
    unittest.main()
