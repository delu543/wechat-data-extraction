from __future__ import annotations

import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from content_vault import cli
from content_vault.cli import _parser


class CLISafetyTests(unittest.TestCase):
    def test_fast_voice_mp4_readiness_does_not_require_swift_helper(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            account = Path(temporary) / "account"
            (account / "msg").mkdir(parents=True)
            with mock.patch.object(
                cli,
                "voice_doctor",
                return_value={
                    "ready_for_plan": True,
                    "ready_for_extract": True,
                    "checks": [],
                },
            ), mock.patch.object(
                cli.importlib.util,
                "find_spec",
                return_value=object(),
            ), mock.patch.object(
                cli,
                "_image_key_candidates",
                return_value=[],
            ):
                report = cli.doctor(
                    "/private/validated-vault",
                    account_root=str(account),
                    swift_bin=None,
                )

        self.assertTrue(report["ready_for_voice_mp4"])
        self.assertFalse(report["ready_for_voice_archive"])
        swift_check = next(
            item for item in report["checks"] if item["name"] == "voice_mp4_helper"
        )
        self.assertFalse(swift_check["ok"])

    def test_scan_requires_explicit_message_types(self) -> None:
        required = [
            "scan",
            "--vault-dir",
            "/private/vault",
            "--chat",
            "Example",
            "--start",
            "2030-01-01 09:00:00",
            "--end",
            "2030-01-01 10:00:00",
            "--output",
            "/private/plan.json",
        ]
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                _parser().parse_args(required)
        parsed = _parser().parse_args(required + ["--type", "all"])
        self.assertEqual(parsed.types, ["all"])

    def test_voice_mp4_only_is_explicit_and_mutually_exclusive_with_partial(
        self,
    ) -> None:
        required = [
            "export",
            "--vault-dir",
            "/private/vault",
            "--account-root",
            "/private/account",
            "--plan",
            "/private/plan.json",
            "--approve-digest",
            "a" * 64,
            "--output-dir",
            "/private/output",
        ]
        parsed = _parser().parse_args(required)
        self.assertFalse(parsed.voice_mp4_only)
        self.assertFalse(parsed.allow_partial)
        parsed = _parser().parse_args(required + ["--voice-mp4-only"])
        self.assertTrue(parsed.voice_mp4_only)
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                _parser().parse_args(
                    required + ["--voice-mp4-only", "--allow-partial"]
                )

    def test_profile_accepts_one_redacted_account_reference(self) -> None:
        base = [
            "configure-profile",
            "--vault-dir",
            "/private/vault",
        ]
        parsed = _parser().parse_args(
            base + ["--account-ref", "account-0123456789ab"]
        )
        self.assertEqual(parsed.account_ref, "account-0123456789ab")
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                _parser().parse_args(base)
            with self.assertRaises(SystemExit):
                _parser().parse_args(
                    base
                    + [
                        "--account-ref",
                        "account-0123456789ab",
                        "--account-root",
                        "/private/account",
                    ]
                )

    def test_configure_profile_with_account_ref_writes_schema_two_registry_entry(self) -> None:
        report = {
            "ready_for_scan": True,
            "ready_for_media_export": True,
            "ready_for_voice_mp4": False,
            "checks": [
                {"name": "account_media_root", "ok": True},
                {"name": "voice_mp4_helper", "ok": False},
            ],
        }
        captured = io.StringIO()
        with mock.patch.object(
            cli, "resolve_account_ref", return_value=Path("/private/account/db_storage")
        ), mock.patch.object(cli, "doctor", return_value=report), mock.patch.object(
            cli, "write_account_profile"
        ) as account_writer, mock.patch.object(cli, "write_profile") as legacy_writer:
            with contextlib.redirect_stdout(captured):
                result = cli.main(
                    [
                        "configure-profile",
                        "--vault-dir",
                        "/private/vault",
                        "--account-ref",
                        "account-0123456789ab",
                    ]
                )

        self.assertEqual(result, 0)
        account_writer.assert_called_once_with(
            "account-0123456789ab",
            {
                "schema_version": 2,
                "account_ref": "account-0123456789ab",
                "vault_dir": "/private/vault",
                "account_root": "/private/account",
                "swift_bin": None,
            },
        )
        legacy_writer.assert_not_called()
        self.assertIn('"contains_database_keys": false', captured.getvalue())

    def test_explicit_account_root_keeps_legacy_source_compatibility(self) -> None:
        report = {
            "ready_for_scan": True,
            "ready_for_media_export": True,
            "ready_for_voice_mp4": False,
            "checks": [
                {"name": "account_media_root", "ok": True},
                {"name": "voice_mp4_helper", "ok": False},
            ],
        }
        with mock.patch.object(cli, "doctor", return_value=report), mock.patch.object(
            cli, "write_account_profile"
        ) as account_writer, mock.patch.object(cli, "write_profile") as legacy_writer:
            with contextlib.redirect_stdout(io.StringIO()):
                result = cli.main(
                    [
                        "configure-profile",
                        "--vault-dir",
                        "/private/vault",
                        "--account-root",
                        "/private/account",
                    ]
                )

        self.assertEqual(result, 0)
        account_writer.assert_not_called()
        legacy_writer.assert_called_once_with(
            {
                "schema_version": 1,
                "vault_dir": "/private/vault",
                "account_root": "/private/account",
                "swift_bin": None,
            }
        )


if __name__ == "__main__":
    unittest.main()
