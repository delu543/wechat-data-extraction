from __future__ import annotations

import hashlib
from pathlib import Path
import sqlite3
import tempfile
import unittest

from live_tools.wechat_online_refresh import (
    OnlineRefreshError,
    refresh_online_snapshot,
    snapshot_database_requests,
)


class Binding:
    account_ref = "account-0123456789ab"


class OnlineRefreshTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.vault = self.root / "vault"
        (self.vault / "contact").mkdir(parents=True)
        (self.vault / "message").mkdir()
        (self.vault / "contact/contact.db").write_bytes(b"contact")
        self.chat_id = "fixture@chatroom"
        table = "Msg_" + hashlib.md5(self.chat_id.encode()).hexdigest()
        with sqlite3.connect(self.vault / "message/message_0.db") as connection:
            connection.execute(f"CREATE TABLE [{table}](id INTEGER)")
        with sqlite3.connect(self.vault / "message/message_1.db") as connection:
            connection.execute("CREATE TABLE unrelated(id INTEGER)")
        with sqlite3.connect(self.vault / "message/media_0.db") as connection:
            connection.execute("CREATE TABLE VoiceInfo(svr_id INTEGER)")
        with sqlite3.connect(
            self.vault / "message/message_resource.db"
        ) as connection:
            connection.execute("CREATE TABLE MessageResourceInfo(id INTEGER)")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_requests_only_target_chat_message_shards(self) -> None:
        self.assertEqual(
            snapshot_database_requests(
                self.vault,
                kinds=["text"],
                chat_id=self.chat_id,
            ),
            ["contact", "message_0"],
        )
        self.assertEqual(
            snapshot_database_requests(
                self.vault,
                kinds=["voice"],
                chat_id=self.chat_id,
            ),
            ["contact", "message_0", "media_0"],
        )
        self.assertEqual(
            snapshot_database_requests(
                self.vault,
                kinds=["all"],
                chat_id=self.chat_id,
            ),
            ["contact", "message_0", "media_0", "message_resource"],
        )

    def test_refresh_uses_online_snapshot_and_updates_profile_last(self) -> None:
        run = self.root / "run"
        (run / "decrypted").mkdir(parents=True)
        calls: dict[str, object] = {}

        def snapshotter(**kwargs: object) -> dict[str, object]:
            calls["snapshot"] = kwargs
            return {
                "status": "complete",
                "database_count": 3,
                "run_directory": str(run),
                "safety": {
                    "snapshot_mode": "online_sqlite_shm_coordinated_apfs_clone"
                },
            }

        def profile_writer(account_ref: str, profile: object) -> None:
            calls["profile"] = (account_ref, profile)

        report = refresh_online_snapshot(
            Binding(),
            {
                "schema_version": 2,
                "account_ref": Binding.account_ref,
                "vault_dir": str(self.vault),
                "account_root": str(self.root / "account"),
                "swift_bin": str(self.root / "swift"),
            },
            kinds=["voice"],
            chat_id=self.chat_id,
            output_root=self.root / "snapshots",
            resolver=lambda account_ref: self.root / "db_storage",
            snapshotter=snapshotter,
            doctor_fn=lambda *args, **kwargs: {
                "ready_for_scan": True,
                "ready_for_voice_mp4": True,
            },
            profile_writer=profile_writer,
        )
        snapshot = calls["snapshot"]
        self.assertTrue(snapshot["online"])
        self.assertIsNone(snapshot["keys_file"])
        self.assertEqual(
            snapshot["databases"],
            ["contact", "message_0", "media_0"],
        )
        self.assertIn("profile", calls)
        self.assertTrue(report["profile_updated"])
        self.assertFalse(report["page_hmac_verified"])

    def test_profile_is_not_updated_when_new_snapshot_fails_doctor(self) -> None:
        run = self.root / "failed-run"
        (run / "decrypted").mkdir(parents=True)
        wrote: list[object] = []
        with self.assertRaisesRegex(OnlineRefreshError, "doctor"):
            refresh_online_snapshot(
                Binding(),
                {
                    "schema_version": 2,
                    "account_ref": Binding.account_ref,
                    "vault_dir": str(self.vault),
                    "account_root": str(self.root / "account"),
                    "swift_bin": str(self.root / "swift"),
                },
                kinds=["text"],
                chat_id=self.chat_id,
                output_root=self.root / "snapshots",
                resolver=lambda account_ref: self.root / "db_storage",
                snapshotter=lambda **kwargs: {
                    "status": "complete",
                    "database_count": 2,
                    "run_directory": str(run),
                    "safety": {
                        "snapshot_mode": (
                            "online_sqlite_shm_coordinated_apfs_clone"
                        )
                    },
                },
                doctor_fn=lambda *args, **kwargs: {
                    "ready_for_scan": False,
                    "ready_for_voice_mp4": False,
                },
                profile_writer=lambda *args: wrote.append(args),
            )
        self.assertEqual(wrote, [])


if __name__ == "__main__":
    unittest.main()
