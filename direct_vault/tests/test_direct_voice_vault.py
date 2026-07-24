from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import struct
import subprocess
import tempfile
from typing import Optional
import unittest
from unittest.mock import patch

import direct_vault.direct_voice_vault as voice_vault
from direct_vault.direct_voice_vault import (
    SILK_MAGIC,
    VaultError,
    _convert_pcm_with_ffmpeg,
    _convert_pcm_with_swift,
    build_plan,
    decode,
    doctor,
    extract,
    inspect_silk,
)


def make_silk(duration_ms: int, *, tencent_prefix: bool = True) -> bytes:
    if duration_ms % 20:
        raise ValueError("fixture duration must be a multiple of 20 ms")
    packets = []
    for index in range(duration_ms // 20):
        payload = bytes(((index + 1) & 0xFF, 0x7A, 0x31))
        packets.append(struct.pack("<h", len(payload)) + payload)
    prefix = b"\x02" if tencent_prefix else b""
    return prefix + SILK_MAGIC + b"".join(packets)


class FixtureVault:
    def __init__(self, root: Path) -> None:
        self.root = root
        (root / "contact").mkdir(parents=True)
        (root / "message").mkdir()
        self.chat_id = "123456789@chatroom"
        self.chat_name = "测试语音群"
        self.contact = root / "contact/contact.db"
        self.message = root / "message/message_0.db"
        self.media = root / "message/media_0.db"
        self._create_contact()
        self._create_message()
        self._create_media()

    @property
    def table(self) -> str:
        return "Msg_" + hashlib.md5(self.chat_id.encode()).hexdigest()

    def _create_contact(self) -> None:
        with sqlite3.connect(self.contact) as connection:
            connection.execute(
                "CREATE TABLE contact (id INTEGER, username TEXT, nick_name TEXT, remark TEXT, alias TEXT)"
            )
            connection.execute(
                "INSERT INTO contact VALUES (1, ?, ?, '', '')",
                (self.chat_id, self.chat_name),
            )

    def _create_message(self) -> None:
        with sqlite3.connect(self.message) as connection:
            connection.execute(
                f"CREATE TABLE [{self.table}] ("
                "local_id INTEGER, server_id INTEGER, local_type INTEGER, "
                "create_time INTEGER, message_content TEXT, "
                "compress_content BLOB, WCDB_CT_message_content INTEGER)"
            )

    def _create_media(self) -> None:
        with sqlite3.connect(self.media) as connection:
            connection.execute(
                "CREATE TABLE VoiceInfo (svr_id INTEGER, voice_data BLOB, "
                "local_id INTEGER, create_time INTEGER, chat_name_id INTEGER)"
            )
            connection.execute("CREATE TABLE Name2Id (user_name TEXT)")
            connection.execute(
                "INSERT INTO Name2Id(rowid, user_name) VALUES (7, ?)",
                (self.chat_id,),
            )

    def add_message(
        self,
        local_id: int,
        server_id: int,
        create_time: int,
        duration_ms: int,
        *,
        local_type: int = 34,
        compressed_fallback: bool = False,
    ) -> None:
        xml = f'<msg><voicemsg voicelength="{duration_ms}" /></msg>'
        content = "" if compressed_fallback else xml
        compressed = xml.encode("utf-8") if compressed_fallback else None
        with sqlite3.connect(self.message) as connection:
            connection.execute(
                f"INSERT INTO [{self.table}] VALUES (?, ?, ?, ?, ?, ?, ?)",
                (local_id, server_id, local_type, create_time, content, compressed, None),
            )

    def add_voice(
        self,
        server_id: int,
        duration_ms: int,
        *,
        local_id: int = 0,
        blob: Optional[bytes] = None,
        database: Optional[Path] = None,
        chat_name_id: int = 7,
    ) -> None:
        target = database or self.media
        with sqlite3.connect(target) as connection:
            connection.execute(
                "INSERT INTO VoiceInfo VALUES (?, ?, ?, ?, ?)",
                (
                    server_id,
                    blob if blob is not None else make_silk(duration_ms),
                    local_id,
                    100,
                    chat_name_id,
                ),
            )


class DirectVoiceVaultTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.vault = FixtureVault(self.base / "vault")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def plan(self, expected: Optional[int] = None) -> dict:
        return build_plan(
            self.vault.root,
            self.vault.chat_name,
            "100",
            "300",
            expected=expected,
        )

    def write_plan(self, plan: dict) -> Path:
        path = self.base / "plan.json"
        path.write_text(json.dumps(plan, ensure_ascii=False), encoding="utf-8")
        return path

    def fake_swift_bin(self) -> Path:
        path = self.base / "fake-swift-bin"
        path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        path.chmod(0o700)
        return path

    def extract_one(self, duration_ms: int = 200) -> Path:
        self.vault.add_message(1, 9101, 150, duration_ms)
        self.vault.add_voice(9101, duration_ms, local_id=1)
        output = self.base / "extracted"
        extract(
            self.vault.root,
            self.write_plan(self.plan(expected=1)),
            output,
        )
        return output

    def extract_many(self, count: int, duration_ms: int = 200) -> Path:
        for sequence in range(1, count + 1):
            server_id = 9200 + sequence
            self.vault.add_message(
                sequence,
                server_id,
                150 + sequence,
                duration_ms,
            )
            self.vault.add_voice(
                server_id,
                duration_ms,
                local_id=sequence,
            )
        output = self.base / "extracted"
        extract(
            self.vault.root,
            self.write_plan(self.plan(expected=count)),
            output,
        )
        return output

    @staticmethod
    def fake_decoder_for(duration_ms: int):
        def fake_decoder(source: Path, destination: Path, sample_rate: int) -> None:
            assert source.suffix == ".silk"
            destination.write_bytes(
                b"\x00\x00" * (sample_rate * duration_ms // 1_000)
            )

        return fake_decoder

    @staticmethod
    def fake_converter(
        swift_bin: Path,
        pcm_path: Path,
        output_path: Path,
        sample_rate: int,
        expected_duration_ms: int,
    ) -> dict:
        assert os.access(swift_bin, os.X_OK)
        assert pcm_path.is_file()
        assert sample_rate == 24_000
        payload = b"fixture-m4a-" + str(expected_duration_ms).encode("ascii")
        output_path.write_bytes(payload)
        return {
            "output": str(output_path.resolve()),
            "durationMilliseconds": expected_duration_ms,
            "sha256": hashlib.sha256(payload).hexdigest(),
        }

    def test_doctor_reports_read_only_vault_ready(self) -> None:
        report = doctor(self.vault.root)
        self.assertTrue(report["ready_for_plan"])
        self.assertTrue(report["ready_for_extract"])
        self.assertIn("read_keys", report["prohibited_actions"])

    def test_wal_mode_main_only_snapshot_is_immutable_and_sidecars_fail(self) -> None:
        databases = (self.vault.contact, self.vault.message, self.vault.media)
        for database in databases:
            header = bytearray(database.read_bytes())
            header[18:20] = b"\x02\x02"
            database.write_bytes(header)
            self.assertEqual(database.read_bytes()[18:20], b"\x02\x02")
            self.assertFalse(Path(str(database) + "-wal").exists())
            database.chmod(0o400)

        directories = (
            self.vault.root / "contact",
            self.vault.root / "message",
            self.vault.root,
        )
        for directory in directories:
            directory.chmod(0o500)
        try:
            report = doctor(self.vault.root)
            self.assertTrue(report["ready_for_plan"])
            self.assertTrue(report["ready_for_extract"])
        finally:
            for directory in reversed(directories):
                directory.chmod(0o700)
            for database in databases:
                database.chmod(0o600)

        Path(str(self.vault.message) + "-wal").write_bytes(b"unmerged")
        rejected = doctor(self.vault.root)
        self.assertFalse(rejected["ready_for_plan"])
        self.assertIn("message_0.db", rejected["checks"][1]["unreadable"])

    def test_plan_filters_voice_and_orders_unique_server_rows(self) -> None:
        self.vault.add_message(2, 9002, 200, 40)
        self.vault.add_message(1, 9001, 150, 40)
        self.vault.add_message(3, 9003, 200, 40, local_type=(7 << 32) | 34)
        self.vault.add_message(4, 9004, 201, 40, local_type=1)
        self.vault.add_message(5, 9005, 301, 40)
        plan = self.plan(expected=3)
        self.assertEqual([row["local_id"] for row in plan["voices"]], ["1", "2", "3"])
        self.assertEqual([row["server_id"] for row in plan["voices"]], ["9001", "9002", "9003"])
        self.assertEqual([row["sequence"] for row in plan["voices"]], [1, 2, 3])

    def test_plan_rejects_duplicate_nonzero_server_id(self) -> None:
        self.vault.add_message(1, 9002, 150, 40)
        self.vault.add_message(2, 9002, 160, 40)
        with self.assertRaisesRegex(VaultError, "server_id=9002.*重复"):
            self.plan()

    def test_compress_content_is_used_when_message_content_is_empty(self) -> None:
        self.vault.add_message(1, 9012, 150, 60, compressed_fallback=True)
        plan = self.plan(expected=1)
        self.assertEqual(plan["voices"][0]["duration_ms"], 60)

    def test_group_name_ambiguity_is_rejected(self) -> None:
        with sqlite3.connect(self.vault.contact) as connection:
            connection.execute(
                "INSERT INTO contact VALUES (2, ?, ?, '', '')",
                ("987654321@chatroom", self.vault.chat_name),
            )
        with self.assertRaisesRegex(VaultError, "歧义"):
            self.plan()

    def test_private_chat_plan_and_extract_use_exact_chat_id(self) -> None:
        private_id = "wxid_private_fixture"
        private_name = "测试私聊"
        private_table = "Msg_" + hashlib.md5(private_id.encode()).hexdigest()
        with sqlite3.connect(self.vault.contact) as connection:
            connection.execute(
                "INSERT INTO contact VALUES (2, ?, ?, '', '')",
                (private_id, private_name),
            )
        with sqlite3.connect(self.vault.message) as connection:
            connection.execute(
                f"CREATE TABLE [{private_table}] ("
                "local_id INTEGER, server_id INTEGER, local_type INTEGER, "
                "create_time INTEGER, message_content TEXT, "
                "compress_content BLOB, WCDB_CT_message_content INTEGER)"
            )
            connection.execute(
                f"INSERT INTO [{private_table}] VALUES (?, ?, ?, ?, ?, ?, ?)",
                (1, 9030, 34, 150, '<msg><voicemsg voicelength="200" /></msg>', None, None),
            )
        with sqlite3.connect(self.vault.media) as connection:
            connection.execute(
                "INSERT INTO Name2Id(rowid, user_name) VALUES (8, ?)",
                (private_id,),
            )
        self.vault.add_voice(9030, 200, local_id=1, chat_name_id=8)

        plan = build_plan(
            self.vault.root,
            private_name,
            "100",
            "300",
            expected=1,
        )
        self.assertEqual(plan["chat"]["chat_id"], private_id)
        self.assertEqual(plan["chat"]["kind"], "direct")
        output = self.base / "private-extracted"
        report = extract(self.vault.root, self.write_plan(plan), output)
        self.assertEqual(report["voice_count"], 1)
        self.assertEqual(report["chat"]["kind"], "direct")
        self.assertEqual(
            report["voices"][0]["chat_binding"]["status"], "verified"
        )

    def test_extract_uses_unique_server_id_and_preserves_prefix(self) -> None:
        self.vault.add_message(1, 9001, 150, 40)
        self.vault.add_message(2, 9002, 160, 60)
        self.vault.add_voice(9001, 40, local_id=1)
        self.vault.add_voice(9002, 60, local_id=2)
        source_hash = hashlib.sha256(self.vault.media.read_bytes()).hexdigest()
        plan_path = self.write_plan(self.plan(expected=2))
        output = self.base / "extracted"
        report = extract(self.vault.root, plan_path, output)
        self.assertEqual(report["voice_count"], 2)
        files = sorted(output.glob("*.silk"))
        self.assertEqual(len(files), 2)
        self.assertTrue(files[0].read_bytes().startswith(b"\x02" + SILK_MAGIC))
        manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual([row["server_id"] for row in manifest["voices"]], ["9001", "9002"])
        self.assertEqual(manifest["chat"]["chat_id"], self.vault.chat_id)
        self.assertEqual(manifest["chat"]["display_name"], self.vault.chat_name)
        self.assertEqual(manifest["time_range"]["start_unix"], 100)
        self.assertEqual(manifest["time_range"]["end_unix"], 300)
        self.assertEqual(manifest["voices"][0]["chat_binding"]["status"], "verified")
        self.assertEqual(
            manifest["voices"][0]["sha256"],
            hashlib.sha256(files[0].read_bytes()).hexdigest(),
        )
        self.assertEqual(
            hashlib.sha256(self.vault.media.read_bytes()).hexdigest(), source_hash
        )

    def test_extract_batches_voice_lookup_and_uses_chat_server_index(self) -> None:
        with sqlite3.connect(self.vault.media) as connection:
            connection.execute(
                "CREATE INDEX voice_chat_server_idx "
                "ON VoiceInfo(chat_name_id, svr_id)"
            )
        for sequence, server_id in enumerate((9051, 9052, 9053), 1):
            self.vault.add_message(sequence, server_id, 149 + sequence, 40)
            self.vault.add_voice(server_id, 40, local_id=sequence)

        original_connect = voice_vault._connect_read_only
        media_connections = 0
        statements: list[str] = []

        @contextmanager
        def traced_connect(path: Path, vault: Path):
            nonlocal media_connections
            with original_connect(path, vault) as connection:
                if path.name.startswith("media_"):
                    media_connections += 1
                    connection.set_trace_callback(statements.append)
                yield connection

        output = self.base / "batched-output"
        with patch(
            "direct_vault.direct_voice_vault._connect_read_only",
            side_effect=traced_connect,
        ):
            report = extract(
                self.vault.root,
                self.write_plan(self.plan(expected=3)),
                output,
            )

        voice_selects = [
            statement
            for statement in statements
            if statement.lstrip().upper().startswith("SELECT")
            and 'FROM "VoiceInfo"' in statement
        ]
        name_lookups = [
            statement
            for statement in statements
            if statement.lstrip().upper().startswith("SELECT")
            and 'FROM "Name2Id"' in statement
        ]
        self.assertEqual(report["voice_count"], 3)
        self.assertEqual(media_connections, 1)
        self.assertEqual(len(name_lookups), 1)
        self.assertEqual(len(voice_selects), 1)
        self.assertIn("UNION ALL", voice_selects[0])

        with sqlite3.connect(self.vault.media) as connection:
            query_plan = [
                str(row[3])
                for row in connection.execute(
                    "EXPLAIN QUERY PLAN " + voice_selects[0]
                )
            ]
        self.assertTrue(
            any("voice_chat_server_idx" in detail for detail in query_plan),
            query_plan,
        )

    def test_extract_batches_at_configured_limit(self) -> None:
        for sequence, server_id in enumerate((9061, 9062, 9063), 1):
            self.vault.add_message(sequence, server_id, 149 + sequence, 40)
            self.vault.add_voice(server_id, 40, local_id=sequence)

        original_connect = voice_vault._connect_read_only
        statements: list[str] = []

        @contextmanager
        def traced_connect(path: Path, vault: Path):
            with original_connect(path, vault) as connection:
                if path.name.startswith("media_"):
                    connection.set_trace_callback(statements.append)
                yield connection

        with (
            patch(
                "direct_vault.direct_voice_vault._connect_read_only",
                side_effect=traced_connect,
            ),
            patch(
                "direct_vault.direct_voice_vault.VOICE_LOOKUP_BATCH_SIZE",
                2,
            ),
        ):
            report = extract(
                self.vault.root,
                self.write_plan(self.plan(expected=3)),
                self.base / "multi-batch-output",
            )
        voice_selects = [
            statement
            for statement in statements
            if statement.lstrip().upper().startswith("SELECT")
            and 'FROM "VoiceInfo"' in statement
        ]
        self.assertEqual(report["voice_count"], 3)
        self.assertEqual(len(voice_selects), 2)

    def test_missing_name2id_schema_preserves_unavailable_binding(self) -> None:
        self.vault.add_message(1, 9071, 150, 40)
        self.vault.add_voice(9071, 40)
        with sqlite3.connect(self.vault.media) as connection:
            connection.execute("DROP TABLE Name2Id")
        report = extract(
            self.vault.root,
            self.write_plan(self.plan(expected=1)),
            self.base / "schema-fallback-output",
        )
        self.assertEqual(
            report["voices"][0]["chat_binding"],
            {
                "status": "unavailable",
                "reason": "Name2Id.user_name unavailable",
            },
        )

    def test_wrong_chat_duplicate_is_not_hidden_by_preferred_filter(self) -> None:
        self.vault.add_message(1, 9081, 150, 40)
        self.vault.add_voice(9081, 40, chat_name_id=7)
        with sqlite3.connect(self.vault.media) as connection:
            connection.execute(
                "INSERT INTO Name2Id(rowid, user_name) VALUES (8, ?)",
                ("other@chatroom",),
            )
        self.vault.add_voice(9081, 40, chat_name_id=8)
        with self.assertRaisesRegex(VaultError, "不是计划聊天"):
            extract(
                self.vault.root,
                self.write_plan(self.plan(expected=1)),
                self.base / "wrong-chat-duplicate-output",
            )

    def test_chat_name_id_mismatch_is_rejected(self) -> None:
        self.vault.add_message(1, 9008, 150, 40)
        self.vault.add_voice(9008, 40)
        with sqlite3.connect(self.vault.media) as connection:
            connection.execute(
                "UPDATE Name2Id SET user_name=? WHERE rowid=7",
                ("other@chatroom",),
            )
        plan_path = self.write_plan(self.plan(expected=1))
        output = self.base / "wrong-chat-output"
        with self.assertRaisesRegex(VaultError, "不是计划聊天"):
            extract(self.vault.root, plan_path, output)
        self.assertFalse(output.exists())

    def test_missing_voice_fails_without_partial_output(self) -> None:
        self.vault.add_message(1, 9010, 150, 40)
        plan_path = self.write_plan(self.plan(expected=1))
        output = self.base / "missing-output"
        with self.assertRaisesRegex(VaultError, "缺失"):
            extract(self.vault.root, plan_path, output)
        self.assertFalse(output.exists())

    def test_extract_rejects_symbolic_link_output(self) -> None:
        self.vault.add_message(1, 9011, 150, 200)
        self.vault.add_voice(9011, 200)
        plan_path = self.write_plan(self.plan(expected=1))
        output = self.base / "linked-output"
        output.symlink_to(self.base / "missing-target", target_is_directory=True)
        with self.assertRaisesRegex(VaultError, "符号链接"):
            extract(self.vault.root, plan_path, output)
        self.assertFalse((self.base / "missing-target").exists())

    def test_ambiguous_voice_across_media_shards_is_rejected(self) -> None:
        self.vault.add_message(1, 9020, 150, 40)
        self.vault.add_voice(9020, 40)
        second = self.vault.root / "message/media_1.db"
        with sqlite3.connect(second) as connection:
            connection.execute(
                "CREATE TABLE VoiceInfo (svr_id INTEGER, voice_data BLOB, "
                "local_id INTEGER, create_time INTEGER, chat_name_id INTEGER)"
            )
        self.vault.add_voice(9020, 40, database=second)
        plan_path = self.write_plan(self.plan(expected=1))
        with self.assertRaisesRegex(VaultError, "命中 2 行"):
            extract(self.vault.root, plan_path, self.base / "ambiguous-output")

    def test_server_id_zero_is_rejected(self) -> None:
        self.vault.add_message(1, 0, 150, 40)
        plan_path = self.write_plan(self.plan(expected=1))
        with self.assertRaisesRegex(VaultError, "server_id=0"):
            extract(self.vault.root, plan_path, self.base / "zero-output")

    def test_silk_header_frames_and_duration_are_validated(self) -> None:
        inspection = inspect_silk(make_silk(100), 100)
        self.assertEqual(inspection["packet_count"], 5)
        with self.assertRaisesRegex(VaultError, "魔数"):
            inspect_silk(b"not-silk", 100)
        with self.assertRaisesRegex(VaultError, "截断"):
            inspect_silk(b"\x02" + SILK_MAGIC + struct.pack("<h", 8) + b"xx", 20)
        with self.assertRaisesRegex(VaultError, "时长不符"):
            inspect_silk(make_silk(1_000), 2_000)

    def test_decode_writes_private_atomic_swift_manifest_and_removes_pcm(self) -> None:
        extracted = self.extract_one(200)
        output = self.base / "decoded"
        report = decode(
            extracted,
            output,
            self.fake_swift_bin(),
            decoder=self.fake_decoder_for(200),
            converter=self.fake_converter,
        )

        self.assertEqual(report["item_count"], 1)
        manifest = json.loads(
            (output / "direct-manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            set(manifest),
            {
                "schema_version",
                "title",
                "expected_count",
                "items",
                "source_plan_digest",
                "source_extract_manifest_sha256",
                "chat",
                "time_range",
                "conversion_stats",
            },
        )
        self.assertEqual(manifest["schema_version"], 1)
        self.assertEqual(manifest["title"], f"{self.vault.chat_name} 微信语音")
        self.assertEqual(manifest["expected_count"], 1)
        self.assertEqual(manifest["chat"]["chat_id"], self.vault.chat_id)
        self.assertEqual(manifest["time_range"]["start_unix"], 100)
        self.assertEqual(
            manifest["source_extract_manifest_sha256"],
            report["source_manifest_sha256"],
        )
        self.assertEqual(
            manifest["conversion_stats"],
            {
                "converter_mode": "custom",
                "item_count": 1,
                "conversion_attempt_count": 1,
                "swift_attempt_count": 0,
                "swift_success_count": 0,
                "swift_known_coreaudio_failure_count": 0,
                "ffmpeg_fallback_count": 0,
                "custom_converter_attempt_count": 1,
                "circuit_breaker_opened": False,
                "circuit_breaker_opened_at_sequence": None,
            },
        )
        self.assertEqual(
            report["conversion_stats"],
            manifest["conversion_stats"],
        )
        self.assertEqual(
            set(manifest["items"][0]),
            {
                "sequence",
                "server_id",
                "source_path",
                "expected_duration_milliseconds",
                "sha256",
            },
        )
        m4a = output / manifest["items"][0]["source_path"]
        self.assertEqual(
            hashlib.sha256(m4a.read_bytes()).hexdigest(),
            manifest["items"][0]["sha256"],
        )
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(m4a.stat().st_mode), 0o600)
        self.assertEqual(
            stat.S_IMODE((output / "direct-manifest.json").stat().st_mode), 0o600
        )
        self.assertEqual(list(output.glob("*.pcm")), [])
        self.assertEqual(list(output.glob(".*.pcm")), [])
        self.assertEqual(list(self.base.glob(".decoded-*")), [])

    def test_decode_rejects_manifest_path_escape_before_decoder_runs(self) -> None:
        extracted = self.extract_one(200)
        manifest_path = extracted / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["voices"][0]["relative_path"] = "../outside.silk"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        calls = []

        def should_not_decode(source: Path, destination: Path, sample_rate: int) -> None:
            calls.append((source, destination, sample_rate))

        with self.assertRaisesRegex(VaultError, "relative_path"):
            decode(
                extracted,
                self.base / "decoded",
                self.fake_swift_bin(),
                "测试",
                decoder=should_not_decode,
                converter=self.fake_converter,
            )
        self.assertEqual(calls, [])
        self.assertFalse((self.base / "decoded").exists())

    def test_decode_rejects_changed_silk_hash_before_decoder_runs(self) -> None:
        extracted = self.extract_one(200)
        source = next(extracted.glob("*.silk"))
        source.write_bytes(source.read_bytes() + b"tampered")
        calls = []

        def should_not_decode(input_path: Path, output_path: Path, rate: int) -> None:
            calls.append((input_path, output_path, rate))

        with self.assertRaisesRegex(VaultError, "字节数|SHA-256"):
            decode(
                extracted,
                self.base / "decoded",
                self.fake_swift_bin(),
                "测试",
                decoder=should_not_decode,
                converter=self.fake_converter,
            )
        self.assertEqual(calls, [])
        self.assertFalse((self.base / "decoded").exists())

    def test_decode_rejects_bad_sequence_and_duration(self) -> None:
        source_extracted = self.extract_one(200)
        for field, value, pattern in (
            ("sequence", 2, "sequence"),
            ("expected_duration_ms", 61_001, "expected_duration_ms"),
        ):
            with self.subTest(field=field):
                temporary = tempfile.TemporaryDirectory(dir=self.base)
                try:
                    isolated = Path(temporary.name)
                    extracted = isolated / "extracted"
                    shutil.copytree(source_extracted, extracted)
                    manifest_path = extracted / "manifest.json"
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                    manifest["voices"][0][field] = value
                    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                    with self.assertRaisesRegex(VaultError, pattern):
                        decode(
                            extracted,
                            isolated / "decoded",
                            self.fake_swift_bin(),
                            "测试",
                            decoder=self.fake_decoder_for(200),
                            converter=self.fake_converter,
                        )
                finally:
                    temporary.cleanup()

    def test_decode_accepts_direct_voice_duration_just_over_sixty_seconds(
        self,
    ) -> None:
        extracted = self.extract_one(60_060)
        output = self.base / "decoded"

        report = decode(
            extracted,
            output,
            self.fake_swift_bin(),
            "测试",
            decoder=self.fake_decoder_for(60_060),
            converter=self.fake_converter,
        )

        self.assertEqual(report["item_count"], 1)
        direct_manifest = json.loads(
            (output / "direct-manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            direct_manifest["items"][0]["expected_duration_milliseconds"],
            60_060,
        )

    def test_decode_failure_leaves_no_output_or_pcm(self) -> None:
        extracted = self.extract_one(200)
        output = self.base / "decoded"

        def failing_converter(
            swift_bin: Path,
            pcm_path: Path,
            output_path: Path,
            sample_rate: int,
            expected_duration_ms: int,
        ) -> dict:
            self.assertTrue(pcm_path.exists())
            output_path.write_bytes(b"partial-m4a")
            raise VaultError("injected converter failure")

        with self.assertRaisesRegex(VaultError, "injected converter failure"):
            decode(
                extracted,
                output,
                self.fake_swift_bin(),
                "测试",
                decoder=self.fake_decoder_for(200),
                converter=failing_converter,
            )
        self.assertFalse(output.exists())
        self.assertEqual(list(self.base.glob(".decoded-*")), [])
        self.assertEqual(list(self.base.rglob("*.pcm")), [])

    def test_swift_converter_uses_argument_array_without_shell(self) -> None:
        swift = self.fake_swift_bin().resolve()
        pcm = self.base / "input.pcm"
        output = self.base / "output.m4a"
        pcm.write_bytes(b"\x00\x00" * 4_800)
        payload = b"fixture-m4a"

        def fake_run(arguments, **kwargs):
            self.assertIsInstance(arguments, list)
            self.assertEqual(
                arguments,
                [
                    str(swift),
                    "pcm-to-m4a",
                    "--input",
                    str(pcm),
                    "--output",
                    str(output),
                    "--sample-rate",
                    "24000",
                    "--expected-ms",
                    "200",
                ],
            )
            self.assertNotIn("shell", kwargs)
            output.write_bytes(payload)
            stdout = json.dumps(
                {
                    "output": str(output),
                    "durationMilliseconds": 200,
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
            )
            return subprocess.CompletedProcess(arguments, 0, stdout, "")

        with patch(
            "direct_vault.direct_voice_vault.subprocess.run", side_effect=fake_run
        ):
            report = _convert_pcm_with_swift(swift, pcm, output, 24_000, 200)
        self.assertEqual(report["durationMilliseconds"], 200)

    def test_known_coreaudio_format_failure_uses_local_ffmpeg_fallback(self) -> None:
        swift = self.fake_swift_bin().resolve()
        pcm = self.base / "fallback-input.pcm"
        output = self.base / "fallback-output.m4a"
        pcm.write_bytes(b"\x00\x00" * 4_800)
        failure = subprocess.CompletedProcess(
            [str(swift)],
            1,
            "",
            (
                "The operation couldn’t be completed. "
                "(com.apple.coreaudio.avfaudio error 1718449215.)"
            ),
        )
        fallback_report = {
            "output": str(output),
            "durationMilliseconds": 200,
            "sha256": "0" * 64,
        }
        with patch(
            "direct_vault.direct_voice_vault.subprocess.run",
            return_value=failure,
        ), patch(
            "direct_vault.direct_voice_vault._convert_pcm_with_ffmpeg",
            return_value=fallback_report,
        ) as fallback:
            report = _convert_pcm_with_swift(
                swift,
                pcm,
                output,
                24_000,
                200,
            )
        self.assertEqual(report, fallback_report)
        fallback.assert_called_once_with(pcm, output, 24_000, 200)

    def test_known_coreaudio_failure_removes_regular_partial_before_fallback(
        self,
    ) -> None:
        swift = self.fake_swift_bin().resolve()
        pcm = self.base / "partial-input.pcm"
        output = self.base / "partial-output.m4a"
        pcm.write_bytes(b"\x00\x00" * 4_800)

        def fail_after_partial(arguments, **kwargs):
            output.write_bytes(b"partial")
            return subprocess.CompletedProcess(
                arguments,
                1,
                "",
                "(com.apple.coreaudio.avfaudio error 1718449215.)",
            )

        def fallback(
            pcm_path: Path,
            output_path: Path,
            sample_rate: int,
            expected_duration_ms: int,
        ) -> dict:
            self.assertFalse(output_path.exists())
            payload = b"fallback"
            output_path.write_bytes(payload)
            return {
                "output": str(output_path.resolve()),
                "durationMilliseconds": expected_duration_ms,
                "sha256": hashlib.sha256(payload).hexdigest(),
            }

        with patch(
            "direct_vault.direct_voice_vault.subprocess.run",
            side_effect=fail_after_partial,
        ), patch(
            "direct_vault.direct_voice_vault._convert_pcm_with_ffmpeg",
            side_effect=fallback,
        ):
            report = _convert_pcm_with_swift(swift, pcm, output, 24_000, 200)

        self.assertEqual(report["durationMilliseconds"], 200)
        self.assertEqual(output.read_bytes(), b"fallback")

    def test_known_coreaudio_failure_rejects_symlink_partial_output(self) -> None:
        swift = self.fake_swift_bin().resolve()
        pcm = self.base / "symlink-input.pcm"
        output = self.base / "symlink-output.m4a"
        target = self.base / "must-remain"
        pcm.write_bytes(b"\x00\x00" * 4_800)
        target.write_bytes(b"private")

        def fail_after_symlink(arguments, **kwargs):
            output.symlink_to(target)
            return subprocess.CompletedProcess(
                arguments,
                1,
                "",
                "(com.apple.coreaudio.avfaudio error 1718449215.)",
            )

        with patch(
            "direct_vault.direct_voice_vault.subprocess.run",
            side_effect=fail_after_symlink,
        ), patch(
            "direct_vault.direct_voice_vault._convert_pcm_with_ffmpeg",
        ) as fallback:
            with self.assertRaisesRegex(VaultError, "不安全"):
                _convert_pcm_with_swift(swift, pcm, output, 24_000, 200)

        fallback.assert_not_called()
        self.assertTrue(output.is_symlink())
        self.assertEqual(target.read_bytes(), b"private")

    def test_decode_known_coreaudio_failure_opens_one_batch_circuit(self) -> None:
        item_count = 5
        extracted = self.extract_many(item_count)
        output = self.base / "decoded"
        swift_failure = subprocess.CompletedProcess(
            ["swift"],
            1,
            "",
            (
                "The operation couldn’t be completed. "
                "(com.apple.coreaudio.avfaudio error 1718449215.)"
            ),
        )

        def fake_ffmpeg(
            pcm_path: Path,
            output_path: Path,
            sample_rate: int,
            expected_duration_ms: int,
        ) -> dict:
            self.assertTrue(pcm_path.is_file())
            self.assertEqual(sample_rate, 24_000)
            payload = b"ffmpeg-" + output_path.name.encode("utf-8")
            output_path.write_bytes(payload)
            return {
                "output": str(output_path.resolve()),
                "durationMilliseconds": expected_duration_ms,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "encoder": "local-imageio-ffmpeg-aac",
            }

        with patch(
            "direct_vault.direct_voice_vault.subprocess.run",
            return_value=swift_failure,
        ) as swift_attempt, patch(
            "direct_vault.direct_voice_vault._convert_pcm_with_ffmpeg",
            side_effect=fake_ffmpeg,
        ) as ffmpeg_fallback:
            report = decode(
                extracted,
                output,
                self.fake_swift_bin(),
                "测试",
                decoder=self.fake_decoder_for(200),
            )

        self.assertEqual(swift_attempt.call_count, 1)
        self.assertEqual(ffmpeg_fallback.call_count, item_count)
        stats = report["conversion_stats"]
        self.assertEqual(
            stats,
            {
                "converter_mode": "swift-with-batch-ffmpeg-fallback",
                "item_count": item_count,
                "conversion_attempt_count": item_count,
                "swift_attempt_count": 1,
                "swift_success_count": 0,
                "swift_known_coreaudio_failure_count": 1,
                "ffmpeg_fallback_count": item_count,
                "custom_converter_attempt_count": 0,
                "circuit_breaker_opened": True,
                "circuit_breaker_opened_at_sequence": 1,
            },
        )
        manifest = json.loads(
            (output / "direct-manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(manifest["conversion_stats"], stats)
        self.assertEqual(
            [item["sequence"] for item in manifest["items"]],
            list(range(1, item_count + 1)),
        )

    def test_decode_unknown_coreaudio_failure_remains_fail_closed(self) -> None:
        extracted = self.extract_many(3)
        output = self.base / "decoded"
        unknown_failure = subprocess.CompletedProcess(
            ["swift"],
            1,
            "",
            "(com.apple.coreaudio.avfaudio error 1718449999.)",
        )

        with patch(
            "direct_vault.direct_voice_vault.subprocess.run",
            return_value=unknown_failure,
        ) as swift_attempt, patch(
            "direct_vault.direct_voice_vault._convert_pcm_with_ffmpeg",
        ) as ffmpeg_fallback:
            with self.assertRaisesRegex(VaultError, "Swift PCM 转换失败"):
                decode(
                    extracted,
                    output,
                    self.fake_swift_bin(),
                    "测试",
                    decoder=self.fake_decoder_for(200),
                )

        self.assertEqual(swift_attempt.call_count, 1)
        ffmpeg_fallback.assert_not_called()
        self.assertFalse(output.exists())
        self.assertEqual(list(self.base.glob(".decoded-*")), [])
        self.assertEqual(list(self.base.rglob("*.pcm")), [])

    def test_local_ffmpeg_fallback_encodes_private_m4a(self) -> None:
        pcm = self.base / "ffmpeg-input.pcm"
        output = self.base / "ffmpeg-output.m4a"
        pcm.write_bytes(b"\x00\x00" * 4_800)
        report = _convert_pcm_with_ffmpeg(pcm, output, 24_000, 200)
        self.assertTrue(output.is_file())
        self.assertGreater(output.stat().st_size, 0)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertEqual(report["durationMilliseconds"], 200)
        self.assertEqual(
            report["sha256"],
            hashlib.sha256(output.read_bytes()).hexdigest(),
        )


if __name__ == "__main__":
    unittest.main()
