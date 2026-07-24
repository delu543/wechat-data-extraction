from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from unittest import mock

import content_vault.archive_export as archive_export_module
from content_vault.archive_export import export_archive
from content_vault.scanner import (
    build_content_plan,
    find_chat_candidates,
    load_content_plan,
    verify_plan_sources,
)
from direct_vault.direct_voice_vault import (
    VaultError,
    _convert_pcm_with_ffmpeg,
    _write_json_private,
)


CREATE_TIME = 1_704_067_200


class FakeStreamStdin:
    def __init__(self) -> None:
        self.data = bytearray()
        self.closed = False

    def close(self) -> None:
        self.closed = True


class FakeStreamProcess:
    def __init__(self, output: Path, *, partial_on_start: bool = True) -> None:
        self.output = output
        self.stdin = FakeStreamStdin()
        self.returncode: int | None = None
        self.terminated = False
        self.killed = False
        self.wait_count = 0
        if partial_on_start:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(b"partial-mp4")

    def poll(self) -> int | None:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        self.wait_count += 1
        if self.returncode is None:
            self.returncode = 0
            self.output.write_bytes(b"streamed-mp4")
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = -15

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9


class ContentFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        (root / "contact").mkdir(parents=True)
        (root / "message").mkdir()
        self.chat_id = "fixture-chat@chatroom"
        self.chat_name = "归档测试群"
        self.table = "Msg_" + hashlib.md5(self.chat_id.encode()).hexdigest()
        with sqlite3.connect(root / "contact/contact.db") as connection:
            connection.execute(
                "CREATE TABLE contact (id INTEGER, username TEXT, nick_name TEXT, remark TEXT, alias TEXT)"
            )
            connection.execute(
                "INSERT INTO contact VALUES (1, ?, ?, '', '')",
                (self.chat_id, self.chat_name),
            )
        self.create_message_db(root / "message/message_0.db")
        with sqlite3.connect(root / "message/media_0.db") as connection:
            connection.execute(
                "CREATE TABLE VoiceInfo (svr_id INTEGER, voice_data BLOB, local_id INTEGER)"
            )

    def create_message_db(self, path: Path) -> None:
        with sqlite3.connect(path) as connection:
            connection.execute(
                f"CREATE TABLE [{self.table}] ("
                "local_id INTEGER, server_id INTEGER, local_type INTEGER, "
                "create_time INTEGER, message_content TEXT, compress_content BLOB, "
                "WCDB_CT_message_content INTEGER, packed_info_data BLOB, "
                "real_sender_id TEXT, sort_seq INTEGER, server_seq INTEGER)"
            )

    def add(
        self,
        local_id: int,
        server_id: int,
        local_type: int,
        content: str,
        *,
        packed: bytes | None = None,
        create_time: int = CREATE_TIME,
        database: str = "message_0.db",
    ) -> None:
        with sqlite3.connect(self.root / "message" / database) as connection:
            connection.execute(
                f"INSERT INTO [{self.table}] VALUES (?, ?, ?, ?, ?, NULL, NULL, ?, '', ?, ?)",
                (
                    local_id,
                    server_id,
                    local_type,
                    create_time,
                    content,
                    packed,
                    local_id,
                    server_id,
                ),
            )


class ScannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.fixture = ContentFixture(self.base / "vault")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def scan(self) -> dict:
        return build_content_plan(
            self.fixture.root,
            self.fixture.chat_name,
            str(CREATE_TIME - 1),
            str(CREATE_TIME + 1),
        )

    def test_all_types_are_kept_and_same_text_is_not_deduplicated(self) -> None:
        self.fixture.add(1, 101, 1, "相同正文")
        self.fixture.add(2, 102, 1, "相同正文")
        self.fixture.add(
            3,
            103,
            (9 << 32) | 49,
            "<msg><appmsg><title>材料.pdf</title><type>6</type>"
            "<appattach><totallen>12</totallen></appattach></appmsg></msg>",
        )
        self.fixture.add(
            4,
            104,
            34,
            '<msg><voicemsg voicelength="52000" /></msg>',
        )
        self.fixture.add(5, 105, 43, "<msg><videomsg playlength='5'/></msg>")
        self.fixture.add(6, 106, 999, "未识别消息")
        plan = self.scan()
        self.assertEqual(plan["message_count"], 6)
        self.assertEqual(plan["counts_by_kind"]["text"], 2)
        self.assertEqual(plan["messages"][2]["base_type"], 49)
        self.assertEqual(plan["messages"][2]["type_flags_hi32"], 9)
        self.assertEqual(plan["messages"][2]["kind"], "file")
        self.assertEqual(plan["messages"][3]["payload"]["duration_ms"], 52000)
        self.assertEqual(plan["messages"][4]["parse"]["status"], "excluded_by_policy")
        self.assertEqual(plan["messages"][5]["kind"], "unknown")

    def test_type_selection_persists_only_explicit_kinds(self) -> None:
        self.fixture.add(1, 201, 1, "不应进入语音计划的正文")
        self.fixture.add(
            2,
            202,
            34,
            '<msg><voicemsg voicelength="12000" /></msg>',
        )
        plan = build_content_plan(
            self.fixture.root,
            self.fixture.chat_name,
            str(CREATE_TIME - 1),
            str(CREATE_TIME + 1),
            kinds={"voice"},
        )
        self.assertEqual(plan["message_count"], 1)
        self.assertEqual(plan["counts_by_kind"], {"voice": 1})
        self.assertEqual(plan["messages"][0]["kind"], "voice")
        self.assertEqual(plan["messages"][0]["sequence"], 1)
        self.assertEqual(plan["selection"]["types"], ["voice"])
        self.assertEqual(plan["selection"]["unselected_message_count"], 1)

    def test_chat_candidate_normalization_never_auto_selects(self) -> None:
        candidates = find_chat_candidates(self.fixture.root, "归档 测试群")
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["chat_id"], self.fixture.chat_id)
        self.assertEqual(candidates[0]["match"], "normalized")

    def test_exact_server_duplicate_merges_but_conflict_stops(self) -> None:
        second = self.fixture.root / "message/message_1.db"
        self.fixture.create_message_db(second)
        self.fixture.add(1, 701, 1, "同一源行")
        self.fixture.add(1, 701, 1, "同一源行", database="message_1.db")
        plan = self.scan()
        self.assertEqual(plan["message_count"], 1)
        self.assertEqual(len(plan["messages"][0]["source_refs"]), 2)

        with sqlite3.connect(second) as connection:
            connection.execute(f"DELETE FROM [{self.fixture.table}]")
            connection.execute(
                f"INSERT INTO [{self.fixture.table}] VALUES (1, 701, 1, ?, '冲突', NULL, NULL, NULL, '', 1, 701)",
                (CREATE_TIME,),
            )
        with self.assertRaisesRegex(VaultError, "跨分片内容冲突"):
            self.scan()

    def test_plan_digest_and_database_fingerprint_are_enforced(self) -> None:
        self.fixture.add(1, 801, 1, "内容")
        plan = self.scan()
        plan_path = self.base / "plan.json"
        _write_json_private(plan_path, plan, vault=None)
        loaded = load_content_plan(plan_path)
        verify_plan_sources(self.fixture.root, loaded)

        tampered = dict(plan)
        tampered["message_count"] = 99
        _write_json_private(self.base / "tampered.json", tampered, vault=None)
        with self.assertRaisesRegex(VaultError, "摘要不匹配"):
            load_content_plan(self.base / "tampered.json")

        with sqlite3.connect(self.fixture.root / "message/message_0.db") as connection:
            connection.execute(f"INSERT INTO [{self.fixture.table}] VALUES (2, 802, 1, ?, 'later', NULL, NULL, NULL, '', 2, 802)", (CREATE_TIME,))
        with self.assertRaisesRegex(VaultError, "已变化"):
            verify_plan_sources(self.fixture.root, loaded)


class ArchiveExportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.fixture = ContentFixture(self.base / "vault")
        self.account = self.base / "account"
        (self.account / "msg").mkdir(parents=True)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def packed(resource_md5: str) -> bytes:
        return b"prefix\x12\x22\x0a\x20" + resource_md5.encode("ascii") + b"suffix"

    def plan_path(self) -> tuple[Path, dict]:
        plan = build_content_plan(
            self.fixture.root,
            self.fixture.chat_name,
            str(CREATE_TIME - 1),
            str(CREATE_TIME + 1),
        )
        path = self.base / "plan.json"
        _write_json_private(path, plan, vault=None)
        return path, plan

    def add_resolved_file(self, *, server_id: int = 401) -> None:
        payload = b"verified-file-payload"
        expected_md5 = hashlib.md5(payload).hexdigest()
        self.fixture.add(
            1,
            server_id,
            49,
            "<msg><appmsg><title>验证材料.bin</title><type>6</type><appattach>"
            f"<totallen>{len(payload)}</totallen><filemd5>{expected_md5}</filemd5>"
            "</appattach></appmsg></msg>",
        )
        file_dir = self.account / "msg/file/2024-01"
        file_dir.mkdir(parents=True)
        (file_dir / "验证材料.bin").write_bytes(payload)

    def voice_plan_path(self, *, server_id: int = 601) -> tuple[Path, dict]:
        self.fixture.add(
            1,
            server_id,
            34,
            '<msg><voicemsg voicelength="12000" /></msg>',
        )
        plan = build_content_plan(
            self.fixture.root,
            self.fixture.chat_name,
            str(CREATE_TIME - 1),
            str(CREATE_TIME + 1),
            kinds={"voice"},
        )
        path = self.base / "voice-plan.json"
        _write_json_private(path, plan, vault=None)
        return path, plan

    def fake_voice_pipeline(
        self,
        _vault: Path,
        plan: dict,
        messages: list[dict],
        staging: Path,
        _swift_bin: object,
        _title: str,
    ) -> tuple[list[dict], dict]:
        self.assertEqual(len(messages), 1)
        silk = b"validated-silk"
        m4a = b"validated-m4a"
        mp4 = b"validated-mp4"
        (staging / "media/voices-silk").mkdir(parents=True)
        (staging / "media/voices").mkdir()
        (staging / "media/voices-silk/0001.silk").write_bytes(silk)
        (staging / "media/voices/0001.m4a").write_bytes(m4a)
        (staging / "media/voice.mp4").write_bytes(mp4)
        message = messages[0]
        server_id = message["source_ref"]["server_id"]
        return (
            [
                {
                    "asset_id": archive_export_module._asset_id(message, "voice"),
                    "kind": "voice",
                    "status": "resolved",
                    "server_id": server_id,
                    "voice_sequence": 1,
                    "relative_path": "media/voices/0001.m4a",
                    "format": "m4a",
                    "duration_ms": 12000,
                    "sha256": hashlib.sha256(m4a).hexdigest(),
                    "byte_count": len(m4a),
                    "source_voice_data_sha256": hashlib.sha256(silk).hexdigest(),
                    "frame_duration_ms": 12000,
                    "packet_count": 600,
                    "chat_binding": {
                        "status": "verified",
                        "mapped_chat_id": plan["chat"]["chat_id"],
                    },
                }
            ],
            {
                "relative_path": "media/voice.mp4",
                "sha256": hashlib.sha256(mp4).hexdigest(),
                "byte_count": len(mp4),
                "item_count": 1,
                "source_extract_plan_digest": "a" * 64,
            },
        )

    def fake_fast_voice_pipeline(
        self,
        _vault: Path,
        plan: dict,
        messages: list[dict],
        staging: Path,
        _title: str,
    ) -> tuple[list[dict], dict]:
        self.assertEqual(len(messages), 1)
        mp4 = b"validated-mp4"
        pcm_marker = b"validated-pcm"
        media = staging / "media"
        (media / "voices-silk").mkdir(parents=True)
        (media / "voice.mp4").write_bytes(mp4)
        message = messages[0]
        server_id = message["source_ref"]["server_id"]
        sample_count = 12_000 * 24
        source_hash = hashlib.sha256(b"validated-silk").hexdigest()
        pcm_hash = hashlib.sha256(pcm_marker).hexdigest()
        return (
            [
                {
                    "asset_id": archive_export_module._asset_id(message, "voice"),
                    "kind": "voice",
                    "status": "resolved",
                    "server_id": server_id,
                    "voice_sequence": 1,
                    "duration_ms": 12_000,
                    "frame_duration_ms": 12_000,
                    "packet_count": 600,
                    "source_voice_data_sha256": source_hash,
                    "chat_binding": {
                        "status": "verified",
                        "mapped_chat_id": plan["chat"]["chat_id"],
                    },
                    "decoded_pcm_sha256": pcm_hash,
                    "decoded_pcm_byte_count": sample_count * 2,
                    "decoded_pcm_sample_count": sample_count,
                    "decoded_pcm_duration_ms": 12_000,
                    "pcm_start_sample": 0,
                    "pcm_end_sample": sample_count,
                    "gap_after_samples": 0,
                }
            ],
            {
                "relative_path": "media/voice.mp4",
                "sha256": hashlib.sha256(mp4).hexdigest(),
                "byte_count": len(mp4),
                "item_count": 1,
                "source_extract_plan_digest": archive_export_module._voice_subplan(
                    plan, messages
                )["plan_digest"],
                "duration_ms": 12_000,
                "container_duration_ms": 12_000,
                "duration_tolerance_ms": (
                    archive_export_module.VOICE_MP4_DURATION_TOLERANCE_MILLISECONDS
                ),
                "audio_codec": "aac",
                "video_codec": "h264",
                "encoder": "local-imageio-ffmpeg-stream",
                "ffmpeg_package_version": "fixture-0.6.0",
                "ffmpeg_binary_sha256": hashlib.sha256(b"ffmpeg").hexdigest(),
                "pcm_sample_rate": 24_000,
                "pcm_channels": 1,
                "pcm_sample_format": "s16le",
                "pcm_stream_sha256": pcm_hash,
                "pcm_total_samples": sample_count,
                "pcm_total_bytes": sample_count * 2,
                "gap_milliseconds": 300,
                "gap_samples": 7_200,
            },
        )

    def streaming_fixture(self, label: str = "stream") -> dict:
        extract = self.base / f"{label}-extract"
        extract.mkdir()
        manifest_path = extract / "manifest.json"
        manifest_path.write_bytes(b"stable-extract-manifest")
        source_plan_digest = "d" * 64
        chat_id = self.fixture.chat_id
        messages: list[dict] = []
        voices: list[dict] = []
        extracted_items: list[dict] = []
        for sequence, duration_ms in ((1, 100), (2, 200)):
            server_id = str(700 + sequence)
            source = extract / f"{sequence:04d}.silk"
            source.write_bytes(f"silk-{sequence}".encode("ascii"))
            source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
            messages.append(
                {
                    "sequence": sequence,
                    "message_id": f"message-{sequence}",
                    "kind": "voice",
                    "create_time": CREATE_TIME + sequence,
                    "source_ref": {"server_id": server_id},
                    "payload": {"duration_ms": duration_ms},
                }
            )
            voices.append(
                {
                    "sequence": sequence,
                    "server_id": server_id,
                    "expected_duration_ms": duration_ms,
                    "frame_duration_ms": duration_ms,
                    "source": source,
                    "sha256": source_hash,
                    "byte_count": source.stat().st_size,
                }
            )
            extracted_items.append(
                {
                    "sequence": sequence,
                    "server_id": server_id,
                    "expected_duration_ms": duration_ms,
                    "frame_duration_ms": duration_ms,
                    "packet_count": duration_ms // 20,
                    "sha256": source_hash,
                    "source_voice_data_sha256": source_hash,
                    "byte_count": source.stat().st_size,
                    "chat_binding": {
                        "status": "verified",
                        "mapped_chat_id": chat_id,
                    },
                }
            )
        extract_report = {
            "source_plan_digest": source_plan_digest,
            "voices": extracted_items,
        }
        loaded = (
            extract,
            manifest_path,
            hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
            source_plan_digest,
            {"chat_id": chat_id},
            {},
            voices,
        )
        return {
            "extract": extract,
            "extract_report": extract_report,
            "messages": messages,
            "loaded": loaded,
            "chat_id": chat_id,
            "source_plan_digest": source_plan_digest,
            "output": self.base / f"{label}-media/voice.mp4",
        }

    @staticmethod
    def fake_stream_decoder(source: Path, destination: Path, sample_rate: int) -> None:
        if sample_rate != 24_000:
            raise AssertionError("unexpected sample rate")
        sequence = int(source.name.split(".", 1)[0])
        sample_count = 2_400 if sequence == 1 else 4_800
        value = b"\x01\x00" if sequence == 1 else b"\x02\x00"
        destination.write_bytes(value * sample_count)

    def test_text_image_file_and_sticker_export_to_readable_archive(self) -> None:
        self.fixture.add(1, 101, 1, "<script>alert(1)</script>")

        image_md5 = "a" * 32
        self.fixture.add(
            2,
            102,
            3,
            "<msg><img/></msg>",
            packed=self.packed(image_md5),
        )
        image_plain = b"GIF89a" + b"fixture-image" + b";"
        image_encrypted = bytes(value ^ 0x5A for value in image_plain)
        chat_hash = hashlib.md5(self.fixture.chat_id.encode()).hexdigest()
        image_dir = self.account / f"msg/attach/{chat_hash}/2024-01/Img"
        image_dir.mkdir(parents=True)
        (image_dir / f"{image_md5}.dat").write_bytes(image_encrypted)

        file_payload = b"fixture-pdf"
        file_md5 = hashlib.md5(file_payload).hexdigest()
        self.fixture.add(
            3,
            103,
            49,
            "<msg><appmsg><title>材料.pdf</title><type>6</type><appattach>"
            f"<totallen>{len(file_payload)}</totallen><filemd5>{file_md5}</filemd5>"
            "</appattach></appmsg></msg>",
        )
        file_dir = self.account / "msg/file/2024-01"
        file_dir.mkdir(parents=True)
        (file_dir / "材料.pdf").write_bytes(file_payload)

        sticker_payload = b"GIF89a" + b"fixture-sticker" + b";"
        sticker_md5 = hashlib.md5(sticker_payload).hexdigest()
        self.fixture.add(
            4,
            104,
            47,
            f"<msg><emoji md5='{sticker_md5}'/></msg>",
        )
        sticker_dir = self.account / "business/emoticon/Persist/aa"
        sticker_dir.mkdir(parents=True)
        (sticker_dir / sticker_md5).write_bytes(sticker_payload)

        plan_path, plan = self.plan_path()
        output = self.base / "archive"
        report = export_archive(
            self.fixture.root,
            self.account,
            plan_path,
            plan["plan_digest"],
            output,
        )
        self.assertEqual(report["message_count"], 4)
        self.assertEqual(
            report["verification"]["status"],
            "verified-before-atomic-publish",
        )
        self.assertEqual(report["verification"]["resolved_file_count"], 3)
        manifest = json.loads((output / "manifest.json").read_text())
        self.assertEqual(manifest["summary"]["asset_status_counts"], {"resolved": 3})
        self.assertTrue((output / "index.html").is_file())
        self.assertTrue((output / "chat.md").is_file())
        self.assertIn("&lt;script&gt;", (output / "index.html").read_text())
        self.assertNotIn("<script>alert", (output / "index.html").read_text())
        self.assertEqual((output / "manifest.json").stat().st_mode & 0o777, 0o600)
        for asset in manifest["assets"]:
            target = output / asset["relative_path"]
            self.assertTrue(target.is_file())
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_strict_missing_media_leaves_no_output_and_partial_is_explicit(self) -> None:
        self.fixture.add(
            1,
            201,
            3,
            "<msg><img/></msg>",
            packed=self.packed("b" * 32),
        )
        plan_path, plan = self.plan_path()
        strict_output = self.base / "strict"
        with self.assertRaisesRegex(VaultError, "严格导出发现"):
            export_archive(
                self.fixture.root,
                self.account,
                plan_path,
                plan["plan_digest"],
                strict_output,
            )
        self.assertFalse(strict_output.exists())

        partial_output = self.base / "partial"
        report = export_archive(
            self.fixture.root,
            self.account,
            plan_path,
            plan["plan_digest"],
            partial_output,
            allow_partial=True,
        )
        self.assertEqual(report["issue_count"], 1)
        self.assertEqual(
            report["verification"]["status"],
            "verified-before-atomic-publish",
        )
        manifest = json.loads((partial_output / "manifest.json").read_text())
        self.assertEqual(manifest["mode"], "partial-explicit")
        self.assertEqual(manifest["issues"][0]["status"], "missing")

    def test_wrong_approval_digest_is_rejected(self) -> None:
        self.fixture.add(1, 301, 1, "content")
        plan_path, _ = self.plan_path()
        with self.assertRaisesRegex(VaultError, "approve-digest"):
            export_archive(
                self.fixture.root,
                self.account,
                plan_path,
                "0" * 64,
                self.base / "archive",
            )

    def test_staged_asset_tamper_fails_before_atomic_publish(self) -> None:
        self.add_resolved_file()
        plan_path, plan = self.plan_path()
        output = self.base / "tampered-archive"
        original_verify = archive_export_module._verify_staged_archive

        def tamper_then_verify(staging: Path, manifest: dict, messages: list[dict]) -> dict:
            asset = manifest["assets"][0]
            (staging / asset["relative_path"]).write_bytes(b"tampered-after-manifest")
            return original_verify(staging, manifest, messages)

        with mock.patch.object(
            archive_export_module,
            "_verify_staged_archive",
            side_effect=tamper_then_verify,
        ):
            with self.assertRaisesRegex(VaultError, "发布前哈希不一致"):
                export_archive(
                    self.fixture.root,
                    self.account,
                    plan_path,
                    plan["plan_digest"],
                    output,
                )

        self.assertFalse(output.exists())
        self.assertEqual(list(self.base.glob(".tampered-archive-*")), [])

    def test_duplicate_asset_reference_fails_before_atomic_publish(self) -> None:
        self.add_resolved_file(server_id=402)
        plan_path, plan = self.plan_path()
        output = self.base / "duplicate-reference-archive"
        original_verify = archive_export_module._verify_staged_archive

        def duplicate_then_verify(staging: Path, manifest: dict, messages: list[dict]) -> dict:
            messages[0]["asset_ids"].append(messages[0]["asset_ids"][0])
            (staging / "messages.json").write_text(
                json.dumps(messages, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            (staging / "messages.jsonl").write_text(
                "".join(
                    json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n"
                    for item in messages
                ),
                encoding="utf-8",
            )
            return original_verify(staging, manifest, messages)

        with mock.patch.object(
            archive_export_module,
            "_verify_staged_archive",
            side_effect=duplicate_then_verify,
        ):
            with self.assertRaisesRegex(VaultError, "重复资源引用"):
                export_archive(
                    self.fixture.root,
                    self.account,
                    plan_path,
                    plan["plan_digest"],
                    output,
                )

        self.assertFalse(output.exists())
        self.assertEqual(list(self.base.glob(".duplicate-reference-archive-*")), [])

    def test_stream_fast_path_uses_one_encode_and_one_probe_in_pcm_order(
        self,
    ) -> None:
        case = self.streaming_fixture()
        process = FakeStreamProcess(case["output"], partial_on_start=False)
        popen = mock.Mock(return_value=process)
        probe_output = (
            "Input #0, mov, from 'voice.mp4':\n"
            "  Duration: 00:00:00.60, start: 0.000000\n"
            "  Stream #0:0[0x1](und): Video: h264 (High), yuv420p\n"
            "  Stream #0:1[0x2](und): Audio: aac (LC), 48000 Hz, mono\n"
            "Stream mapping:\n"
            "frame=2 time=00:00:00.60 bitrate=10kbits/s\n"
        )
        probe = mock.Mock(
            return_value=mock.Mock(returncode=0, stdout="", stderr=probe_output)
        )

        def collect_stdin(
            current_process: FakeStreamProcess,
            data: bytes,
            _deadline: float,
        ) -> None:
            current_process.stdin.data.extend(data)

        with mock.patch.object(
            archive_export_module,
            "_load_extract_manifest",
            return_value=case["loaded"],
        ), mock.patch.object(
            archive_export_module,
            "_default_silk_decoder",
            side_effect=self.fake_stream_decoder,
        ), mock.patch.object(
            archive_export_module,
            "_resolve_local_ffmpeg",
            return_value=(
                Path("/bin/echo"),
                "fixture-7.1",
                hashlib.sha256(b"ffmpeg").hexdigest(),
            ),
        ), mock.patch.object(
            archive_export_module,
            "_write_ffmpeg_stdin",
            side_effect=collect_stdin,
        ), mock.patch.object(
            archive_export_module.subprocess,
            "Popen",
            popen,
        ), mock.patch.object(
            archive_export_module.subprocess,
            "run",
            probe,
        ):
            evidence, report = archive_export_module._stream_voice_pcm_to_mp4(
                case["extract"],
                case["extract_report"],
                case["messages"],
                case["output"],
                title="stream fixture",
                expected_chat_id=case["chat_id"],
                expected_source_plan_digest=case["source_plan_digest"],
            )

        expected = (
            b"\x01\x00" * 2_400
            + bytes(7_200 * 2)
            + b"\x02\x00" * 4_800
        )
        self.assertEqual(bytes(process.stdin.data), expected)
        self.assertEqual(popen.call_count, 1)
        self.assertEqual(probe.call_count, 1)
        self.assertIn("pipe:0", popen.call_args.args[0])
        self.assertNotIn("pcm-to-m4a", popen.call_args.args[0])
        self.assertEqual(
            [
                (
                    item["pcm_start_sample"],
                    item["pcm_end_sample"],
                    item["gap_after_samples"],
                )
                for item in evidence
            ],
            [(0, 2_400, 7_200), (9_600, 14_400, 0)],
        )
        self.assertEqual(report["pcm_total_samples"], 14_400)
        self.assertEqual(report["pcm_total_bytes"], len(expected))
        self.assertEqual(
            report["pcm_stream_sha256"],
            hashlib.sha256(expected).hexdigest(),
        )
        self.assertEqual(report["audio_codec"], "aac")
        self.assertEqual(report["video_codec"], "h264")
        self.assertTrue(case["output"].is_file())
        self.assertFalse((case["output"].parent / ".voice-pcm").exists())
        self.assertFalse(
            (case["output"].parent / ".voice-ffmpeg.stderr").exists()
        )

    def test_stream_fast_path_real_ffmpeg_pipe_produces_aac_h264(self) -> None:
        case = self.streaming_fixture("real-stream")
        real_popen = subprocess.Popen
        real_run = subprocess.run
        with mock.patch.object(
            archive_export_module,
            "_load_extract_manifest",
            return_value=case["loaded"],
        ), mock.patch.object(
            archive_export_module,
            "_default_silk_decoder",
            side_effect=self.fake_stream_decoder,
        ), mock.patch.object(
            archive_export_module.subprocess,
            "Popen",
            wraps=real_popen,
        ) as popen, mock.patch.object(
            archive_export_module.subprocess,
            "run",
            wraps=real_run,
        ) as run:
            evidence, report = archive_export_module._stream_voice_pcm_to_mp4(
                case["extract"],
                case["extract_report"],
                case["messages"],
                case["output"],
                title="real pipe fixture",
                expected_chat_id=case["chat_id"],
                expected_source_plan_digest=case["source_plan_digest"],
            )

        self.assertEqual(len(evidence), 2)
        self.assertEqual(popen.call_count, 2)
        self.assertEqual(run.call_count, 1)
        self.assertIn("pipe:0", popen.call_args_list[0].args[0])
        self.assertEqual(
            popen.call_args_list[1].args[0][-3:],
            ["-f", "null", "-"],
        )
        self.assertEqual(report["encoder"], "local-imageio-ffmpeg-stream")
        self.assertEqual(report["audio_codec"], "aac")
        self.assertEqual(report["video_codec"], "h264")
        self.assertEqual(report["pcm_total_samples"], 14_400)
        self.assertTrue(case["output"].is_file())
        self.assertGreater(case["output"].stat().st_size, 0)
        self.assertEqual(case["output"].stat().st_mode & 0o777, 0o600)

    def test_stream_fast_path_timeout_and_broken_pipe_remove_partial(
        self,
    ) -> None:
        for label, failure, message in (
            (
                "timeout",
                subprocess.TimeoutExpired("ffmpeg-stream", 1),
                "编码超时",
            ),
            ("broken", BrokenPipeError("closed"), "PCM 输入失败"),
        ):
            with self.subTest(label=label):
                case = self.streaming_fixture(label)
                process = FakeStreamProcess(
                    case["output"],
                    partial_on_start=False,
                )
                probe = mock.Mock()

                def start_process(*_args, **_kwargs):
                    case["output"].parent.mkdir(parents=True, exist_ok=True)
                    case["output"].write_bytes(b"partial-mp4")
                    return process

                with mock.patch.object(
                    archive_export_module,
                    "_load_extract_manifest",
                    return_value=case["loaded"],
                ), mock.patch.object(
                    archive_export_module,
                    "_default_silk_decoder",
                    side_effect=self.fake_stream_decoder,
                ), mock.patch.object(
                    archive_export_module,
                    "_resolve_local_ffmpeg",
                    return_value=(
                        Path("/bin/echo"),
                        "fixture-7.1",
                        hashlib.sha256(b"ffmpeg").hexdigest(),
                    ),
                ), mock.patch.object(
                    archive_export_module,
                    "_write_ffmpeg_stdin",
                    side_effect=failure,
                ), mock.patch.object(
                    archive_export_module.subprocess,
                    "Popen",
                    side_effect=start_process,
                ), mock.patch.object(
                    archive_export_module.subprocess,
                    "run",
                    probe,
                ):
                    with self.assertRaisesRegex(VaultError, message):
                        archive_export_module._stream_voice_pcm_to_mp4(
                            case["extract"],
                            case["extract_report"],
                            case["messages"],
                            case["output"],
                            title="failure fixture",
                            expected_chat_id=case["chat_id"],
                            expected_source_plan_digest=case[
                                "source_plan_digest"
                            ],
                        )
                self.assertTrue(process.terminated)
                self.assertFalse(case["output"].exists())
                self.assertFalse(
                    (case["output"].parent / ".voice-pcm").exists()
                )
                self.assertFalse(
                    (case["output"].parent / ".voice-ffmpeg.stderr").exists()
                )
                probe.assert_not_called()
                shutil_target = case["extract"]
                for child in list(shutil_target.iterdir()):
                    if child.name.endswith(".pcm"):
                        self.fail("PCM 临时文件未删除")

    def test_ffmpeg_input_codecs_requires_exactly_one_aac_and_h264(self) -> None:
        valid = (
            "Input #0, mov, from 'voice.mp4':\n"
            "  Stream #0:0[0x1](und): Video: h264 (High), yuv420p\n"
            "  Stream #0:1[0x2](und): Audio: aac (LC), 48000 Hz\n"
            "Stream mapping:\n"
            "  Stream #0:0 -> #0:0\n"
        )
        self.assertEqual(
            archive_export_module._ffmpeg_input_codecs(valid),
            ("h264", "aac"),
        )
        invalid = {
            "extra_audio": valid.replace(
                "Stream mapping:",
                "  Stream #0:2: Audio: aac, 48000 Hz\nStream mapping:",
            ),
            "subtitle": valid.replace(
                "Stream mapping:",
                "  Stream #0:2: Subtitle: mov_text\nStream mapping:",
            ),
            "missing_audio": valid.replace(
                "  Stream #0:1[0x2](und): Audio: aac (LC), 48000 Hz\n",
                "",
            ),
            "hevc": valid.replace("Video: h264", "Video: hevc"),
            "mp3": valid.replace("Audio: aac", "Audio: mp3"),
        }
        for label, output in invalid.items():
            with self.subTest(label=label):
                with self.assertRaises(VaultError):
                    archive_export_module._ffmpeg_input_codecs(output)

    def test_full_archive_voice_keeps_legacy_m4a_pipeline(self) -> None:
        plan_path, plan = self.voice_plan_path()
        output = self.base / "legacy-full-voice"
        with mock.patch.object(
            archive_export_module,
            "_export_voices_mp4_only_fast",
            side_effect=AssertionError("fast path must not run"),
        ) as fast, mock.patch.object(
            archive_export_module,
            "_export_voices",
            side_effect=self.fake_voice_pipeline,
        ) as legacy:
            report = export_archive(
                self.fixture.root,
                self.account,
                plan_path,
                plan["plan_digest"],
                output,
                swift_bin=self.base / "unused-swift",
            )
        fast.assert_not_called()
        legacy.assert_called_once()
        self.assertEqual(Path(report["output_dir"]), output.resolve())
        self.assertTrue((output / "media/voices/0001.m4a").is_file())
        self.assertTrue((output / "index.html").is_file())
        self.assertTrue((output / "chat.md").is_file())
        self.assertTrue((output / "messages.json").is_file())

    def test_voice_mp4_only_unknown_failure_never_publishes(self) -> None:
        plan_path, plan = self.voice_plan_path()
        output = self.base / "unknown-fast-failure"
        with mock.patch.object(
            archive_export_module,
            "_export_voices_mp4_only_fast",
            side_effect=RuntimeError("unknown decoder failure"),
        ):
            with self.assertRaisesRegex(RuntimeError, "unknown decoder failure"):
                export_archive(
                    self.fixture.root,
                    self.account,
                    plan_path,
                    plan["plan_digest"],
                    output,
                    voice_mp4_only=True,
                )
        self.assertFalse(output.exists())
        self.assertEqual(list(self.base.glob(".unknown-fast-failure-*")), [])

    def test_voice_mp4_only_publishes_two_verified_files_and_cleans_intermediates(
        self,
    ) -> None:
        plan_path, plan = self.voice_plan_path()
        output = self.base / "voice-mp4-only"
        with mock.patch.object(
            archive_export_module,
            "_export_voices_mp4_only_fast",
            side_effect=self.fake_fast_voice_pipeline,
        ):
            report = export_archive(
                self.fixture.root,
                self.account,
                plan_path,
                plan["plan_digest"],
                output,
                swift_bin=self.base / "unused-swift",
                voice_mp4_only=True,
            )

        self.assertEqual(report["output_mode"], "voice-mp4-only")
        self.assertEqual(
            report["verification"]["status"],
            "verified-before-atomic-publish",
        )
        self.assertEqual({path.name for path in output.iterdir()}, {"voice.mp4", "manifest.json"})
        self.assertFalse((output / "media").exists())
        manifest = json.loads((output / "manifest.json").read_text())
        self.assertEqual(manifest["schema_version"], 2)
        self.assertEqual(manifest["mode"], "strict")
        self.assertEqual(manifest["summary"]["voice_count"], 1)
        self.assertEqual(manifest["issues"], [])
        self.assertEqual(manifest["voices"][0]["chat_binding"], "verified")
        self.assertIn("decoded_pcm_sha256", manifest["voices"][0])
        self.assertNotIn("converted_audio_sha256", manifest["voices"][0])
        self.assertEqual(
            manifest["voice_mp4"]["sha256"],
            hashlib.sha256(b"validated-mp4").hexdigest(),
        )
        self.assertEqual((output / "voice.mp4").stat().st_mode & 0o777, 0o600)

    def test_ffmpeg_direct_assembler_verifies_real_m4a_inputs(self) -> None:
        media = self.base / "ffmpeg-voices"
        media.mkdir()
        items = []
        for sequence in (1, 2):
            pcm = media / f"{sequence:04d}.pcm"
            m4a = media / f"{sequence:04d}.m4a"
            pcm.write_bytes(b"\0\0" * 2_400)
            encoded = _convert_pcm_with_ffmpeg(pcm, m4a, 24_000, 100)
            items.append(
                {
                    "sequence": sequence,
                    "server_id": str(700 + sequence),
                    "source_path": m4a.name,
                    "expected_duration_milliseconds": 100,
                    "sha256": encoded["sha256"],
                }
            )
        manifest_path = media / "manifest.json"
        _write_json_private(
            manifest_path,
            {"expected_count": len(items), "items": items},
            vault=None,
        )
        output = self.base / "ffmpeg-voice.mp4"

        report = archive_export_module._assemble_direct_with_ffmpeg(
            manifest_path,
            output,
            title="ffmpeg fallback test",
        )

        self.assertEqual(report["itemCount"], 2)
        self.assertEqual(report["sha256"], hashlib.sha256(output.read_bytes()).hexdigest())
        self.assertEqual(report["encoder"], "local-imageio-ffmpeg")
        self.assertGreater(report["durationMilliseconds"], 0)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_ffmpeg_direct_assembler_accepts_60060_milliseconds(self) -> None:
        media = self.base / "ffmpeg-duration-accepted"
        media.mkdir()
        source = media / "0001.m4a"
        source.write_bytes(b"fixture-m4a")
        manifest_path = media / "manifest.json"
        _write_json_private(
            manifest_path,
            {
                "expected_count": 1,
                "items": [
                    {
                        "sequence": 1,
                        "server_id": "701",
                        "source_path": source.name,
                        "expected_duration_milliseconds": 60_060,
                        "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                    }
                ],
            },
            vault=None,
        )
        output = self.base / "ffmpeg-duration-accepted.mp4"
        fake_imageio_ffmpeg = mock.Mock()
        fake_imageio_ffmpeg.get_ffmpeg_exe.return_value = "/bin/echo"

        def fake_run(arguments, **_kwargs):
            if "-filter_complex" in arguments:
                output.write_bytes(b"fixture-mp4")
                return mock.Mock(returncode=0, stdout="", stderr="")
            probe = (
                "Duration: 00:01:00.06, start: 0.000000\n"
                "frame=120 time=00:01:00.06 bitrate=10kbits/s\n"
            )
            return mock.Mock(returncode=0, stdout="", stderr=probe)

        with mock.patch.dict(
            "sys.modules", {"imageio_ffmpeg": fake_imageio_ffmpeg}
        ), mock.patch.object(
            archive_export_module.subprocess,
            "run",
            side_effect=fake_run,
        ):
            report = archive_export_module._assemble_direct_with_ffmpeg(
                manifest_path,
                output,
                title="duration boundary accepted",
            )

        self.assertEqual(report["durationMilliseconds"], 60_060)
        self.assertEqual(report["itemCount"], 1)

    def test_ffmpeg_direct_assembler_rejects_61001_milliseconds(self) -> None:
        media = self.base / "ffmpeg-duration-rejected"
        media.mkdir()
        source = media / "0001.m4a"
        source.write_bytes(b"fixture-m4a")
        manifest_path = media / "manifest.json"
        _write_json_private(
            manifest_path,
            {
                "expected_count": 1,
                "items": [
                    {
                        "sequence": 1,
                        "server_id": "701",
                        "source_path": source.name,
                        "expected_duration_milliseconds": 61_001,
                        "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                    }
                ],
            },
            vault=None,
        )
        output = self.base / "ffmpeg-duration-rejected.mp4"

        with mock.patch.object(
            archive_export_module.subprocess,
            "run",
        ) as run:
            with self.assertRaisesRegex(VaultError, "清单条目无效"):
                archive_export_module._assemble_direct_with_ffmpeg(
                    manifest_path,
                    output,
                    title="duration boundary rejected",
                )

        run.assert_not_called()
        self.assertFalse(output.exists())

    def test_ffmpeg_duration_uses_decoded_stream_progress_and_tracks_container(
        self,
    ) -> None:
        output = (
            "Duration: 00:00:00.83, start: 0.000000\n"
            "frame=1 time=00:00:00.50 bitrate=10kbits/s\n"
        )
        self.assertEqual(
            archive_export_module._ffmpeg_duration_milliseconds(output),
            500,
        )
        self.assertEqual(
            archive_export_module._ffmpeg_container_duration_milliseconds(output),
            830,
        )

    def test_voice_mp4_only_rejects_mixed_plan_and_partial_mode(self) -> None:
        self.fixture.add(1, 611, 1, "正文")
        self.fixture.add(
            2,
            612,
            34,
            '<msg><voicemsg voicelength="12000" /></msg>',
        )
        mixed_path, mixed = self.plan_path()
        with self.assertRaisesRegex(VaultError, "明确仅选择 voice"):
            export_archive(
                self.fixture.root,
                self.account,
                mixed_path,
                mixed["plan_digest"],
                self.base / "mixed-output",
                voice_mp4_only=True,
            )
        self.assertFalse((self.base / "mixed-output").exists())

        voice_path, voice = self.voice_plan_path(server_id=613)
        with self.assertRaisesRegex(VaultError, "不允许 --allow-partial"):
            export_archive(
                self.fixture.root,
                self.account,
                voice_path,
                voice["plan_digest"],
                self.base / "partial-mp4-output",
                allow_partial=True,
                voice_mp4_only=True,
            )
        self.assertFalse((self.base / "partial-mp4-output").exists())

    def test_voice_mp4_only_tamper_fails_before_atomic_publish(self) -> None:
        plan_path, plan = self.voice_plan_path()
        output = self.base / "tampered-mp4-only"
        original_verify = archive_export_module._verify_staged_voice_mp4_only

        def tamper_then_verify(staging: Path, manifest: dict, current_plan: dict) -> dict:
            (staging / "voice.mp4").write_bytes(b"tampered")
            return original_verify(staging, manifest, current_plan)

        with mock.patch.object(
            archive_export_module,
            "_export_voices_mp4_only_fast",
            side_effect=self.fake_fast_voice_pipeline,
        ), mock.patch.object(
            archive_export_module,
            "_verify_staged_voice_mp4_only",
            side_effect=tamper_then_verify,
        ):
            with self.assertRaisesRegex(VaultError, "哈希或大小不一致"):
                export_archive(
                    self.fixture.root,
                    self.account,
                    plan_path,
                    plan["plan_digest"],
                    output,
                    swift_bin=self.base / "unused-swift",
                    voice_mp4_only=True,
                )

        self.assertFalse(output.exists())
        self.assertEqual(list(self.base.glob(".tampered-mp4-only-*")), [])


if __name__ == "__main__":
    unittest.main()
