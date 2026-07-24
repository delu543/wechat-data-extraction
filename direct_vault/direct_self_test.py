#!/usr/bin/env python3
"""Exercise the complete direct SQLite -> SILK -> M4A -> MP4 path with fixtures."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import sqlite3
import struct
import subprocess
import sys
import tempfile
from typing import Any, Optional

from direct_voice_vault import build_plan, decode, doctor, extract


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)


def _write_pcm(path: Path, duration_ms: int, frequency: int) -> None:
    sample_rate = 24_000
    frames = sample_rate * duration_ms // 1_000
    with path.open("wb") as handle:
        os.fchmod(handle.fileno(), 0o600)
        for index in range(frames):
            value = int(
                math.sin(2 * math.pi * frequency * index / sample_rate) * 4_000
            )
            handle.write(struct.pack("<h", value))


def _encode_silk(pcm: Path, silk: Path) -> bytes:
    try:
        from pilk import SilkEncoder  # type: ignore[import-not-found]
    except ImportError as error:
        raise RuntimeError(
            "缺少 pilk；请先运行 scripts/setup_direct_tools.sh"
        ) from error
    result = SilkEncoder(pcm_rate=24_000, silk_rate=24_000).encode(
        str(pcm), str(silk), tencent=True
    )
    if result != 1 or not silk.is_file() or silk.stat().st_size == 0:
        raise RuntimeError("自检 SILK 编码失败")
    return silk.read_bytes()


def _make_vault(root: Path) -> tuple[str, str]:
    chat_id = "123456789@chatroom"
    chat_name = "直取全链路自检群"
    message_table = "Msg_" + hashlib.md5(chat_id.encode("utf-8")).hexdigest()
    (root / "contact").mkdir(parents=True, mode=0o700)
    (root / "message").mkdir(mode=0o700)

    contact = root / "contact/contact.db"
    with sqlite3.connect(contact) as connection:
        connection.execute(
            "CREATE TABLE contact (id INTEGER, username TEXT, nick_name TEXT, "
            "remark TEXT, alias TEXT)"
        )
        connection.execute(
            "INSERT INTO contact VALUES (1, ?, ?, '', '')", (chat_id, chat_name)
        )

    message = root / "message/message_0.db"
    with sqlite3.connect(message) as connection:
        connection.execute(
            f"CREATE TABLE [{message_table}] ("
            "local_id INTEGER, server_id INTEGER, local_type INTEGER, "
            "create_time INTEGER, message_content TEXT, "
            "compress_content BLOB, WCDB_CT_message_content INTEGER)"
        )
        for sequence, duration in enumerate((1_000, 1_200), 1):
            connection.execute(
                f"INSERT INTO [{message_table}] VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    sequence,
                    9_100_000_000_000 + sequence,
                    34,
                    100 + sequence,
                    f'<msg><voicemsg voicelength="{duration}" /></msg>',
                    None,
                    None,
                ),
            )

    media = root / "message/media_0.db"
    with sqlite3.connect(media) as connection:
        connection.execute(
            "CREATE TABLE VoiceInfo (svr_id INTEGER, voice_data BLOB, "
            "local_id INTEGER, create_time INTEGER, chat_name_id INTEGER)"
        )
        connection.execute("CREATE TABLE Name2Id (user_name TEXT)")
        connection.execute(
            "INSERT INTO Name2Id(rowid, user_name) VALUES (7, ?)", (chat_id,)
        )
        for sequence, (duration, frequency) in enumerate(
            ((1_000, 440), (1_200, 660)), 1
        ):
            pcm = root / f"fixture-{sequence}.pcm"
            silk = root / f"fixture-{sequence}.silk"
            _write_pcm(pcm, duration, frequency)
            blob = _encode_silk(pcm, silk)
            connection.execute(
                "INSERT INTO VoiceInfo VALUES (?, ?, ?, ?, ?)",
                (
                    9_100_000_000_000 + sequence,
                    blob,
                    sequence,
                    100 + sequence,
                    7,
                ),
            )
            pcm.unlink()
            silk.unlink()
    return chat_id, chat_name


def run(swift_bin: Path, output: Path) -> dict[str, Any]:
    swift = swift_bin.expanduser().resolve()
    if not swift.is_file() or not os.access(swift, os.X_OK):
        raise RuntimeError(f"Swift 工具不可执行：{swift}")
    destination = output.expanduser().resolve()
    if destination.exists():
        raise RuntimeError(f"自检输出已存在，拒绝覆盖：{destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="wechat-voice-direct-self-test-") as name:
        root = Path(name)
        os.chmod(root, 0o700)
        vault = root / "vault"
        _, chat_name = _make_vault(vault)
        diagnosis = doctor(vault)
        if not diagnosis["ready_for_extract"]:
            raise RuntimeError(f"fixture doctor 未通过：{_json(diagnosis)}")
        plan = build_plan(vault, chat_name, "100", "300", expected=2)
        plan_path = root / "plan.json"
        plan_path.write_text(_json(plan) + "\n", encoding="utf-8")
        os.chmod(plan_path, 0o600)
        extracted = root / "extracted"
        extract(vault, plan_path, extracted)
        decoded = root / "decoded"
        decode(extracted, decoded, swift)
        completed = subprocess.run(
            [
                str(swift),
                "assemble-direct",
                "--manifest",
                str(decoded / "direct-manifest.json"),
                "--output",
                str(destination),
                "--gap-ms",
                "100",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=300,
        )
        if completed.returncode != 0:
            raise RuntimeError(
                "直取 MP4 自检失败：" + (completed.stderr or completed.stdout).strip()
            )
        report = json.loads(completed.stdout)
        if not destination.is_file() or destination.stat().st_size == 0:
            raise RuntimeError("直取 MP4 自检没有生成有效输出")
        return {
            "passed": True,
            "voice_count": plan["voice_count"],
            "output": str(destination),
            "mp4": report,
        }


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="离线验证数据库直取语音的完整媒体管线")
    parser.add_argument("--swift-bin", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        print(_json(run(Path(args.swift_bin), Path(args.output))))
        return 0
    except (OSError, RuntimeError, sqlite3.Error, subprocess.SubprocessError) as error:
        print(f"错误：{error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
