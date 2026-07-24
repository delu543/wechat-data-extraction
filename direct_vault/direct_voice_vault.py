#!/usr/bin/env python3
"""Read voice messages directly from an already-decrypted Mac WeChat 4.x vault.

This helper deliberately does not read encryption keys, attach to WeChat, re-sign
applications, control the UI, or write to the decrypted vault.  Message rows are
selected from ``message_*.db`` and joined exactly by
``message.server_id == VoiceInfo.svr_id``.  No timestamp/file-order guess is used.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
from typing import Any, Callable, Iterable, Iterator, Optional, Union


PLAN_SCHEMA_VERSION = 1
SILK_MAGIC = b"#!SILK_V3"
TENCENT_SILK_PREFIX = b"\x02"
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
VOICE_TYPE = 34
MAX_VOICE_BLOB_BYTES = 64 * 1024 * 1024
MAX_SILK_PACKET_BYTES = 32_767
SILK_PACKET_MILLISECONDS = 20
PCM_SAMPLE_RATE = 24_000
PCM_BYTES_PER_SAMPLE = 2
DIRECT_MANIFEST_SCHEMA_VERSION = 1
DIRECT_VOICE_MIN_DURATION_MILLISECONDS = 100
DIRECT_VOICE_MAX_DURATION_MILLISECONDS = 61_000
MAX_TOOL_OUTPUT_CHARACTERS = 4_000
# Keep comfortably below SQLite builds that still use the historical 999
# bound-variable default.  The chat-bound query uses every server id twice
# (the preferred-chat branch and the fail-closed non-chat branch).
VOICE_LOOKUP_BATCH_SIZE = 400
SQLITE_SAFE_BOUND_VARIABLES = 900

SilkDecoder = Callable[[Path, Path, int], None]
PCMConverter = Callable[[Path, Path, Path, int, int], dict[str, Any]]


class VaultError(RuntimeError):
    """Expected, user-actionable validation failure."""


class _KnownCoreAudioFormatFailure(VaultError):
    """Internal signal used to open the current decode batch's fallback circuit."""


def _is_known_coreaudio_format_failure(detail: str) -> bool:
    return (
        "com.apple.coreaudio.avfaudio" in detail.casefold()
        and re.search(r"(?<!\d)1718449215(?!\d)", detail) is not None
    )


def _remove_known_failed_conversion_output(output_path: Path) -> None:
    """Remove only a regular partial file left by the exact known encoder failure."""

    if not output_path.exists() and not output_path.is_symlink():
        return
    if output_path.is_symlink() or not output_path.is_file():
        raise VaultError("CoreAudio 失败后出现不安全的 M4A 输出路径")
    try:
        output_path.unlink()
    except OSError as error:
        raise VaultError("无法清理 CoreAudio 失败后留下的 M4A 临时文件") from error


def _json_dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1_048_576)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _plan_digest(plan: dict[str, Any]) -> str:
    unsigned = dict(plan)
    unsigned.pop("plan_digest", None)
    return _sha256_bytes(_canonical_json(unsigned))


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _resolve_vault(path: Union[str, Path]) -> Path:
    vault = Path(path).expanduser().resolve()
    if not vault.is_dir():
        raise VaultError(f"已解密 vault 不存在或不是目录：{vault}")
    return vault


def _ensure_output_outside_vault(output: Path, vault: Path) -> Path:
    expanded = output.expanduser()
    if expanded.is_symlink():
        raise VaultError(f"输出路径不能是符号链接：{expanded}")
    resolved = expanded.resolve()
    if resolved == vault or _is_relative_to(resolved, vault):
        raise VaultError("输出不能写入已解密 vault；请选择独立的私有输出目录")
    return resolved


def _assert_source_path(path: Path, vault: Path) -> Path:
    resolved = path.resolve()
    if not _is_relative_to(resolved, vault):
        raise VaultError(f"数据库路径逃逸出 vault：{path}")
    if not resolved.is_file():
        raise VaultError(f"数据库不存在：{path}")
    return resolved


@contextmanager
def _connect_read_only(path: Path, vault: Path) -> Iterator[sqlite3.Connection]:
    source = _assert_source_path(path, vault)
    # This module accepts only a frozen, already-merged plaintext snapshot.
    # ``immutable=1`` prevents SQLite from creating WAL/SHM files while opening
    # a WAL-mode database header read-only.  Reject sidecars first so immutable
    # mode can never silently ignore an unmerged WAL supplied by the caller.
    for suffix in ("-wal", "-shm"):
        sidecar = Path(str(source) + suffix)
        if sidecar.is_symlink() or sidecar.exists():
            raise VaultError(
                f"不可变明文快照仍包含 {sidecar.name}；请先制作并验证一致快照"
            )
    connection = sqlite3.connect(
        f"{source.as_uri()}?mode=ro&immutable=1", uri=True
    )
    try:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        yield connection
    finally:
        connection.close()


def _quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _table_names(connection: sqlite3.Connection) -> list[str]:
    return [
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
    ]


def _find_table(connection: sqlite3.Connection, expected: str) -> Optional[str]:
    matches = [name for name in _table_names(connection) if name.lower() == expected.lower()]
    if len(matches) > 1:
        raise VaultError(f"数据库中存在多个大小写冲突的表：{expected}")
    return matches[0] if matches else None


def _columns(connection: sqlite3.Connection, table: str) -> dict[str, str]:
    quoted = _quote_identifier(table)
    return {
        str(row[1]).lower(): str(row[1])
        for row in connection.execute(f"PRAGMA table_info({quoted})")
    }


def _choose_column(
    columns: dict[str, str], choices: Iterable[str], *, required: bool = True
) -> Optional[str]:
    for choice in choices:
        match = columns.get(choice.lower())
        if match:
            return match
    if required:
        raise VaultError(f"缺少必要列，候选：{', '.join(choices)}")
    return None


def _find_database(vault: Path, preferred: str, basename: str) -> Path:
    direct = vault / preferred
    if direct.is_file():
        return _assert_source_path(direct, vault)
    matches = sorted(
        path for path in vault.rglob(basename) if path.is_file() and not path.is_symlink()
    )
    if len(matches) != 1:
        raise VaultError(f"无法唯一定位 {basename}：找到 {len(matches)} 个")
    return _assert_source_path(matches[0], vault)


def _message_databases(vault: Path) -> list[Path]:
    preferred = sorted((vault / "message").glob("message_*.db"))
    matches = preferred or sorted(vault.rglob("message_*.db"))
    unique: dict[Path, Path] = {}
    for path in matches:
        if path.is_file() and not path.is_symlink():
            resolved = _assert_source_path(path, vault)
            unique[resolved] = resolved
    if not unique:
        raise VaultError("没有找到已解密 message_*.db")
    return sorted(unique.values())


def _media_databases(vault: Path) -> list[Path]:
    # WeChat 4.x/yichen decrypted layouts put media shards beside message
    # shards.  Keep the older top-level media/ layout as a compatibility
    # fallback, then use a bounded recursive discovery as the last resort.
    preferred_message = sorted((vault / "message").glob("media_*.db"))
    preferred_legacy = sorted((vault / "media").glob("media_*.db"))
    matches = preferred_message or preferred_legacy or sorted(vault.rglob("media_*.db"))
    unique: dict[Path, Path] = {}
    for path in matches:
        if path.is_file() and not path.is_symlink():
            resolved = _assert_source_path(path, vault)
            unique[resolved] = resolved
    return sorted(unique.values())


def _sqlite_readable(path: Path, vault: Path) -> tuple[bool, Optional[str]]:
    try:
        with _connect_read_only(path, vault) as connection:
            connection.execute("SELECT count(*) FROM sqlite_master").fetchone()
            quick_check = [str(row[0]) for row in connection.execute("PRAGMA quick_check")]
            if quick_check != ["ok"]:
                detail = "; ".join(quick_check[:5]) or "no result"
                return False, f"SQLite quick_check 失败：{detail}"
        return True, None
    except (sqlite3.Error, VaultError) as error:
        return False, str(error)


def _voice_info_schema_from_connection(
    connection: sqlite3.Connection,
) -> Optional[tuple[str, str, str, dict[str, Optional[str]]]]:
    table = _find_table(connection, "VoiceInfo")
    if not table:
        return None
    columns = _columns(connection, table)
    server_column = _choose_column(columns, ("svr_id", "server_id", "msg_svr_id"))
    data_column = _choose_column(columns, ("voice_data", "voiceData"))
    optional = {
        "local_id": _choose_column(columns, ("local_id",), required=False),
        "create_time": _choose_column(columns, ("create_time",), required=False),
        "chat_name_id": _choose_column(columns, ("chat_name_id",), required=False),
    }
    assert server_column is not None and data_column is not None
    return table, server_column, data_column, optional


def _voice_info_schema(
    path: Path, vault: Path
) -> Optional[tuple[str, str, str, dict[str, Optional[str]]]]:
    with _connect_read_only(path, vault) as connection:
        return _voice_info_schema_from_connection(connection)


def _name2id_schema(
    connection: sqlite3.Connection,
) -> Optional[tuple[str, str]]:
    table = _find_table(connection, "Name2Id")
    if not table:
        return None
    columns = _columns(connection, table)
    user_name = _choose_column(
        columns, ("user_name", "username", "userName"), required=False
    )
    return (table, user_name) if user_name else None


def doctor(vault_dir: Union[str, Path]) -> dict[str, Any]:
    vault = _resolve_vault(vault_dir)
    checks: list[dict[str, Any]] = []

    try:
        contact = _find_database(vault, "contact/contact.db", "contact.db")
        readable, detail = _sqlite_readable(contact, vault)
        checks.append({"name": "contact_db", "ok": readable, "detail": detail})
    except VaultError as error:
        checks.append({"name": "contact_db", "ok": False, "detail": str(error)})

    try:
        messages = _message_databases(vault)
        failures = [
            path.name
            for path in messages
            if not _sqlite_readable(path, vault)[0]
        ]
        checks.append(
            {
                "name": "message_dbs",
                "ok": not failures,
                "count": len(messages),
                "unreadable": failures,
            }
        )
    except VaultError as error:
        checks.append({"name": "message_dbs", "ok": False, "detail": str(error)})

    media = _media_databases(vault)
    compatible = 0
    media_errors: list[str] = []
    for path in media:
        try:
            readable, detail = _sqlite_readable(path, vault)
            if not readable:
                media_errors.append(f"{path.name}: {detail}")
                continue
            if _voice_info_schema(path, vault):
                compatible += 1
        except (sqlite3.Error, VaultError) as error:
            media_errors.append(f"{path.name}: {error}")
    checks.append(
        {
            "name": "voice_media_dbs",
            "ok": compatible > 0 and not media_errors,
            "database_count": len(media),
            "voiceinfo_count": compatible,
            "errors": media_errors,
        }
    )
    ready_for_plan = all(
        item["ok"] for item in checks if item["name"] in {"contact_db", "message_dbs"}
    )
    ready_for_extract = ready_for_plan and checks[-1]["ok"]
    return {
        "mode": "decrypted-vault-read-only",
        "ready_for_plan": ready_for_plan,
        "ready_for_extract": ready_for_extract,
        "checks": checks,
        "prohibited_actions": [
            "read_keys",
            "attach_to_wechat",
            "resign_wechat",
            "control_wechat_ui",
            "write_source_databases",
        ],
    }


def _normalize_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _resolve_chat(
    vault: Path, chat_name: str, chat_id: Optional[str] = None
) -> tuple[str, str, str]:
    requested = chat_name.strip()
    if not requested:
        raise VaultError("--chat 不能为空")
    contact_path = _find_database(vault, "contact/contact.db", "contact.db")
    with _connect_read_only(contact_path, vault) as connection:
        table = _find_table(connection, "contact")
        if not table:
            raise VaultError("contact.db 中没有 contact 表")
        columns = _columns(connection, table)
        username = _choose_column(columns, ("username", "userName"))
        display_columns = [
            column
            for column in (
                _choose_column(columns, ("remark",), required=False),
                _choose_column(columns, ("nick_name", "nickname"), required=False),
                _choose_column(columns, ("alias",), required=False),
            )
            if column
        ]
        assert username is not None
        selected = [username, *display_columns]
        sql = "SELECT " + ", ".join(_quote_identifier(item) for item in selected)
        sql += " FROM " + _quote_identifier(table)
        candidates: list[tuple[str, str]] = []
        for row in connection.execute(sql):
            internal_id = _normalize_text(row[username]).strip()
            if not internal_id:
                continue
            names = [_normalize_text(row[column]).strip() for column in display_columns]
            if chat_id:
                if internal_id != chat_id:
                    continue
                if requested != internal_id and requested not in names:
                    raise VaultError("--chat-id 对应聊天与 --chat 名称不一致")
            elif requested != internal_id and requested not in names:
                continue
            display = next((name for name in names if name), internal_id)
            candidates.append((internal_id, display))
    distinct = {item[0]: item for item in candidates}
    if len(distinct) == 0:
        raise VaultError(f"没有找到精确匹配的聊天：{requested}")
    if len(distinct) > 1:
        raise VaultError(
            f"聊天名称存在歧义：{requested} 精确匹配 {len(distinct)} 个会话；请传 --chat-id"
        )
    internal_id, display = next(iter(distinct.values()))
    kind = "group" if internal_id.endswith("@chatroom") else "direct"
    return internal_id, display, kind


def _parse_time(value: str) -> int:
    stripped = value.strip()
    # Unix seconds are also useful for fixtures and for old/short-lived test
    # vaults.  Do not require a modern ten-digit timestamp here; SQLite will
    # still compare the resulting integer against create_time exactly.
    if re.fullmatch(r"\d{1,12}", stripped):
        return int(stripped)
    for pattern in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return int(datetime.strptime(stripped, pattern).timestamp())
        except ValueError:
            pass
    raise VaultError(f"不支持的时间格式：{value}")


def _decode_message_content(value: Any, compression_flag: Any = None) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    data = bytes(value)
    if data.startswith(ZSTD_MAGIC) or compression_flag == 4:
        try:
            import zstandard  # type: ignore[import-not-found]
        except ImportError as error:
            raise VaultError("消息内容为 zstd；请先安装 Python zstandard") from error
        try:
            data = zstandard.ZstdDecompressor().decompress(
                data, max_output_size=2_000_000
            )
        except Exception as error:
            raise VaultError("zstd 消息内容解压失败") from error
    return data.decode("utf-8", errors="replace")


def _duration_from_content(content: str) -> Optional[int]:
    match = re.search(r"\bvoicelength\s*=\s*['\"](\d+)['\"]", content)
    if not match:
        return None
    duration = int(match.group(1))
    return duration if duration > 0 else None


def _message_columns(
    connection: sqlite3.Connection, table: str
) -> dict[str, Optional[str]]:
    columns = _columns(connection, table)
    return {
        "local_id": _choose_column(columns, ("local_id", "id")),
        "server_id": _choose_column(columns, ("server_id", "svr_id")),
        "local_type": _choose_column(columns, ("local_type", "type")),
        "create_time": _choose_column(columns, ("create_time", "timestamp")),
        "message_content": _choose_column(
            columns,
            ("message_content", "content"),
            required=False,
        ),
        "compress_content": _choose_column(
            columns, ("compress_content",), required=False
        ),
        "compression_flag": _choose_column(
            columns, ("WCDB_CT_message_content",), required=False
        ),
    }


def _duration_from_message_row(row: sqlite3.Row) -> Optional[int]:
    flag = row["compression_flag"]
    for key in ("message_content", "compress_content"):
        value = row[key]
        if value is None or value == "" or value == b"":
            continue
        duration = _duration_from_content(_decode_message_content(value, flag))
        if duration is not None:
            return duration
    return None


def _server_id_as_int(value: Any, sequence: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as error:
        raise VaultError(
            f"第 {sequence} 条 server_id 不是整数：{value!r}"
        ) from error


def _validate_unique_server_ids(voices: list[dict[str, Any]]) -> None:
    seen: dict[int, int] = {}
    for voice in voices:
        sequence = voice.get("sequence", "?")
        server_value = _server_id_as_int(voice.get("server_id"), sequence)
        if server_value != 0 and server_value in seen:
            raise VaultError(
                f"server_id={server_value} 在第 {seen[server_value]}、{sequence} 条重复，计划存在歧义"
            )
        if server_value != 0:
            seen[server_value] = int(sequence)


def build_plan(
    vault_dir: Union[str, Path],
    chat_name: str,
    start: str,
    end: str,
    *,
    expected: Optional[int] = None,
    chat_id: Optional[str] = None,
) -> dict[str, Any]:
    vault = _resolve_vault(vault_dir)
    start_ts = _parse_time(start)
    end_ts = _parse_time(end)
    if start_ts > end_ts:
        raise VaultError("开始时间必须不晚于结束时间")
    if expected is not None and expected <= 0:
        raise VaultError("--expected 必须大于 0")
    internal_id, display_name, chat_kind = _resolve_chat(vault, chat_name, chat_id)
    message_table = "Msg_" + hashlib.md5(internal_id.encode("utf-8")).hexdigest()

    rows: list[dict[str, Any]] = []
    matched_shards = 0
    for path in _message_databases(vault):
        with _connect_read_only(path, vault) as connection:
            table = _find_table(connection, message_table)
            if not table:
                continue
            matched_shards += 1
            columns = _message_columns(connection, table)
            required = [
                columns["local_id"],
                columns["server_id"],
                columns["local_type"],
                columns["create_time"],
            ]
            assert all(item is not None for item in required)
            aliases = []
            for key, column in columns.items():
                if column:
                    aliases.append(f"{_quote_identifier(column)} AS {_quote_identifier(key)}")
                else:
                    aliases.append(f"NULL AS {_quote_identifier(key)}")
            local_type = _quote_identifier(str(columns["local_type"]))
            create_time = _quote_identifier(str(columns["create_time"]))
            local_id = _quote_identifier(str(columns["local_id"]))
            server_id = _quote_identifier(str(columns["server_id"]))
            sql = (
                f"SELECT {', '.join(aliases)} FROM {_quote_identifier(table)} "
                f"WHERE ({local_type} & 4294967295) = ? "
                f"AND {create_time} >= ? AND {create_time} <= ? "
                f"ORDER BY {create_time}, {local_id}, {server_id}"
            )
            for row in connection.execute(sql, (VOICE_TYPE, start_ts, end_ts)):
                rows.append(
                    {
                        "source_db": str(path.relative_to(vault)),
                        "source_table": table,
                        "local_id": str(row["local_id"] if row["local_id"] is not None else ""),
                        "server_id": str(row["server_id"] if row["server_id"] is not None else ""),
                        "create_time": int(row["create_time"] or 0),
                        "duration_ms": _duration_from_message_row(row),
                    }
                )
    if matched_shards == 0:
        raise VaultError("所有 message_*.db 都没有目标聊天表")
    rows.sort(
        key=lambda item: (
            item["create_time"],
            int(item["local_id"] or 0),
            int(item["server_id"] or 0),
            item["source_db"],
        )
    )
    for sequence, row in enumerate(rows, 1):
        row["sequence"] = sequence
    _validate_unique_server_ids(rows)
    if expected is not None and len(rows) != expected:
        raise VaultError(f"时间范围内找到 {len(rows)} 条语音，预期 {expected} 条")
    plan: dict[str, Any] = {
        "schema_version": PLAN_SCHEMA_VERSION,
        "mode": "decrypted-vault-read-only",
        "chat": {
            "requested_name": chat_name.strip(),
            "display_name": display_name,
            "chat_id": internal_id,
            "kind": chat_kind,
        },
        "time_range": {
            "start_input": start,
            "end_input": end,
            "start_unix": start_ts,
            "end_unix": end_ts,
            "end_inclusive": True,
        },
        "expected_count": expected,
        "voice_count": len(rows),
        "message_table": message_table,
        "voices": rows,
    }
    plan["plan_digest"] = _plan_digest(plan)
    return plan


def _load_plan(path: Union[str, Path]) -> dict[str, Any]:
    plan_path = Path(path).expanduser().resolve()
    try:
        with plan_path.open(encoding="utf-8") as handle:
            plan = json.load(handle)
    except (OSError, json.JSONDecodeError) as error:
        raise VaultError(f"无法读取计划：{plan_path}") from error
    if not isinstance(plan, dict):
        raise VaultError("计划根节点必须是 JSON 对象")
    if plan.get("schema_version") != PLAN_SCHEMA_VERSION:
        raise VaultError("计划 schema 版本不受支持")
    if plan.get("mode") != "decrypted-vault-read-only":
        raise VaultError("计划来源模式不受支持")
    if plan.get("plan_digest") != _plan_digest(plan):
        raise VaultError("计划摘要不匹配，文件已被修改")
    voices = plan.get("voices")
    if not isinstance(voices, list) or len(voices) != plan.get("voice_count"):
        raise VaultError("计划语音清单损坏")
    if not all(isinstance(item, dict) for item in voices):
        raise VaultError("计划语音条目格式损坏")
    if [item.get("sequence") for item in voices] != list(range(1, len(voices) + 1)):
        raise VaultError("计划顺序损坏")
    for item in voices:
        duration = item.get("duration_ms")
        if duration is not None and (not isinstance(duration, int) or duration <= 0):
            raise VaultError(f"第 {item['sequence']} 条 duration_ms 非法")
    _validate_unique_server_ids(voices)
    return plan


def _validated_chat_and_time_range(
    value: dict[str, Any], description: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    chat = value.get("chat")
    time_range = value.get("time_range")
    if not isinstance(chat, dict) or not isinstance(time_range, dict):
        raise VaultError(f"{description}缺少 chat/time_range")
    requested_name = chat.get("requested_name")
    display_name = chat.get("display_name")
    chat_id = chat.get("chat_id")
    kind = chat.get("kind")
    if (
        not isinstance(requested_name, str)
        or not requested_name.strip()
        or not isinstance(display_name, str)
        or not display_name.strip()
        or not isinstance(chat_id, str)
        or not chat_id.strip()
        or len(chat_id) > 512
        or kind not in {"group", "direct"}
        or (kind == "group") != chat_id.endswith("@chatroom")
    ):
        raise VaultError(f"{description}的 chat 字段无效")
    start_input = time_range.get("start_input")
    end_input = time_range.get("end_input")
    start_unix = time_range.get("start_unix")
    end_unix = time_range.get("end_unix")
    end_inclusive = time_range.get("end_inclusive")
    if (
        not isinstance(start_input, str)
        or not start_input.strip()
        or not isinstance(end_input, str)
        or not end_input.strip()
        or type(start_unix) is not int
        or type(end_unix) is not int
        or start_unix > end_unix
        or end_inclusive is not True
    ):
        raise VaultError(f"{description}的 time_range 字段无效")
    return (
        {
            "requested_name": requested_name,
            "display_name": display_name,
            "chat_id": chat_id,
            "kind": kind,
        },
        {
            "start_input": start_input,
            "end_input": end_input,
            "start_unix": start_unix,
            "end_unix": end_unix,
            "end_inclusive": True,
        },
    )


def inspect_silk(blob: bytes, expected_duration_ms: Optional[int]) -> dict[str, Any]:
    if not blob:
        raise VaultError("VoiceInfo.voice_data 为空")
    if len(blob) > MAX_VOICE_BLOB_BYTES:
        raise VaultError("VoiceInfo.voice_data 超出安全大小上限")
    has_tencent_prefix = blob.startswith(TENCENT_SILK_PREFIX)
    normalized = blob[1:] if has_tencent_prefix else blob
    if not normalized.startswith(SILK_MAGIC):
        raise VaultError("voice_data 不是可识别的 SILK_V3（魔数不匹配）")
    cursor = len(SILK_MAGIC)
    packet_count = 0
    terminal_marker = False
    while cursor < len(normalized):
        if len(normalized) - cursor < 2:
            raise VaultError("SILK 帧长度字段被截断")
        packet_length = struct.unpack_from("<h", normalized, cursor)[0]
        cursor += 2
        if packet_length == -1:
            if cursor != len(normalized):
                raise VaultError("SILK 结束标记后仍有多余数据")
            terminal_marker = True
            break
        if packet_length <= 0 or packet_length > MAX_SILK_PACKET_BYTES:
            raise VaultError(f"SILK 帧长度非法：{packet_length}")
        if cursor + packet_length > len(normalized):
            raise VaultError("SILK 帧数据被截断")
        cursor += packet_length
        packet_count += 1
    if packet_count == 0:
        raise VaultError("SILK 中没有音频帧")
    frame_duration_ms = packet_count * SILK_PACKET_MILLISECONDS
    if expected_duration_ms is None:
        raise VaultError("消息 XML 缺少 voicelength，无法做帧时长校验")
    tolerance = max(120, int(expected_duration_ms * 0.02))
    if abs(frame_duration_ms - expected_duration_ms) > tolerance:
        raise VaultError(
            "SILK 帧时长与消息时长不符："
            f"帧={frame_duration_ms}ms，消息={expected_duration_ms}ms"
        )
    return {
        "has_tencent_prefix": has_tencent_prefix,
        "packet_count": packet_count,
        "frame_duration_ms": frame_duration_ms,
        "terminal_marker": terminal_marker,
        "raw_sha256": _sha256_bytes(blob),
    }


def _voice_match_from_row(
    vault: Path,
    path: Path,
    row: sqlite3.Row,
    expected_chat_id: str,
    *,
    chat_binding_available: bool,
    unavailable_reason: Optional[str],
) -> tuple[int, dict[str, Any]]:
    server_id = _server_id_as_int(row["__server_id"], "?")
    value = row["__voice_data"]
    if isinstance(value, memoryview):
        value = value.tobytes()
    if not isinstance(value, (bytes, bytearray)):
        raise VaultError(
            f"{path.name}.VoiceInfo.voice_data 不是 BLOB（server_id={server_id}）"
        )

    if chat_binding_available:
        chat_name_id = row["chat_name_id"]
        if chat_name_id is None:
            raise VaultError(
                f"{path.name} server_id={server_id} 的 chat_name_id 为空"
            )
        mapped_chat_id = _normalize_text(row["__mapped_chat_id"]).strip()
        if not mapped_chat_id:
            raise VaultError(
                f"{path.name} server_id={server_id} 的 "
                f"chat_name_id={chat_name_id} 无法解析"
            )
        if mapped_chat_id != expected_chat_id:
            raise VaultError(
                f"{path.name} server_id={server_id} 属于 {mapped_chat_id}，"
                f"不是计划聊天 {expected_chat_id}"
            )
        chat_binding = {
            "status": "verified",
            "chat_name_id": str(chat_name_id),
            "mapped_chat_id": mapped_chat_id,
        }
    else:
        assert unavailable_reason is not None
        chat_binding = {"status": "unavailable", "reason": unavailable_reason}

    return (
        server_id,
        {
            "source_db": str(path.relative_to(vault)),
            "source_rowid": int(row["__rowid"]),
            "blob": bytes(value),
            "media_local_id": row["local_id"],
            "media_create_time": row["create_time"],
            "media_chat_name_id": row["chat_name_id"],
            "chat_binding": chat_binding,
        },
    )


def _voice_matches(
    vault: Path,
    server_ids: Iterable[str],
    media_dbs: list[Path],
    expected_chat_id: str,
) -> dict[int, list[dict[str, Any]]]:
    """Resolve all planned voice ids with one connection and batched SQL per shard.

    When both binding tables are available, the first UNION branch is the
    preferred indexed path: ``chat_name_id`` equality followed by
    ``svr_id IN (...)``.  The second branch deliberately retains rows from
    other/null chat ids so a duplicate or wrong-chat row cannot be hidden by
    the optimization.
    """

    server_values: list[int] = []
    for server_id in server_ids:
        server_value = _server_id_as_int(server_id, "?")
        if server_value == 0:
            raise VaultError("server_id=0 无法精确联接 VoiceInfo")
        server_values.append(server_value)
    # The plan loader already rejects duplicates.  Keep this helper safe if it
    # is called directly and avoid wasting bound parameters.
    server_values = list(dict.fromkeys(server_values))
    matches: dict[int, list[dict[str, Any]]] = {
        server_value: [] for server_value in server_values
    }
    if not server_values:
        return matches

    for path in media_dbs:
        with _connect_read_only(path, vault) as connection:
            schema = _voice_info_schema_from_connection(connection)
            if not schema:
                continue
            table, server_column, data_column, optional = schema
            name2id = _name2id_schema(connection)
            chat_name_column = optional["chat_name_id"]
            binding_available = bool(chat_name_column and name2id)
            unavailable_reason: Optional[str] = None
            expected_chat_name_ids: list[int] = []

            voice_alias = "voice"
            selected = [
                f"{voice_alias}.rowid AS __rowid",
                f"{voice_alias}.{_quote_identifier(server_column)} AS __server_id",
                f"{voice_alias}.{_quote_identifier(data_column)} AS __voice_data",
            ]
            for key, column in optional.items():
                selected.append(
                    f"{voice_alias}.{_quote_identifier(column)} "
                    f"AS {_quote_identifier(key)}"
                    if column
                    else f"NULL AS {_quote_identifier(key)}"
                )

            from_sql = f"FROM {_quote_identifier(table)} AS {voice_alias}"
            if binding_available:
                assert chat_name_column is not None and name2id is not None
                name_table, user_name_column = name2id
                name_alias = "chat_names"
                selected.append(
                    f"{name_alias}.{_quote_identifier(user_name_column)} "
                    "AS __mapped_chat_id"
                )
                from_sql += (
                    f" LEFT JOIN {_quote_identifier(name_table)} AS {name_alias}"
                    f" ON {name_alias}.rowid = "
                    f"{voice_alias}.{_quote_identifier(chat_name_column)}"
                )
                mapping_rows = connection.execute(
                    f"SELECT rowid AS __chat_name_id, "
                    f"{_quote_identifier(user_name_column)} AS __user_name "
                    f"FROM {_quote_identifier(name_table)} "
                    f"WHERE {_quote_identifier(user_name_column)} = ?",
                    (expected_chat_id,),
                )
                expected_chat_name_ids = [
                    int(row["__chat_name_id"])
                    for row in mapping_rows
                    if _normalize_text(row["__user_name"]).strip()
                    == expected_chat_id
                ]
            else:
                selected.append("NULL AS __mapped_chat_id")
                unavailable_reason = (
                    "VoiceInfo.chat_name_id unavailable"
                    if not chat_name_column
                    else "Name2Id.user_name unavailable"
                )

            if binding_available and expected_chat_name_ids:
                # Each id appears in both UNION branches.  Adapt the server
                # batch if a damaged Name2Id table contains many exact rows.
                available_for_servers = (
                    SQLITE_SAFE_BOUND_VARIABLES
                    - (2 * len(expected_chat_name_ids))
                ) // 2
                if available_for_servers < 1:
                    raise VaultError(
                        f"{path.name} 中计划聊天的 Name2Id 映射过多，拒绝歧义联接"
                    )
                batch_size = min(VOICE_LOOKUP_BATCH_SIZE, available_for_servers)
            else:
                batch_size = VOICE_LOOKUP_BATCH_SIZE

            for offset in range(0, len(server_values), batch_size):
                batch = server_values[offset : offset + batch_size]
                server_placeholders = ", ".join("?" for _ in batch)
                server_expression = (
                    f"{voice_alias}.{_quote_identifier(server_column)} "
                    f"IN ({server_placeholders})"
                )
                if binding_available and expected_chat_name_ids:
                    assert chat_name_column is not None
                    chat_placeholders = ", ".join(
                        "?" for _ in expected_chat_name_ids
                    )
                    chat_expression = (
                        f"{voice_alias}.{_quote_identifier(chat_name_column)} "
                        f"IN ({chat_placeholders})"
                    )
                    # UNION ALL keeps the preferred composite-index path while
                    # also surfacing every wrong/null-chat duplicate.
                    sql = (
                        f"SELECT {', '.join(selected)} {from_sql} "
                        f"WHERE {chat_expression} AND {server_expression} "
                        "UNION ALL "
                        f"SELECT {', '.join(selected)} {from_sql} "
                        f"WHERE ({voice_alias}.{_quote_identifier(chat_name_column)} "
                        f"IS NULL OR NOT {chat_expression}) "
                        f"AND {server_expression}"
                    )
                    parameters: tuple[Any, ...] = (
                        *expected_chat_name_ids,
                        *batch,
                        *expected_chat_name_ids,
                        *batch,
                    )
                else:
                    sql = (
                        f"SELECT {', '.join(selected)} {from_sql} "
                        f"WHERE {server_expression}"
                    )
                    parameters = tuple(batch)

                for row in connection.execute(sql, parameters):
                    server_value, match = _voice_match_from_row(
                        vault,
                        path,
                        row,
                        expected_chat_id,
                        chat_binding_available=binding_available,
                        unavailable_reason=unavailable_reason,
                    )
                    # The WHERE clause should make this impossible, but do not
                    # let a driver/coercion surprise escape the requested set.
                    if server_value not in matches:
                        raise VaultError(
                            f"{path.name} 返回了未请求的 server_id={server_value}"
                        )
                    matches[server_value].append(match)
    return matches


def extract(
    vault_dir: Union[str, Path],
    plan_path: Union[str, Path],
    output_dir: Union[str, Path],
) -> dict[str, Any]:
    vault = _resolve_vault(vault_dir)
    plan = _load_plan(plan_path)
    output = _ensure_output_outside_vault(Path(output_dir), vault)
    if output.exists():
        raise VaultError(f"输出目录已存在，拒绝覆盖：{output}")
    media_dbs = _media_databases(vault)
    if not media_dbs:
        raise VaultError("没有找到已解密 media_*.db")
    chat, time_range = _validated_chat_and_time_range(plan, "计划")
    expected_chat_id = chat["chat_id"]

    all_matches = _voice_matches(
        vault,
        (str(voice.get("server_id", "")) for voice in plan["voices"]),
        media_dbs,
        expected_chat_id,
    )
    prepared: list[dict[str, Any]] = []
    for voice in plan["voices"]:
        server_id = str(voice.get("server_id", ""))
        server_value = _server_id_as_int(server_id, voice["sequence"])
        matches = all_matches[server_value]
        if len(matches) == 0:
            raise VaultError(
                f"第 {voice['sequence']} 条 server_id={server_id} 在 VoiceInfo 中缺失"
            )
        if len(matches) > 1:
            raise VaultError(
                f"第 {voice['sequence']} 条 server_id={server_id} 在 VoiceInfo 中命中 {len(matches)} 行，拒绝猜测"
            )
        match = matches[0]
        silk = inspect_silk(match["blob"], voice.get("duration_ms"))
        prepared.append({"voice": voice, "match": match, "silk": silk})

    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}-", dir=output.parent))
    os.chmod(staging, 0o700)
    manifest_rows: list[dict[str, Any]] = []
    try:
        for item in prepared:
            voice = item["voice"]
            match = item["match"]
            silk = item["silk"]
            try:
                server_component = str(int(voice["server_id"]))
                local_component = str(int(voice["local_id"]))
            except (TypeError, ValueError) as error:
                raise VaultError(
                    f"第 {voice['sequence']} 条 local_id/server_id 不是整数"
                ) from error
            name = (
                f"{int(voice['sequence']):04d}-"
                f"{server_component}-{local_component}.silk"
            )
            destination = staging / name
            with destination.open("xb") as handle:
                os.fchmod(handle.fileno(), 0o600)
                # Preserve VoiceInfo.voice_data byte-for-byte.  Tencent's
                # optional 0x02 prefix is part of the source artifact and is
                # accepted by the decoder used in the next stage.
                handle.write(match["blob"])
                handle.flush()
                os.fsync(handle.fileno())
            manifest_rows.append(
                {
                    "sequence": voice["sequence"],
                    "local_id": voice["local_id"],
                    "server_id": voice["server_id"],
                    "create_time": voice["create_time"],
                    "expected_duration_ms": voice["duration_ms"],
                    "frame_duration_ms": silk["frame_duration_ms"],
                    "packet_count": silk["packet_count"],
                    "relative_path": name,
                    "source_media_db": match["source_db"],
                    "source_rowid": match["source_rowid"],
                    "sha256": silk["raw_sha256"],
                    "source_voice_data_sha256": silk["raw_sha256"],
                    "byte_count": len(match["blob"]),
                    "had_tencent_prefix": silk["has_tencent_prefix"],
                    "chat_binding": match["chat_binding"],
                }
            )
        manifest = {
            "schema_version": 1,
            "source_plan_digest": plan["plan_digest"],
            "chat": chat,
            "time_range": time_range,
            "voice_count": len(manifest_rows),
            "format": "VoiceInfo.voice_data preserved byte-for-byte (Tencent SILK_V3)",
            "voices": manifest_rows,
        }
        _write_json_private(staging / "manifest.json", manifest, vault=None)
        staging.rename(output)
        return {"output_dir": str(output), **manifest}
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _write_json_private(path: Path, value: Any, vault: Optional[Path]) -> None:
    destination = path.expanduser().resolve()
    if vault is not None:
        _ensure_output_outside_vault(destination, vault)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(_json_dump(value))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        os.chmod(destination, 0o600)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        raise


def _require_plain_file(path: Path, description: str) -> Path:
    """Require an existing regular file without following a final symlink."""

    try:
        if path.is_symlink() or not path.is_file():
            raise VaultError(f"{description} 不是普通文件或是符号链接：{path}")
    except OSError as error:
        raise VaultError(f"无法检查{description}：{path}") from error
    return path


def _duration_matches_strict(expected_ms: int, actual_ms: int) -> bool:
    tolerance = max(120, int(expected_ms * 0.02))
    return abs(expected_ms - actual_ms) <= tolerance


def _load_extract_manifest(
    extract_dir: Union[str, Path],
) -> tuple[
    Path,
    Path,
    str,
    str,
    dict[str, Any],
    dict[str, Any],
    list[dict[str, Any]],
]:
    raw_extract = Path(extract_dir).expanduser()
    if raw_extract.is_symlink():
        raise VaultError(f"SILK 提取目录不能是符号链接：{raw_extract}")
    extract = raw_extract.resolve()
    if not extract.is_dir():
        raise VaultError(f"SILK 提取目录不存在或不是目录：{extract}")
    manifest_path = _require_plain_file(extract / "manifest.json", "提取清单")
    try:
        manifest_bytes = manifest_path.read_bytes()
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VaultError(f"无法读取提取清单：{manifest_path}") from error
    if not isinstance(manifest, dict):
        raise VaultError("提取清单根节点必须是 JSON 对象")
    if manifest.get("schema_version") != 1:
        raise VaultError("提取清单 schema 版本不受支持")
    source_plan_digest = manifest.get("source_plan_digest")
    if not isinstance(source_plan_digest, str) or not re.fullmatch(
        r"[0-9a-f]{64}", source_plan_digest
    ):
        raise VaultError("提取清单缺少有效的 source_plan_digest")
    chat, time_range = _validated_chat_and_time_range(manifest, "提取清单")
    voice_count = manifest.get("voice_count")
    voices = manifest.get("voices")
    if (
        type(voice_count) is not int
        or voice_count <= 0
        or not isinstance(voices, list)
        or len(voices) != voice_count
    ):
        raise VaultError("提取清单 voice_count/voices 不一致或为空")
    if not all(isinstance(item, dict) for item in voices):
        raise VaultError("提取清单语音条目格式损坏")
    sequences = [item.get("sequence") for item in voices]
    if sequences != list(range(1, voice_count + 1)):
        raise VaultError("提取清单 sequence 必须从 1 连续递增")

    seen_server_ids: set[str] = set()
    seen_relative_paths: set[str] = set()
    validated: list[dict[str, Any]] = []
    for item in voices:
        sequence = item["sequence"]
        server_id = item.get("server_id")
        if (
            not isinstance(server_id, str)
            or not server_id.isdigit()
            or int(server_id) == 0
            or server_id != str(int(server_id))
            or server_id in seen_server_ids
        ):
            raise VaultError(f"第 {sequence} 条 server_id 无效或重复")
        seen_server_ids.add(server_id)

        local_id = item.get("local_id")
        if (
            not isinstance(local_id, str)
            or not local_id.isdigit()
            or local_id != str(int(local_id))
        ):
            raise VaultError(f"第 {sequence} 条 local_id 无效")

        expected_ms = item.get("expected_duration_ms")
        frame_ms = item.get("frame_duration_ms")
        packet_count = item.get("packet_count")
        if (
            type(expected_ms) is not int
            or not DIRECT_VOICE_MIN_DURATION_MILLISECONDS
            <= expected_ms
            <= DIRECT_VOICE_MAX_DURATION_MILLISECONDS
        ):
            raise VaultError(
                f"第 {sequence} 条 expected_duration_ms 超出 "
                f"{DIRECT_VOICE_MIN_DURATION_MILLISECONDS}..."
                f"{DIRECT_VOICE_MAX_DURATION_MILLISECONDS}"
            )
        if (
            type(frame_ms) is not int
            or frame_ms <= 0
            or type(packet_count) is not int
            or packet_count <= 0
            or packet_count * SILK_PACKET_MILLISECONDS != frame_ms
            or not _duration_matches_strict(expected_ms, frame_ms)
        ):
            raise VaultError(f"第 {sequence} 条 SILK 帧时长字段不一致")

        relative_path = item.get("relative_path")
        expected_name = f"{sequence:04d}-{server_id}-{local_id}.silk"
        if (
            not isinstance(relative_path, str)
            or not relative_path
            or Path(relative_path).name != relative_path
            or Path(relative_path).suffix.lower() != ".silk"
            or relative_path != expected_name
            or relative_path in seen_relative_paths
        ):
            raise VaultError(f"第 {sequence} 条 relative_path 越界、重复或扩展名无效")
        seen_relative_paths.add(relative_path)
        source = extract / relative_path
        _require_plain_file(source, f"第 {sequence} 条 SILK")
        if source.resolve().parent != extract:
            raise VaultError(f"第 {sequence} 条 SILK 路径逃逸出提取目录")

        expected_hash = item.get("sha256")
        source_hash = item.get("source_voice_data_sha256")
        byte_count = item.get("byte_count")
        if not isinstance(expected_hash, str) or not re.fullmatch(
            r"[0-9a-f]{64}", expected_hash
        ):
            raise VaultError(f"第 {sequence} 条 SHA-256 字段无效")
        if source_hash != expected_hash:
            raise VaultError(f"第 {sequence} 条源 BLOB 与文件 SHA-256 不一致")
        if (
            type(byte_count) is not int
            or byte_count <= 0
            or byte_count > MAX_VOICE_BLOB_BYTES
            or source.stat().st_size != byte_count
        ):
            raise VaultError(f"第 {sequence} 条 SILK 字节数不一致或超限")
        actual_hash = _sha256_file(source)
        if actual_hash != expected_hash:
            raise VaultError(f"第 {sequence} 条 SILK SHA-256 校验失败")
        try:
            source_bytes = source.read_bytes()
        except OSError as error:
            raise VaultError(f"第 {sequence} 条 SILK 无法读取") from error
        inspection = inspect_silk(source_bytes, expected_ms)
        if (
            inspection["packet_count"] != packet_count
            or inspection["frame_duration_ms"] != frame_ms
            or inspection["raw_sha256"] != expected_hash
            or type(item.get("had_tencent_prefix")) is not bool
            or inspection["has_tencent_prefix"] != item["had_tencent_prefix"]
        ):
            raise VaultError(f"第 {sequence} 条 SILK 内容与提取清单不一致")
        validated.append(
            {
                "sequence": sequence,
                "server_id": server_id,
                "expected_duration_ms": expected_ms,
                "frame_duration_ms": frame_ms,
                "source": source,
                "sha256": expected_hash,
                "byte_count": byte_count,
            }
        )
    return (
        extract,
        manifest_path,
        _sha256_bytes(manifest_bytes),
        source_plan_digest,
        chat,
        time_range,
        validated,
    )


def _default_silk_decoder(source: Path, destination: Path, sample_rate: int) -> None:
    try:
        import pilk  # type: ignore[import-not-found]
    except ImportError as error:
        raise VaultError("缺少 pilk；请先运行 scripts/setup_direct_tools.sh") from error
    try:
        pilk.decode(str(source), str(destination), pcm_rate=sample_rate)
    except Exception as error:
        raise VaultError(f"SILK 解码失败：{source.name}") from error


def _convert_pcm_with_swift(
    swift_bin: Path,
    pcm_path: Path,
    output_path: Path,
    sample_rate: int,
    expected_duration_ms: int,
    *,
    fallback_on_known_coreaudio: bool = True,
) -> dict[str, Any]:
    arguments = [
        str(swift_bin),
        "pcm-to-m4a",
        "--input",
        str(pcm_path),
        "--output",
        str(output_path),
        "--sample-rate",
        str(sample_rate),
        "--expected-ms",
        str(expected_duration_ms),
    ]
    try:
        completed = subprocess.run(
            arguments,
            capture_output=True,
            text=True,
            check=False,
            timeout=180,
        )
    except subprocess.TimeoutExpired as error:
        raise VaultError("Swift PCM 转换超时") from error
    except OSError as error:
        raise VaultError(f"无法运行 Swift 工具：{swift_bin}") from error
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "没有错误输出").strip()
        if len(detail) > MAX_TOOL_OUTPUT_CHARACTERS:
            detail = detail[-MAX_TOOL_OUTPUT_CHARACTERS:]
        # macOS can expose the AAC writer but reject its format at runtime
        # (CoreAudio/AVFAudio "fmt?" = 1718449215).  Only this exact local
        # encoder-unavailable condition may use the pinned offline ffmpeg
        # fallback; all other Swift validation failures remain fail-closed.
        if _is_known_coreaudio_format_failure(detail):
            _remove_known_failed_conversion_output(output_path)
            if not fallback_on_known_coreaudio:
                raise _KnownCoreAudioFormatFailure(
                    "CoreAudio/AVFoundation AAC 编码器命中已知格式错误 1718449215"
                )
            return _convert_pcm_with_ffmpeg(
                pcm_path,
                output_path,
                sample_rate,
                expected_duration_ms,
            )
        raise VaultError(f"Swift PCM 转换失败（exit={completed.returncode}）：{detail}")
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise VaultError("Swift PCM 转换没有返回有效 JSON") from error
    if not isinstance(report, dict):
        raise VaultError("Swift PCM 转换报告格式无效")
    return report


def _convert_pcm_with_ffmpeg(
    pcm_path: Path,
    output_path: Path,
    sample_rate: int,
    expected_duration_ms: int,
) -> dict[str, Any]:
    """Encode validated PCM with the pinned local ffmpeg binary."""

    try:
        import imageio_ffmpeg  # type: ignore[import-not-found]
    except ImportError as error:
        raise VaultError(
            "CoreAudio AAC 不可用，且缺少本地 imageio-ffmpeg 兜底"
        ) from error
    try:
        executable = Path(imageio_ffmpeg.get_ffmpeg_exe()).resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise VaultError("无法定位本地 ffmpeg 编码器") from error
    _require_plain_file(executable, "ffmpeg 编码器")
    if not os.access(executable, os.X_OK):
        raise VaultError("本地 ffmpeg 编码器不可执行")
    _require_plain_file(pcm_path, "解码后的 PCM")
    if output_path.exists() or output_path.is_symlink():
        raise VaultError("ffmpeg M4A 输出已存在，拒绝覆盖")
    byte_count = pcm_path.stat().st_size
    if byte_count <= 0 or byte_count % PCM_BYTES_PER_SAMPLE:
        raise VaultError("ffmpeg 输入 PCM 大小无效")
    duration_ms = int(
        round(
            byte_count
            * 1_000
            / (PCM_BYTES_PER_SAMPLE * sample_rate)
        )
    )
    if not _duration_matches_strict(expected_duration_ms, duration_ms):
        raise VaultError("ffmpeg 输入 PCM 时长与消息不一致")
    arguments = [
        str(executable),
        "-nostdin",
        "-hide_banner",
        "-loglevel",
        "error",
        "-f",
        "s16le",
        "-ar",
        str(sample_rate),
        "-ac",
        "1",
        "-i",
        str(pcm_path),
        "-vn",
        "-c:a",
        "aac",
        "-b:a",
        "64000",
        "-ar",
        "48000",
        "-ac",
        "1",
        "-movflags",
        "+faststart",
        "-n",
        str(output_path),
    ]
    try:
        completed = subprocess.run(
            arguments,
            capture_output=True,
            text=True,
            check=False,
            timeout=180,
        )
    except subprocess.TimeoutExpired as error:
        raise VaultError("ffmpeg PCM 转换超时") from error
    except OSError as error:
        raise VaultError("无法运行本地 ffmpeg 编码器") from error
    if completed.returncode != 0 or not output_path.is_file():
        detail = (completed.stderr or completed.stdout or "没有错误输出").strip()
        if len(detail) > MAX_TOOL_OUTPUT_CHARACTERS:
            detail = detail[-MAX_TOOL_OUTPUT_CHARACTERS:]
        raise VaultError(
            f"ffmpeg PCM 转换失败（exit={completed.returncode}）：{detail}"
        )
    os.chmod(output_path, 0o600)
    return {
        "output": str(output_path.resolve()),
        "durationMilliseconds": duration_ms,
        "sha256": _sha256_file(output_path),
        "encoder": "local-imageio-ffmpeg-aac",
    }


def _validate_pcm(path: Path, expected_duration_ms: int, frame_duration_ms: int) -> int:
    _require_plain_file(path, "解码后的 PCM")
    byte_count = path.stat().st_size
    if byte_count <= 0 or byte_count % PCM_BYTES_PER_SAMPLE != 0:
        raise VaultError("解码后的 PCM 必须是非空 16-bit little-endian 单声道数据")
    sample_count = byte_count // PCM_BYTES_PER_SAMPLE
    actual_ms = int(round(sample_count * 1_000 / PCM_SAMPLE_RATE))
    if not _duration_matches_strict(frame_duration_ms, actual_ms):
        raise VaultError(
            f"PCM 时长与 SILK 帧不符：帧={frame_duration_ms}ms，PCM={actual_ms}ms"
        )
    if not _duration_matches_strict(expected_duration_ms, actual_ms):
        raise VaultError(
            f"PCM 时长与消息不符：消息={expected_duration_ms}ms，PCM={actual_ms}ms"
        )
    return actual_ms


def _validate_conversion_report(
    report: dict[str, Any],
    output_path: Path,
    expected_duration_ms: int,
) -> tuple[int, str]:
    _require_plain_file(output_path, "转换后的 M4A")
    if output_path.stat().st_size <= 0:
        raise VaultError("转换后的 M4A 为空")
    reported_output = report.get("output")
    reported_duration = report.get("durationMilliseconds")
    reported_hash = report.get("sha256")
    if (
        not isinstance(reported_output, str)
        or Path(reported_output).expanduser().resolve() != output_path.resolve()
    ):
        raise VaultError("Swift 转换报告的 output 与目标文件不一致")
    if (
        type(reported_duration) is not int
        or not _duration_matches_strict(expected_duration_ms, reported_duration)
    ):
        raise VaultError("Swift 转换报告的音频时长与消息不一致")
    if not isinstance(reported_hash, str) or not re.fullmatch(
        r"[0-9a-f]{64}", reported_hash
    ):
        raise VaultError("Swift 转换报告的 SHA-256 无效")
    actual_hash = _sha256_file(output_path)
    if actual_hash != reported_hash:
        raise VaultError("转换后的 M4A 与 Swift 报告 SHA-256 不一致")
    return reported_duration, actual_hash


def decode(
    extract_dir: Union[str, Path],
    output_dir: Union[str, Path],
    swift_bin: Union[str, Path],
    title: Optional[str] = None,
    *,
    decoder: Optional[SilkDecoder] = None,
    converter: Optional[PCMConverter] = None,
) -> dict[str, Any]:
    """Decode a validated extract atomically into M4A files and a Swift manifest."""

    (
        extract,
        source_manifest,
        source_manifest_hash,
        source_plan_digest,
        chat,
        time_range,
        voices,
    ) = _load_extract_manifest(extract_dir)
    clean_title = (title if title is not None else f"{chat['display_name']} 微信语音").strip()
    if not clean_title or len(clean_title) > 200 or any(
        ord(character) < 32 for character in clean_title
    ):
        raise VaultError("--title 必须是 1...200 个不含控制字符的可见字符")

    raw_swift = Path(swift_bin).expanduser()
    swift = _require_plain_file(raw_swift.resolve(), "Swift 工具")
    if not os.access(swift, os.X_OK):
        raise VaultError(f"Swift 工具不可执行：{swift}")

    raw_output = Path(output_dir).expanduser()
    if raw_output.is_symlink():
        raise VaultError(f"输出目录不能是符号链接：{raw_output}")
    output = raw_output.resolve()
    if output == extract or _is_relative_to(output, extract):
        raise VaultError("M4A 输出目录不能位于 SILK 提取目录内")
    if output.exists():
        raise VaultError(f"输出目录已存在，拒绝覆盖：{output}")
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}-", dir=output.parent))
    os.chmod(staging, 0o700)
    decode_one = decoder or _default_silk_decoder
    conversion_stats: dict[str, Any] = {
        "converter_mode": (
            "custom" if converter is not None else "swift-with-batch-ffmpeg-fallback"
        ),
        "item_count": len(voices),
        "conversion_attempt_count": 0,
        "swift_attempt_count": 0,
        "swift_success_count": 0,
        "swift_known_coreaudio_failure_count": 0,
        "ffmpeg_fallback_count": 0,
        "custom_converter_attempt_count": 0,
        "circuit_breaker_opened": False,
        "circuit_breaker_opened_at_sequence": None,
    }
    swift_fallback_circuit_open = False
    items: list[dict[str, Any]] = []
    try:
        for voice in voices:
            sequence = voice["sequence"]
            source = voice["source"]
            _require_plain_file(source, f"第 {sequence} 条 SILK")
            if (
                source.stat().st_size != voice["byte_count"]
                or _sha256_file(source) != voice["sha256"]
            ):
                raise VaultError(f"第 {sequence} 条 SILK 在解码前发生变化")

            base_name = f"{sequence:04d}-{voice['server_id']}"
            pcm_path = staging / f".{base_name}.pcm"
            m4a_path = staging / f"{base_name}.m4a"
            try:
                with pcm_path.open("xb") as handle:
                    os.fchmod(handle.fileno(), 0o600)
                previous_umask = os.umask(0o077)
                try:
                    decode_one(source, pcm_path, PCM_SAMPLE_RATE)
                finally:
                    os.umask(previous_umask)
                _require_plain_file(pcm_path, "解码后的 PCM")
                os.chmod(pcm_path, 0o600)
                _validate_pcm(
                    pcm_path,
                    voice["expected_duration_ms"],
                    voice["frame_duration_ms"],
                )
                if (
                    source.stat().st_size != voice["byte_count"]
                    or _sha256_file(source) != voice["sha256"]
                ):
                    raise VaultError(f"第 {sequence} 条 SILK 在解码过程中发生变化")

                previous_umask = os.umask(0o077)
                try:
                    conversion_stats["conversion_attempt_count"] += 1
                    if converter is not None:
                        conversion_stats["custom_converter_attempt_count"] += 1
                        report = converter(
                            swift,
                            pcm_path,
                            m4a_path,
                            PCM_SAMPLE_RATE,
                            voice["expected_duration_ms"],
                        )
                    elif swift_fallback_circuit_open:
                        conversion_stats["ffmpeg_fallback_count"] += 1
                        report = _convert_pcm_with_ffmpeg(
                            pcm_path,
                            m4a_path,
                            PCM_SAMPLE_RATE,
                            voice["expected_duration_ms"],
                        )
                    else:
                        conversion_stats["swift_attempt_count"] += 1
                        try:
                            report = _convert_pcm_with_swift(
                                swift,
                                pcm_path,
                                m4a_path,
                                PCM_SAMPLE_RATE,
                                voice["expected_duration_ms"],
                                fallback_on_known_coreaudio=False,
                            )
                        except _KnownCoreAudioFormatFailure:
                            conversion_stats[
                                "swift_known_coreaudio_failure_count"
                            ] += 1
                            conversion_stats["ffmpeg_fallback_count"] += 1
                            conversion_stats["circuit_breaker_opened"] = True
                            conversion_stats[
                                "circuit_breaker_opened_at_sequence"
                            ] = sequence
                            swift_fallback_circuit_open = True
                            report = _convert_pcm_with_ffmpeg(
                                pcm_path,
                                m4a_path,
                                PCM_SAMPLE_RATE,
                                voice["expected_duration_ms"],
                            )
                        else:
                            conversion_stats["swift_success_count"] += 1
                finally:
                    os.umask(previous_umask)
                if not isinstance(report, dict):
                    raise VaultError("PCM 转换器必须返回 JSON 对象格式的报告")
                _require_plain_file(m4a_path, "转换后的 M4A")
                os.chmod(m4a_path, 0o600)
                converted_duration, converted_hash = _validate_conversion_report(
                    report, m4a_path, voice["expected_duration_ms"]
                )
                items.append(
                    {
                        "sequence": sequence,
                        "server_id": voice["server_id"],
                        "source_path": m4a_path.name,
                        "expected_duration_milliseconds": voice[
                            "expected_duration_ms"
                        ],
                        "sha256": converted_hash,
                    }
                )
            finally:
                pcm_path.unlink(missing_ok=True)

        if _sha256_file(source_manifest) != source_manifest_hash:
            raise VaultError("提取清单在解码过程中发生变化")
        direct_manifest = {
            "schema_version": DIRECT_MANIFEST_SCHEMA_VERSION,
            "title": clean_title,
            "expected_count": len(items),
            "items": items,
            "source_plan_digest": source_plan_digest,
            "source_extract_manifest_sha256": source_manifest_hash,
            "chat": chat,
            "time_range": time_range,
            "conversion_stats": conversion_stats,
        }
        _write_json_private(staging / "direct-manifest.json", direct_manifest, vault=None)
        for path in staging.iterdir():
            if path.name != "direct-manifest.json" and path.suffix.lower() != ".m4a":
                raise VaultError(f"临时输出目录出现未预期文件：{path.name}")
            _require_plain_file(path, "最终输出")
            os.chmod(path, 0o600)
        staging.rename(output)
        return {
            "output_dir": str(output),
            "manifest": str(output / "direct-manifest.json"),
            "item_count": len(items),
            "source_manifest_sha256": source_manifest_hash,
            "conversion_stats": conversion_stats,
        }
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="从已解密的 Mac 微信 4.x vault 精确提取语音 BLOB"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor_parser = subparsers.add_parser("doctor", help="只读检查 vault 和 VoiceInfo schema")
    doctor_parser.add_argument("--vault-dir", required=True)

    plan_parser = subparsers.add_parser("plan", help="按聊天名/ID和时间生成冻结语音清单")
    plan_parser.add_argument("--vault-dir", required=True)
    plan_parser.add_argument("--chat", required=True)
    plan_parser.add_argument("--chat-id")
    plan_parser.add_argument("--start", required=True)
    plan_parser.add_argument("--end", required=True)
    plan_parser.add_argument(
        "--expected",
        type=int,
        required=True,
        help="用户事先确认的准确语音条数；不匹配即停止",
    )
    plan_parser.add_argument("--output", required=True)

    extract_parser = subparsers.add_parser("extract", help="按 server_id 精确提取 SILK BLOB")
    extract_parser.add_argument("--vault-dir", required=True)
    extract_parser.add_argument("--plan", required=True)
    extract_parser.add_argument("--output-dir", required=True)

    decode_parser = subparsers.add_parser(
        "decode", help="严格校验 SILK 后解码为 M4A，并生成 Swift 直连清单"
    )
    decode_parser.add_argument("--extract-dir", required=True)
    decode_parser.add_argument("--output-dir", required=True)
    decode_parser.add_argument("--swift-bin", required=True)
    decode_parser.add_argument(
        "--title", help="MP4 标题；默认使用“聊天显示名 微信语音”"
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "doctor":
            report = doctor(args.vault_dir)
            print(_json_dump(report))
            return 0 if report["ready_for_extract"] else 2
        if args.command == "plan":
            vault = _resolve_vault(args.vault_dir)
            plan = build_plan(
                vault,
                args.chat,
                args.start,
                args.end,
                expected=args.expected,
                chat_id=args.chat_id,
            )
            output = _ensure_output_outside_vault(Path(args.output), vault)
            _write_json_private(output, plan, vault)
            print(_json_dump({"plan": str(output), "plan_digest": plan["plan_digest"], "voice_count": plan["voice_count"]}))
            return 0
        if args.command == "extract":
            report = extract(args.vault_dir, args.plan, args.output_dir)
            print(_json_dump(report))
            return 0
        if args.command == "decode":
            report = decode(
                args.extract_dir,
                args.output_dir,
                args.swift_bin,
                args.title,
            )
            print(_json_dump(report))
            return 0
        raise VaultError(f"未知命令：{args.command}")
    except (VaultError, sqlite3.Error, OSError) as error:
        print(f"错误：{error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
