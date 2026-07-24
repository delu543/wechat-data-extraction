"""Build and validate a frozen, type-scoped content export plan."""

from __future__ import annotations

from datetime import datetime
import hashlib
from pathlib import Path
import re
import sqlite3
from typing import Any, Iterable, Optional, Union
import unicodedata

from direct_vault.direct_voice_vault import (
    VaultError,
    _canonical_json,
    _choose_column,
    _columns,
    _connect_read_only,
    _decode_message_content,
    _find_database,
    _find_table,
    _message_databases,
    _media_databases,
    _normalize_text,
    _parse_time,
    _plan_digest,
    _quote_identifier,
    _resolve_chat,
    _resolve_vault,
    _sha256_bytes,
    _sha256_file,
    _validated_chat_and_time_range,
)

from content_vault.message_parser import parse_message


CONTENT_PLAN_SCHEMA_VERSION = 1
MAX_PACKED_INFO_BYTES = 8 * 1024 * 1024
SUPPORTED_CONTENT_KINDS = frozenset(
    {
        "text",
        "image",
        "voice",
        "contact_card",
        "video",
        "sticker",
        "location",
        "file",
        "link",
        "mini_program",
        "quote",
        "forwarded_record",
        "app_message",
        "call",
        "system",
        "unknown",
    }
)


def _chat_candidate_key(value: str, *, drop_decorative_symbols: bool) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    result: list[str] = []
    for character in normalized:
        if character.isspace():
            continue
        if drop_decorative_symbols and (
            unicodedata.category(character) in {"So", "Sk"}
            or character in {"\ufe0f", "\u200d"}
        ):
            continue
        result.append(character)
    return "".join(result)


def find_chat_candidates(
    vault_dir: Union[str, Path], query: str, *, limit: int = 8
) -> list[dict[str, str]]:
    """Return bounded read-only chat candidates without selecting one.

    Exact raw matches are labelled ``exact``. Unicode/whitespace normalization,
    decorative-symbol folding, and substring matching only produce candidates;
    callers must require an explicit chat ID before using a non-exact result.
    """

    requested = query.strip()
    if not requested:
        raise VaultError("--chat 不能为空")
    if limit < 1 or limit > 20:
        raise VaultError("聊天候选上限必须在 1 到 20 之间")
    query_key = _chat_candidate_key(requested, drop_decorative_symbols=False)
    query_plain = _chat_candidate_key(requested, drop_decorative_symbols=True)
    contact_path = _find_database(
        _resolve_vault(vault_dir), "contact/contact.db", "contact.db"
    )
    ranked: dict[str, tuple[int, dict[str, str]]] = {}
    with _connect_read_only(contact_path, contact_path.parent.parent) as connection:
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
        for row in connection.execute(sql):
            internal_id = _normalize_text(row[username]).strip()
            if not internal_id:
                continue
            names = [
                _normalize_text(row[column]).strip()
                for column in display_columns
                if _normalize_text(row[column]).strip()
            ]
            display = names[0] if names else internal_id
            score: Optional[int] = None
            match = ""
            for name in [internal_id, *names]:
                name_key = _chat_candidate_key(name, drop_decorative_symbols=False)
                name_plain = _chat_candidate_key(name, drop_decorative_symbols=True)
                if requested == name:
                    candidate_score, candidate_match = 0, "exact"
                elif query_key and query_key == name_key:
                    candidate_score, candidate_match = 1, "normalized"
                elif query_plain and query_plain == name_plain:
                    candidate_score, candidate_match = 2, "decorative-folded"
                elif (
                    len(query_key) >= 2
                    and name != internal_id
                    and (query_key in name_key or name_key in query_key)
                ):
                    candidate_score, candidate_match = 3, "contains"
                else:
                    continue
                if score is None or candidate_score < score:
                    score, match = candidate_score, candidate_match
            if score is None:
                continue
            candidate = {
                "chat_id": internal_id,
                "display_name": display,
                "kind": "group" if internal_id.endswith("@chatroom") else "direct",
                "match": match,
            }
            previous = ranked.get(internal_id)
            if previous is None or score < previous[0]:
                ranked[internal_id] = (score, candidate)
    ordered = sorted(
        ranked.values(),
        key=lambda item: (item[0], item[1]["display_name"].casefold(), item[1]["chat_id"]),
    )
    return [candidate for _, candidate in ordered[:limit]]


def _optional_column(columns: dict[str, str], *names: str) -> Optional[str]:
    return _choose_column(columns, names, required=False)


def _message_columns(connection: sqlite3.Connection, table: str) -> dict[str, Optional[str]]:
    columns = _columns(connection, table)
    return {
        "local_id": _choose_column(columns, ("local_id", "id")),
        "server_id": _choose_column(columns, ("server_id", "svr_id")),
        "local_type": _choose_column(columns, ("local_type", "type")),
        "create_time": _choose_column(columns, ("create_time", "timestamp")),
        "message_content": _optional_column(columns, "message_content", "content"),
        "compress_content": _optional_column(columns, "compress_content"),
        "compression_flag": _optional_column(columns, "WCDB_CT_message_content"),
        "packed_info_data": _optional_column(columns, "packed_info_data", "packed_info"),
        "real_sender_id": _optional_column(columns, "real_sender_id", "sender_id"),
        "sort_seq": _optional_column(columns, "sort_seq"),
        "server_seq": _optional_column(columns, "server_seq"),
    }


def _row_content(row: sqlite3.Row) -> str:
    for key in ("message_content", "compress_content"):
        value = row[key]
        if value not in (None, "", b""):
            return _decode_message_content(value, row["compression_flag"])
    return ""


def _row_packed_info(row: sqlite3.Row) -> bytes:
    value = row["packed_info_data"]
    if value is None:
        return b""
    if isinstance(value, str):
        data = value.encode("utf-8", errors="replace")
    else:
        data = bytes(value)
    if len(data) > MAX_PACKED_INFO_BYTES:
        raise VaultError("packed_info_data 超出安全大小上限")
    return data


def _resource_md5_candidates(packed: bytes) -> list[str]:
    if not packed:
        return []
    from content_vault.image_crypto import extract_packed_info_md5_candidates

    return list(extract_packed_info_md5_candidates(packed))


def _as_int(value: Any, label: str) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError) as error:
        raise VaultError(f"消息 {label} 不是整数") from error


def _database_fingerprint(path: Path, vault: Path, role: str) -> dict[str, Any]:
    relative = str(path.relative_to(vault))
    return {
        "role": role,
        "relative_path": relative,
        "byte_count": path.stat().st_size,
        "sha256": _sha256_file(path),
    }


def _row_digest(item: dict[str, Any]) -> str:
    stable = {
        "create_time": item["create_time"],
        "raw_local_type": item["raw_local_type"],
        "raw_sha256": item["parse"]["raw_sha256"],
        "packed_info_sha256": item["packed_info_sha256"],
    }
    return _sha256_bytes(_canonical_json(stable))


def _deduplicate_server_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge only exact nonzero-server duplicates; never content/time dedupe."""

    result: list[dict[str, Any]] = []
    by_server: dict[str, tuple[str, dict[str, Any]]] = {}
    for item in rows:
        server_id = item["source_ref"]["server_id"]
        if server_id in {"", "0"}:
            result.append(item)
            continue
        digest = _row_digest(item)
        previous = by_server.get(server_id)
        if previous is None:
            item["source_refs"] = [dict(item["source_ref"])]
            by_server[server_id] = (digest, item)
            result.append(item)
            continue
        previous_digest, previous_item = previous
        if previous_digest != digest:
            raise VaultError(f"server_id={server_id} 跨分片内容冲突")
        previous_item["source_refs"].append(dict(item["source_ref"]))
    return result


def build_content_plan(
    vault_dir: Union[str, Path],
    chat_name: str,
    start: str,
    end: str,
    *,
    expected: Optional[int] = None,
    chat_id: Optional[str] = None,
    kinds: Optional[Iterable[str]] = None,
) -> dict[str, Any]:
    vault = _resolve_vault(vault_dir)
    start_unix = _parse_time(start)
    end_unix = _parse_time(end)
    if start_unix > end_unix:
        raise VaultError("开始时间必须不晚于结束时间")
    if expected is not None and expected < 0:
        raise VaultError("--expected 不能小于 0")
    selected_kinds: Optional[frozenset[str]] = None
    if kinds is not None:
        if isinstance(kinds, (str, bytes)):
            raise VaultError("消息类型筛选格式无效")
        kind_values = list(kinds)
        if not kind_values:
            raise VaultError("消息类型筛选不能为空")
        if any(not isinstance(kind, str) or not kind for kind in kind_values):
            raise VaultError("消息类型筛选格式无效")
        selected_kinds = frozenset(kind_values)
        unsupported = selected_kinds - SUPPORTED_CONTENT_KINDS
        if unsupported:
            raise VaultError("不支持的消息类型：" + ", ".join(sorted(unsupported)))
    internal_id, display_name, chat_kind = _resolve_chat(vault, chat_name, chat_id)
    table_name = "Msg_" + hashlib.md5(internal_id.encode("utf-8")).hexdigest()

    rows: list[dict[str, Any]] = []
    matched_databases: list[Path] = []
    message_databases = _message_databases(vault)
    for database in message_databases:
        with _connect_read_only(database, vault) as connection:
            table = _find_table(connection, table_name)
            if not table:
                continue
            matched_databases.append(database)
            columns = _message_columns(connection, table)
            aliases: list[str] = []
            for alias, column in columns.items():
                if column:
                    aliases.append(
                        f"{_quote_identifier(column)} AS {_quote_identifier(alias)}"
                    )
                else:
                    aliases.append(f"NULL AS {_quote_identifier(alias)}")
            create_time_column = _quote_identifier(str(columns["create_time"]))
            order_columns = [
                create_time_column,
                _quote_identifier(str(columns["sort_seq"] or columns["local_id"])),
                _quote_identifier(str(columns["server_seq"] or columns["server_id"])),
                _quote_identifier(str(columns["local_id"])),
                _quote_identifier(str(columns["server_id"])),
            ]
            sql = (
                f"SELECT {', '.join(aliases)} FROM {_quote_identifier(table)} "
                f"WHERE {create_time_column} >= ? AND {create_time_column} <= ? "
                f"ORDER BY {', '.join(order_columns)}"
            )
            for row in connection.execute(sql, (start_unix, end_unix)):
                raw_type = _as_int(row["local_type"], "local_type")
                create_time = _as_int(row["create_time"], "create_time")
                content = _row_content(row)
                packed = _row_packed_info(row)
                real_sender = _normalize_text(row["real_sender_id"]).strip()
                parsed = parse_message(
                    raw_type,
                    content,
                    is_group=chat_kind == "group",
                    real_sender_id=real_sender,
                )
                if not isinstance(parsed, dict):
                    raise VaultError("消息 parser 返回值不是对象")
                local_id = _normalize_text(row["local_id"]).strip()
                server_id = _normalize_text(row["server_id"]).strip()
                source_ref = {
                    "source_db": str(database.relative_to(vault)),
                    "source_table": table,
                    "local_id": local_id,
                    "server_id": server_id,
                    "sort_seq": _normalize_text(row["sort_seq"]).strip(),
                    "server_seq": _normalize_text(row["server_seq"]).strip(),
                }
                raw_hash = _sha256_bytes(content.encode("utf-8"))
                parse_meta = dict(parsed.get("parse") or {})
                parse_meta.setdefault("raw_sha256", raw_hash)
                parse_meta.setdefault("raw_byte_count", len(content.encode("utf-8")))
                payload = dict(parsed.get("payload") or {})
                candidates = _resource_md5_candidates(packed)
                if (raw_type & 0xFFFFFFFF) == 3:
                    message_md5 = payload.get("md5")
                    if isinstance(message_md5, str) and re.fullmatch(
                        r"[0-9A-Fa-f]{32}", message_md5
                    ):
                        candidates.append(message_md5.lower())
                    payload["resource_md5_candidates"] = list(
                        dict.fromkeys(candidates)
                    )
                stable_id = {
                    "source_db": source_ref["source_db"],
                    "source_table": table,
                    "local_id": local_id,
                    "server_id": server_id,
                    "create_time": create_time,
                    "raw_local_type": str(raw_type),
                    "raw_sha256": raw_hash,
                }
                rows.append(
                    {
                        "message_id": "wxmsg:v1:sha256:"
                        + _sha256_bytes(_canonical_json(stable_id)),
                        "source_ref": source_ref,
                        "create_time": create_time,
                        "time_iso8601": datetime.fromtimestamp(create_time).astimezone().isoformat(),
                        "raw_local_type": str(raw_type),
                        "base_type": raw_type & 0xFFFFFFFF,
                        "type_flags_hi32": raw_type >> 32,
                        "sender_id": parsed.get("sender_id") or real_sender,
                        "kind": str(parsed.get("kind") or "unknown"),
                        "payload": payload,
                        "parse": parse_meta,
                        "packed_info_sha256": _sha256_bytes(packed) if packed else None,
                    }
                )
    if not matched_databases:
        raise VaultError("所有 message_*.db 都没有目标聊天表")

    def sort_key(item: dict[str, Any]) -> tuple[Any, ...]:
        source = item["source_ref"]
        return (
            item["create_time"],
            _as_int(source["sort_seq"], "sort_seq"),
            _as_int(source["server_seq"], "server_seq"),
            _as_int(source["local_id"], "local_id"),
            _as_int(source["server_id"], "server_id"),
            source["source_db"],
        )

    rows.sort(key=sort_key)
    rows = _deduplicate_server_rows(rows)
    inventory_count = len(rows)
    if selected_kinds is not None:
        rows = [row for row in rows if row["kind"] in selected_kinds]
    for sequence, row in enumerate(rows, 1):
        row["sequence"] = sequence
    if expected is not None and len(rows) != expected:
        raise VaultError(f"时间范围内找到 {len(rows)} 条消息，预期 {expected} 条")

    counts: dict[str, int] = {}
    for row in rows:
        counts[row["kind"]] = counts.get(row["kind"], 0) + 1
    contact = _find_database(vault, "contact/contact.db", "contact.db")
    source_databases = [_database_fingerprint(contact, vault, "contact")]
    source_databases.extend(
        _database_fingerprint(path, vault, "message") for path in matched_databases
    )
    if any(row["kind"] == "voice" for row in rows):
        media_databases = _media_databases(vault)
        if not media_databases:
            raise VaultError("计划含语音，但快照没有 media_*.db")
        source_databases.extend(
            _database_fingerprint(path, vault, "voice-media")
            for path in media_databases
        )
    plan: dict[str, Any] = {
        "schema_version": CONTENT_PLAN_SCHEMA_VERSION,
        "mode": "decrypted-vault-read-only",
        "network_policy": "offline",
        "video_policy": "exclude_body",
        "selection": {
            "types": ["all"] if selected_kinds is None else sorted(selected_kinds),
            "all_messages_in_range": selected_kinds is None,
            "unselected_message_count": inventory_count - len(rows),
        },
        "chat": {
            "requested_name": chat_name.strip(),
            "display_name": display_name,
            "chat_id": internal_id,
            "kind": chat_kind,
        },
        "time_range": {
            "start_input": start,
            "end_input": end,
            "start_unix": start_unix,
            "end_unix": end_unix,
            "end_inclusive": True,
        },
        "message_table": table_name,
        "expected_count": expected,
        "message_count": len(rows),
        "counts_by_kind": dict(sorted(counts.items())),
        "source_databases": source_databases,
        "messages": rows,
    }
    plan["plan_digest"] = _plan_digest(plan)
    return plan


def load_content_plan(path: Union[str, Path]) -> dict[str, Any]:
    import json

    plan_path = Path(path).expanduser().resolve()
    try:
        with plan_path.open(encoding="utf-8") as handle:
            plan = json.load(handle)
    except (OSError, json.JSONDecodeError) as error:
        raise VaultError(f"无法读取内容计划：{plan_path}") from error
    if not isinstance(plan, dict):
        raise VaultError("内容计划根节点必须是 JSON 对象")
    if plan.get("schema_version") != CONTENT_PLAN_SCHEMA_VERSION:
        raise VaultError("内容计划 schema 版本不受支持")
    if plan.get("mode") != "decrypted-vault-read-only":
        raise VaultError("内容计划来源模式不受支持")
    if plan.get("plan_digest") != _plan_digest(plan):
        raise VaultError("内容计划摘要不匹配，文件已被修改")
    messages = plan.get("messages")
    if not isinstance(messages, list) or len(messages) != plan.get("message_count"):
        raise VaultError("内容计划消息清单损坏")
    if [item.get("sequence") for item in messages if isinstance(item, dict)] != list(
        range(1, len(messages) + 1)
    ):
        raise VaultError("内容计划消息顺序损坏")
    _validated_chat_and_time_range(plan, "内容计划")
    if plan.get("network_policy") != "offline" or plan.get("video_policy") != "exclude_body":
        raise VaultError("内容计划安全策略不受支持")
    return plan


def verify_plan_sources(vault_dir: Union[str, Path], plan: dict[str, Any]) -> Path:
    vault = _resolve_vault(vault_dir)
    databases = plan.get("source_databases")
    if not isinstance(databases, list) or not databases:
        raise VaultError("内容计划缺少源数据库指纹")
    for item in databases:
        if not isinstance(item, dict):
            raise VaultError("源数据库指纹格式损坏")
        relative = item.get("relative_path")
        if not isinstance(relative, str) or relative.startswith("/") or ".." in relative.split("/"):
            raise VaultError("源数据库相对路径无效")
        path = vault / relative
        if path.is_symlink() or not path.is_file():
            raise VaultError(f"计划源数据库不存在：{relative}")
        if path.stat().st_size != item.get("byte_count") or _sha256_file(path) != item.get("sha256"):
            raise VaultError(f"计划源数据库已变化：{relative}")
    return vault
