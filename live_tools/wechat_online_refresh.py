"""High-level online refresh for an already initialized local WeChat account.

This module is the non-secret bridge between current-account routing and the
bounded snapshot helper.  It never accepts or returns a database key.  A caller
supplies the chat identity and requested content kinds; only the required
initialized shards are refreshed, validated, and then published through the
account's credential-free local profile.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
import sqlite3
import stat
from typing import Any, Callable, Mapping, Sequence

from content_vault.cli import doctor
from content_vault.profile import write_account_profile
from direct_vault.direct_voice_vault import _resolve_vault
from live_tools.wechat_key_init import resolve_account_ref
from live_tools.wechat_safe_snapshot import snapshot_and_decrypt


DEFAULT_SNAPSHOT_ROOT = (
    Path.home()
    / "Library"
    / "Application Support"
    / "WeChatLocalExport"
    / "snapshots"
)
MESSAGE_NAME = re.compile(r"message_([0-9]+)\.db\Z")
MEDIA_NAME = re.compile(r"media_([0-9]+)\.db\Z")
MEDIA_BODY_KINDS = frozenset({"image", "file", "sticker", "video"})


class OnlineRefreshError(RuntimeError):
    """A safe, non-secret online refresh failure."""


def _regular_files(directory: Path, pattern: re.Pattern[str]) -> list[Path]:
    if directory.is_symlink() or not directory.is_dir():
        raise OnlineRefreshError("已验证快照缺少 message 目录")
    result: list[tuple[int, Path]] = []
    for path in directory.iterdir():
        match = pattern.fullmatch(path.name)
        if match is None:
            continue
        try:
            info = path.lstat()
        except OSError as exc:
            raise OnlineRefreshError("无法检查快照数据库分片") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise OnlineRefreshError("快照数据库分片不是普通文件")
        result.append((int(match.group(1)), path))
    return [path for _, path in sorted(result)]


def _message_shards_for_chat(vault: Path, chat_id: str) -> list[Path]:
    if not isinstance(chat_id, str) or not chat_id.strip():
        raise OnlineRefreshError("在线刷新需要已解析的精确聊天标识")
    table = "Msg_" + hashlib.md5(chat_id.encode("utf-8")).hexdigest()
    matched: list[Path] = []
    for path in _regular_files(vault / "message", MESSAGE_NAME):
        uri = f"file:{path.as_posix()}?mode=ro&immutable=1"
        try:
            with sqlite3.connect(uri, uri=True) as connection:
                row = connection.execute(
                    "SELECT 1 FROM sqlite_master "
                    "WHERE type='table' AND name=? LIMIT 1",
                    (table,),
                ).fetchone()
        except sqlite3.Error as exc:
            raise OnlineRefreshError("无法只读检查目标聊天分片") from exc
        if row is not None:
            matched.append(path)
    if not matched:
        raise OnlineRefreshError("已验证快照中没有目标聊天表")
    return matched


def snapshot_database_requests(
    vault_dir: str | Path,
    *,
    kinds: Sequence[str],
    chat_id: str,
) -> list[str]:
    """Return the minimal previously initialized database set for one request."""

    if not kinds or any(not isinstance(kind, str) or not kind for kind in kinds):
        raise OnlineRefreshError("在线刷新必须明确指定消息类型")
    normalized = set(kinds)
    if "all" in normalized and normalized != {"all"}:
        raise OnlineRefreshError("all 不能与具体消息类型混用")
    vault = _resolve_vault(vault_dir)
    contact = vault / "contact" / "contact.db"
    if contact.is_symlink() or not contact.is_file():
        raise OnlineRefreshError("已验证快照缺少 contact 数据库")
    requested = ["contact"]
    requested.extend(
        f"message_{int(MESSAGE_NAME.fullmatch(path.name).group(1))}"
        for path in _message_shards_for_chat(vault, chat_id)
    )

    needs_voice = "all" in normalized or "voice" in normalized
    if needs_voice:
        media = _regular_files(vault / "message", MEDIA_NAME)
        if not media:
            raise OnlineRefreshError("语音在线刷新缺少已初始化的 media 分片")
        requested.extend(
            f"media_{int(MEDIA_NAME.fullmatch(path.name).group(1))}"
            for path in media
        )

    needs_resource = "all" in normalized or bool(normalized & MEDIA_BODY_KINDS)
    resource = vault / "message" / "message_resource.db"
    if needs_resource and resource.is_file() and not resource.is_symlink():
        requested.append("message_resource")
    return requested


def refresh_online_snapshot(
    binding: Any,
    profile: Mapping[str, Any],
    *,
    kinds: Sequence[str],
    chat_id: str,
    output_root: str | Path = DEFAULT_SNAPSHOT_ROOT,
    resolver: Callable[[str], Path] = resolve_account_ref,
    snapshotter: Callable[..., dict[str, Any]] = snapshot_and_decrypt,
    doctor_fn: Callable[..., dict[str, Any]] = doctor,
    profile_writer: Callable[[str, Mapping[str, Any]], Any] = write_account_profile,
) -> dict[str, Any]:
    """Refresh, validate, and atomically point the current account at a new vault."""

    account_ref = getattr(binding, "account_ref", None)
    if (
        not isinstance(account_ref, str)
        or profile.get("schema_version") != 2
        or profile.get("account_ref") != account_ref
    ):
        raise OnlineRefreshError("当前账号与本机 profile 不匹配")
    vault_dir = profile.get("vault_dir")
    account_root = profile.get("account_root")
    swift_bin = profile.get("swift_bin")
    if not isinstance(vault_dir, str) or not isinstance(account_root, str):
        raise OnlineRefreshError("当前账号 profile 路径不完整")

    databases = snapshot_database_requests(
        vault_dir,
        kinds=kinds,
        chat_id=chat_id,
    )
    db_base = resolver(account_ref)
    report = snapshotter(
        db_base=db_base,
        output_root=output_root,
        keys_file=None,
        databases=databases,
        account_ref=account_ref,
        online=True,
    )
    if (
        not isinstance(report, Mapping)
        or report.get("status") != "complete"
        or report.get("database_count") != len(databases)
        or report.get("safety", {}).get("snapshot_mode")
        != "online_sqlite_shm_coordinated_apfs_clone"
    ):
        raise OnlineRefreshError("在线快照没有返回完整的协调克隆结果")
    run_directory = report.get("run_directory")
    if not isinstance(run_directory, str):
        raise OnlineRefreshError("在线快照缺少运行目录")
    new_vault = Path(run_directory) / "decrypted"
    readiness = doctor_fn(
        str(new_vault),
        account_root=account_root,
        swift_bin=swift_bin,
    )
    if not readiness.get("ready_for_scan"):
        raise OnlineRefreshError("在线快照未通过扫描 doctor")
    if ("all" in kinds or "voice" in kinds) and not readiness.get(
        "ready_for_voice_mp4"
    ):
        raise OnlineRefreshError("在线快照未通过语音 MP4 doctor")

    new_profile = {
        "schema_version": 2,
        "account_ref": account_ref,
        "vault_dir": str(new_vault.resolve(strict=True)),
        "account_root": account_root,
        "swift_bin": swift_bin,
    }
    profile_writer(account_ref, new_profile)
    return {
        "status": "online-refresh-complete",
        "database_count": len(databases),
        "requested_types": list(kinds),
        "profile_updated": True,
        "ready_for_scan": True,
        "ready_for_voice_mp4": bool(readiness.get("ready_for_voice_mp4")),
        "page_hmac_verified": False,
    }
