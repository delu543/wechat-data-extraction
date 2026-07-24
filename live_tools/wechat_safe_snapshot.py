#!/usr/bin/env python3
"""Create a bounded encrypted WeChat DB snapshot and decrypt only that snapshot.

This helper is intentionally conservative.  It accepts an explicit ``db_storage``
directory, an explicit private output root, and an explicit private JSON key file.
Only the contact database, requested message/media shards, and the exact
``message_resource`` database are eligible.  It never opens a live database
through SQLite and never decrypts directly from the live tree.

The WeChat 4.x page layout implemented here is the layout used by the reviewed
reference implementation: 4096-byte pages, 80 reserved trailer bytes, a 16-byte
IV at the start of the trailer, and AES-256-CBC over the usable page payload.
The page HMAC in the reserved trailer is NOT verified; successful SQLite
``quick_check`` and expected-table gates are required before plaintext is
published.
"""

from __future__ import annotations

import argparse
import ctypes
from dataclasses import dataclass
from datetime import datetime, timezone
import errno
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys
import time
from typing import Any, Callable, Iterable, Mapping, Optional, Sequence


PAGE_SIZE = 4096
RESERVED_BYTES = 80
IV_SIZE = 16
COPY_CHUNK_BYTES = 1024 * 1024
MAX_KEYS_FILE_BYTES = 1024 * 1024
MANIFEST_SCHEMA_VERSION = 2
SQLITE_HEADER = b"SQLite format 3\x00"
WAL_HEADER_BYTES = 32
WAL_FRAME_HEADER_BYTES = 24
WAL_INDEX_HEADER_BYTES = 48
WAL_SHM_BYTES = 32 * 1024
WAL_SHM_LOCK_OFFSET = 120
WAL_SHM_COORDINATION_LOCK_BYTES = 3
WAL_SHM_HEADER_PREFIX_BYTES = 136
WAL_FORMAT_VERSION = 3_007_000
WAL_MAGIC_LITTLE_CHECKSUM = 0x377F0682
WAL_MAGIC_BIG_CHECKSUM = 0x377F0683
CLONE_NOFOLLOW = 0x0001
CLONE_NOOWNERCOPY = 0x0002
DEFAULT_XWECHAT_ROOT = Path(
    "~/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files"
).expanduser()
DEFAULT_PRIVATE_ROOT = Path(
    "~/Library/Application Support/WeChatVoiceMP4/private"
).expanduser()

KEYS_FILENAME = "wechat-db-keys.json"
CONFIG_FILENAME = "local-vault.json"
ACCOUNT_REF_RE = re.compile(r"account-[0-9a-f]{12}\Z")

CONTACT_REL = "contact/contact.db"
RESOURCE_REL = "message/message_resource.db"
SHARD_REL_RE = re.compile(r"message/(message|media)_([0-9]+)\.db\Z")
ALIAS_RE = re.compile(r"(message|media)_([0-9]+)\Z")


class SnapshotError(RuntimeError):
    """A fail-closed validation or snapshot error."""


class OnlineSnapshotUnavailable(SnapshotError):
    """The live SQLite state cannot be cloned with the required guarantees."""


@dataclass(frozen=True)
class FileFingerprint:
    device: int
    inode: int
    mode: int
    uid: int
    gid: int
    size: int
    mtime_ns: int
    ctime_ns: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> "FileFingerprint":
        return cls(
            device=value.st_dev,
            inode=value.st_ino,
            mode=value.st_mode,
            uid=value.st_uid,
            gid=value.st_gid,
            size=value.st_size,
            mtime_ns=value.st_mtime_ns,
            ctime_ns=value.st_ctime_ns,
        )


@dataclass(frozen=True)
class SidecarState:
    status: str
    fingerprint: Optional[FileFingerprint]


@dataclass(frozen=True)
class Holder:
    pid: int
    command: str
    paths: tuple[str, ...]


@dataclass(frozen=True)
class AccountKeyBinding:
    """Redacted proof that one key set belongs to one resolved account."""

    account_ref: str
    keys_file: Path
    binding_kind: str
    config_schema_version: Optional[int]


@dataclass(frozen=True)
class WalFrame:
    """One checksum-valid encrypted page frame in a copied WAL."""

    frame_number: int
    page_number: int
    database_pages: int
    page_offset: int


@dataclass(frozen=True)
class WalReplayPlan:
    """SQLite recovery boundary derived from the copied WAL itself."""

    status: str
    wal_bytes: int
    physical_frames: int
    valid_frames: int
    last_commit_frame: int
    committed_database_pages: int
    commit_count: int
    ignored_uncommitted_frames: int
    scan_stop: str
    frames: tuple[WalFrame, ...]
    wal_salt: Optional[bytes]
    last_commit_checksum: Optional[tuple[int, int]]


@dataclass(frozen=True)
class OnlineWalAnchor:
    """Stable WalIndexHdr state read while SQLite coordination locks are held."""

    max_frame: int
    database_pages: int
    frame_checksum: tuple[int, int]
    salt: bytes
    n_backfill: int
    n_backfill_attempted: int
    shm_bytes: int


@dataclass
class OnlineWalLease:
    relative: str
    path: Path
    descriptor: int
    fingerprint: FileFingerprint


@dataclass
class OnlineWalLockSet:
    leases: tuple[OnlineWalLease, ...]
    released: bool = False

    def release(self) -> None:
        if self.released:
            return
        self.released = True
        for lease in reversed(self.leases):
            try:
                try:
                    _set_darwin_ofd_lock(lease.descriptor, fcntl.F_UNLCK)
                except (OSError, OnlineSnapshotUnavailable):
                    # Closing the final descriptor releases the OFD lock.
                    pass
            finally:
                try:
                    os.close(lease.descriptor)
                except OSError:
                    pass

    def by_relative(self) -> dict[str, OnlineWalLease]:
        return {lease.relative: lease for lease in self.leases}


CommandRunner = Callable[..., subprocess.CompletedProcess[str]]
HolderProbe = Callable[[Sequence[Path]], Sequence[Holder]]
OnlineCloner = Callable[[Path, Path, FileFingerprint], dict[str, Any]]


class _DarwinFlock(ctypes.Structure):
    _fields_ = [
        ("l_start", ctypes.c_longlong),
        ("l_len", ctypes.c_longlong),
        ("l_pid", ctypes.c_int32),
        ("l_type", ctypes.c_short),
        ("l_whence", ctypes.c_short),
    ]


def _set_darwin_ofd_lock(descriptor: int, lock_type: int) -> None:
    """Use a macOS open-file-description lock that conflicts with SQLite."""

    command = getattr(fcntl, "F_OFD_SETLK", None)
    if sys.platform != "darwin" or command is None or ctypes.sizeof(_DarwinFlock) != 24:
        raise OnlineSnapshotUnavailable("当前 macOS 不支持安全的 OFD 在线协调锁")
    lock = _DarwinFlock(
        l_start=WAL_SHM_LOCK_OFFSET,
        l_len=WAL_SHM_COORDINATION_LOCK_BYTES,
        l_pid=0,
        l_type=lock_type,
        l_whence=os.SEEK_SET,
    )
    fcntl.fcntl(descriptor, command, bytes(lock))


def _is_beneath(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _same_regular_file_identity(
    current: FileFingerprint,
    expected: FileFingerprint,
) -> bool:
    """Compare stable identity fields while allowing live SHM timestamp changes."""

    return (
        stat.S_ISREG(current.mode)
        and current.device == expected.device
        and current.inode == expected.inode
        and current.mode == expected.mode
        and current.uid == expected.uid
        and current.gid == expected.gid
        and current.size == expected.size
    )


def normalize_database_request(value: str) -> str:
    """Return one exact allowlisted relative database path."""

    if not isinstance(value, str) or not value:
        raise SnapshotError("数据库请求不能为空")
    if "\\" in value or value.startswith("/") or ".." in value.split("/"):
        raise SnapshotError(f"数据库请求包含路径逃逸：{value!r}")
    if value in {"contact", CONTACT_REL}:
        return CONTACT_REL
    if value in {"message_resource", RESOURCE_REL}:
        return RESOURCE_REL

    alias = ALIAS_RE.fullmatch(value)
    if alias:
        kind, number = alias.groups()
        if str(int(number)) != number:
            raise SnapshotError(f"分片编号必须使用规范十进制：{value!r}")
        return f"message/{kind}_{number}.db"

    relative = SHARD_REL_RE.fullmatch(value)
    if relative:
        kind, number = relative.groups()
        if str(int(number)) != number:
            raise SnapshotError(f"分片编号必须使用规范十进制：{value!r}")
        return f"message/{kind}_{number}.db"

    raise SnapshotError(
        "数据库不在允许列表；只允许 contact/contact.db、"
        "message/message_N.db、message/media_N.db、"
        "message/message_resource.db"
    )


def normalize_database_requests(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        relative = normalize_database_request(value)
        if relative in seen:
            raise SnapshotError(f"数据库请求重复：{relative}")
        result.append(relative)
        seen.add(relative)
    if not result:
        raise SnapshotError("至少需要一个 --database")
    return result


def _explicit_path(value: str | Path, label: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise SnapshotError(f"{label} 必须是显式绝对路径")
    return path


def _path_entry_exists(path: Path, label: str) -> bool:
    """Distinguish an absent entry from an unsafe or unreadable existing one."""

    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise SnapshotError(f"无法检查 {label}：{exc.strerror or exc}") from exc
    return True


def _lstat(path: Path, label: str) -> os.stat_result:
    try:
        return path.lstat()
    except FileNotFoundError as exc:
        raise SnapshotError(f"{label} 不存在") from exc
    except OSError as exc:
        raise SnapshotError(f"无法检查 {label}：{exc.strerror or exc}") from exc


def _assert_directory(path: Path, label: str) -> os.stat_result:
    info = _lstat(path, label)
    if stat.S_ISLNK(info.st_mode):
        raise SnapshotError(f"{label} 不能是符号链接")
    if not stat.S_ISDIR(info.st_mode):
        raise SnapshotError(f"{label} 不是目录")
    return info


def _assert_regular(path: Path, label: str) -> FileFingerprint:
    info = _lstat(path, label)
    if stat.S_ISLNK(info.st_mode):
        raise SnapshotError(f"{label} 不能是符号链接")
    if not stat.S_ISREG(info.st_mode):
        raise SnapshotError(f"{label} 不是普通文件")
    return FileFingerprint.from_stat(info)


def validate_db_base(
    value: str | Path,
    xwechat_root: str | Path = DEFAULT_XWECHAT_ROOT,
) -> Path:
    requested = _explicit_path(value, "db-base")
    requested_root = _explicit_path(xwechat_root, "xwechat-root")
    _assert_directory(requested_root, "xwechat-root")
    _assert_directory(requested.parent, "微信账号目录")
    _assert_directory(requested, "db-base")
    root = requested_root.resolve(strict=True)
    resolved = requested.resolve(strict=True)
    if resolved.name != "db_storage":
        raise SnapshotError("db-base 必须明确指向名为 db_storage 的目录")
    if resolved.parent.parent != root or not resolved.parent.name:
        raise SnapshotError(
            "db-base 必须严格位于 xwechat_files/<one-account>/db_storage"
        )
    for child in (resolved / "contact", resolved / "message"):
        _assert_directory(child, f"数据库子目录 {child.name}")
    if not os.access(resolved, os.R_OK | os.X_OK):
        raise SnapshotError("db-base 不可读")
    return resolved


def _create_private_path(path: Path) -> None:
    """Create a missing absolute directory chain with mode 0700."""

    missing: list[str] = []
    cursor = path
    while True:
        try:
            info = cursor.lstat()
        except FileNotFoundError:
            missing.append(cursor.name)
            cursor = cursor.parent
            continue
        if stat.S_ISLNK(info.st_mode):
            # System aliases such as /var -> /private/var may be ancestors.  We
            # canonicalize the nearest existing ancestor, but never accept the
            # requested output root itself as a symlink.
            cursor = cursor.resolve(strict=True)
        elif not stat.S_ISDIR(info.st_mode):
            raise SnapshotError("output-root 的已存在祖先不是目录")
        break

    current = cursor.resolve(strict=True)
    for name in reversed(missing):
        current = current / name
        try:
            os.mkdir(current, 0o700)
        except FileExistsError:
            _assert_directory(current, "output-root 路径组件")
        os.chmod(current, 0o700)


def validate_private_output_root(value: str | Path) -> Path:
    requested = _explicit_path(value, "output-root")
    try:
        existing = requested.lstat()
    except FileNotFoundError:
        _create_private_path(requested)
    else:
        if stat.S_ISLNK(existing.st_mode):
            raise SnapshotError("output-root 不能是符号链接")
        if not stat.S_ISDIR(existing.st_mode):
            raise SnapshotError("output-root 不是目录")

    resolved = requested.resolve(strict=True)
    info = _assert_directory(resolved, "output-root")
    if info.st_uid != os.geteuid():
        raise SnapshotError("output-root 必须由当前用户拥有")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise SnapshotError("output-root 必须是私有目录（权限不得超过 0700）")
    if not os.access(resolved, os.R_OK | os.W_OK | os.X_OK):
        raise SnapshotError("output-root 不可读写")
    return resolved


def _assert_disjoint_roots(db_base: Path, output_root: Path) -> None:
    if (
        db_base == output_root
        or _is_beneath(output_root, db_base)
        or _is_beneath(db_base, output_root)
    ):
        raise SnapshotError("output-root 与 db-base 必须完全分离")


def resolve_source(db_base: Path, relative: str) -> tuple[Path, FileFingerprint]:
    normalized = normalize_database_request(relative)
    path = db_base.joinpath(*normalized.split("/"))
    if not _is_beneath(path, db_base):
        raise SnapshotError("数据库路径逃逸出 db-base")
    _assert_directory(path.parent, "数据库父目录")
    fingerprint = _assert_regular(path, f"数据库 {normalized}")
    if fingerprint.size < PAGE_SIZE or fingerprint.size % PAGE_SIZE != 0:
        raise SnapshotError(f"数据库大小不是 {PAGE_SIZE} 字节页的整数倍：{normalized}")
    return path, fingerprint


def inspect_sidecar(path: Path, suffix: str) -> SidecarState:
    """Inspect a sidecar using the original literal nonempty-WAL gate.

    This public helper deliberately retains its historical behavior.  The
    snapshot workflow uses ``inspect_sidecar_metadata`` and validates a copied
    WAL separately, so no WAL contents are interpreted from the live tree.
    """

    state = inspect_sidecar_metadata(path, suffix)
    if suffix == "-wal" and state.fingerprint and state.fingerprint.size > 0:
        raise SnapshotError(
            "检测到非空 WAL；即使它可能已 checkpoint，也不会猜测旧帧可忽略。"
            "请让微信正常退出并由 SQLite 完成 checkpoint 后重试"
        )
    return state


def inspect_sidecar_metadata(path: Path, suffix: str) -> SidecarState:
    """Return sidecar metadata without interpreting its contents."""

    if suffix not in {"-wal", "-shm"}:
        raise SnapshotError("只允许检查 -wal 或 -shm 侧车")
    sidecar = Path(str(path) + suffix)
    try:
        info = sidecar.lstat()
    except FileNotFoundError:
        return SidecarState("absent", None)
    if stat.S_ISLNK(info.st_mode):
        raise SnapshotError(f"{suffix} 侧车文件不能是符号链接")
    if not stat.S_ISREG(info.st_mode):
        raise SnapshotError(f"{suffix} 侧车路径不是普通文件")
    fingerprint = FileFingerprint.from_stat(info)
    return SidecarState("zero" if fingerprint.size == 0 else "present", fingerprint)


def _assert_sidecar_unchanged(
    path: Path, suffix: str, before: SidecarState
) -> SidecarState:
    after = inspect_sidecar(path, suffix)
    if after != before:
        raise SnapshotError(f"复制期间 {suffix} 侧车状态发生变化，拒绝不一致快照")
    return after


def _assert_sidecar_metadata_unchanged(
    path: Path, suffix: str, before: SidecarState
) -> SidecarState:
    after = inspect_sidecar_metadata(path, suffix)
    if after != before:
        raise SnapshotError(f"复制期间 {suffix} 侧车状态发生变化，拒绝不一致快照")
    return after


def parse_lsof_records(output: str) -> list[Holder]:
    holders: list[Holder] = []
    pid: Optional[int] = None
    command = ""
    paths: list[str] = []

    def finish() -> None:
        nonlocal pid, command, paths
        if pid is not None:
            holders.append(Holder(pid, command, tuple(paths)))
        pid = None
        command = ""
        paths = []

    for raw in output.splitlines():
        if not raw:
            continue
        tag, value = raw[0], raw[1:]
        if tag == "p":
            finish()
            if value.isdigit():
                pid = int(value)
        elif tag == "c" and pid is not None:
            command = value
        elif tag == "n" and pid is not None:
            paths.append(value)
    finish()
    return holders


def _looks_like_wechat(command: str) -> bool:
    normalized = command.casefold().replace(" ", "")
    return "wechat" in normalized or "xinwechat" in normalized or "微信" in normalized


def find_wechat_holders(
    targets: Sequence[Path], runner: CommandRunner = subprocess.run
) -> list[Holder]:
    if not targets:
        return []
    command = ["/usr/sbin/lsof", "-nP", "-Fpcn", "--", *map(str, targets)]
    try:
        result = runner(command, capture_output=True, text=True, check=False)
    except (FileNotFoundError, OSError) as exc:
        raise SnapshotError("无法运行 lsof 验证微信是否仍持有数据库") from exc
    # lsof uses exit 1 for no matches.
    if result.returncode not in (0, 1):
        raise SnapshotError("lsof 持有者检查失败，拒绝继续")
    if result.returncode == 1 and (result.stdout.strip() or result.stderr.strip()):
        raise SnapshotError("lsof 返回不完整结果，拒绝继续")
    return [item for item in parse_lsof_records(result.stdout) if _looks_like_wechat(item.command)]


def assert_no_wechat_holders(
    targets: Sequence[Path], probe: HolderProbe = find_wechat_holders
) -> None:
    holders = list(probe(targets))
    if holders:
        summary = ", ".join(f"pid={item.pid} {item.command}" for item in holders)
        raise SnapshotError(f"微信仍持有目标数据库：{summary}")


def _open_readonly_no_follow(path: Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        return os.open(path, flags)
    except OSError as exc:
        raise SnapshotError("无法安全打开源数据库") from exc


def _open_private_exclusive(path: Path) -> int:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        return os.open(path, flags, 0o600)
    except OSError as exc:
        raise SnapshotError("无法创建私有临时文件") from exc


def _private_mkdir(path: Path) -> None:
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = _assert_directory(path, "私有输出目录")
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise SnapshotError("输出子目录不是当前用户的私有目录")


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _publish_temp(temp: Path, destination: Path) -> None:
    if destination.exists() or destination.is_symlink():
        raise SnapshotError("拒绝覆盖已有输出文件")
    try:
        os.link(temp, destination, follow_symlinks=False)
    except FileExistsError as exc:
        raise SnapshotError("输出文件在发布前已出现，拒绝覆盖") from exc
    except OSError as exc:
        raise SnapshotError("无法原子发布输出文件") from exc
    os.unlink(temp)
    _fsync_directory(destination.parent)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    descriptor = _open_readonly_no_follow(path)
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            while True:
                chunk = handle.read(COPY_CHUNK_BYTES)
                if not chunk:
                    break
                digest.update(chunk)
    finally:
        # fdopen normally owns the descriptor; this handles errors before it did.
        try:
            os.close(descriptor)
        except OSError:
            pass
    return digest.hexdigest()


def copy_stable_file_atomic(
    source: Path,
    destination: Path,
    expected: FileFingerprint,
) -> dict[str, Any]:
    """Stream one unchanged regular source into an atomic private snapshot."""

    _private_mkdir(destination.parent)
    temp = destination.with_name(f".{destination.name}.{os.getpid()}.partial")
    source_fd = _open_readonly_no_follow(source)
    temp_fd: Optional[int] = None
    digest = hashlib.sha256()
    copied = 0
    try:
        opened = FileFingerprint.from_stat(os.fstat(source_fd))
        if opened != expected or not stat.S_ISREG(opened.mode):
            raise SnapshotError("源数据库在打开前发生变化")
        temp_fd = _open_private_exclusive(temp)
        while True:
            chunk = os.read(source_fd, COPY_CHUNK_BYTES)
            if not chunk:
                break
            view = memoryview(chunk)
            while view:
                written = os.write(temp_fd, view)
                if written <= 0:
                    raise SnapshotError("快照写入中断")
                view = view[written:]
            copied += len(chunk)
            digest.update(chunk)
        os.fsync(temp_fd)
        os.close(temp_fd)
        temp_fd = None

        after_fd = FileFingerprint.from_stat(os.fstat(source_fd))
        after_path = _assert_regular(source, "源数据库")
        if after_fd != expected or after_path != expected or copied != expected.size:
            raise SnapshotError("源数据库在复制期间发生变化")
        _publish_temp(temp, destination)
        os.chmod(destination, 0o600)
        copied_hash = sha256_file(destination)
        if copied_hash != digest.hexdigest():
            raise SnapshotError("快照发布后的哈希与流式复制哈希不一致")
        return {"bytes": copied, "sha256": copied_hash}
    finally:
        os.close(source_fd)
        if temp_fd is not None:
            os.close(temp_fd)
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def apfs_clone_file_atomic(
    source: Path,
    destination: Path,
    expected: FileFingerprint,
) -> dict[str, Any]:
    """Publish a private APFS copy-on-write clone without streaming source data."""

    if sys.platform != "darwin":
        raise OnlineSnapshotUnavailable("在线快照需要 macOS APFS 文件克隆")
    _private_mkdir(destination.parent)
    temp = destination.with_name(f".{destination.name}.{os.getpid()}.clone")
    if temp.exists() or temp.is_symlink():
        raise SnapshotError("在线快照临时文件已存在")

    source_fd = _open_readonly_no_follow(source)
    parent_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    parent_fd = os.open(destination.parent, parent_flags)
    temp_fd: Optional[int] = None
    try:
        opened = FileFingerprint.from_stat(os.fstat(source_fd))
        if opened != expected or not stat.S_ISREG(opened.mode):
            raise OnlineSnapshotUnavailable("在线快照源文件在加锁前后发生变化")
        libc = ctypes.CDLL(None, use_errno=True)
        try:
            clone = libc.fclonefileat
        except AttributeError as exc:
            raise OnlineSnapshotUnavailable("当前 macOS 不提供 fclonefileat") from exc
        clone.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
        clone.restype = ctypes.c_int
        ctypes.set_errno(0)
        result = clone(
            source_fd,
            parent_fd,
            os.fsencode(temp.name),
            CLONE_NOFOLLOW | CLONE_NOOWNERCOPY,
        )
        if result != 0:
            failure = ctypes.get_errno()
            if failure in {
                errno.EXDEV,
                errno.ENOTSUP,
                getattr(errno, "EOPNOTSUPP", errno.ENOTSUP),
            }:
                raise OnlineSnapshotUnavailable("当前磁盘不支持 APFS 写时复制")
            raise SnapshotError(f"APFS 文件克隆失败（errno={failure}）")
        cloned = _assert_regular(temp, "在线快照临时克隆")
        if cloned.size != expected.size or cloned.uid != os.geteuid():
            raise SnapshotError("APFS 克隆的大小或所有者不符合预期")
        os.chmod(temp, 0o600)
        temp_fd = _open_readonly_no_follow(temp)
        os.fsync(temp_fd)
        os.close(temp_fd)
        temp_fd = None
        if (
            FileFingerprint.from_stat(os.fstat(source_fd)) != expected
            or _assert_regular(source, "在线快照源文件") != expected
        ):
            raise OnlineSnapshotUnavailable("在线快照源文件在克隆期间发生变化")
        _publish_temp(temp, destination)
        os.chmod(destination, 0o600)
        return {
            "bytes": expected.size,
            "clone_method": "apfs_fclonefileat",
        }
    finally:
        if temp_fd is not None:
            os.close(temp_fd)
        os.close(parent_fd)
        os.close(source_fd)
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def acquire_online_wal_locks(
    sources: Mapping[str, tuple[Path, FileFingerprint]],
    *,
    timeout_seconds: float = 2.0,
) -> OnlineWalLockSet:
    """Take shared WRITE/CKPT/RECOVER locks for every target WAL index."""

    if not math.isfinite(timeout_seconds) or timeout_seconds < 0:
        raise SnapshotError("在线锁等待时间不能为负数")
    deadline = time.monotonic() + timeout_seconds
    while True:
        leases: list[OnlineWalLease] = []
        busy = False
        try:
            for relative in sorted(sources):
                shm_path = Path(str(sources[relative][0]) + "-shm")
                try:
                    before = _assert_regular(shm_path, "在线快照 SHM")
                except SnapshotError as exc:
                    raise OnlineSnapshotUnavailable(
                        "在线快照缺少可协调的 SHM；请完全退出微信后重试"
                    ) from exc
                if (
                    before.size < WAL_SHM_BYTES
                    or before.size % WAL_SHM_BYTES
                ):
                    raise OnlineSnapshotUnavailable(
                        "在线快照 SHM 大小不是有效的 32KiB 区域倍数"
                    )
                descriptor = _open_readonly_no_follow(shm_path)
                try:
                    opened = FileFingerprint.from_stat(os.fstat(descriptor))
                    if not _same_regular_file_identity(opened, before):
                        raise OnlineSnapshotUnavailable(
                            "在线快照 SHM 在打开前发生变化"
                        )
                    try:
                        _set_darwin_ofd_lock(descriptor, fcntl.F_RDLCK)
                    except OSError as exc:
                        if exc.errno not in (errno.EACCES, errno.EAGAIN):
                            raise OnlineSnapshotUnavailable(
                                "无法取得 SQLite 在线协调锁"
                            ) from exc
                        busy = True
                        os.close(descriptor)
                        break
                    after = FileFingerprint.from_stat(os.fstat(descriptor))
                    if not _same_regular_file_identity(
                        after, before
                    ) or not _same_regular_file_identity(
                        _assert_regular(shm_path, "在线快照 SHM"),
                        before,
                    ):
                        raise OnlineSnapshotUnavailable(
                            "在线快照 SHM 在加锁期间发生变化"
                        )
                    leases.append(
                        OnlineWalLease(
                            relative=relative,
                            path=shm_path,
                            descriptor=descriptor,
                            fingerprint=before,
                        )
                    )
                except BaseException:
                    if not busy:
                        try:
                            os.close(descriptor)
                        except OSError:
                            pass
                    raise
            if not busy:
                return OnlineWalLockSet(tuple(leases))
        except BaseException:
            OnlineWalLockSet(tuple(leases)).release()
            raise
        finally:
            if busy:
                OnlineWalLockSet(tuple(leases)).release()
        if time.monotonic() >= deadline:
            raise OnlineSnapshotUnavailable(
                "SQLite 正在写入或检查点处理中；在线快照未取得协调锁"
            )
        time.sleep(0.025)


def _read_locked_online_wal_anchor(
    lease: OnlineWalLease,
    database_path: Path,
) -> tuple[OnlineWalAnchor, FileFingerprint]:
    """Read and validate a stable live WalIndexHdr using an already-held fd."""

    current = FileFingerprint.from_stat(os.fstat(lease.descriptor))
    if not _same_regular_file_identity(
        current, lease.fingerprint
    ) or not _same_regular_file_identity(
        _assert_regular(lease.path, "在线快照 SHM"),
        lease.fingerprint,
    ):
        raise OnlineSnapshotUnavailable("在线快照 SHM 锁定后身份发生变化")
    header_prefix = os.pread(
        lease.descriptor,
        WAL_SHM_LOCK_OFFSET,
        0,
    )
    checkpoint_tail = os.pread(
        lease.descriptor,
        WAL_SHM_HEADER_PREFIX_BYTES - 128,
        128,
    )
    if (
        len(header_prefix) != WAL_SHM_LOCK_OFFSET
        or len(checkpoint_tail) != WAL_SHM_HEADER_PREFIX_BYTES - 128
    ):
        raise OnlineSnapshotUnavailable("在线快照 SHM header 读取不完整")
    first = header_prefix[:WAL_INDEX_HEADER_BYTES]
    second = header_prefix[
        WAL_INDEX_HEADER_BYTES : 2 * WAL_INDEX_HEADER_BYTES
    ]
    if first != second:
        raise OnlineSnapshotUnavailable("在线快照 SHM 两份 WalIndexHdr 不一致")
    stored_header_checksum = (
        int.from_bytes(first[40:44], sys.byteorder),
        int.from_bytes(first[44:48], sys.byteorder),
    )
    if _wal_checksum_words(first[:40], sys.byteorder) != stored_header_checksum:
        raise OnlineSnapshotUnavailable("在线快照 SHM header checksum 无效")
    version = int.from_bytes(first[0:4], sys.byteorder)
    initialized = first[12]
    checksum_flag = first[13]
    page_size = int.from_bytes(first[14:16], sys.byteorder)
    max_frame = int.from_bytes(first[16:20], sys.byteorder)
    database_pages = int.from_bytes(first[20:24], sys.byteorder)
    frame_checksum = (
        int.from_bytes(first[24:28], sys.byteorder),
        int.from_bytes(first[28:32], sys.byteorder),
    )
    salt = first[32:40]
    n_backfill = int.from_bytes(header_prefix[96:100], sys.byteorder)
    n_backfill_attempted = int.from_bytes(checkpoint_tail[:4], sys.byteorder)
    if version != WAL_FORMAT_VERSION or initialized != 1:
        raise OnlineSnapshotUnavailable(
            "在线快照 SHM version 或初始化标志无效"
        )
    if page_size not in (0, PAGE_SIZE) or (max_frame and page_size != PAGE_SIZE):
        raise OnlineSnapshotUnavailable("在线快照 SHM page_size 无效")
    if n_backfill > max_frame:
        raise OnlineSnapshotUnavailable("在线快照 SHM nBackfill 超过 mxFrame")
    if n_backfill_attempted > max_frame:
        raise OnlineSnapshotUnavailable(
            "在线快照 SHM nBackfillAttempted 超过 mxFrame"
        )

    wal_path = Path(str(database_path) + "-wal")
    try:
        wal_fingerprint = _assert_regular(wal_path, "在线快照 WAL")
    except SnapshotError as exc:
        raise OnlineSnapshotUnavailable(
            "在线快照缺少 WAL；请完全退出微信后重试"
        ) from exc
    if wal_fingerprint.size == 0:
        if max_frame != 0:
            raise OnlineSnapshotUnavailable(
                "在线快照 SHM 声明有效帧但 WAL 为空"
            )
    else:
        if wal_fingerprint.size < WAL_HEADER_BYTES:
            raise OnlineSnapshotUnavailable("在线快照 WAL header 不完整")
        wal_fd = _open_readonly_no_follow(wal_path)
        try:
            if FileFingerprint.from_stat(os.fstat(wal_fd)) != wal_fingerprint:
                raise OnlineSnapshotUnavailable(
                    "在线快照 WAL 在打开前发生变化"
                )
            wal_header = os.pread(wal_fd, WAL_HEADER_BYTES, 0)
            wal_magic, _ = _validate_wal_header(wal_header)
            if checksum_flag != (wal_magic & 1):
                raise OnlineSnapshotUnavailable(
                    "在线快照 SHM 与 WAL checksum byte-order 不一致"
                )
            if salt != wal_header[16:24]:
                raise OnlineSnapshotUnavailable(
                    "在线快照 SHM 与 WAL salt 不一致"
                )
            complete_frames = max(
                0,
                (wal_fingerprint.size - WAL_HEADER_BYTES)
                // (WAL_FRAME_HEADER_BYTES + PAGE_SIZE),
            )
            if max_frame > complete_frames:
                raise OnlineSnapshotUnavailable(
                    "在线快照 WAL 不包含 SHM 声明的全部提交帧"
                )
            if (
                FileFingerprint.from_stat(os.fstat(wal_fd)) != wal_fingerprint
                or _assert_regular(wal_path, "在线快照 WAL") != wal_fingerprint
            ):
                raise OnlineSnapshotUnavailable(
                    "在线快照 WAL 在读取期间发生变化"
                )
        finally:
            os.close(wal_fd)
    return (
        OnlineWalAnchor(
            max_frame=max_frame,
            database_pages=database_pages,
            frame_checksum=frame_checksum,
            salt=salt,
            n_backfill=n_backfill,
            n_backfill_attempted=n_backfill_attempted,
            shm_bytes=lease.fingerprint.size,
        ),
        wal_fingerprint,
    )


def _validate_replay_plan_against_online_anchor(
    plan: WalReplayPlan,
    anchor: OnlineWalAnchor,
) -> None:
    if plan.last_commit_frame != anchor.max_frame:
        raise OnlineSnapshotUnavailable(
            "克隆 WAL 的最后提交边界与在线 SHM 不一致"
        )
    if anchor.max_frame == 0:
        return
    if plan.valid_frames < anchor.max_frame:
        raise OnlineSnapshotUnavailable("克隆 WAL 缺少在线 SHM 声明的提交帧")
    if plan.wal_salt != anchor.salt:
        raise OnlineSnapshotUnavailable("克隆 WAL salt 与在线 SHM 不一致")
    if plan.last_commit_checksum != anchor.frame_checksum:
        raise OnlineSnapshotUnavailable(
            "克隆 WAL 提交 checksum 与在线 SHM 不一致"
        )
    if plan.committed_database_pages != anchor.database_pages:
        raise OnlineSnapshotUnavailable(
            "克隆 WAL 数据库页数与在线 SHM 不一致"
        )


def _wal_checksum_words(
    data: bytes,
    byteorder: str,
    initial: tuple[int, int] = (0, 0),
) -> tuple[int, int]:
    """Implement SQLite's rolling WAL checksum over complete word pairs."""

    if byteorder not in {"little", "big"} or len(data) % 8:
        raise SnapshotError("WAL checksum 输入格式无效")
    first, second = initial
    for offset in range(0, len(data), 8):
        left = int.from_bytes(data[offset : offset + 4], byteorder)
        right = int.from_bytes(data[offset + 4 : offset + 8], byteorder)
        first = (first + left + second) & 0xFFFFFFFF
        second = (second + right + first) & 0xFFFFFFFF
    return first, second


def _read_stable_prefix(
    path: Path,
    label: str,
    maximum_bytes: int,
) -> tuple[bytes, FileFingerprint]:
    """Read only a bounded validation prefix and prove metadata stability."""

    before = _assert_regular(path, label)
    descriptor = _open_readonly_no_follow(path)
    try:
        if FileFingerprint.from_stat(os.fstat(descriptor)) != before:
            raise SnapshotError(f"{label} 在打开前发生变化")
        chunks: list[bytes] = []
        remaining = min(before.size, maximum_bytes)
        while remaining:
            chunk = os.read(descriptor, min(COPY_CHUNK_BYTES, remaining))
            if not chunk:
                raise SnapshotError(f"{label} 读取提前结束")
            chunks.append(chunk)
            remaining -= len(chunk)
        if (
            FileFingerprint.from_stat(os.fstat(descriptor)) != before
            or _assert_regular(path, label) != before
        ):
            raise SnapshotError(f"{label} 在读取期间发生变化")
        return b"".join(chunks), before
    finally:
        os.close(descriptor)


def _validate_wal_header(header: bytes) -> tuple[int, str]:
    if len(header) != WAL_HEADER_BYTES:
        raise SnapshotError("物理非空 WAL 缺少完整 32 字节 header")
    magic = int.from_bytes(header[0:4], "big")
    if magic == WAL_MAGIC_LITTLE_CHECKSUM:
        checksum_order = "little"
    elif magic == WAL_MAGIC_BIG_CHECKSUM:
        checksum_order = "big"
    else:
        raise SnapshotError("物理非空 WAL 的 SQLite header magic 无效")
    if int.from_bytes(header[4:8], "big") != WAL_FORMAT_VERSION:
        raise SnapshotError("物理非空 WAL 的 SQLite format version 无效")
    declared_page_size = int.from_bytes(header[8:12], "big") or 65_536
    if declared_page_size != PAGE_SIZE:
        raise SnapshotError("物理非空 WAL 的 page_size 与目标数据库不一致")
    stored = (
        int.from_bytes(header[24:28], "big"),
        int.from_bytes(header[28:32], "big"),
    )
    calculated = _wal_checksum_words(header[:24], checksum_order)
    if calculated != stored:
        raise SnapshotError("物理非空 WAL 的 SQLite header checksum 无效")
    return magic, checksum_order


def _validate_empty_wal_index(shm: bytes, wal_header: bytes, wal_magic: int) -> dict[str, Any]:
    """Validate the two SQLite WalIndexHdr copies and require mxFrame == 0."""

    if len(shm) != WAL_SHM_BYTES:
        raise SnapshotError("物理非空 WAL 必须配有精确 32KiB 的 SHM")
    first = shm[:WAL_INDEX_HEADER_BYTES]
    second = shm[WAL_INDEX_HEADER_BYTES : 2 * WAL_INDEX_HEADER_BYTES]
    if first != second:
        raise SnapshotError("SHM 中两份 WalIndexHdr 不一致")

    for header in (first, second):
        stored = (
            int.from_bytes(header[40:44], sys.byteorder),
            int.from_bytes(header[44:48], sys.byteorder),
        )
        calculated = _wal_checksum_words(header[:40], sys.byteorder)
        if calculated != stored:
            raise SnapshotError("SHM WalIndexHdr checksum 无效")

    version = int.from_bytes(first[0:4], sys.byteorder)
    initialized = first[12]
    big_end_checksum = first[13]
    page_size = int.from_bytes(first[14:16], sys.byteorder)
    max_frame = int.from_bytes(first[16:20], sys.byteorder)
    database_pages = int.from_bytes(first[20:24], sys.byteorder)
    if version != WAL_FORMAT_VERSION or initialized != 1:
        raise SnapshotError("SHM WalIndexHdr version 或初始化标志无效")
    if big_end_checksum != (wal_magic & 1):
        raise SnapshotError("SHM checksum byte-order 标志与 WAL 不一致")
    if page_size not in (0, PAGE_SIZE):
        raise SnapshotError("SHM WalIndexHdr page_size 无效")
    if max_frame != 0:
        raise SnapshotError("检测到 SHM mxFrame 非零；存在有效 WAL 帧，拒绝合并或忽略")
    if first[32:40] != wal_header[16:24]:
        raise SnapshotError("SHM WalIndexHdr salt 与 WAL header 不一致")
    return {
        "bytes": len(shm),
        "duplicate_headers": "identical",
        "header_checksums": "valid",
        "salt_match": True,
        "mx_frame": max_frame,
        "page_size": page_size,
        "database_pages": database_pages,
    }


def validate_copied_wal_logically_empty(
    wal_path: Path,
    shm_path: Path,
) -> dict[str, Any]:
    """Accept a physical WAL only when copied WAL+SHM prove it is logical empty.

    Active WAL frames are intentionally unsupported.  A valid WAL header, two
    identical and checksummed WalIndexHdr copies with matching salts, mxFrame
    zero, and a first preallocated frame whose salt is not current collectively
    establish the bounded empty state used by SQLite.  All validation occurs on
    the private snapshot, never on the live source.
    """

    try:
        wal_info = wal_path.lstat()
    except FileNotFoundError:
        return {
            "status": "absent",
            "bytes": 0,
            "wal_header": "not_present",
            "shm_index": "not_required",
            "wal_frames_applied": 0,
        }
    if stat.S_ISLNK(wal_info.st_mode) or not stat.S_ISREG(wal_info.st_mode):
        raise SnapshotError("加密快照 WAL 不是普通文件")
    if wal_info.st_size == 0:
        return {
            "status": "zero_bytes",
            "bytes": 0,
            "wal_header": "not_present",
            "shm_index": "not_required",
            "wal_frames_applied": 0,
        }

    wal_prefix, wal_fingerprint = _read_stable_prefix(
        wal_path,
        "加密快照 WAL",
        WAL_HEADER_BYTES + WAL_FRAME_HEADER_BYTES,
    )
    if wal_fingerprint.size < WAL_HEADER_BYTES:
        raise SnapshotError("物理非空 WAL 太短，无法证明逻辑为空")
    header = wal_prefix[:WAL_HEADER_BYTES]
    magic, _ = _validate_wal_header(header)
    try:
        shm, shm_fingerprint = _read_stable_prefix(
            shm_path,
            "加密快照 SHM",
            WAL_SHM_BYTES,
        )
    except SnapshotError as exc:
        raise SnapshotError("物理非空 WAL 缺少可验证的 SHM") from exc
    if shm_fingerprint.size != WAL_SHM_BYTES:
        raise SnapshotError("物理非空 WAL 必须配有精确 32KiB 的 SHM")
    shm_details = _validate_empty_wal_index(shm, header, magic)

    physical_remainder = wal_fingerprint.size - WAL_HEADER_BYTES
    frame_header = wal_prefix[WAL_HEADER_BYTES:]
    if physical_remainder:
        if physical_remainder < WAL_FRAME_HEADER_BYTES:
            raise SnapshotError("WAL 含不完整的预分配 frame header")
        if frame_header[8:16] == header[16:24]:
            raise SnapshotError("首个 WAL frame 使用当前 salt；无法证明逻辑为空")

    return {
        "status": "logical_empty_preallocated",
        "bytes": wal_fingerprint.size,
        "wal_header": "valid",
        "shm_index": "valid_empty",
        "wal_frames_applied": 0,
        "first_frame_current_salt": False if physical_remainder else None,
        "shm": shm_details,
    }


def scan_copied_wal_for_replay(
    wal_path: Path,
    *,
    database_pages: int,
) -> WalReplayPlan:
    """Recover the last committed SQLite state from one immutable copied WAL.

    The WAL file, not ``-shm``, is the durable recovery oracle.  Frames are
    accepted only in sequence with the current salts and rolling checksum.
    Checksum-valid frames after the last commit are an uncommitted transaction
    and are deliberately ignored.
    """

    if database_pages < 1:
        raise SnapshotError("加密快照数据库页数无效")
    try:
        info = wal_path.lstat()
    except FileNotFoundError:
        return WalReplayPlan(
            status="absent",
            wal_bytes=0,
            physical_frames=0,
            valid_frames=0,
            last_commit_frame=0,
            committed_database_pages=0,
            commit_count=0,
            ignored_uncommitted_frames=0,
            scan_stop="not_present",
            frames=(),
            wal_salt=None,
            last_commit_checksum=None,
        )
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise SnapshotError("加密快照 WAL 不是普通文件")
    fingerprint = FileFingerprint.from_stat(info)
    if fingerprint.size == 0:
        return WalReplayPlan(
            status="zero_bytes",
            wal_bytes=0,
            physical_frames=0,
            valid_frames=0,
            last_commit_frame=0,
            committed_database_pages=0,
            commit_count=0,
            ignored_uncommitted_frames=0,
            scan_stop="not_present",
            frames=(),
            wal_salt=None,
            last_commit_checksum=None,
        )
    if fingerprint.size < WAL_HEADER_BYTES:
        raise SnapshotError("物理非空 WAL 缺少完整 32 字节 header")

    descriptor = _open_readonly_no_follow(wal_path)
    frames: list[WalFrame] = []
    valid_frames = 0
    last_commit_frame = 0
    committed_database_pages = 0
    commit_count = 0
    last_commit_checksum: Optional[tuple[int, int]] = None
    scan_stop = "physical_end"
    wal_salt: Optional[bytes] = None
    try:
        if FileFingerprint.from_stat(os.fstat(descriptor)) != fingerprint:
            raise SnapshotError("加密快照 WAL 在打开前发生变化")
        header = os.read(descriptor, WAL_HEADER_BYTES)
        _, checksum_order = _validate_wal_header(header)
        salts = header[16:24]
        wal_salt = salts
        rolling = (
            int.from_bytes(header[24:28], "big"),
            int.from_bytes(header[28:32], "big"),
        )
        frame_bytes = WAL_FRAME_HEADER_BYTES + PAGE_SIZE
        physical_frames, trailing_bytes = divmod(
            fingerprint.size - WAL_HEADER_BYTES, frame_bytes
        )
        for frame_index in range(physical_frames):
            frame_header = os.read(descriptor, WAL_FRAME_HEADER_BYTES)
            page = os.read(descriptor, PAGE_SIZE)
            if len(frame_header) != WAL_FRAME_HEADER_BYTES or len(page) != PAGE_SIZE:
                raise SnapshotError("WAL frame 读取提前结束")
            if frame_header[8:16] != salts:
                scan_stop = "salt_generation_end"
                break
            page_number = int.from_bytes(frame_header[0:4], "big")
            database_size = int.from_bytes(frame_header[4:8], "big")
            if page_number == 0:
                raise SnapshotError("WAL 当前 salt 世代包含零页号 frame")
            calculated = _wal_checksum_words(
                frame_header[:8] + page,
                checksum_order,
                rolling,
            )
            stored = (
                int.from_bytes(frame_header[16:20], "big"),
                int.from_bytes(frame_header[20:24], "big"),
            )
            if calculated != stored:
                raise SnapshotError("WAL 当前 salt 世代的 frame checksum 无效")
            rolling = calculated
            valid_frames += 1
            frames.append(
                WalFrame(
                    frame_number=frame_index + 1,
                    page_number=page_number,
                    database_pages=database_size,
                    page_offset=(
                        WAL_HEADER_BYTES
                        + frame_index * frame_bytes
                        + WAL_FRAME_HEADER_BYTES
                    ),
                )
            )
            if database_size:
                if database_size > 0x7FFFFFFE:
                    raise SnapshotError("WAL commit 数据库页数超出 SQLite 上限")
                last_commit_frame = valid_frames
                committed_database_pages = database_size
                commit_count += 1
                last_commit_checksum = calculated

        if trailing_bytes and scan_stop == "physical_end":
            scan_stop = "incomplete_physical_tail"
        if (
            FileFingerprint.from_stat(os.fstat(descriptor)) != fingerprint
            or _assert_regular(wal_path, "加密快照 WAL") != fingerprint
        ):
            raise SnapshotError("WAL 扫描期间加密快照发生变化")
    finally:
        os.close(descriptor)

    if last_commit_frame:
        committed = tuple(frames[:last_commit_frame])
        new_pages = {
            frame.page_number
            for frame in committed
            if frame.page_number > database_pages
            and frame.page_number <= committed_database_pages
        }
        if committed_database_pages > database_pages + len(new_pages):
            raise SnapshotError("WAL commit 声明了没有对应 page frame 的数据库扩展")
        status = "committed_frames"
    else:
        committed = ()
        status = (
            "logical_empty_preallocated"
            if valid_frames == 0 and scan_stop == "salt_generation_end"
            else "uncommitted_only"
        )
    return WalReplayPlan(
        status=status,
        wal_bytes=fingerprint.size,
        physical_frames=physical_frames,
        valid_frames=valid_frames,
        last_commit_frame=last_commit_frame,
        committed_database_pages=committed_database_pages,
        commit_count=commit_count,
        ignored_uncommitted_frames=valid_frames - last_commit_frame,
        scan_stop=scan_stop,
        frames=committed,
        wal_salt=wal_salt,
        last_commit_checksum=last_commit_checksum,
    )


def materialize_copied_database_with_wal(
    database_path: Path,
    wal_path: Path,
    destination: Path,
    *,
    online_anchor: Optional[OnlineWalAnchor] = None,
) -> dict[str, Any]:
    """Create one private encrypted DB image at the WAL's last commit."""

    database_fingerprint = _assert_regular(database_path, "复制后的加密数据库")
    if database_fingerprint.size < PAGE_SIZE or database_fingerprint.size % PAGE_SIZE:
        raise SnapshotError("复制后的加密数据库大小不是完整页")
    database_pages = database_fingerprint.size // PAGE_SIZE
    plan = scan_copied_wal_for_replay(
        wal_path,
        database_pages=database_pages,
    )
    if online_anchor is not None:
        _validate_replay_plan_against_online_anchor(plan, online_anchor)

    _private_mkdir(destination.parent)
    work = destination.with_name(
        f".{destination.name}.{os.getpid()}.wal-materialize"
    )
    if work.exists() or work.is_symlink():
        raise SnapshotError("WAL materialize 临时文件已存在")
    copy_stable_file_atomic(database_path, work, database_fingerprint)
    wal_descriptor: Optional[int] = None
    database_descriptor: Optional[int] = None
    try:
        if plan.frames:
            wal_descriptor = _open_readonly_no_follow(wal_path)
            flags = (
                os.O_RDWR
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            database_descriptor = os.open(work, flags)
            database_salt = os.pread(database_descriptor, 16, 0)
            for frame in plan.frames:
                page = os.pread(
                    wal_descriptor,
                    PAGE_SIZE,
                    frame.page_offset,
                )
                if len(page) != PAGE_SIZE:
                    raise SnapshotError("WAL materialize 读取到不完整 page")
                if frame.page_number == 1 and page[:16] != database_salt:
                    raise SnapshotError("WAL page 1 与数据库 salt 不一致")
                if frame.page_number <= plan.committed_database_pages:
                    written = os.pwrite(
                        database_descriptor,
                        page,
                        (frame.page_number - 1) * PAGE_SIZE,
                    )
                    if written != PAGE_SIZE:
                        raise SnapshotError("WAL materialize 写入不完整 page")
            os.ftruncate(
                database_descriptor,
                plan.committed_database_pages * PAGE_SIZE,
            )
            os.fsync(database_descriptor)
        final = _assert_regular(work, "WAL materialize 输出")
        expected_pages = (
            plan.committed_database_pages
            if plan.last_commit_frame
            else database_pages
        )
        if final.size != expected_pages * PAGE_SIZE:
            raise SnapshotError("WAL materialize 输出页数与 commit 不一致")
        materialized_hash = sha256_file(work)
        _publish_temp(work, destination)
        os.chmod(destination, 0o600)
        if sha256_file(destination) != materialized_hash:
            raise SnapshotError("WAL materialize 发布后哈希不一致")
        return {
            "status": plan.status,
            "bytes": final.size,
            "sha256": materialized_hash,
            "physical_frames": plan.physical_frames,
            "valid_frames": plan.valid_frames,
            "last_commit_frame": plan.last_commit_frame,
            "committed_database_pages": plan.committed_database_pages,
            "commit_count": plan.commit_count,
            "wal_frames_applied": len(plan.frames),
            "ignored_uncommitted_frames": plan.ignored_uncommitted_frames,
            "scan_stop": plan.scan_stop,
        }
    finally:
        if wal_descriptor is not None:
            os.close(wal_descriptor)
        if database_descriptor is not None:
            os.close(database_descriptor)
        try:
            work.unlink()
        except FileNotFoundError:
            pass


def _key_alias(relative: str) -> str:
    if relative == CONTACT_REL:
        return "contact"
    return Path(relative).stem


def _canonical_private_file(value: str | Path, label: str) -> Path:
    """Return one existing owner-only regular file using its canonical path."""

    explicit = _explicit_path(value, label)
    fingerprint = _assert_regular(explicit, label)
    if fingerprint.size > MAX_KEYS_FILE_BYTES:
        raise SnapshotError(f"{label} 超出安全大小上限")
    if fingerprint.mode & 0o077:
        raise SnapshotError(f"{label} 权限必须是 0600 或更严格")
    if fingerprint.uid != os.geteuid():
        raise SnapshotError(f"{label} 必须由当前用户拥有")
    try:
        resolved = explicit.resolve(strict=True)
    except OSError as exc:
        raise SnapshotError(f"无法解析 {label}") from exc
    if resolved.name != explicit.name:
        raise SnapshotError(f"{label} 路径不安全")
    return resolved


def _read_private_json(value: str | Path, label: str) -> tuple[Path, Mapping[str, Any]]:
    """Read one small private JSON object while proving metadata stability."""

    path = _canonical_private_file(value, label)
    fingerprint = _assert_regular(path, label)
    descriptor = _open_readonly_no_follow(path)
    try:
        if FileFingerprint.from_stat(os.fstat(descriptor)) != fingerprint:
            raise SnapshotError(f"{label} 在打开前发生变化")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(
                descriptor,
                min(65_536, MAX_KEYS_FILE_BYTES + 1 - total),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_KEYS_FILE_BYTES:
                raise SnapshotError(f"{label} 超出安全大小上限")
        if (
            FileFingerprint.from_stat(os.fstat(descriptor)) != fingerprint
            or _assert_regular(path, label) != fingerprint
        ):
            raise SnapshotError(f"{label} 在读取期间发生变化")
        payload = json.loads(b"".join(chunks).decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SnapshotError(f"{label} 不是有效的私有 JSON") from exc
    finally:
        os.close(descriptor)
    if not isinstance(payload, Mapping):
        raise SnapshotError(f"{label} 顶层必须是对象")
    return path, payload


def _validate_existing_private_root(value: str | Path) -> Path:
    requested = _explicit_path(value, "private-root")
    info = _assert_directory(requested, "private-root")
    if info.st_uid != os.geteuid():
        raise SnapshotError("private-root 必须由当前用户拥有")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise SnapshotError("private-root 必须是私有目录（权限不得超过 0700）")
    try:
        return requested.resolve(strict=True)
    except OSError as exc:
        raise SnapshotError("无法解析 private-root") from exc


def _stable_database_prefix(
    path: Path,
    expected: FileFingerprint,
    length: int,
    label: str,
) -> bytes:
    prefix, observed = _read_stable_prefix(path, label, length)
    if observed != expected or len(prefix) != length:
        raise SnapshotError(f"{label} 在账号绑定期间发生变化")
    return prefix


def _inspect_contact_account_ref(
    db_base: Path,
) -> tuple[str, Path, FileFingerprint]:
    contact_path, fingerprint = resolve_source(db_base, CONTACT_REL)
    salt = _stable_database_prefix(
        contact_path,
        fingerprint,
        16,
        "账号 contact 数据库",
    )
    account_ref = "account-" + hashlib.sha256(
        b"wechat-account-ref-v1\x00" + salt
    ).hexdigest()[:12]
    return account_ref, contact_path, fingerprint


def derive_account_ref_from_db_base(db_base: Path) -> str:
    """Derive the same redacted reference as key-init from the contact salt."""

    return _inspect_contact_account_ref(db_base)[0]


def _requested_salt_fingerprints(
    sources: Mapping[str, tuple[Path, FileFingerprint]],
) -> dict[str, str]:
    result: dict[str, str] = {}
    for relative, (path, fingerprint) in sources.items():
        salt = _stable_database_prefix(
            path,
            fingerprint,
            16,
            f"目标数据库 {_key_alias(relative)}",
        )
        result[_key_alias(relative)] = hashlib.sha256(salt).hexdigest()
    return result


def _validated_config_targets(payload: Mapping[str, Any]) -> Mapping[str, str]:
    raw = payload.get("targets")
    if not isinstance(raw, Mapping) or not raw:
        raise SnapshotError("local-vault.json 缺少精确 targets 绑定")
    result: dict[str, str] = {}
    for alias, relative in raw.items():
        if not isinstance(alias, str) or not isinstance(relative, str):
            raise SnapshotError("local-vault.json targets 格式无效")
        try:
            normalized = normalize_database_request(alias)
        except SnapshotError as exc:
            raise SnapshotError("local-vault.json targets 格式无效") from exc
        if alias != _key_alias(normalized) or relative != normalized:
            raise SnapshotError("local-vault.json targets 不是精确数据库映射")
        result[alias] = relative
    return result


def _validate_config_common(
    payload: Mapping[str, Any],
    *,
    db_base: Path,
    keys_path: Path,
    requested: Sequence[str],
) -> None:
    if payload.get("db_base_path") != str(db_base):
        raise SnapshotError("密钥配置绑定的是另一个微信账号数据库")
    if payload.get("keys_file") != str(keys_path):
        raise SnapshotError("local-vault.json 未精确绑定 sibling keys-file")
    configured = _validated_config_targets(payload)
    for relative in requested:
        alias = _key_alias(relative)
        if configured.get(alias) != relative:
            raise SnapshotError(f"密钥配置未覆盖目标 {alias}")


def resolve_account_key_binding(
    *,
    account_ref: str,
    db_base: Path,
    requested: Sequence[str],
    sources: Mapping[str, tuple[Path, FileFingerprint]],
    keys_file: str | Path | None,
    private_root: str | Path = DEFAULT_PRIVATE_ROOT,
    binding_config: str | Path | None = None,
) -> AccountKeyBinding:
    """Resolve and validate an account-scoped or explicitly configured key set."""

    if not isinstance(account_ref, str) or not ACCOUNT_REF_RE.fullmatch(account_ref):
        raise SnapshotError("account-ref 格式无效")
    state_root = _validate_existing_private_root(private_root)
    default_keys = state_root / "accounts" / account_ref / KEYS_FILENAME
    legacy_keys = state_root / KEYS_FILENAME
    if keys_file is None:
        # New per-account state always wins.  The root-level schema1 file is a
        # read-only compatibility candidate only when the exact scoped entry
        # is absent.  Any existing scoped entry must pass the normal canonical
        # private-file/config/key validation below; never mask a damaged or
        # unsafe scoped entry by silently falling back.
        selected_value: str | Path = (
            default_keys
            if _path_entry_exists(default_keys, "scoped keys-file")
            else legacy_keys
        )
    else:
        selected_value = keys_file
    selected = _canonical_private_file(selected_value, "keys-file")
    is_default = selected == default_keys
    is_legacy_root = selected == legacy_keys
    if not (is_default or is_legacy_root):
        raise SnapshotError(
            "account-ref 模式只接受该账号的 scoped keys-file 或精确 legacy 根文件"
        )

    sibling_config = selected.parent / CONFIG_FILENAME
    if binding_config is not None:
        configured_path = _explicit_path(binding_config, "binding-config")
        try:
            configured_path = configured_path.resolve(strict=True)
        except OSError as exc:
            raise SnapshotError("binding-config 不存在") from exc
        if configured_path != sibling_config:
            raise SnapshotError("binding-config 必须是 keys-file 的 sibling local-vault.json")

    config_present = sibling_config.exists() or sibling_config.is_symlink()
    if not config_present:
        if binding_config is not None:
            raise SnapshotError("binding-config 不存在")
        if not is_default:
            raise SnapshotError("非默认 keys-file 缺少 sibling local-vault.json 账号绑定")
        return AccountKeyBinding(
            account_ref=account_ref,
            keys_file=selected,
            binding_kind="default_account_path",
            config_schema_version=None,
        )

    config_path, payload = _read_private_json(sibling_config, "local-vault.json")
    if config_path != sibling_config:
        raise SnapshotError("local-vault.json sibling 路径不安全")
    schema_version = payload.get("schema_version")
    if isinstance(schema_version, bool) or schema_version not in (1, 2):
        raise SnapshotError("local-vault.json schema_version 不受支持")
    _validate_config_common(
        payload,
        db_base=db_base,
        keys_path=selected,
        requested=requested,
    )

    expected_salts = _requested_salt_fingerprints(sources)
    stored_salts = payload.get("salt_fingerprints")
    if schema_version == 1:
        if not is_legacy_root:
            raise SnapshotError("schema1 legacy 密钥只允许位于 private-root 根目录")
        # The existing root-level initialization predates salt fingerprints.
        # If a later schema1 file contains them, never ignore a mismatch.
        if stored_salts is not None:
            if not isinstance(stored_salts, Mapping):
                raise SnapshotError("schema1 salt_fingerprints 格式无效")
            for alias, expected in expected_salts.items():
                if stored_salts.get(alias) != expected:
                    raise SnapshotError(f"schema1 密钥配置的 {alias} salt 已变化")
        return AccountKeyBinding(
            account_ref=account_ref,
            keys_file=selected,
            binding_kind="legacy_schema1_exact_path",
            config_schema_version=1,
        )

    if payload.get("account_ref") != account_ref:
        raise SnapshotError("schema2 密钥配置绑定的是另一个 account-ref")
    if not isinstance(stored_salts, Mapping):
        raise SnapshotError("schema2 密钥配置缺少 salt_fingerprints")
    for alias, expected in expected_salts.items():
        stored = stored_salts.get(alias)
        if (
            not isinstance(stored, str)
            or not re.fullmatch(r"[0-9a-f]{64}", stored)
            or stored != expected
        ):
            raise SnapshotError(f"schema2 密钥配置的 {alias} salt 不匹配")
    return AccountKeyBinding(
        account_ref=account_ref,
        keys_file=selected,
        binding_kind="schema2_scoped_config",
        config_schema_version=2,
    )


def load_requested_keys(
    keys_file: str | Path, requested: Sequence[str]
) -> dict[str, bytes]:
    explicit = _explicit_path(keys_file, "keys-file")
    fingerprint = _assert_regular(explicit, "keys-file")
    if fingerprint.size > MAX_KEYS_FILE_BYTES:
        raise SnapshotError("keys-file 超出安全大小上限")
    if fingerprint.mode & 0o077:
        raise SnapshotError("keys-file 权限必须是 0600 或更严格")
    if fingerprint.uid != os.geteuid():
        raise SnapshotError("keys-file 必须由当前用户拥有")
    descriptor = _open_readonly_no_follow(explicit)
    try:
        if FileFingerprint.from_stat(os.fstat(descriptor)) != fingerprint:
            raise SnapshotError("keys-file 在打开前发生变化")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65_536, MAX_KEYS_FILE_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_KEYS_FILE_BYTES:
                raise SnapshotError("keys-file 超出安全大小上限")
        if (
            FileFingerprint.from_stat(os.fstat(descriptor)) != fingerprint
            or _assert_regular(explicit, "keys-file") != fingerprint
        ):
            raise SnapshotError("keys-file 在读取期间发生变化")
        payload = json.loads(b"".join(chunks).decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SnapshotError("keys-file 不是有效的私有 JSON") from exc
    finally:
        os.close(descriptor)
    if not isinstance(payload, dict):
        raise SnapshotError("keys-file 顶层必须是对象")

    result: dict[str, bytes] = {}
    for relative in requested:
        alias = _key_alias(relative)
        raw = payload.get(alias, payload.get(relative))
        if not isinstance(raw, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", raw):
            raise SnapshotError(f"keys-file 缺少 {alias} 的 32 字节密钥")
        result[relative] = bytes.fromhex(raw)
    return result


def _validate_first_plain_page(page: bytes) -> None:
    if len(page) != PAGE_SIZE or not page.startswith(SQLITE_HEADER):
        raise SnapshotError("密钥不匹配：首个解密页没有 SQLite 标识")
    page_size = int.from_bytes(page[16:18], "big")
    if page_size != PAGE_SIZE:
        raise SnapshotError("解密页声明了不支持的 SQLite page_size")
    if page[18] not in (1, 2) or page[19] not in (1, 2):
        raise SnapshotError("密钥不匹配：SQLite 读写版本无效")
    if page[20] != RESERVED_BYTES or tuple(page[21:24]) != (64, 32, 32):
        raise SnapshotError("密钥不匹配：SQLite 保留区或负载比例无效")


def _decrypt_page(page: bytes, page_number: int, key: bytes) -> bytes:
    try:
        from Crypto.Cipher import AES
    except ImportError as exc:
        raise SnapshotError("缺少 pycryptodome（Crypto.Cipher.AES）") from exc
    if len(page) != PAGE_SIZE:
        raise SnapshotError("加密数据库包含不完整页")
    encrypted_start = 16 if page_number == 1 else 0
    encrypted_end = PAGE_SIZE - RESERVED_BYTES
    payload = page[encrypted_start:encrypted_end]
    if len(payload) % AES.block_size:
        raise SnapshotError("加密页负载不是 AES 块的整数倍")
    iv = page[encrypted_end : encrypted_end + IV_SIZE]
    plaintext = AES.new(key, AES.MODE_CBC, iv).decrypt(payload)
    output = bytearray(PAGE_SIZE)
    if page_number == 1:
        output[:16] = SQLITE_HEADER
        output[16:encrypted_end] = plaintext
    else:
        output[:encrypted_end] = plaintext
    return bytes(output)


def _preflight_account_keys(
    sources: Mapping[str, tuple[Path, FileFingerprint]],
    keys: Mapping[str, bytes],
) -> None:
    """Reject wrong-account key material before any run directory is created."""

    for relative, (path, fingerprint) in sources.items():
        encrypted_page = _stable_database_prefix(
            path,
            fingerprint,
            PAGE_SIZE,
            f"目标数据库 {_key_alias(relative)} 首个页",
        )
        try:
            plaintext = _decrypt_page(encrypted_page, 1, keys[relative])
            _validate_first_plain_page(plaintext)
        except (KeyError, SnapshotError) as exc:
            raise SnapshotError(
                f"账号绑定失败：{_key_alias(relative)} 密钥与目标数据库不匹配"
            ) from exc


def expected_table_gate(path: Path, relative: str) -> dict[str, Any]:
    uri = path.resolve(strict=True).as_uri() + "?mode=ro&immutable=1"
    try:
        connection = sqlite3.connect(uri, uri=True)
        try:
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            quick = [str(row[0]) for row in connection.execute("PRAGMA quick_check")]
            if quick != ["ok"]:
                detail = "; ".join(quick[:3]) or "no result"
                raise SnapshotError(f"SQLite quick_check 失败：{detail}")

            if relative == CONTACT_REL:
                gate = "contact"
                count = int(
                    connection.execute(
                        "SELECT count(*) FROM sqlite_master "
                        "WHERE type='table' AND lower(name)=lower('contact')"
                    ).fetchone()[0]
                )
            elif relative == RESOURCE_REL:
                gate = "MessageResourceInfo"
                count = int(
                    connection.execute(
                        "SELECT count(*) FROM sqlite_master "
                        "WHERE type='table' AND "
                        "lower(name)=lower('MessageResourceInfo')"
                    ).fetchone()[0]
                )
            elif Path(relative).name.startswith("message_"):
                gate = "Msg_*"
                count = int(
                    connection.execute(
                        "SELECT count(*) FROM sqlite_master "
                        "WHERE type='table' AND substr(lower(name),1,4)='msg_'"
                    ).fetchone()[0]
                )
            else:
                gate = "VoiceInfo"
                count = int(
                    connection.execute(
                        "SELECT count(*) FROM sqlite_master "
                        "WHERE type='table' AND lower(name)=lower('VoiceInfo')"
                    ).fetchone()[0]
                )
            if count < 1:
                raise SnapshotError(f"{relative} 缺少预期表门禁 {gate}")
            return {"quick_check": "ok", "expected_table": gate, "match_count": count}
        finally:
            connection.close()
    except sqlite3.Error as exc:
        raise SnapshotError(f"SQLite 验证失败：{relative}") from exc


def decrypt_snapshot_database(
    snapshot_root: Path,
    relative: str,
    output_root: Path,
    key: bytes,
) -> dict[str, Any]:
    """Decrypt one file that is already inside the immutable run snapshot."""

    if len(key) != 32:
        raise SnapshotError("数据库密钥必须正好是 32 字节")
    relative = normalize_database_request(relative)
    snapshot = snapshot_root.joinpath(*relative.split("/"))
    if not _is_beneath(snapshot, snapshot_root):
        raise SnapshotError("快照路径逃逸")
    before = _assert_regular(snapshot, "加密快照")
    if before.size < PAGE_SIZE or before.size % PAGE_SIZE:
        raise SnapshotError("加密快照大小不是完整页")

    destination = output_root.joinpath(*relative.split("/"))
    _private_mkdir(destination.parent)
    temp = destination.with_name(f".{destination.name}.{os.getpid()}.partial")
    source_fd = _open_readonly_no_follow(snapshot)
    temp_fd: Optional[int] = None
    digest = hashlib.sha256()
    written = 0
    try:
        if FileFingerprint.from_stat(os.fstat(source_fd)) != before:
            raise SnapshotError("加密快照在打开前发生变化")
        temp_fd = _open_private_exclusive(temp)
        page_number = 0
        while True:
            page = os.read(source_fd, PAGE_SIZE)
            if not page:
                break
            page_number += 1
            plain = _decrypt_page(page, page_number, key)
            if page_number == 1:
                _validate_first_plain_page(plain)
            view = memoryview(plain)
            while view:
                count = os.write(temp_fd, view)
                if count <= 0:
                    raise SnapshotError("解密输出写入中断")
                view = view[count:]
            digest.update(plain)
            written += len(plain)
        os.fsync(temp_fd)
        os.close(temp_fd)
        temp_fd = None

        after_fd = FileFingerprint.from_stat(os.fstat(source_fd))
        after_path = _assert_regular(snapshot, "加密快照")
        if after_fd != before or after_path != before or written != before.size:
            raise SnapshotError("解密期间加密快照发生变化")
        gate = expected_table_gate(temp, relative)
        _publish_temp(temp, destination)
        os.chmod(destination, 0o600)
        published_hash = sha256_file(destination)
        if published_hash != digest.hexdigest():
            raise SnapshotError("解密文件发布后的哈希不一致")
        return {
            "bytes": written,
            "sha256": published_hash,
            "relative_path": f"decrypted/{relative}",
            **gate,
        }
    finally:
        os.close(source_fd)
        if temp_fd is not None:
            os.close(temp_fd)
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def _write_json_atomic(path: Path, value: Mapping[str, Any]) -> None:
    _private_mkdir(path.parent)
    temp = path.with_name(f".{path.name}.{os.getpid()}.partial")
    descriptor: Optional[int] = None
    try:
        descriptor = _open_private_exclusive(temp)
        payload = (
            json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        view = memoryview(payload)
        while view:
            count = os.write(descriptor, view)
            if count <= 0:
                raise SnapshotError("manifest 写入中断")
            view = view[count:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        _publish_temp(temp, path)
        os.chmod(path, 0o600)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def _new_run_directory(output_root: Path) -> tuple[Path, str]:
    created = datetime.now(timezone.utc)
    stamp = created.strftime("%Y%m%dT%H%M%S.%fZ")
    run = output_root / f"run-{stamp}"
    try:
        os.mkdir(run, 0o700)
    except FileExistsError as exc:
        raise SnapshotError("时间戳运行目录已存在；拒绝复用或清理旧运行") from exc
    _fsync_directory(output_root)
    return run, created.isoformat(timespec="microseconds").replace("+00:00", "Z")


def snapshot_and_decrypt(
    *,
    db_base: str | Path,
    output_root: str | Path,
    keys_file: str | Path | None,
    databases: Sequence[str],
    xwechat_root: str | Path = DEFAULT_XWECHAT_ROOT,
    holder_probe: HolderProbe = find_wechat_holders,
    account_ref: Optional[str] = None,
    private_root: str | Path = DEFAULT_PRIVATE_ROOT,
    binding_config: str | Path | None = None,
    online: bool = False,
    online_cloner: OnlineCloner = apfs_clone_file_atomic,
    online_lock_timeout_seconds: float = 2.0,
) -> dict[str, Any]:
    """Create a new run directory, snapshot exact DBs, then decrypt snapshots.

    Passing ``account_ref`` selects the strict ordinary workflow: the resolved
    contact salt, key location/configuration, requested target salts, and key
    material are all verified before a run directory is created.  Omitting it
    retains the explicit developer API, including an arbitrary private key file
    and the historical ``output_root/run-*`` layout.
    """

    base = validate_db_base(db_base, xwechat_root=xwechat_root)
    requested = normalize_database_requests(databases)
    sources: dict[str, tuple[Path, FileFingerprint]] = {
        relative: resolve_source(base, relative) for relative in requested
    }

    account_binding: Optional[AccountKeyBinding] = None
    contact_binding: Optional[tuple[Path, FileFingerprint]] = None
    if account_ref is not None:
        if not isinstance(account_ref, str) or not ACCOUNT_REF_RE.fullmatch(account_ref):
            raise SnapshotError("account-ref 格式无效")
        derived_ref, contact_path, contact_fingerprint = _inspect_contact_account_ref(base)
        if derived_ref != account_ref:
            raise SnapshotError("account-ref 与 db-base 的 contact salt 不匹配")
        contact_binding = (contact_path, contact_fingerprint)
        account_binding = resolve_account_key_binding(
            account_ref=account_ref,
            db_base=base,
            requested=requested,
            sources=sources,
            keys_file=keys_file,
            private_root=private_root,
            binding_config=binding_config,
        )
        keys = load_requested_keys(account_binding.keys_file, requested)
        _preflight_account_keys(sources, keys)
    else:
        if binding_config is not None:
            raise SnapshotError("binding-config 只允许与 account-ref 一起使用")
        if keys_file is None:
            raise SnapshotError("开发调试模式必须显式提供 keys-file")
        keys = load_requested_keys(keys_file, requested)

    snapshot_root = validate_private_output_root(output_root)
    _assert_disjoint_roots(base, snapshot_root)
    if contact_binding is not None:
        if account_binding is None:
            raise SnapshotError("账号绑定状态不完整")
        account_output_root = snapshot_root / account_binding.account_ref
        _private_mkdir(account_output_root)
        run_parent = account_output_root
    else:
        run_parent = snapshot_root

    wal_before: dict[str, SidecarState] = {}
    shm_before: dict[str, SidecarState] = {}
    online_anchors: dict[str, OnlineWalAnchor] = {}
    online_locks: Optional[OnlineWalLockSet] = None
    encrypted_records: dict[str, dict[str, Any]] = {}
    if online:
        online_locks = acquire_online_wal_locks(
            sources,
            timeout_seconds=online_lock_timeout_seconds,
        )
    try:
        if online:
            leases = online_locks.by_relative() if online_locks else {}
            refreshed: dict[str, tuple[Path, FileFingerprint]] = {}
            for relative in requested:
                path, fingerprint = resolve_source(base, relative)
                if path != sources[relative][0]:
                    raise OnlineSnapshotUnavailable(
                        "在线快照数据库路径在加锁前后发生变化"
                    )
                refreshed[relative] = (path, fingerprint)
                anchor, wal_fingerprint = _read_locked_online_wal_anchor(
                    leases[relative],
                    path,
                )
                online_anchors[relative] = anchor
                wal_before[relative] = SidecarState(
                    status="zero" if wal_fingerprint.size == 0 else "nonempty",
                    fingerprint=wal_fingerprint,
                )
                shm_before[relative] = SidecarState(
                    status="nonempty",
                    fingerprint=leases[relative].fingerprint,
                )
            sources = refreshed
            if account_ref is not None:
                refreshed_ref, _, _ = _inspect_contact_account_ref(base)
                if refreshed_ref != account_ref:
                    raise OnlineSnapshotUnavailable(
                        "在线快照账号绑定在加锁后发生变化"
                    )
        else:
            wal_before = {
                relative: inspect_sidecar_metadata(sources[relative][0], "-wal")
                for relative in requested
            }
            shm_before = {
                relative: inspect_sidecar_metadata(sources[relative][0], "-shm")
                for relative in requested
            }
            source_paths = [sources[relative][0] for relative in requested]
            for relative in requested:
                source = sources[relative][0]
                for suffix, states in (("-wal", wal_before), ("-shm", shm_before)):
                    if states[relative].fingerprint is not None:
                        source_paths.append(Path(str(source) + suffix))
            assert_no_wechat_holders(source_paths, holder_probe)
            if contact_binding is not None:
                contact_path, contact_fingerprint = contact_binding
                if _assert_regular(
                    contact_path, "账号 contact 数据库"
                ) != contact_fingerprint:
                    raise SnapshotError("账号 contact 数据库在创建快照前发生变化")

        run, created_at = _new_run_directory(run_parent)
        encrypted_root = run / "encrypted"
        materialized_root = run / "materialized"
        decrypted_root = run / "decrypted"
        _private_mkdir(encrypted_root)
        _private_mkdir(materialized_root)
        _private_mkdir(decrypted_root)

        for relative in requested:
            source, fingerprint = sources[relative]
            destination = encrypted_root.joinpath(*relative.split("/"))
            if online:
                copied = online_cloner(source, destination, fingerprint)
            else:
                copied = copy_stable_file_atomic(source, destination, fingerprint)
            sidecars: dict[str, dict[str, Any]] = {}
            for suffix, state in (
                ("-wal", wal_before[relative]),
                ("-shm", shm_before[relative]),
            ):
                if state.fingerprint is None:
                    sidecars[suffix[1:]] = {"status": "absent"}
                    continue
                if online and suffix == "-shm":
                    sidecars["shm"] = {
                        "status": "locked_live_index_not_copied",
                        "bytes": state.fingerprint.size,
                    }
                    continue
                sidecar_source = Path(str(source) + suffix)
                sidecar_destination = Path(str(destination) + suffix)
                if online:
                    sidecar_copy = online_cloner(
                        sidecar_source,
                        sidecar_destination,
                        state.fingerprint,
                    )
                else:
                    sidecar_copy = copy_stable_file_atomic(
                        sidecar_source,
                        sidecar_destination,
                        state.fingerprint,
                    )
                sidecars[suffix[1:]] = {
                    "status": state.status,
                    **sidecar_copy,
                    "relative_path": f"encrypted/{relative}{suffix}",
                }
            encrypted_records[relative] = {
                **copied,
                "relative_path": f"encrypted/{relative}",
                "sidecars": sidecars,
            }

        if online:
            leases = online_locks.by_relative() if online_locks else {}
            for relative in requested:
                source, fingerprint = sources[relative]
                if _assert_regular(source, "在线快照源数据库") != fingerprint:
                    raise OnlineSnapshotUnavailable(
                        "在线快照数据库在克隆期间发生变化"
                    )
                state = wal_before[relative]
                if state.fingerprint is None or _assert_regular(
                    Path(str(source) + "-wal"), "在线快照 WAL"
                ) != state.fingerprint:
                    raise OnlineSnapshotUnavailable(
                        "在线快照 WAL 在克隆期间发生变化"
                    )
                final_anchor, final_wal_fingerprint = (
                    _read_locked_online_wal_anchor(leases[relative], source)
                )
                if (
                    final_anchor != online_anchors[relative]
                    or final_wal_fingerprint != state.fingerprint
                ):
                    raise OnlineSnapshotUnavailable(
                        "在线快照协调状态在克隆期间发生变化"
                    )
        else:
            # A cross-file stability pass prevents a quiet writer from changing
            # an earlier database while a later database was being copied.
            for relative in requested:
                source, fingerprint = sources[relative]
                if _assert_regular(source, "源数据库") != fingerprint:
                    raise SnapshotError("多数据库复制窗口内源文件发生变化")
                _assert_sidecar_metadata_unchanged(
                    source, "-wal", wal_before[relative]
                )
                _assert_sidecar_metadata_unchanged(
                    source, "-shm", shm_before[relative]
                )
            assert_no_wechat_holders(source_paths, holder_probe)
    finally:
        if online_locks is not None:
            online_locks.release()

    if online:
        for relative in requested:
            encrypted_database = encrypted_root.joinpath(*relative.split("/"))
            encrypted_record = encrypted_records[relative]
            encrypted_record["bytes"] = _assert_regular(
                encrypted_database, "在线加密快照"
            ).size
            encrypted_record["sha256"] = sha256_file(encrypted_database)
            encrypted_wal = Path(str(encrypted_database) + "-wal")
            wal_record = encrypted_record["sidecars"]["wal"]
            wal_record["bytes"] = _assert_regular(
                encrypted_wal, "在线加密 WAL 快照"
            ).size
            wal_record["sha256"] = sha256_file(encrypted_wal)

    wal_validation: dict[str, dict[str, Any]] = {}
    for relative in requested:
        encrypted_database = encrypted_root.joinpath(*relative.split("/"))
        materialized_database = materialized_root.joinpath(*relative.split("/"))
        wal_validation[relative] = materialize_copied_database_with_wal(
            encrypted_database,
            Path(str(encrypted_database) + "-wal"),
            materialized_database,
            online_anchor=online_anchors.get(relative),
        )

    records: list[dict[str, Any]] = []
    for relative in requested:
        decrypted = decrypt_snapshot_database(
            materialized_root, relative, decrypted_root, keys[relative]
        )
        records.append(
            {
                "database": relative,
                "encrypted": encrypted_records[relative],
                "materialized": {
                    "bytes": wal_validation[relative]["bytes"],
                    "sha256": wal_validation[relative]["sha256"],
                    "relative_path": f"materialized/{relative}",
                },
                "decrypted": decrypted,
                "wal_gate": wal_validation[relative]["status"],
                "wal_validation": wal_validation[relative],
                "shm_state": (
                    "locked_live_index_not_copied"
                    if online
                    else shm_before[relative].status
                ),
                **(
                    {
                        "online_wal_anchor": {
                            "validated": True,
                            "mx_frame": online_anchors[relative].max_frame,
                            "database_pages": online_anchors[
                                relative
                            ].database_pages,
                            "n_backfill": online_anchors[relative].n_backfill,
                            "n_backfill_attempted": online_anchors[
                                relative
                            ].n_backfill_attempted,
                        }
                    }
                    if online
                    else {}
                ),
            }
        )

    manifest: dict[str, Any] = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "created_at": created_at,
        "status": "complete",
        "database_count": len(records),
        "records": records,
        "safety": {
            "source_paths_recorded": False,
            "secrets_recorded": False,
            "snapshot_mode": (
                "online_sqlite_shm_coordinated_apfs_clone"
                if online
                else "offline_stable_stream_copy"
            ),
            "wechat_holder_check": (
                "not_required_online_sqlite_coordination_locks"
                if online
                else "passed_before_and_after_snapshot"
            ),
            "wal_policy": (
                "checksum_and_salt_validated_replay_through_last_commit"
            ),
            "wal_active_frame_policy": (
                "apply_only_checksum_valid_frames_through_last_commit; "
                "ignore_checksum_valid_uncommitted_tail"
            ),
            "wal_validation_source": (
                "cloned_encrypted_wal_plus_locked_live_shm_anchor"
                if online
                else "encrypted_snapshot_sidecars_only"
            ),
            "source_stat_stability": (
                "shared_write_checkpoint_recovery_locks_held_during_clone"
                if online
                else "passed_before_and_after_stream_copy"
            ),
            "decryption_source": "wal_materialized_encrypted_snapshot_only",
            "sqlite_quick_check": "required_ok",
            "expected_table_gate": "required",
            "page_hmac_verified": False,
            "page_hmac_limitation": (
                "reserved trailer HMAC is not verified; AES-CBC plus SQLite "
                "quick_check and expected-table gates are the current integrity checks"
            ),
        },
    }
    if account_binding is not None:
        manifest["account_binding"] = {
            "mode": "strict_account_ref",
            "account_ref": account_binding.account_ref,
            "contact_salt_reference": "matched",
            "key_binding": account_binding.binding_kind,
            "config_schema_version": account_binding.config_schema_version,
            "requested_key_first_page_validation": "passed_before_run_creation",
            "output_scope": "account_ref",
        }
    manifest_path = run / "manifest.json"
    _write_json_atomic(manifest_path, manifest)
    manifest["run_directory"] = str(run)
    manifest["manifest_path"] = str(manifest_path)
    return manifest


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "默认在微信完全退出后创建稳定快照；--online 使用 SQLite "
            "协调锁和 APFS 克隆创建在线账号隔离快照，随后仅从快照解密。"
        )
    )
    account = parser.add_mutually_exclusive_group(required=True)
    account.add_argument(
        "--account-ref",
        help="setup-doctor 返回的脱敏账号编号",
    )
    account.add_argument(
        "--db-base",
        help="仅供显式开发调试；不是普通账号模式",
    )
    parser.add_argument(
        "--output-root",
        required=True,
        help="固定私有 snapshots 根目录；普通模式会再按 account-ref 隔离",
    )
    parser.add_argument(
        "--keys-file",
        help=(
            "私有 JSON 密钥文件；account-ref 模式默认使用 "
            "private/accounts/<account-ref>/wechat-db-keys.json，"
            "开发调试模式必须显式提供"
        ),
    )
    parser.add_argument(
        "--private-root",
        default=str(DEFAULT_PRIVATE_ROOT),
        help="key-init 私有状态根目录（默认使用应用私有目录）",
    )
    parser.add_argument(
        "--binding-config",
        help="可选；必须是 keys-file 的 sibling local-vault.json",
    )
    parser.add_argument(
        "--database",
        action="append",
        required=True,
        help=(
            "重复指定 contact、message_N、media_N、message_resource "
            "或其精确相对路径"
        ),
    )
    parser.add_argument(
        "--online",
        action="store_true",
        help=(
            "微信保持打开时，使用 SQLite SHM 协调锁、APFS 写时复制与 "
            "WAL 提交锚点校验；不可用时安全停止"
        ),
    )
    return parser


def _resolve_cli_db_base(
    args: argparse.Namespace,
    *,
    xwechat_root: str | Path = DEFAULT_XWECHAT_ROOT,
) -> str | Path:
    if args.account_ref:
        try:
            try:
                from live_tools import wechat_key_init
            except ImportError:
                import wechat_key_init  # type: ignore
        except ImportError as exc:
            raise SnapshotError("无法加载脱敏账号解析器") from exc
        try:
            resolved = wechat_key_init.resolve_account_ref(
                args.account_ref,
                Path(xwechat_root),
            )
        except wechat_key_init.SafeInitError as exc:
            raise SnapshotError("脱敏账号编号无效；请重新运行 setup-doctor") from exc
        base = validate_db_base(resolved, xwechat_root=xwechat_root)
        if derive_account_ref_from_db_base(base) != args.account_ref:
            raise SnapshotError("脱敏账号编号与 db-base 的 contact salt 不匹配")
        return base
    if args.db_base:
        return args.db_base
    raise SnapshotError("必须选择 setup-doctor 返回的脱敏账号编号")


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _argument_parser().parse_args(argv)
    try:
        report = snapshot_and_decrypt(
            db_base=_resolve_cli_db_base(args),
            output_root=args.output_root,
            keys_file=args.keys_file,
            databases=args.database,
            account_ref=args.account_ref,
            private_root=args.private_root,
            binding_config=args.binding_config,
            online=args.online,
        )
    except SnapshotError as exc:
        print(f"安全停止：{exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "status": report["status"],
                "database_count": report["database_count"],
                "run_directory": report["run_directory"],
                "manifest_path": report["manifest_path"],
                "snapshot_mode": report["safety"]["snapshot_mode"],
                "page_hmac_verified": False,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
