"""Deterministic, offline resolvers for ordinary files and sticker caches."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import os
from pathlib import Path
import stat
from typing import Any, Iterable, Optional
import unicodedata

from direct_vault.direct_voice_vault import VaultError, _is_relative_to


MAX_ATTACHMENT_BYTES = 4 * 1024 * 1024 * 1024
MD5_HEX = frozenset("0123456789abcdef")


@dataclass(frozen=True)
class AssetResolution:
    status: str
    source: Optional[Path] = None
    metadata: dict[str, Any] = field(default_factory=dict)


def _digest_file(path: Path, algorithm: str = "sha256") -> str:
    digest = hashlib.new(algorithm)
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise VaultError("附件候选不是普通文件")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise VaultError("附件候选在打开时发生变化")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    finally:
        os.close(descriptor)
    after = path.lstat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise VaultError("附件候选在哈希过程中发生变化")
    return digest.hexdigest()


def _validated_root(value: Path, label: str) -> Path:
    if value.is_symlink():
        raise VaultError(f"{label} 不能是符号链接")
    root = value.resolve()
    if not root.is_dir():
        raise VaultError(f"{label} 不存在或不是目录：{root}")
    return root


def _plain_candidate(path: Path, root: Path) -> Optional[Path]:
    try:
        info = path.lstat()
    except (FileNotFoundError, OSError):
        return None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        return None
    if info.st_size < 0 or info.st_size > MAX_ATTACHMENT_BYTES:
        return None
    resolved = path.resolve()
    if not _is_relative_to(resolved, root):
        return None
    return resolved


def safe_basename(value: str) -> str:
    if not isinstance(value, str):
        raise VaultError("附件文件名必须是文本")
    name = value.strip()
    if (
        not name
        or name in {".", ".."}
        or "\x00" in name
        or "/" in name
        or "\\" in name
        or Path(name).name != name
        or any(ord(character) < 32 for character in name)
    ):
        raise VaultError("附件文件名包含路径或控制字符")
    return name


def _month_names(timestamp: int) -> list[str]:
    current = datetime.fromtimestamp(timestamp)
    month_index = current.year * 12 + current.month - 1
    values: list[str] = []
    for offset in (0, -1, 1):
        index = month_index + offset
        year, zero_month = divmod(index, 12)
        values.append(f"{year:04d}-{zero_month + 1:02d}")
    return values


def _normalized_name_matches(directory: Path, expected: str) -> Iterable[Path]:
    if directory.is_symlink() or not directory.is_dir():
        return ()
    normalized = unicodedata.normalize("NFC", expected)
    try:
        return tuple(
            entry
            for entry in directory.iterdir()
            if unicodedata.normalize("NFC", entry.name) == normalized
        )
    except OSError:
        return ()


def resolve_regular_file(
    account_root: Path,
    create_time: int,
    filename: str,
    *,
    expected_size: Optional[int] = None,
    expected_md5: Optional[str] = None,
) -> AssetResolution:
    """Resolve a type-49 file without accepting a name-only match as content."""

    account = _validated_root(account_root, "微信账号目录")
    file_root_value = account / "msg" / "file"
    if not file_root_value.exists():
        return AssetResolution("missing", metadata={"reason": "file_root_missing"})
    file_root = _validated_root(file_root_value, "微信文件目录")
    name = safe_basename(filename)
    if expected_size is not None and (type(expected_size) is not int or expected_size < 0):
        raise VaultError("附件 expected_size 无效")
    clean_md5: Optional[str] = None
    if expected_md5:
        clean_md5 = expected_md5.strip().lower()
        if len(clean_md5) != 32 or any(char not in MD5_HEX for char in clean_md5):
            raise VaultError("附件 expected_md5 无效")

    candidates: dict[Path, Path] = {}
    for month in _month_names(create_time):
        for value in _normalized_name_matches(file_root / month, name):
            resolved = _plain_candidate(value, file_root)
            if resolved:
                candidates[resolved] = resolved
    if not candidates:
        return AssetResolution("missing", metadata={"filename": name})

    inspected: list[tuple[Path, int, str, str]] = []
    for candidate in sorted(candidates):
        size = candidate.stat().st_size
        if expected_size is not None and size != expected_size:
            continue
        md5_value = _digest_file(candidate, "md5")
        sha256_value = _digest_file(candidate, "sha256")
        if clean_md5 is not None and md5_value != clean_md5:
            continue
        inspected.append((candidate, size, md5_value, sha256_value))

    if not inspected:
        return AssetResolution(
            "corrupt",
            metadata={"filename": name, "candidate_count": len(candidates)},
        )
    if clean_md5 is None:
        return AssetResolution(
            "metadata_only",
            metadata={
                "filename": name,
                "candidate_count": len(inspected),
                "reason": "content_hash_unavailable",
            },
        )
    by_sha: dict[str, list[tuple[Path, int, str, str]]] = {}
    for item in inspected:
        by_sha.setdefault(item[3], []).append(item)
    if len(by_sha) != 1:
        return AssetResolution(
            "ambiguous",
            metadata={"filename": name, "candidate_count": len(inspected)},
        )
    chosen = sorted(inspected, key=lambda item: str(item[0]))[0]
    return AssetResolution(
        "resolved",
        source=chosen[0],
        metadata={
            "filename": name,
            "byte_count": chosen[1],
            "md5": chosen[2],
            "sha256": chosen[3],
            "duplicate_identical": len(inspected) > 1,
            "candidate_count": len(inspected),
        },
    )


def detect_sticker_format(data: bytes) -> Optional[str]:
    if data.startswith(b"\xff\xd8\xff"):
        return "jpg"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if len(data) >= 12 and data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return "webp"
    return None


def _sticker_search_roots(account: Path, create_time: int) -> list[Path]:
    roots = [
        account / "business" / "emoticon" / "Persist",
        account / "business" / "emoticon" / "PersistStore",
    ]
    for month in _month_names(create_time):
        roots.append(account / "cache" / month / "Emoticon")
    return roots


def resolve_sticker(
    account_root: Path,
    create_time: int,
    expected_md5: str,
) -> AssetResolution:
    account = _validated_root(account_root, "微信账号目录")
    clean_md5 = expected_md5.strip().lower()
    if len(clean_md5) != 32 or any(char not in MD5_HEX for char in clean_md5):
        raise VaultError("表情 MD5 无效")

    originals: dict[Path, Path] = {}
    previews = 0
    for candidate_root in _sticker_search_roots(account, create_time):
        if candidate_root.is_symlink() or not candidate_root.is_dir():
            continue
        root = candidate_root.resolve()
        if not _is_relative_to(root, account):
            continue
        try:
            iterator = root.rglob("*")
            for candidate in iterator:
                if candidate.name not in {clean_md5, f"{clean_md5}.thumb"}:
                    continue
                resolved = _plain_candidate(candidate, root)
                if not resolved:
                    continue
                if candidate.name.endswith(".thumb"):
                    previews += 1
                else:
                    originals[resolved] = resolved
        except OSError:
            continue
    if not originals:
        status = "metadata_only" if previews else "missing"
        return AssetResolution(
            status,
            metadata={"md5": clean_md5, "preview_count": previews},
        )

    matching: list[tuple[Path, str, int, Optional[str]]] = []
    mismatched = 0
    for candidate in sorted(originals):
        actual_md5 = _digest_file(candidate, "md5")
        if actual_md5 != clean_md5:
            mismatched += 1
            continue
        sha256_value = _digest_file(candidate, "sha256")
        with candidate.open("rb") as handle:
            fmt = detect_sticker_format(handle.read(32))
        matching.append((candidate, sha256_value, candidate.stat().st_size, fmt))
    if not matching:
        return AssetResolution(
            "corrupt",
            metadata={"md5": clean_md5, "mismatched_count": mismatched},
        )
    hashes = {item[1] for item in matching}
    if len(hashes) != 1:
        return AssetResolution(
            "ambiguous",
            metadata={"md5": clean_md5, "candidate_count": len(matching)},
        )
    chosen = matching[0]
    status = "resolved" if chosen[3] else "unsupported"
    return AssetResolution(
        status,
        source=chosen[0],
        metadata={
            "md5": clean_md5,
            "sha256": chosen[1],
            "byte_count": chosen[2],
            "format": chosen[3] or "opaque",
            "duplicate_identical": len(matching) > 1,
            "candidate_count": len(matching),
            "preview_count": previews,
        },
    )


def copy_verified_file(source: Path, destination: Path, expected_sha256: str) -> dict[str, Any]:
    """Copy one regular file with no-follow semantics and a stability check."""

    before = source.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise VaultError("附件源文件不再是普通文件")
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    source_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    destination_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    digest = hashlib.sha256()
    written = 0
    source_fd = os.open(source, source_flags)
    try:
        destination_fd = os.open(destination, destination_flags, 0o600)
        try:
            os.fchmod(destination_fd, 0o600)
            while True:
                chunk = os.read(source_fd, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                written += len(chunk)
                cursor = 0
                while cursor < len(chunk):
                    cursor += os.write(destination_fd, chunk[cursor:])
            os.fsync(destination_fd)
        finally:
            os.close(destination_fd)
    finally:
        os.close(source_fd)
    after = source.lstat()
    stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in stable_fields):
        destination.unlink(missing_ok=True)
        raise VaultError("附件在复制过程中发生变化")
    actual_sha256 = digest.hexdigest()
    if actual_sha256 != expected_sha256:
        destination.unlink(missing_ok=True)
        raise VaultError("附件 SHA-256 与扫描结果不一致")
    return {"byte_count": written, "sha256": actual_sha256}
