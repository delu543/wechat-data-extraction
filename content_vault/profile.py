"""Private, credential-free local configuration for the content exporter.

The profile intentionally contains paths only.  Database keys and other
credentials belong to the separate one-time initialization boundary and must
never be accepted here.
"""

from __future__ import annotations

import errno
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Mapping
import uuid


PROFILE_SCHEMA_VERSION = 1
ACCOUNT_PROFILE_SCHEMA_VERSION = 2
MAX_PROFILE_BYTES = 64 * 1024
MAX_ACCOUNT_PROFILES = 64
MAX_PROFILE_REGISTRY_ENTRIES = 128
ACCOUNT_REF_RE = re.compile(r"account-[0-9a-f]{12}\Z")
_LEGACY_ALLOWED_FIELDS = frozenset(
    {"schema_version", "vault_dir", "account_root", "swift_bin"}
)
_ACCOUNT_ALLOWED_FIELDS = frozenset(
    {"schema_version", "account_ref", "vault_dir", "account_root", "swift_bin"}
)


class ProfileError(ValueError):
    """Raised when a local profile is malformed or stored unsafely."""


def _default_profile_path() -> Path:
    return (
        Path.home()
        / "Library"
        / "Application Support"
        / "WeChatLocalExport"
        / "profile.json"
    )


def _default_profiles_dir() -> Path:
    return _default_profile_path().parent / "profiles"


def _target_path(path: os.PathLike[str] | str | None) -> Path:
    candidate = _default_profile_path() if path is None else Path(path).expanduser()
    # Make a relative caller-supplied location unambiguous without resolving
    # symlinks.  The profile values themselves remain strictly absolute.
    return Path(os.path.abspath(os.fspath(candidate)))


def _profiles_dir_path(path: os.PathLike[str] | str | None) -> Path:
    candidate = _default_profiles_dir() if path is None else Path(path).expanduser()
    raw = os.fspath(candidate)
    if "\x00" in raw or not candidate.is_absolute():
        raise ProfileError("profiles directory must be an absolute path")
    return Path(os.path.abspath(raw))


def _account_profile_target(
    account_ref: str, profiles_dir: os.PathLike[str] | str | None
) -> Path:
    normalized_ref = _validate_account_ref(account_ref)
    registry = _profiles_dir_path(profiles_dir)
    target = registry / f"{normalized_ref}.json"
    if target.parent != registry:
        raise ProfileError("account profile path escapes the registry")
    return target


def _validate_absolute_path(value: Any, field: str, *, nullable: bool) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ProfileError(f"{field} must be an absolute path string")
    if not Path(value).is_absolute():
        raise ProfileError(f"{field} must be an absolute path string")
    return value


def _validate_profile(profile: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the legacy schema-1 profile.

    New account-scoped state must use :func:`write_account_profile`; this
    validator remains available so existing ``profile.json`` files stay
    readable without an in-place migration.
    """

    if not isinstance(profile, Mapping):
        raise ProfileError("profile must be an object")

    fields = set(profile.keys())
    if any(not isinstance(field, str) for field in fields):
        raise ProfileError("profile field names must be strings")
    if fields != _LEGACY_ALLOWED_FIELDS:
        # Do not reproduce unknown fields or their values in an exception: an
        # accidentally supplied credential should not leak into logs.
        raise ProfileError("profile contains missing or unsupported fields")
    if type(profile["schema_version"]) is not int or profile["schema_version"] != 1:
        raise ProfileError("unsupported profile schema_version")

    return {
        "schema_version": PROFILE_SCHEMA_VERSION,
        "vault_dir": _validate_absolute_path(
            profile["vault_dir"], "vault_dir", nullable=False
        ),
        "account_root": _validate_absolute_path(
            profile["account_root"], "account_root", nullable=False
        ),
        "swift_bin": _validate_absolute_path(
            profile["swift_bin"], "swift_bin", nullable=True
        ),
    }


def _validate_account_ref(account_ref: Any) -> str:
    if not isinstance(account_ref, str) or not ACCOUNT_REF_RE.fullmatch(account_ref):
        raise ProfileError("account reference is invalid")
    return account_ref


def _validate_account_profile(
    profile: Mapping[str, Any], *, expected_account_ref: str
) -> dict[str, Any]:
    if not isinstance(profile, Mapping):
        raise ProfileError("profile must be an object")

    fields = set(profile.keys())
    if any(not isinstance(field, str) for field in fields):
        raise ProfileError("profile field names must be strings")
    if fields != _ACCOUNT_ALLOWED_FIELDS:
        # Never reproduce an unknown field/value: callers can accidentally
        # pass credentials into a configuration mapping.
        raise ProfileError("profile contains missing or unsupported fields")
    if (
        type(profile["schema_version"]) is not int
        or profile["schema_version"] != ACCOUNT_PROFILE_SCHEMA_VERSION
    ):
        raise ProfileError("unsupported account profile schema_version")
    account_ref = _validate_account_ref(profile["account_ref"])
    if account_ref != expected_account_ref:
        raise ProfileError("account profile reference does not match its registry entry")

    return {
        "schema_version": ACCOUNT_PROFILE_SCHEMA_VERSION,
        "account_ref": account_ref,
        "vault_dir": _validate_absolute_path(
            profile["vault_dir"], "vault_dir", nullable=False
        ),
        "account_root": _validate_absolute_path(
            profile["account_root"], "account_root", nullable=False
        ),
        "swift_bin": _validate_absolute_path(
            profile["swift_bin"], "swift_bin", nullable=True
        ),
    }


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProfileError("profile contains a duplicate field")
        result[key] = value
    return result


def _validate_file_stat(info: os.stat_result) -> None:
    if not stat.S_ISREG(info.st_mode):
        raise ProfileError("profile must be a regular non-symlink file")
    if info.st_uid != os.getuid():
        raise ProfileError("profile must be owned by the current user")
    if stat.S_IMODE(info.st_mode) & ~0o600:
        raise ProfileError("profile permissions must not exceed 0600")
    if info.st_size > MAX_PROFILE_BYTES:
        raise ProfileError("profile exceeds the size limit")


def _read_profile_descriptor(
    descriptor: int, before: os.stat_result
) -> Mapping[str, Any]:
    try:
        opened = os.fstat(descriptor)
        _validate_file_stat(opened)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise ProfileError("profile changed while being opened")

        chunks: list[bytes] = []
        remaining = MAX_PROFILE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 16 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > MAX_PROFILE_BYTES:
            raise ProfileError("profile exceeds the size limit")

        after = os.fstat(descriptor)
        _validate_file_stat(after)
        stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(opened, name) != getattr(after, name) for name in stable_fields):
            raise ProfileError("profile changed while being read")
    except ProfileError:
        raise
    except OSError as exc:
        raise ProfileError("profile cannot be read safely") from exc

    try:
        decoded = payload.decode("utf-8")
        value = json.loads(decoded, object_pairs_hook=_reject_duplicate_keys)
    except ProfileError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProfileError("profile is not valid UTF-8 JSON") from exc
    if not isinstance(value, Mapping):
        raise ProfileError("profile must be an object")
    return value


def _load_profile_value(target: Path) -> Mapping[str, Any]:
    try:
        before = target.lstat()
    except OSError as exc:
        raise ProfileError("profile cannot be inspected") from exc
    _validate_file_stat(before)

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(target, flags)
        return _read_profile_descriptor(descriptor, before)
    except ProfileError:
        raise
    except OSError as exc:
        raise ProfileError("profile cannot be read safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def load_profile(path: os.PathLike[str] | str | None = None) -> dict[str, Any]:
    """Load the legacy schema-1 ``profile.json`` without migrating it."""

    return _validate_profile(_load_profile_value(_target_path(path)))


def _open_private_parent(parent: Path) -> int:
    try:
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = parent.lstat()
    except OSError as exc:
        raise ProfileError("profile parent directory cannot be prepared") from exc
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise ProfileError("profile parent must be a non-symlink directory")
    if info.st_uid != os.getuid():
        raise ProfileError("profile parent must be owned by the current user")

    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(parent, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISDIR(opened.st_mode):
            raise ProfileError("profile parent must be a directory")
        if opened.st_uid != os.getuid():
            raise ProfileError("profile parent must be owned by the current user")
        if (info.st_dev, info.st_ino) != (opened.st_dev, opened.st_ino):
            raise ProfileError("profile parent changed while being opened")
        os.fchmod(descriptor, 0o700)
        if stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o700:
            raise ProfileError("profile parent permissions could not be secured")
        return descriptor
    except ProfileError:
        if "descriptor" in locals():
            os.close(descriptor)
        raise
    except OSError as exc:
        if "descriptor" in locals():
            os.close(descriptor)
        raise ProfileError("profile parent cannot be opened safely") from exc


def _open_existing_private_directory(path: Path) -> int:
    """Open an existing owner-private directory without changing its mode."""

    try:
        before = path.lstat()
    except OSError as exc:
        raise ProfileError("profile registry cannot be inspected") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
        raise ProfileError("profile registry must be a non-symlink directory")
    if before.st_uid != os.getuid():
        raise ProfileError("profile registry must be owned by the current user")
    if stat.S_IMODE(before.st_mode) & ~0o700:
        raise ProfileError("profile registry permissions must not exceed 0700")

    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISDIR(opened.st_mode):
            raise ProfileError("profile registry must be a directory")
        if opened.st_uid != os.getuid():
            raise ProfileError("profile registry must be owned by the current user")
        if stat.S_IMODE(opened.st_mode) & ~0o700:
            raise ProfileError("profile registry permissions must not exceed 0700")
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise ProfileError("profile registry changed while being opened")
        return descriptor
    except ProfileError:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise ProfileError("profile registry cannot be opened safely") from exc


def _open_account_registry_for_write(registry: Path) -> int:
    """Prepare the managed registry without following a support-root symlink."""

    support_root = registry.parent
    if support_root.exists() or support_root.is_symlink():
        # The product owns this one fixed directory.  Older setup flows could
        # leave it at the mkdir default (commonly 0755), so a write through the
        # default registry may safely narrow an owner-owned, non-symlink
        # directory to 0700.  Caller-supplied registries remain fail-closed and
        # are never chmod'ed here.
        if support_root == _profiles_dir_path(None).parent:
            support_fd = _open_private_parent(support_root)
        else:
            support_fd = _open_existing_private_directory(support_root)
    else:
        support_fd = _open_private_parent(support_root)
    os.close(support_fd)
    return _open_private_parent(registry)


def _open_account_registry_for_read(registry: Path) -> int:
    """Open the registry only beneath a verified owner-private support root."""

    support_fd = _open_existing_private_directory(registry.parent)
    try:
        return _open_existing_private_directory(registry)
    finally:
        os.close(support_fd)


def _account_profile_entries(parent_fd: int) -> tuple[tuple[str, str], ...]:
    """Return bounded ``(account_ref, filename)`` entries from one open registry."""

    try:
        names = os.listdir(parent_fd)
    except OSError as exc:
        raise ProfileError("profile registry cannot be enumerated safely") from exc
    if len(names) > MAX_PROFILE_REGISTRY_ENTRIES:
        raise ProfileError("profile registry contains too many entries")

    entries: list[tuple[str, str]] = []
    for name in sorted(names):
        match = re.fullmatch(r"(account-[0-9a-f]{12})\.json", name)
        if match is None:
            raise ProfileError("profile registry contains an unsupported entry")
        try:
            info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            raise ProfileError("account profile cannot be inspected safely") from exc
        _validate_file_stat(info)
        entries.append((match.group(1), name))
    if len(entries) > MAX_ACCOUNT_PROFILES:
        raise ProfileError("profile registry contains too many account profiles")
    return tuple(entries)


def _destination_stat(parent_fd: int, name: str) -> os.stat_result | None:
    try:
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ProfileError("profile destination cannot be inspected") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ProfileError("profile destination must be a regular non-symlink file")
    if info.st_uid != os.getuid():
        raise ProfileError("profile destination must be owned by the current user")
    if stat.S_IMODE(info.st_mode) & ~0o600:
        raise ProfileError("profile destination permissions must not exceed 0600")
    return info


def _profile_payload(validated: Mapping[str, Any]) -> bytes:
    payload = (
        json.dumps(validated, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    if len(payload) > MAX_PROFILE_BYTES:
        raise ProfileError("profile exceeds the size limit")
    return payload


def _write_payload_to_parent(parent_fd: int, name: str, payload: bytes) -> None:
    temporary_name = f".{name}.{os.getpid()}.{uuid.uuid4().hex}.partial"
    temporary_fd = -1
    published = False
    try:
        original = _destination_stat(parent_fd, name)
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        temporary_fd = os.open(temporary_name, flags, 0o600, dir_fd=parent_fd)
        os.fchmod(temporary_fd, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(temporary_fd, view)
            if written <= 0:
                raise ProfileError("profile write was interrupted")
            view = view[written:]
        os.fsync(temporary_fd)
        os.close(temporary_fd)
        temporary_fd = -1

        current = _destination_stat(parent_fd, name)
        if original is None:
            if current is not None:
                raise ProfileError("profile destination changed before publication")
        elif current is None or (original.st_dev, original.st_ino) != (
            current.st_dev,
            current.st_ino,
        ):
            raise ProfileError("profile destination changed before publication")

        os.replace(
            temporary_name,
            name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        published = True
        final = _destination_stat(parent_fd, name)
        if final is None or stat.S_IMODE(final.st_mode) != 0o600:
            raise ProfileError("published profile permissions are unsafe")
        try:
            os.fsync(parent_fd)
        except OSError as exc:
            if exc.errno not in {errno.EINVAL, errno.ENOTSUP}:
                raise
    except ProfileError:
        raise
    except OSError as exc:
        raise ProfileError("profile could not be written atomically") from exc
    finally:
        if temporary_fd >= 0:
            os.close(temporary_fd)
        if not published:
            try:
                os.unlink(temporary_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
            except OSError:
                pass


def write_profile(
    profile: Mapping[str, Any], path: os.PathLike[str] | str | None = None
) -> Path:
    """Validate and atomically write a legacy schema-1 local profile.

    New setup flows should use :func:`write_account_profile`.  This API stays
    available for source-development compatibility, but account-profile writes
    never touch this legacy destination.
    """

    validated = _validate_profile(profile)
    target = _target_path(path)
    parent_fd = _open_private_parent(target.parent)
    try:
        _write_payload_to_parent(parent_fd, target.name, _profile_payload(validated))
    finally:
        os.close(parent_fd)

    return target


def list_account_profile_refs(
    profiles_dir: os.PathLike[str] | str | None = None,
) -> tuple[str, ...]:
    """List bounded opaque account references without reading profile values."""

    registry = _profiles_dir_path(profiles_dir)
    if not registry.exists() and not registry.is_symlink():
        if registry.parent.is_symlink():
            raise ProfileError("profile support root must not be a symlink")
        return ()
    parent_fd = _open_account_registry_for_read(registry)
    try:
        return tuple(account_ref for account_ref, _name in _account_profile_entries(parent_fd))
    finally:
        os.close(parent_fd)


def load_account_profile(
    account_ref: str,
    profiles_dir: os.PathLike[str] | str | None = None,
) -> dict[str, Any]:
    """Load one schema-2 profile from the bounded account registry.

    The legacy ``profile.json`` is deliberately not used as an implicit
    fallback because schema 1 has no account binding.  Call :func:`load_profile`
    explicitly when a higher-level router has independently proven that a
    legacy profile belongs to the active account.
    """

    target = _account_profile_target(account_ref, profiles_dir)
    parent_fd = _open_account_registry_for_read(target.parent)
    descriptor = -1
    try:
        entries = dict(_account_profile_entries(parent_fd))
        normalized_ref = _validate_account_ref(account_ref)
        expected_name = f"{normalized_ref}.json"
        if entries.get(normalized_ref) != expected_name:
            raise ProfileError("account profile is not registered")
        try:
            before = os.stat(expected_name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            raise ProfileError("account profile cannot be inspected safely") from exc
        _validate_file_stat(before)
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(expected_name, flags, dir_fd=parent_fd)
        value = _read_profile_descriptor(descriptor, before)
        return _validate_account_profile(value, expected_account_ref=normalized_ref)
    except ProfileError:
        raise
    except OSError as exc:
        raise ProfileError("account profile cannot be read safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_fd)


def write_account_profile(
    account_ref: str,
    profile: Mapping[str, Any],
    profiles_dir: os.PathLike[str] | str | None = None,
) -> Path:
    """Atomically publish one schema-2 account profile.

    The target is always ``profiles/<account-ref>.json``.  The legacy
    ``profile.json`` is outside this registry and is never overwritten.
    """

    normalized_ref = _validate_account_ref(account_ref)
    validated = _validate_account_profile(
        profile, expected_account_ref=normalized_ref
    )
    target = _account_profile_target(normalized_ref, profiles_dir)
    parent_fd = _open_account_registry_for_write(target.parent)
    try:
        entries = dict(_account_profile_entries(parent_fd))
        if normalized_ref not in entries and len(entries) >= MAX_ACCOUNT_PROFILES:
            raise ProfileError("profile registry contains too many account profiles")
        _write_payload_to_parent(
            parent_fd, target.name, _profile_payload(validated)
        )
    finally:
        os.close(parent_fd)
    return target
