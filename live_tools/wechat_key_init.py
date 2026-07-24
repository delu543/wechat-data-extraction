#!/usr/bin/env python3
"""Safe, one-time Mac WeChat 4.x database-key initializer.

This tool is deliberately narrow:

* setup doctor exposes only a redacted account reference; an exact validated
  ``xwechat_files/<account>/db_storage`` path remains the internal boundary;
* only ``contact``, ``message_N``, ``media_N`` and the exact
  ``message_resource`` database are accepted;
* the original WeChat application is only read, never modified;
* Frida rows stay in process memory and are discarded after matching;
* a candidate is accepted only for the same 16-byte database salt and only
  after it decrypts a structurally valid SQLCipher first page;
* final keys, configuration and runtime ownership metadata are atomically
  written with mode 0600 inside a private 0700 directory.

The signed copy is intentionally left running after capture. Quit it normally,
then use the ``cleanup`` command. Cleanup accepts no arbitrary runtime path: it
only removes the run recorded in private ownership metadata, and only after its
recorded PID no longer exists.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import plistlib
import re
import secrets
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import typing
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


PAGE_SIZE = 4096
RESERVE_SIZE = 80
IV_SIZE = 16
SQLITE_HEADER = b"SQLite format 3\x00"

EXPECTED_BUNDLE_ID = "com.tencent.xinWeChat"
EXPECTED_TEAM_ID = "5A4RE8SF68"
OFFICIAL_WECHAT_REQUIREMENT = (
    "(anchor apple generic and "
    "certificate leaf[field.1.2.840.113635.100.6.1.9] exists or "
    "anchor apple generic and "
    "certificate 1[field.1.2.840.113635.100.6.2.6] exists and "
    "certificate leaf[field.1.2.840.113635.100.6.1.13] exists and "
    f'certificate leaf[subject.OU] = "{EXPECTED_TEAM_ID}") and '
    f'identifier "{EXPECTED_BUNDLE_ID}"'
)
DEFAULT_WECHAT_APP = Path("/Applications/微信.app")
DEFAULT_XWECHAT_ROOT = Path(
    "~/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files"
).expanduser()
DEFAULT_PRIVATE_DIR = Path(
    "~/Library/Application Support/WeChatVoiceMP4/private"
).expanduser()

KEYS_FILENAME = "wechat-db-keys.json"
CONFIG_FILENAME = "local-vault.json"
RUNTIME_FILENAME = "key-init-runtime.json"
RUNTIME_OWNER_FILENAME = ".wechat-key-init-owned.json"
RUNTIME_DIRNAME = "runtime"
ACCOUNTS_DIRNAME = "accounts"
MAX_ACCOUNT_ENTRIES = 200
MAX_ACCOUNT_CANDIDATES = 20
MAX_TARGET_ENTRIES = 512
MAX_RUNTIME_ENTRIES = 32
MAX_STATE_JSON_BYTES = 1024 * 1024

TARGET_RE = re.compile(
    r"^(?:contact|message_resource|(?:message|media)_(?:0|[1-9][0-9]*))$"
)
RAW_KEY_RE = re.compile(br"^x'([0-9a-fA-F]{64})'$", re.ASCII)
ACCOUNT_REF_RE = re.compile(r"^account-[0-9a-f]{12}$")
ROUTING_FAILURE_CODES = frozenset(
    {"no-active-account", "multiple-active-accounts", "unstable", "unavailable"}
)


class SafeInitError(RuntimeError):
    """Expected, redacted initialization failure."""


@dataclass(frozen=True)
class TargetDB:
    name: str
    relative_path: str
    path: Path = field(repr=False)
    size: int
    salt: bytes = field(repr=False)
    mtime_ns: int = 0


@dataclass(frozen=True)
class AccountCandidate:
    account_ref: str
    db_base: Path = field(repr=False)
    targets: Mapping[str, TargetDB] = field(repr=False)
    newest_mtime_ns: int


@dataclass(frozen=True)
class WeChatApp:
    app_path: Path
    executable_path: Path
    executable_name: str
    bundle_id: str
    version: str


@dataclass(frozen=True)
class PreparedRuntime:
    run_id: str
    runtime_dir: Path
    app_copy_path: Path
    executable_path: Path


@dataclass(frozen=True)
class OwnedRuntimeDirectory:
    run_id: str
    runtime_dir: Path = field(repr=False)


@dataclass(frozen=True)
class CaptureResult:
    pid: int
    matched_keys: Mapping[str, str] = field(repr=False)
    missing_targets: Tuple[str, ...]


Runner = Callable[..., subprocess.CompletedProcess]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _is_regular_non_symlink(path: Path) -> bool:
    try:
        if path.is_symlink():
            return False
        return stat.S_ISREG(path.lstat().st_mode)
    except OSError:
        return False


def _is_directory_non_symlink(path: Path) -> bool:
    try:
        if path.is_symlink():
            return False
        return stat.S_ISDIR(path.lstat().st_mode)
    except OSError:
        return False


def validate_db_base(db_base: Path, xwechat_root: Path = DEFAULT_XWECHAT_ROOT) -> Path:
    """Validate one explicit ``xwechat_files/<account>/db_storage`` directory."""

    original = db_base.expanduser()
    if not original.is_absolute():
        raise SafeInitError("--db-base must be an absolute path")
    if not _is_directory_non_symlink(original):
        raise SafeInitError("the explicit db_storage directory is missing or unsafe")

    root_original = xwechat_root.expanduser()
    if not _is_directory_non_symlink(root_original):
        raise SafeInitError("the expected xwechat_files root is missing or unsafe")

    try:
        root = root_original.resolve(strict=True)
        resolved = original.resolve(strict=True)
    except OSError as exc:
        raise SafeInitError("the explicit db_storage directory cannot be resolved") from exc

    # Exactly one account component is allowed: root/<account>/db_storage.
    if resolved.name != "db_storage" or resolved.parent.parent != root:
        raise SafeInitError(
            "--db-base must be exactly xwechat_files/<one-account>/db_storage"
        )
    if not _is_directory_non_symlink(resolved.parent):
        raise SafeInitError("the account directory is missing or unsafe")
    return resolved


def parse_targets(raw: str) -> Tuple[str, ...]:
    """Parse exact database aliases. There is intentionally no ``all`` mode."""

    if not raw:
        raise SafeInitError("--targets must name exact databases")
    pieces = [piece.strip() for piece in raw.split(",")]
    if not pieces or any(not piece for piece in pieces):
        raise SafeInitError("--targets contains an empty database name")
    if any(not TARGET_RE.fullmatch(piece) for piece in pieces):
        raise SafeInitError(
            "targets must be exact aliases: contact, message_N, media_N, "
            "or message_resource"
        )
    if len(set(pieces)) != len(pieces):
        raise SafeInitError("--targets contains a duplicate database name")
    return tuple(pieces)


def target_relative_path(name: str) -> str:
    if name == "contact":
        return "contact/contact.db"
    if name == "message_resource":
        return "message/message_resource.db"
    if TARGET_RE.fullmatch(name) and (name.startswith("message_") or name.startswith("media_")):
        return "message/%s.db" % name
    raise SafeInitError("invalid exact target alias")


def inspect_targets(db_base: Path, target_names: Iterable[str]) -> Dict[str, TargetDB]:
    """Inspect only allowlisted, regular, non-symlink database files."""

    result: Dict[str, TargetDB] = {}
    seen_inodes: Dict[Tuple[int, int], str] = {}
    seen_salts: Dict[bytes, str] = {}

    for name in target_names:
        relative = target_relative_path(name)
        path = db_base / relative
        parent = path.parent
        expected_parent_name = "contact" if name == "contact" else "message"
        if (
            parent.parent != db_base
            or parent.name != expected_parent_name
            or not _is_directory_non_symlink(parent)
        ):
            raise SafeInitError("target %s has a missing or unsafe parent directory" % name)
        if not _is_regular_non_symlink(path):
            raise SafeInitError("target %s is missing or is not a regular database file" % name)

        try:
            resolved = path.resolve(strict=True)
            expected_parent = parent.resolve(strict=True)
            file_stat = path.lstat()
        except OSError as exc:
            raise SafeInitError("target %s cannot be safely inspected" % name) from exc
        if resolved.parent != expected_parent:
            raise SafeInitError("target %s resolves outside its exact database directory" % name)
        if file_stat.st_size < PAGE_SIZE or file_stat.st_size % PAGE_SIZE != 0:
            raise SafeInitError(
                "target %s is not a complete sequence of 4096-byte database pages" % name
            )

        inode = (file_stat.st_dev, file_stat.st_ino)
        if inode in seen_inodes:
            raise SafeInitError("two requested targets resolve to the same database file")
        seen_inodes[inode] = name

        try:
            with path.open("rb") as handle:
                salt = handle.read(16)
        except OSError as exc:
            raise SafeInitError("target %s cannot be read" % name) from exc
        if len(salt) != 16:
            raise SafeInitError("target %s does not contain a complete database salt" % name)
        if salt in seen_salts:
            raise SafeInitError("two requested targets have an ambiguous duplicate salt")
        seen_salts[salt] = name

        result[name] = TargetDB(
            name=name,
            relative_path=relative,
            path=resolved,
            size=file_stat.st_size,
            salt=salt,
            mtime_ns=file_stat.st_mtime_ns,
        )
    return result


def _discover_target_names(db_base: Path) -> Tuple[str, ...]:
    names: list[str] = []
    if _is_regular_non_symlink(db_base / "contact/contact.db"):
        names.append("contact")
    message_dir = db_base / "message"
    if not _is_directory_non_symlink(message_dir):
        return tuple(names)
    try:
        entries = sorted(message_dir.iterdir(), key=lambda path: path.name)
    except OSError as exc:
        raise SafeInitError("the account message database directory is not readable") from exc
    if len(entries) > MAX_TARGET_ENTRIES:
        raise SafeInitError("the account has too many database entries to inspect safely")
    for entry in entries:
        if entry.name == "message_resource.db":
            alias = "message_resource"
        else:
            match = re.fullmatch(
                r"(message|media)_(0|[1-9][0-9]*)\.db", entry.name
            )
            if not match:
                continue
            alias = entry.stem
        if _is_regular_non_symlink(entry):
            names.append(alias)
    return tuple(dict.fromkeys(names))


def discover_account_candidates(
    xwechat_root: Path = DEFAULT_XWECHAT_ROOT,
) -> Tuple[AccountCandidate, ...]:
    """Discover bounded account candidates without exposing account directory names."""

    root_original = xwechat_root.expanduser()
    if not _is_directory_non_symlink(root_original):
        raise SafeInitError(
            "the xwechat_files root is unavailable; Full Disk Access may be missing"
        )
    try:
        root = root_original.resolve(strict=True)
        entries = sorted(root.iterdir(), key=lambda path: path.name)
    except (OSError, PermissionError) as exc:
        raise SafeInitError(
            "the xwechat_files root cannot be enumerated; Full Disk Access may be missing"
        ) from exc
    if len(entries) > MAX_ACCOUNT_ENTRIES:
        raise SafeInitError("too many account entries were found to inspect safely")

    result: list[AccountCandidate] = []
    seen_refs: set[str] = set()
    for account in entries:
        if not _is_directory_non_symlink(account):
            continue
        db_base = account / "db_storage"
        try:
            validated = validate_db_base(db_base, root)
        except SafeInitError:
            continue
        names = _discover_target_names(validated)
        if "contact" not in names or not any(
            name.startswith("message_") and name != "message_resource"
            for name in names
        ):
            continue
        targets: Dict[str, TargetDB] = {}
        for name in names:
            try:
                targets.update(inspect_targets(validated, (name,)))
            except SafeInitError:
                continue
        if "contact" not in targets:
            continue
        account_ref = "account-" + hashlib.sha256(
            b"wechat-account-ref-v1\x00" + targets["contact"].salt
        ).hexdigest()[:12]
        if account_ref in seen_refs:
            raise SafeInitError("two account candidates have an ambiguous reference")
        seen_refs.add(account_ref)
        newest = max(
            (target.mtime_ns for target in targets.values()),
            default=0,
        )
        result.append(
            AccountCandidate(
                account_ref=account_ref,
                db_base=validated,
                targets=dict(sorted(targets.items())),
                newest_mtime_ns=newest,
            )
        )
    if len(result) > MAX_ACCOUNT_CANDIDATES:
        raise SafeInitError("too many valid account candidates were found to select safely")
    result.sort(key=lambda item: (-item.newest_mtime_ns, item.account_ref))
    return tuple(result)


def resolve_account_ref(
    account_ref: str,
    xwechat_root: Path = DEFAULT_XWECHAT_ROOT,
) -> Path:
    return resolve_account_candidate(account_ref, xwechat_root).db_base


def resolve_account_candidate(
    account_ref: str,
    xwechat_root: Path = DEFAULT_XWECHAT_ROOT,
) -> AccountCandidate:
    """Resolve one opaque reference without ranking historical directories."""

    if not ACCOUNT_REF_RE.fullmatch(account_ref or ""):
        raise SafeInitError("invalid account reference")
    matches = [
        candidate
        for candidate in discover_account_candidates(xwechat_root)
        if candidate.account_ref == account_ref
    ]
    if len(matches) != 1:
        raise SafeInitError("account reference is missing or ambiguous; rerun doctor")
    return matches[0]


def _redacted_current_account_report(
    status: str,
    *,
    samples_completed: int = 0,
) -> Mapping[str, Any]:
    if status not in ROUTING_FAILURE_CODES:
        status = "unavailable"
    return {
        "status": status,
        "selected": False,
        "method": "official-process-numeric-fd-exact-match",
        "samples_completed": max(0, min(int(samples_completed), 2)),
        "writes_performed": False,
    }


def _route_current_account(
    *,
    app_path: Path,
    xwechat_root: Path,
    runner: Runner,
) -> Tuple[Optional[str], Mapping[str, Any], Optional[str]]:
    """Call the current-session router lazily to avoid its import cycle."""

    try:
        from live_tools.wechat_account_router import (
            AccountRoutingError,
            bind_active_account,
        )
    except ImportError:  # pragma: no cover - direct script execution fallback
        try:
            from wechat_account_router import (  # type: ignore
                AccountRoutingError,
                bind_active_account,
            )
        except ImportError:
            return None, _redacted_current_account_report("unavailable"), "unavailable"

    try:
        binding = bind_active_account(
            app_path=app_path,
            xwechat_root=xwechat_root,
            runner=runner,
        )
    except AccountRoutingError as exc:
        code = exc.code if exc.code in ROUTING_FAILURE_CODES else "unavailable"
        return None, dict(exc.public_report()), code
    except Exception:
        return None, _redacted_current_account_report("unavailable"), "unavailable"
    return binding.account_ref, dict(binding.public_report()), None


def validate_wechat_app(app_path: Path) -> WeChatApp:
    """Validate an official-layout Mac WeChat 4.x application bundle."""

    original = app_path.expanduser()
    if not original.is_absolute():
        raise SafeInitError("--app must be an absolute .app path")
    if original.suffix != ".app" or not _is_directory_non_symlink(original):
        raise SafeInitError("the WeChat application bundle is missing or unsafe")
    try:
        app = original.resolve(strict=True)
    except OSError as exc:
        raise SafeInitError("the WeChat application bundle cannot be resolved") from exc

    plist_path = app / "Contents/Info.plist"
    if not _is_regular_non_symlink(plist_path):
        raise SafeInitError("the application has no safe Info.plist")
    try:
        with plist_path.open("rb") as handle:
            info = plistlib.load(handle)
    except (OSError, plistlib.InvalidFileException) as exc:
        raise SafeInitError("the application Info.plist is invalid") from exc

    bundle_id = info.get("CFBundleIdentifier")
    executable_name = info.get("CFBundleExecutable")
    version = info.get("CFBundleShortVersionString")
    if bundle_id != EXPECTED_BUNDLE_ID:
        raise SafeInitError("the application bundle id is not Mac WeChat")
    if not isinstance(version, str) or not re.match(r"^4(?:\.|$)", version):
        raise SafeInitError("only Mac WeChat 4.x is supported")
    if len(version) > 64 or any(ord(character) < 0x20 for character in version):
        raise SafeInitError("the application declares an unsafe version string")
    if (
        not isinstance(executable_name, str)
        or not executable_name
        or Path(executable_name).name != executable_name
        or executable_name in (".", "..")
    ):
        raise SafeInitError("the application declares an unsafe executable name")

    executable = app / "Contents/MacOS" / executable_name
    if not _is_regular_non_symlink(executable) or not os.access(str(executable), os.X_OK):
        raise SafeInitError("the declared Mac WeChat executable is missing or not executable")
    try:
        executable_resolved = executable.resolve(strict=True)
    except OSError as exc:
        raise SafeInitError("the declared Mac WeChat executable cannot be resolved") from exc
    if executable_resolved.parent != (app / "Contents/MacOS").resolve(strict=True):
        raise SafeInitError("the declared executable resolves outside the application bundle")

    return WeChatApp(
        app_path=app,
        executable_path=executable_resolved,
        executable_name=executable_name,
        bundle_id=bundle_id,
        version=version,
    )


def _import_frida_compat() -> Any:
    """Import Frida 17 safely on Apple's Python 3.9.

    Frida's type declarations import ``NotRequired`` and ``ParamSpec`` from
    :mod:`typing`; those names live in ``typing_extensions`` on Python 3.9.
    Patch only the missing attributes in this process. No package is installed
    or modified.
    """

    missing = [name for name in ("NotRequired", "ParamSpec") if not hasattr(typing, name)]
    if missing:
        try:
            import typing_extensions  # type: ignore
        except ImportError as exc:
            raise SafeInitError(
                "frida on Python 3.9 requires the installed typing_extensions package"
            ) from exc
        for name in missing:
            replacement = getattr(typing_extensions, name, None)
            if replacement is None:
                raise SafeInitError(
                    "typing_extensions is too old for the installed frida package"
                )
            setattr(typing, name, replacement)
    try:
        import frida  # type: ignore
    except ImportError as exc:
        raise SafeInitError(
            "frida is unavailable or incompatible; no package was installed automatically"
        ) from exc
    return frida


def dependency_status() -> Mapping[str, bool]:
    def available(module_name: str) -> bool:
        try:
            return importlib.util.find_spec(module_name) is not None
        except (ImportError, AttributeError, ValueError):
            return False

    frida_ready = available("frida")
    if frida_ready:
        try:
            _import_frida_compat()
        except SafeInitError:
            frida_ready = False
    return {
        "frida": frida_ready,
        "pycryptodome": available("Crypto.Cipher.AES"),
    }


def require_capture_dependencies() -> Any:
    missing = [name for name, present in dependency_status().items() if not present]
    if missing:
        raise SafeInitError(
            "capture dependencies are missing (%s); install them explicitly in an isolated environment"
            % ", ".join(missing)
        )
    return _import_frida_compat()


def ensure_private_dir(path: Path, *, create: bool) -> Path:
    expanded = path.expanduser()
    if not expanded.is_absolute():
        raise SafeInitError("--private-dir must be an absolute path")
    # Resolve existing parent aliases such as /var -> /private/var without ever
    # accepting a symlink as the private directory itself.
    if expanded.is_symlink():
        raise SafeInitError("the private state directory cannot be a symlink")
    if create:
        try:
            expanded.mkdir(parents=True, mode=0o700, exist_ok=True)
        except OSError as exc:
            raise SafeInitError("the private state directory could not be created") from exc
    if not _is_directory_non_symlink(expanded):
        raise SafeInitError("the private state directory is missing or unsafe")
    try:
        resolved = expanded.resolve(strict=True)
        directory_stat = resolved.lstat()
    except OSError as exc:
        raise SafeInitError("the private state directory cannot be inspected") from exc
    if hasattr(os, "getuid") and directory_stat.st_uid != os.getuid():
        raise SafeInitError("the private state directory is not owned by the current user")
    if stat.S_IMODE(directory_stat.st_mode) & 0o077:
        if not create:
            raise SafeInitError("the private state directory permissions are not private")
        try:
            os.chmod(resolved, 0o700)
        except OSError as exc:
            raise SafeInitError("the private state directory permissions could not be secured") from exc
    return resolved


def ensure_account_state_dir(
    private_dir: Path,
    account_ref: str,
    *,
    create: bool,
) -> Path:
    """Return one owner-only ``accounts/<account-ref>`` directory."""

    if not ACCOUNT_REF_RE.fullmatch(account_ref or ""):
        raise SafeInitError("invalid account reference")
    root = ensure_private_dir(private_dir, create=create)
    accounts_root = root / ACCOUNTS_DIRNAME
    if accounts_root.is_symlink():
        raise SafeInitError("the private accounts directory cannot be a symlink")
    if create and not accounts_root.exists():
        try:
            accounts_root.mkdir(mode=0o700)
        except OSError as exc:
            raise SafeInitError("the private accounts directory could not be created") from exc
    accounts_root = ensure_private_dir(accounts_root, create=False)

    scoped = accounts_root / account_ref
    if scoped.is_symlink():
        raise SafeInitError("the account state directory cannot be a symlink")
    if create and not scoped.exists():
        try:
            scoped.mkdir(mode=0o700)
        except OSError as exc:
            raise SafeInitError("the account state directory could not be created") from exc
    return ensure_private_dir(scoped, create=False)


def atomic_write_json(path: Path, data: Mapping[str, Any]) -> None:
    """Atomically replace one JSON file with mode 0600."""

    parent = path.parent
    if not _is_directory_non_symlink(parent):
        raise SafeInitError("a private output directory is missing or unsafe")
    fd = -1
    temporary_name: Optional[str] = None
    try:
        fd, temporary_name = tempfile.mkstemp(prefix=".%s." % path.name, dir=str(parent))
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = -1
            json.dump(data, handle, indent=2, sort_keys=True, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
        temporary_name = None
        os.chmod(path, 0o600)
        try:
            directory_fd = os.open(str(parent), os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            # File fsync + atomic same-directory replace are the important part;
            # some filesystems do not permit fsync on directory descriptors.
            pass
    except OSError as exc:
        raise SafeInitError("a private JSON file could not be written atomically") from exc
    finally:
        if fd >= 0:
            os.close(fd)
        if temporary_name:
            try:
                os.unlink(temporary_name)
            except OSError:
                pass


def _default_runner(command: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess:
    return subprocess.run(command, **kwargs)


def original_wechat_is_running(
    app: WeChatApp,
    *,
    runner: Runner = _default_runner,
) -> bool:
    """Check the validated original bundle process family without exposing PIDs.

    ``pgrep -f`` is intentionally conservative: an unexpected match is treated
    as the original being active, including WeChatAppEx-style child UI
    executables inside the official bundle. Any process-inspection failure
    aborts capture instead of guessing that it is safe.
    """

    pattern = re.escape(str(app.app_path / "Contents")) + "/"
    try:
        result = runner(
            ["/usr/bin/pgrep", "-f", pattern],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise SafeInitError("the original WeChat process state could not be checked") from exc
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    raise SafeInitError("the original WeChat process state could not be checked safely")


def assert_original_wechat_stopped(
    app: WeChatApp,
    *,
    runner: Runner = _default_runner,
) -> None:
    if original_wechat_is_running(app, runner=runner):
        raise SafeInitError(
            "the original WeChat app is still running; quit it normally before capture"
        )


def _target_holder_paths(targets: Mapping[str, TargetDB]) -> Tuple[Path, ...]:
    """Return exact target databases plus existing WAL/SHM sidecars."""

    result: List[Path] = []
    for name in sorted(targets):
        target = targets[name]
        if not _is_regular_non_symlink(target.path):
            raise SafeInitError("a target database changed before its holder check")
        result.append(target.path)
        for suffix in ("-wal", "-shm"):
            sidecar = Path(str(target.path) + suffix)
            try:
                sidecar_stat = sidecar.lstat()
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise SafeInitError(
                    "a target database sidecar could not be inspected safely"
                ) from exc
            if sidecar.is_symlink() or not stat.S_ISREG(sidecar_stat.st_mode):
                raise SafeInitError("a target database sidecar is unsafe")
            try:
                resolved = sidecar.resolve(strict=True)
            except OSError as exc:
                raise SafeInitError(
                    "a target database sidecar could not be resolved safely"
                ) from exc
            if resolved.parent != target.path.parent:
                raise SafeInitError("a target database sidecar resolves outside its directory")
            result.append(resolved)
    return tuple(result)


def _default_holder_probe(paths: Sequence[Path]) -> Sequence[Any]:
    try:
        from live_tools.wechat_safe_snapshot import find_wechat_holders
    except ImportError:  # pragma: no cover - direct script execution fallback
        from wechat_safe_snapshot import find_wechat_holders  # type: ignore

    return find_wechat_holders(paths)


def inspect_target_database_holders(
    targets: Mapping[str, TargetDB],
    *,
    holder_probe: Optional[Callable[[Sequence[Path]], Sequence[Any]]] = None,
) -> Mapping[str, Any]:
    """Inspect exact target holders without exposing process or path details."""

    probe = holder_probe or _default_holder_probe
    try:
        holders = tuple(probe(_target_holder_paths(targets)))
    except SafeInitError:
        raise
    except Exception as exc:
        raise SafeInitError(
            "target database holder state could not be checked safely"
        ) from exc
    return {
        "status": "clear" if not holders else "held",
        "holder_count": len(holders),
    }


def assert_no_target_database_holders(
    targets: Mapping[str, TargetDB],
    *,
    holder_probe: Optional[Callable[[Sequence[Path]], Sequence[Any]]] = None,
) -> None:
    report = inspect_target_database_holders(targets, holder_probe=holder_probe)
    if report["holder_count"]:
        raise SafeInitError(
            "a WeChat process still holds one or more target databases; quit it normally"
        )


def parse_approval_digest(value: str) -> str:
    if not re.fullmatch(r"[0-9a-fA-F]{64}", value or ""):
        raise argparse.ArgumentTypeError("approval digest must be exactly 64 hexadecimal characters")
    return value.lower()


def _approval_account_binding(args: argparse.Namespace, db_base: Path) -> str:
    account_ref = getattr(args, "account_ref", None)
    if isinstance(account_ref, str) and re.fullmatch(r"account-[0-9a-f]{12}", account_ref):
        return account_ref
    # Development-only explicit paths are bound without serializing the path
    # itself into any public report.
    return "development-" + hashlib.sha256(
        str(db_base).encode("utf-8", errors="strict")
    ).hexdigest()


def capture_approval_digest(
    args: argparse.Namespace,
    db_base: Path,
    targets: Mapping[str, TargetDB],
    app: WeChatApp,
    official_cdhash: str,
) -> str:
    """Bind one consent token to the exact account, databases and app identity."""

    if not re.fullmatch(r"[0-9a-f]{40,64}", official_cdhash or ""):
        raise SafeInitError("the official WeChat code identity is invalid")

    target_descriptors: List[Mapping[str, Any]] = []
    for name in sorted(targets):
        target = targets[name]
        try:
            file_stat = target.path.lstat()
        except OSError as exc:
            raise SafeInitError("a target database changed before approval binding") from exc
        if (
            not stat.S_ISREG(file_stat.st_mode)
            or target.path.is_symlink()
            or file_stat.st_size != target.size
        ):
            raise SafeInitError("a target database changed before approval binding")
        target_descriptors.append(
            {
                "alias": name,
                "size": target.size,
                "salt_sha256": hashlib.sha256(target.salt).hexdigest(),
                "device": file_stat.st_dev,
                "inode": file_stat.st_ino,
                "path_sha256": hashlib.sha256(
                    str(target.path).encode("utf-8", errors="strict")
                ).hexdigest(),
            }
        )
    try:
        executable_stat = app.executable_path.lstat()
    except OSError as exc:
        raise SafeInitError("the WeChat executable changed before approval binding") from exc
    descriptor = {
        "schema_version": 1,
        "purpose": "wechat-key-init-capture-consent",
        "account_binding": _approval_account_binding(args, db_base),
        "targets": target_descriptors,
        "application": {
            "bundle_id": app.bundle_id,
            "version": app.version,
            "team_id": EXPECTED_TEAM_ID,
            "cdhash": official_cdhash,
            "designated_requirement_sha256": hashlib.sha256(
                OFFICIAL_WECHAT_REQUIREMENT.encode("utf-8")
            ).hexdigest(),
            "executable_device": executable_stat.st_dev,
            "executable_inode": executable_stat.st_ino,
            "executable_size": executable_stat.st_size,
        },
    }
    canonical = json.dumps(
        descriptor, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    return hashlib.sha256(canonical).hexdigest()


def _read_bounded_json(path: Path, label: str) -> Mapping[str, Any]:
    if not _is_regular_non_symlink(path):
        raise SafeInitError("%s is missing or unsafe" % label)
    try:
        file_stat = path.lstat()
        if file_stat.st_size <= 0 or file_stat.st_size > MAX_STATE_JSON_BYTES:
            raise SafeInitError("%s has an unsafe size" % label)
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SafeInitError("%s is invalid" % label) from exc
    if not isinstance(value, Mapping):
        raise SafeInitError("%s is invalid" % label)
    return value


def _private_file_is_secure(path: Path) -> bool:
    if not _is_regular_non_symlink(path):
        return False
    try:
        file_stat = path.lstat()
    except OSError:
        return False
    if hasattr(os, "getuid") and file_stat.st_uid != os.getuid():
        return False
    return stat.S_IMODE(file_stat.st_mode) & 0o077 == 0


def inspect_existing_private_state(
    private_dir: Path,
    candidates: Sequence[AccountCandidate],
    *,
    account_ref: Optional[str] = None,
) -> Mapping[str, Any]:
    """Inspect shared runtime plus only the selected account's saved key state."""

    result: Dict[str, Any] = {
        "present": False,
        "initialized": False,
        "runtime_cleanup_required": False,
        "runtime_state": "absent",
        "owned_runtime_count": 0,
        "orphaned_runtime_count": 0,
        "salt_state": "not-initialized",
        "matching_account_ref": None,
        "initialized_targets": [],
        "state_scope": "absent",
        "legacy_state": "absent",
        "legacy_exact_validated": False,
    }
    expanded = private_dir.expanduser()
    if not expanded.exists() and not expanded.is_symlink():
        return result
    if not expanded.is_absolute() or expanded.is_symlink() or not _is_directory_non_symlink(expanded):
        return {**result, "present": True, "runtime_state": "unsafe", "salt_state": "unsafe"}
    try:
        resolved = expanded.resolve(strict=True)
        directory_stat = resolved.lstat()
    except OSError:
        return {**result, "present": True, "runtime_state": "unsafe", "salt_state": "unsafe"}
    if (
        (hasattr(os, "getuid") and directory_stat.st_uid != os.getuid())
        or stat.S_IMODE(directory_stat.st_mode) & 0o077
    ):
        return {**result, "present": True, "runtime_state": "unsafe", "salt_state": "unsafe"}

    result["present"] = True
    runtime_path = resolved / RUNTIME_FILENAME
    runtime: Optional[Mapping[str, Any]] = None
    if runtime_path.exists() or runtime_path.is_symlink():
        try:
            runtime = _read_bounded_json(runtime_path, "runtime metadata")
            if runtime.get("owner") != "wechat_key_init.py" or runtime.get("schema_version") != 1:
                result["runtime_state"] = "unsafe"
            else:
                status = runtime.get("status")
                result["runtime_state"] = status if isinstance(status, str) else "unsafe"
                result["runtime_cleanup_required"] = status != "cleaned"
        except SafeInitError:
            result["runtime_state"] = "unsafe"

    try:
        owned_runtimes = discover_owned_runtime_directories(resolved)
    except SafeInitError:
        result["runtime_state"] = "unsafe"
        result["runtime_cleanup_required"] = True
        owned_runtimes = ()
    result["owned_runtime_count"] = len(owned_runtimes)
    if owned_runtimes:
        recorded_matches: Tuple[OwnedRuntimeDirectory, ...] = ()
        if runtime is not None:
            runtime_value = runtime.get("runtime_dir")
            run_id = runtime.get("run_id")
            if isinstance(runtime_value, str) and isinstance(run_id, str):
                recorded_matches = tuple(
                    item
                    for item in owned_runtimes
                    if str(item.runtime_dir) == runtime_value and item.run_id == run_id
                )
        if len(recorded_matches) != 1 or len(owned_runtimes) != 1:
            result["orphaned_runtime_count"] = len(owned_runtimes) - len(recorded_matches)
            result["runtime_state"] = "orphaned-or-unreconciled"
            result["runtime_cleanup_required"] = True
    elif result["runtime_state"] not in ("absent", "cleaned", "unsafe"):
        result["runtime_state"] = "orphaned-or-unreconciled"
        result["runtime_cleanup_required"] = True

    selected: Optional[AccountCandidate] = None
    if isinstance(account_ref, str) and ACCOUNT_REF_RE.fullmatch(account_ref):
        selected = next(
            (item for item in candidates if item.account_ref == account_ref),
            None,
        )
    elif account_ref is None and len(candidates) == 1:
        # Compatibility for direct callers/tests; setup-doctor always passes the
        # account reference proven by the current-session router.
        selected = candidates[0]
        account_ref = selected.account_ref
    if selected is None:
        return result

    accounts_root = resolved / ACCOUNTS_DIRNAME
    scoped_dir = accounts_root / selected.account_ref
    accounts_present = accounts_root.exists() or accounts_root.is_symlink()
    accounts_stat: Optional[os.stat_result] = None
    if accounts_present:
        try:
            accounts_stat = accounts_root.lstat()
        except OSError:
            result["salt_state"] = "unsafe"
            return result
        if (
            accounts_root.is_symlink()
            or not stat.S_ISDIR(accounts_stat.st_mode)
            or (hasattr(os, "getuid") and accounts_stat.st_uid != os.getuid())
            or stat.S_IMODE(accounts_stat.st_mode) & 0o077
        ):
            result["salt_state"] = "unsafe"
            return result
    scoped_present = scoped_dir.exists() or scoped_dir.is_symlink()
    if scoped_present:
        try:
            scoped_stat = scoped_dir.lstat()
        except OSError:
            result["salt_state"] = "unsafe"
            return result
        if (
            scoped_dir.is_symlink()
            or not stat.S_ISDIR(scoped_stat.st_mode)
            or (hasattr(os, "getuid") and scoped_stat.st_uid != os.getuid())
            or stat.S_IMODE(scoped_stat.st_mode) & 0o077
        ):
            result["salt_state"] = "unsafe"
            return result
        return _inspect_saved_key_pair(
            result,
            scoped_dir,
            selected,
            schema_version=2,
            legacy=False,
        )

    legacy_keys = resolved / KEYS_FILENAME
    legacy_config = resolved / CONFIG_FILENAME
    if not (
        legacy_keys.exists()
        or legacy_keys.is_symlink()
        or legacy_config.exists()
        or legacy_config.is_symlink()
    ):
        return result
    return _inspect_saved_key_pair(
        result,
        resolved,
        selected,
        schema_version=1,
        legacy=True,
    )


def _inspect_saved_key_pair(
    result: Dict[str, Any],
    state_dir: Path,
    selected: AccountCandidate,
    *,
    schema_version: int,
    legacy: bool,
) -> Mapping[str, Any]:
    """Validate one fixed key/config pair without following a configured path."""

    keys_path = state_dir / KEYS_FILENAME
    config_path = state_dir / CONFIG_FILENAME
    keys_present = keys_path.exists() or keys_path.is_symlink()
    config_present = config_path.exists() or config_path.is_symlink()
    if legacy:
        result["legacy_state"] = "present"
    if not (
        keys_present
        and config_present
        and _private_file_is_secure(keys_path)
        and _private_file_is_secure(config_path)
    ):
        result["salt_state"] = "unsafe-or-incomplete"
        return result

    try:
        config = _read_bounded_json(config_path, "initializer configuration")
    except SafeInitError:
        result["salt_state"] = "unsafe-or-incomplete"
        return result

    if config.get("schema_version") != schema_version:
        result["salt_state"] = "unsafe-or-incomplete"
        return result
    if not legacy and config.get("account_ref") != selected.account_ref:
        result["salt_state"] = "unsafe-or-incomplete"
        return result

    db_base_value = config.get("db_base_path")
    if not isinstance(db_base_value, str) or db_base_value != str(selected.db_base):
        if legacy:
            # A root-level profile for another historical account is ignored;
            # it is never migrated, selected, overwritten or treated as ready.
            result["legacy_state"] = "different-account-ignored"
            result["salt_state"] = "not-initialized"
            return result
        result["salt_state"] = "unsafe-or-incomplete"
        return result

    try:
        keys = _read_bounded_json(keys_path, "initializer key file")
    except SafeInitError:
        result["salt_state"] = "unsafe-or-incomplete"
        return result

    configured_targets = config.get("targets")
    configured_aliases: set[str] = set()
    if isinstance(configured_targets, Mapping):
        for name, relative in configured_targets.items():
            if not isinstance(name, str) or not isinstance(relative, str):
                configured_aliases.clear()
                break
            try:
                if target_relative_path(name) != relative:
                    configured_aliases.clear()
                    break
            except SafeInitError:
                configured_aliases.clear()
                break
            configured_aliases.add(name)
    key_aliases = {
        name
        for name, value in keys.items()
        if isinstance(name, str)
        and isinstance(value, str)
        and TARGET_RE.fullmatch(name)
        and re.fullmatch(r"[0-9a-f]{64}", value)
    }
    if (
        not configured_aliases
        or key_aliases != configured_aliases
        or len(key_aliases) != len(keys)
        or (
            "target_count" in config
            and config.get("target_count") != len(configured_aliases)
        )
    ):
        result["salt_state"] = "unsafe-or-incomplete"
        return result
    if not legacy and config.get("keys_file") != str(keys_path):
        result["salt_state"] = "unsafe-or-incomplete"
        return result

    result["initialized"] = True
    result["initialized_targets"] = sorted(configured_aliases)
    result["matching_account_ref"] = selected.account_ref
    result["state_scope"] = "legacy-root" if legacy else "account-scoped"
    if legacy:
        result["legacy_state"] = "exact-account"
    if any(name not in selected.targets for name in configured_aliases):
        result["salt_state"] = (
            "legacy-validation-failed" if legacy else "target-set-changed"
        )
        return result

    stored = config.get("salt_fingerprints")
    if isinstance(stored, Mapping) and stored:
        normalized_stored = {
            name: value
            for name, value in stored.items()
            if isinstance(name, str)
            and isinstance(value, str)
            and re.fullmatch(r"[0-9a-f]{64}", value)
        }
        expected = {
            name: hashlib.sha256(selected.targets[name].salt).hexdigest()
            for name in configured_aliases
        }
        if set(normalized_stored) != configured_aliases or len(normalized_stored) != len(stored):
            result["salt_state"] = "target-set-changed"
        elif normalized_stored == expected:
            result["salt_state"] = "match"
        else:
            result["salt_state"] = "changed"
        return result

    if not legacy:
        result["salt_state"] = "unsafe-or-incomplete"
        result["initialized"] = False
        return result

    # Some early schema-1 profiles intentionally lacked salt fingerprints.
    # They are usable only when every configured key still decrypts the current
    # exact target's first page through the existing structural gate.
    for name in sorted(configured_aliases):
        key_value = keys.get(name)
        if not isinstance(key_value, str) or not validate_first_page(
            selected.targets[name].path,
            bytes.fromhex(key_value),
        ):
            result["salt_state"] = "legacy-validation-failed"
            return result
    result["salt_state"] = "validated-legacy"
    result["legacy_exact_validated"] = True
    return result


def _wechat_version(app: WeChatApp) -> str:
    """Return the already validated 4.x version without reopening the bundle."""

    return app.version


def verify_app_signature(
    app: WeChatApp,
    *,
    runner: Runner = _default_runner,
) -> bool:
    try:
        result = runner(
            [
                "/usr/bin/codesign",
                "--verify",
                "--deep",
                "--strict",
                "-R=" + OFFICIAL_WECHAT_REQUIREMENT,
                str(app.app_path),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return False
    return result.returncode == 0


def require_official_wechat_signature(
    app: WeChatApp,
    *,
    runner: Runner = _default_runner,
) -> None:
    if not verify_app_signature(app, runner=runner):
        raise SafeInitError(
            "the WeChat app does not satisfy the pinned official signature identity"
        )


def official_app_cdhash(
    app: WeChatApp,
    *,
    runner: Runner = _default_runner,
) -> str:
    """Return one bounded code-directory hash for an already verified app."""

    try:
        result = runner(
            [
                "/usr/bin/codesign",
                "--display",
                "--verbose=4",
                str(app.app_path),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise SafeInitError("the official WeChat code identity could not be inspected") from exc
    if result.returncode != 0:
        raise SafeInitError("the official WeChat code identity could not be inspected")
    combined = "%s\n%s" % (result.stdout or "", result.stderr or "")
    matches = {
        value.lower()
        for value in re.findall(r"(?m)^CDHash=([0-9a-fA-F]{40,64})\s*$", combined)
    }
    if len(matches) != 1:
        raise SafeInitError("the official WeChat code identity is missing or ambiguous")
    return next(iter(matches))


def _setup_blocker(code: str, category: str) -> Mapping[str, str]:
    return {"code": code, "category": category}


def build_setup_doctor_report(
    *,
    app_path: Path = DEFAULT_WECHAT_APP,
    xwechat_root: Path = DEFAULT_XWECHAT_ROOT,
    private_dir: Path = DEFAULT_PRIVATE_DIR,
    runner: Runner = _default_runner,
) -> Mapping[str, Any]:
    """Build a read-only report scoped to the current official session only."""

    app: Optional[WeChatApp] = None
    application: Dict[str, Any] = {
        "status": "invalid-or-unavailable",
        "bundle_id": None,
        "version": None,
        "code_signature_valid": False,
        "official_signature_valid": False,
        "running": None,
        "process_state": "not-checked",
    }
    try:
        app = validate_wechat_app(app_path)
        official_signature_valid = verify_app_signature(app, runner=runner)
        application.update(
            {
                "status": "validated",
                "bundle_id": app.bundle_id,
                "version": _wechat_version(app),
                "code_signature_valid": official_signature_valid,
                "official_signature_valid": official_signature_valid,
            }
        )
        try:
            application["running"] = original_wechat_is_running(app, runner=runner)
            application["process_state"] = (
                "running" if application["running"] else "stopped"
            )
        except SafeInitError:
            application["process_state"] = "unavailable"
    except SafeInitError:
        pass

    account_ref: Optional[str] = None
    current_account: Mapping[str, Any] = _redacted_current_account_report("unavailable")
    routing_failure: Optional[str] = "unavailable"
    selected: Optional[AccountCandidate] = None
    storage_status = "not-audited"
    storage_reason: Optional[str] = None
    if (
        app is not None
        and application["official_signature_valid"]
        and application["process_state"] == "running"
    ):
        account_ref, current_account, routing_failure = _route_current_account(
            app_path=app.app_path,
            xwechat_root=xwechat_root,
            runner=runner,
        )
        if account_ref is not None and routing_failure is None:
            try:
                selected = resolve_account_candidate(account_ref, xwechat_root)
                storage_status = "readable"
            except SafeInitError:
                account_ref = None
                selected = None
                routing_failure = "unstable"
                current_account = _redacted_current_account_report(
                    "unstable", samples_completed=2
                )
                storage_status = "unavailable"
                storage_reason = "the bound account storage changed during inspection"
    elif application["process_state"] == "stopped":
        routing_failure = "no-active-account"
        current_account = _redacted_current_account_report("no-active-account")

    selected_candidates = (selected,) if selected is not None else ()
    private_state = inspect_existing_private_state(
        private_dir,
        selected_candidates,
        account_ref=account_ref,
    )
    dependencies = dict(dependency_status())
    platform_supported = sys.platform == "darwin"
    existing_initialization_ready = bool(
        platform_supported
        and application["official_signature_valid"]
        and account_ref is not None
        and selected is not None
        and storage_status == "readable"
        and dependencies.get("pycryptodome")
        and private_state["initialized"]
        and private_state["salt_state"] in ("match", "validated-legacy")
        and private_state["runtime_state"] != "unsafe"
        and not private_state["runtime_cleanup_required"]
    )

    blockers: List[Mapping[str, str]] = []
    if private_state["runtime_cleanup_required"]:
        blockers.append(_setup_blocker("temporary-copy-cleanup-required", "safety"))
    if private_state["runtime_state"] == "unsafe" or private_state["salt_state"] in (
        "unsafe",
        "unsafe-or-incomplete",
        "changed",
        "target-set-changed",
    ):
        blockers.append(_setup_blocker("private-state-requires-resolution", "safety"))
    if not platform_supported:
        blockers.append(_setup_blocker("unsupported-platform", "prerequisite"))
    if application["status"] != "validated":
        blockers.append(_setup_blocker("wechat-4x-validation-failed", "prerequisite"))
    elif not application["official_signature_valid"]:
        blockers.append(_setup_blocker("official-signature-invalid", "prerequisite"))
    if routing_failure is not None:
        blockers.append(_setup_blocker(routing_failure, "account-binding"))
    if storage_status == "unavailable":
        blockers.append(_setup_blocker("local-storage-unreadable", "prerequisite"))
    if not dependencies.get("pycryptodome"):
        blockers.append(_setup_blocker("missing-pycryptodome", "prerequisite"))
    if not existing_initialization_ready and not dependencies.get("frida"):
        blockers.append(_setup_blocker("missing-frida", "prerequisite"))
    if private_state["initialized"] and private_state["salt_state"] in (
        "legacy-validation-failed",
        "target-set-changed",
        "changed",
    ):
        blockers.append(_setup_blocker("initialization-refresh-required", "state"))

    prerequisites_ready = not any(
        item["category"] in ("safety", "prerequisite", "account-binding")
        for item in blockers
    )
    ready_for_dry_scan = bool(
        prerequisites_ready
        and not existing_initialization_ready
        and application["running"] is True
        and account_ref is not None
        and selected is not None
    )
    ready_for_capture = False

    blocker_codes = {item["code"] for item in blockers}
    if "temporary-copy-cleanup-required" in blocker_codes:
        next_action = "quit-temporary-copy-and-cleanup"
    elif blocker_codes.intersection(
        {
            "private-state-requires-resolution",
            "unsupported-platform",
            "wechat-4x-validation-failed",
            "official-signature-invalid",
            "local-storage-unreadable",
            "missing-pycryptodome",
            "missing-frida",
        }
    ):
        next_action = "resolve-reported-prerequisites"
    elif existing_initialization_ready:
        next_action = "use-existing-initialization"
    elif "initialization-refresh-required" in blocker_codes:
        next_action = "refresh-initialization"
    elif routing_failure is not None:
        next_action = "prepare-current-official-session"
    elif ready_for_dry_scan:
        next_action = "run-current-account-dry-scan"
    else:
        next_action = "resolve-reported-prerequisites"
    return {
        "schema_version": 2,
        "command": "setup-doctor",
        "mode": "read-only",
        "writes_performed": False,
        "backend": "development-source",
        "signed_companion": False,
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "architecture": platform.machine(),
            "supported": platform_supported,
        },
        "application": application,
        "local_storage": {
            "status": storage_status,
            "full_disk_access_readable": storage_status == "readable",
            "reason": storage_reason,
        },
        "dependencies": dependencies,
        "current_account": current_account,
        "account_ref": account_ref,
        "targets": [
            {
                "alias": name,
                "bytes": selected.targets[name].size,
                "mib": round(selected.targets[name].size / 1024 / 1024, 2),
            }
            for name in sorted(selected.targets)
        ]
        if selected is not None
        else [],
        "private_state": {
            name: value
            for name, value in private_state.items()
            if name != "matching_account_ref"
        },
        "blockers": blockers,
        "prerequisites_ready": prerequisites_ready,
        "ready_for_dry_scan": ready_for_dry_scan,
        "ready_for_capture": ready_for_capture,
        "existing_initialization_ready": existing_initialization_ready,
        "next_action": next_action,
    }


def _inspect_owned_runtime_directory(
    runtime_root: Path,
    candidate: Path,
) -> OwnedRuntimeDirectory:
    if (
        candidate.parent != runtime_root
        or not re.fullmatch(r"init-[A-Za-z0-9._-]{1,128}", candidate.name)
        or candidate.is_symlink()
        or not _is_directory_non_symlink(candidate)
    ):
        raise SafeInitError("the private runtime root contains an unsafe entry")
    try:
        candidate_stat = candidate.lstat()
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise SafeInitError("an owned runtime directory cannot be inspected") from exc
    if resolved.parent != runtime_root:
        raise SafeInitError("an owned runtime directory resolves outside its root")
    if (
        (hasattr(os, "getuid") and candidate_stat.st_uid != os.getuid())
        or stat.S_IMODE(candidate_stat.st_mode) & 0o077
    ):
        raise SafeInitError("an owned runtime directory is not private")

    marker_path = resolved / RUNTIME_OWNER_FILENAME
    if not _private_file_is_secure(marker_path):
        raise SafeInitError("an owned runtime marker is missing or unsafe")
    marker = _read_bounded_json(marker_path, "runtime ownership marker")
    run_id = marker.get("run_id")
    if (
        marker.get("owner") != "wechat_key_init.py"
        or marker.get("schema_version") != 1
        or not isinstance(run_id, str)
        or not re.fullmatch(r"[0-9a-f]{32}", run_id)
    ):
        raise SafeInitError("an owned runtime marker is invalid")
    return OwnedRuntimeDirectory(run_id=run_id, runtime_dir=resolved)


def discover_owned_runtime_directories(private_dir: Path) -> Tuple[OwnedRuntimeDirectory, ...]:
    """Bounded recovery scan for direct, marker-owned initializer runtimes."""

    runtime_root = private_dir / RUNTIME_DIRNAME
    if not runtime_root.exists() and not runtime_root.is_symlink():
        return ()
    if runtime_root.is_symlink() or not _is_directory_non_symlink(runtime_root):
        raise SafeInitError("the private runtime root is unsafe")
    try:
        resolved_root = runtime_root.resolve(strict=True)
        root_stat = resolved_root.lstat()
        entries = sorted(resolved_root.iterdir(), key=lambda value: value.name)
    except OSError as exc:
        raise SafeInitError("the private runtime root cannot be inspected safely") from exc
    if resolved_root.parent != private_dir:
        raise SafeInitError("the private runtime root resolves outside private state")
    if (
        (hasattr(os, "getuid") and root_stat.st_uid != os.getuid())
        or stat.S_IMODE(root_stat.st_mode) & 0o077
    ):
        raise SafeInitError("the private runtime root is not private")
    if len(entries) > MAX_RUNTIME_ENTRIES:
        raise SafeInitError("too many private runtime entries require recovery")
    return tuple(
        _inspect_owned_runtime_directory(resolved_root, entry) for entry in entries
    )


def _remove_fresh_runtime_directory(
    private_dir: Path,
    runtime_dir: Path,
    expected_run_id: str,
) -> None:
    """Remove only the directory created by the current prepare call."""

    try:
        runtime_root = (private_dir / RUNTIME_DIRNAME).resolve(strict=True)
        candidate = runtime_dir.resolve(strict=True)
        candidate_stat = candidate.lstat()
    except OSError as exc:
        raise SafeInitError("the fresh private runtime could not be verified for cleanup") from exc
    if (
        candidate.parent != runtime_root
        or not candidate.name.startswith("init-")
        or candidate.is_symlink()
        or not stat.S_ISDIR(candidate_stat.st_mode)
        or (hasattr(os, "getuid") and candidate_stat.st_uid != os.getuid())
    ):
        raise SafeInitError("the fresh private runtime failed its cleanup boundary")
    marker_path = candidate / RUNTIME_OWNER_FILENAME
    if marker_path.exists() or marker_path.is_symlink():
        owned = _inspect_owned_runtime_directory(runtime_root, candidate)
        if owned.run_id != expected_run_id:
            raise SafeInitError("the fresh private runtime ownership changed")
    try:
        shutil.rmtree(candidate)
    except OSError as exc:
        raise SafeInitError("the fresh private runtime could not be removed") from exc
    if candidate.exists() or candidate.is_symlink():
        raise SafeInitError("the fresh private runtime cleanup was incomplete")


def prepare_runtime_copy(
    app: WeChatApp,
    private_dir: Path,
    source_cdhash: str,
    *,
    runner: Runner = _default_runner,
    quiescence_check: Optional[Callable[[], None]] = None,
) -> PreparedRuntime:
    """Copy one unchanged official app, then ad-hoc sign it in private storage."""

    if not re.fullmatch(r"[0-9a-f]{40,64}", source_cdhash or ""):
        raise SafeInitError("the source WeChat code identity is invalid")

    runtime_root = private_dir / RUNTIME_DIRNAME
    try:
        runtime_root.mkdir(mode=0o700, exist_ok=True)
        os.chmod(runtime_root, 0o700)
    except OSError as exc:
        raise SafeInitError("the private runtime root could not be prepared") from exc
    if not _is_directory_non_symlink(runtime_root):
        raise SafeInitError("the private runtime root is unsafe")

    run_id = secrets.token_hex(16)
    try:
        runtime_dir = Path(tempfile.mkdtemp(prefix="init-", dir=str(runtime_root)))
        os.chmod(runtime_dir, 0o700)
    except OSError as exc:
        raise SafeInitError("a private random runtime directory could not be created") from exc

    app_copy = runtime_dir / "微信-keyinit.app"
    prepared = PreparedRuntime(
        run_id=run_id,
        runtime_dir=runtime_dir,
        app_copy_path=app_copy,
        executable_path=app_copy / "Contents/MacOS" / app.executable_name,
    )
    owner_record = {
        "schema_version": 1,
        "owner": "wechat_key_init.py",
        "run_id": run_id,
        "created_at": utc_now(),
    }
    try:
        atomic_write_json(runtime_dir / RUNTIME_OWNER_FILENAME, owner_record)
        shutil.copytree(app.app_path, app_copy, symlinks=True, copy_function=shutil.copy2)
        if quiescence_check is not None:
            quiescence_check()
        copied_official_app = validate_wechat_app(app_copy)
        require_official_wechat_signature(copied_official_app, runner=runner)
        copied_cdhash = official_app_cdhash(copied_official_app, runner=runner)
        if not secrets.compare_digest(source_cdhash, copied_cdhash):
            raise SafeInitError(
                "the copied WeChat code identity changed before private signing"
            )
        result = runner(
            ["/usr/bin/codesign", "--force", "--deep", "--sign", "-", str(app_copy)],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise SafeInitError("ad-hoc signing the private WeChat copy failed")
        verification = runner(
            ["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app_copy)],
            capture_output=True,
            text=True,
            check=False,
        )
        if verification.returncode != 0:
            raise SafeInitError("strict verification of the private WeChat copy failed")
        copied_app = validate_wechat_app(app_copy)
        if quiescence_check is not None:
            quiescence_check()
        prepared = PreparedRuntime(
            run_id=run_id,
            runtime_dir=runtime_dir,
            app_copy_path=app_copy,
            executable_path=copied_app.executable_path,
        )
        # Persist recovery metadata inside the prepare transaction. If this
        # write fails, the fresh runtime is removed and verified before the
        # error leaves this function.
        atomic_write_json(
            private_dir / RUNTIME_FILENAME,
            runtime_metadata(prepared, status="prepared", pid=None),
        )
    except BaseException as exc:
        try:
            _remove_fresh_runtime_directory(private_dir, runtime_dir, run_id)
        except SafeInitError as cleanup_exc:
            raise SafeInitError(
                "private runtime preparation failed and owned cleanup requires recovery"
            ) from cleanup_exc
        # If an atomic metadata replace completed immediately before an
        # interruption, reconcile it with the verified removal.
        try:
            atomic_write_json(
                private_dir / RUNTIME_FILENAME,
                {
                    "schema_version": 1,
                    "owner": "wechat_key_init.py",
                    "run_id": run_id,
                    "status": "cleaned",
                    "updated_at": utc_now(),
                    "pid": None,
                    "runtime_dir": None,
                    "app_copy_path": None,
                    "executable_path": None,
                    "missing_targets": [],
                    "normal_quit_required": False,
                },
            )
        except SafeInitError:
            # The owned runtime is already verified absent; stale metadata is
            # fail-closed and will be reported by doctor.
            pass
        if isinstance(exc, SafeInitError):
            raise
        if isinstance(exc, (KeyboardInterrupt, SystemExit, GeneratorExit)):
            raise
        raise SafeInitError("the private WeChat copy could not be prepared safely") from exc

    return prepared


def build_frida_script(targets: Mapping[str, TargetDB]) -> str:
    """Build a memory-only Frida hook filtered to exact target salts."""

    targets_by_salt = {target.salt.hex(): [name] for name, target in targets.items()}
    encoded_targets = json.dumps(targets_by_salt, sort_keys=True, separators=(",", ":"))
    return r"""
'use strict';

const TARGETS_BY_SALT = Object.freeze(__TARGETS_BY_SALT__);
const seen = Object.create(null);
let installed = false;
let moduleObserver = null;

function bytesToHex(pointer, length, maximum) {
  if (pointer.isNull() || length <= 0 || length > maximum) return null;
  try {
    const data = new Uint8Array(pointer.readByteArray(length));
    let result = '';
    for (let index = 0; index < data.length; index++) {
      result += ('0' + data[index].toString(16)).slice(-2);
    }
    return result;
  } catch (_) {
    return null;
  }
}

function installAt(address) {
  if (installed) return;
  Interceptor.attach(address, {
    onEnter(args) {
      this.passwordLength = args[2].toUInt32();
      this.passwordPointer = args[1];
      this.saltLength = args[4].toUInt32();
      this.salt = bytesToHex(args[3], this.saltLength, 16);
      this.prf = args[5].toInt32();
      this.rounds = args[6].toUInt32();
      this.derivedKey = args[7];
      this.derivedKeyLength = args[8].toUInt32();
    },
    onLeave(retval) {
      if (retval.toInt32() !== 0) return;
      if (this.saltLength !== 16) return;
      const salt = this.salt;
      if (!salt || !Object.prototype.hasOwnProperty.call(TARGETS_BY_SALT, salt)) return;
      if (this.derivedKeyLength < 32 || this.derivedKeyLength > 128) return;
      const derivedKey = bytesToHex(this.derivedKey, this.derivedKeyLength, 128);
      if (!derivedKey) return;
      const password = bytesToHex(this.passwordPointer, this.passwordLength, 256);
      const identity = salt + ':' + derivedKey + ':' + (password || '');
      if (seen[identity]) return;
      seen[identity] = true;
      send({
        type: 'pbkdf2',
        salt: salt,
        targets: TARGETS_BY_SALT[salt],
        rounds: this.rounds,
        prf: this.prf,
        derived_key_length: this.derivedKeyLength,
        derived_key: derivedKey,
        password_length: this.passwordLength,
        password: password
      });
    }
  });
  installed = true;
  if (moduleObserver !== null) {
    moduleObserver.detach();
    moduleObserver = null;
  }
  send({type: 'status', code: 'hook-installed'});
}

function inspectModule(module) {
  if (installed) return;
  let exportsList;
  try {
    exportsList = module.enumerateExports();
  } catch (_) {
    return;
  }
  for (let exportIndex = 0; exportIndex < exportsList.length; exportIndex++) {
    if (exportsList[exportIndex].name === 'CCKeyDerivationPBKDF') {
      installAt(exportsList[exportIndex].address);
      return;
    }
  }
}

send({type: 'status', code: 'script-loaded'});
moduleObserver = Process.attachModuleObserver({
  onAdded(module) {
    inspectModule(module);
  }
});
""".replace("__TARGETS_BY_SALT__", encoded_targets)


def _decode_hex(value: Any, maximum_bytes: int) -> Optional[bytes]:
    if not isinstance(value, str) or len(value) % 2 or len(value) > maximum_bytes * 2:
        return None
    try:
        return bytes.fromhex(value)
    except ValueError:
        return None


def candidate_keys_from_row(row: Mapping[str, Any]) -> Tuple[bytes, ...]:
    """Extract 32-byte candidates without retaining a raw PBKDF row."""

    candidates: List[bytes] = []
    derived_key = _decode_hex(row.get("derived_key"), 128)
    if derived_key is not None and len(derived_key) >= 32:
        candidates.append(derived_key[:32])

    password = _decode_hex(row.get("password"), 256)
    if password is not None:
        if len(password) == 32:
            candidates.append(password)
        raw_match = RAW_KEY_RE.fullmatch(password)
        if raw_match:
            candidates.append(bytes.fromhex(raw_match.group(1).decode("ascii")))

    unique: List[bytes] = []
    for candidate in candidates:
        if candidate not in unique:
            unique.append(candidate)
    return tuple(unique)


def validate_first_page(path: Path, key: bytes) -> bool:
    """Validate a 32-byte candidate against one SQLCipher 4 first page."""

    if len(key) != 32:
        return False
    try:
        from Crypto.Cipher import AES  # type: ignore

        with path.open("rb") as handle:
            page = handle.read(PAGE_SIZE)
        if len(page) != PAGE_SIZE:
            return False
        encrypted_start = 16
        encrypted_size = PAGE_SIZE - RESERVE_SIZE - encrypted_start
        iv_start = PAGE_SIZE - RESERVE_SIZE
        iv = page[iv_start : iv_start + IV_SIZE]
        decrypted = AES.new(key, AES.MODE_CBC, iv).decrypt(
            page[encrypted_start : encrypted_start + encrypted_size]
        )
        rebuilt = bytearray(PAGE_SIZE)
        rebuilt[:16] = SQLITE_HEADER
        rebuilt[16 : 16 + len(decrypted)] = decrypted
        return (
            struct.unpack(">H", rebuilt[16:18])[0] == PAGE_SIZE
            and rebuilt[18] in (1, 2)
            and rebuilt[19] in (1, 2)
            and rebuilt[20] == RESERVE_SIZE
            and rebuilt[21] == 64
            and rebuilt[22] == 32
            and rebuilt[23] == 32
        )
    except (OSError, ValueError, ImportError):
        return False


def match_pbkdf_row(
    row: Mapping[str, Any],
    targets: Mapping[str, TargetDB],
    matched: Dict[str, str],
) -> Tuple[str, ...]:
    """Match one row only to targets with its exact salt."""

    salt = _decode_hex(row.get("salt"), 16)
    if salt is None or len(salt) != 16:
        return ()
    exact_targets = [target for target in targets.values() if target.salt == salt]
    if not exact_targets:
        return ()

    newly_matched: List[str] = []
    candidates = candidate_keys_from_row(row)
    for target in exact_targets:
        if target.name in matched:
            continue
        for candidate in candidates:
            if validate_first_page(target.path, candidate):
                matched[target.name] = candidate.hex()
                newly_matched.append(target.name)
                break
    return tuple(newly_matched)


def capture_keys(
    frida_module: Any,
    runtime: PreparedRuntime,
    targets: Mapping[str, TargetDB],
    duration: int,
    *,
    pre_spawn: Optional[Callable[[], None]] = None,
    on_pid: Optional[Callable[[int], None]] = None,
) -> CaptureResult:
    """Spawn the private copy and keep PBKDF material only in process memory."""

    matched: Dict[str, str] = {}
    lock = threading.Lock()
    finished = threading.Event()
    hook_errors: List[str] = []
    device = None
    session = None
    script = None
    pid = 0
    resumed = False

    def on_message(message: Mapping[str, Any], _data: Any) -> None:
        if message.get("type") == "error":
            hook_errors.append("instrumentation-script-error")
            finished.set()
            return
        if message.get("type") != "send":
            return
        payload = message.get("payload")
        if not isinstance(payload, Mapping):
            return
        payload_type = payload.get("type")
        if payload_type == "hook-error":
            hook_errors.append("pbkdf-hook-unavailable")
            finished.set()
            return
        if payload_type != "pbkdf2":
            return
        with lock:
            new_names = match_pbkdf_row(payload, targets, matched)
            for name in new_names:
                print("  validated exact target: %s" % name, flush=True)
            if len(matched) == len(targets):
                finished.set()

    def on_detached(*_args: Any) -> None:
        if not finished.is_set():
            hook_errors.append("wechat-copy-detached-before-capture-finished")
            finished.set()

    try:
        device = frida_module.get_local_device()
        if pre_spawn is not None:
            pre_spawn()
        pid = int(device.spawn(str(runtime.executable_path)))
        if pid <= 0:
            raise SafeInitError("the private WeChat copy did not return a valid PID")
        if on_pid is not None:
            on_pid(pid)
        session = device.attach(pid)
        if hasattr(session, "on"):
            session.on("detached", on_detached)
        script = session.create_script(build_frida_script(targets))
        script.on("message", on_message)
        script.load()
        device.resume(pid)
        resumed = True

        deadline = time.monotonic() + duration
        while not finished.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            finished.wait(min(0.25, remaining))
    except Exception as exc:
        if device is not None and pid > 0 and not resumed:
            try:
                device.kill(pid)
            except Exception:
                pass
        if isinstance(exc, SafeInitError):
            raise
        raise SafeInitError(
            "Frida could not launch or attach to the private WeChat copy; cleanup metadata was retained"
        ) from exc
    finally:
        if script is not None:
            try:
                script.unload()
            except Exception:
                pass
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass

    if hook_errors:
        raise SafeInitError("the PBKDF hook failed; cleanup metadata was retained")
    missing = tuple(name for name in targets if name not in matched)
    return CaptureResult(pid=pid, matched_keys=dict(matched), missing_targets=missing)


def runtime_metadata(
    runtime: PreparedRuntime,
    *,
    status: str,
    pid: Optional[int],
    missing_targets: Sequence[str] = (),
) -> Mapping[str, Any]:
    return {
        "schema_version": 1,
        "owner": "wechat_key_init.py",
        "run_id": runtime.run_id,
        "status": status,
        "updated_at": utc_now(),
        "pid": pid,
        "runtime_dir": str(runtime.runtime_dir),
        "app_copy_path": str(runtime.app_copy_path),
        "executable_path": str(runtime.executable_path),
        "missing_targets": list(missing_targets),
        "normal_quit_required": status not in ("cleaned",),
    }


def ensure_no_owned_runtime(private_dir: Path) -> None:
    owned_runtimes = discover_owned_runtime_directories(private_dir)
    if owned_runtimes:
        raise SafeInitError(
            "one or more previous private copies require normal quit and cleanup"
        )
    metadata_path = private_dir / RUNTIME_FILENAME
    if not metadata_path.exists() and not metadata_path.is_symlink():
        return
    if not _is_regular_non_symlink(metadata_path):
        raise SafeInitError("existing runtime metadata is unsafe")
    try:
        with metadata_path.open("r", encoding="utf-8") as handle:
            metadata = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise SafeInitError("existing runtime metadata is invalid") from exc
    if not isinstance(metadata, Mapping):
        raise SafeInitError("existing runtime metadata is invalid")
    if metadata.get("owner") != "wechat_key_init.py" or metadata.get("schema_version") != 1:
        raise SafeInitError("existing runtime metadata is unsafe")
    if metadata.get("status") == "cleaned":
        return
    raise SafeInitError("existing runtime metadata requires recovery before capture")


def write_success_files(
    private_dir: Path,
    db_base: Path,
    targets: Mapping[str, TargetDB],
    matched_keys: Mapping[str, str],
    *,
    account_ref: Optional[str] = None,
) -> None:
    if set(matched_keys) != set(targets):
        raise SafeInitError("refusing to write a partial key set")
    if any(
        not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)
        for value in matched_keys.values()
    ):
        raise SafeInitError("refusing to write an invalid key set")

    state_dir = private_dir
    schema_version = 1
    if account_ref is not None:
        state_dir = ensure_account_state_dir(private_dir, account_ref, create=True)
        schema_version = 2
    keys_data = {name: matched_keys[name] for name in sorted(matched_keys)}
    config_data = {
        "schema_version": schema_version,
        "initialized_at": utc_now(),
        "db_base_path": str(db_base),
        "keys_file": str(state_dir / KEYS_FILENAME),
        "targets": {
            name: targets[name].relative_path for name in sorted(targets)
        },
        "salt_fingerprints": {
            name: hashlib.sha256(targets[name].salt).hexdigest()
            for name in sorted(targets)
        },
    }
    if account_ref is not None:
        config_data["account_ref"] = account_ref
    atomic_write_json(state_dir / KEYS_FILENAME, keys_data)
    atomic_write_json(state_dir / CONFIG_FILENAME, config_data)


def pid_exists(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return True
    return True


def runtime_directory_process_is_running(
    runtime_dir: Path,
    *,
    runner: Runner = _default_runner,
) -> bool:
    """Check for any process launched from one exact owned runtime directory."""

    pattern = re.escape(str(runtime_dir)) + "/"
    try:
        result = runner(
            ["/usr/bin/pgrep", "-f", pattern],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise SafeInitError("an owned runtime process state could not be checked") from exc
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    raise SafeInitError("an owned runtime process state could not be checked safely")


def _load_runtime_for_cleanup(private_dir: Path) -> Tuple[Mapping[str, Any], Path]:
    metadata_path = private_dir / RUNTIME_FILENAME
    if not _is_regular_non_symlink(metadata_path):
        raise SafeInitError("private runtime metadata is missing or unsafe")
    try:
        with metadata_path.open("r", encoding="utf-8") as handle:
            metadata = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise SafeInitError("private runtime metadata is invalid") from exc
    if not isinstance(metadata, Mapping):
        raise SafeInitError("private runtime metadata is invalid")
    if metadata.get("owner") != "wechat_key_init.py" or metadata.get("schema_version") != 1:
        raise SafeInitError("private runtime metadata has an unknown owner")
    run_id = metadata.get("run_id")
    runtime_value = metadata.get("runtime_dir")
    if not isinstance(run_id, str) or not re.fullmatch(r"[0-9a-f]{32}", run_id):
        raise SafeInitError("private runtime metadata has an invalid run id")
    if not isinstance(runtime_value, str) or not Path(runtime_value).is_absolute():
        raise SafeInitError("private runtime metadata has an invalid runtime directory")

    try:
        runtime_root = (private_dir / RUNTIME_DIRNAME).resolve(strict=True)
    except OSError as exc:
        raise SafeInitError("the private runtime root is missing or unsafe") from exc
    if not _is_directory_non_symlink(runtime_root):
        raise SafeInitError("the private runtime root is missing or unsafe")
    runtime_original = Path(runtime_value)
    if runtime_original.is_symlink() or not _is_directory_non_symlink(runtime_original):
        raise SafeInitError("the recorded runtime directory is missing or unsafe")
    try:
        runtime_dir = runtime_original.resolve(strict=True)
    except OSError as exc:
        raise SafeInitError("the recorded runtime directory cannot be resolved") from exc
    if runtime_dir.parent != runtime_root or not runtime_dir.name.startswith("init-"):
        raise SafeInitError("the recorded runtime directory is outside the owned runtime root")

    owner_path = runtime_dir / RUNTIME_OWNER_FILENAME
    if not _is_regular_non_symlink(owner_path):
        raise SafeInitError("the runtime ownership marker is missing or unsafe")
    try:
        with owner_path.open("r", encoding="utf-8") as handle:
            owner = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise SafeInitError("the runtime ownership marker is invalid") from exc
    if not isinstance(owner, Mapping):
        raise SafeInitError("the runtime ownership marker is invalid")
    if owner.get("owner") != "wechat_key_init.py" or owner.get("run_id") != run_id:
        raise SafeInitError("the runtime ownership marker does not match the recorded run")
    return metadata, runtime_dir


def cleanup_owned_runtime(
    private_dir: Path,
    *,
    runner: Runner = _default_runner,
) -> int:
    """Remove bounded marker-owned runtimes only after every process is gone."""

    owned_runtimes = discover_owned_runtime_directories(private_dir)
    metadata_path = private_dir / RUNTIME_FILENAME
    metadata: Optional[Mapping[str, Any]] = None
    recorded_runtime: Optional[Path] = None
    if metadata_path.exists() or metadata_path.is_symlink():
        metadata = _read_bounded_json(metadata_path, "runtime metadata")
        if metadata.get("owner") != "wechat_key_init.py" or metadata.get("schema_version") != 1:
            raise SafeInitError("private runtime metadata has an unknown owner")

    if not owned_runtimes:
        if metadata is not None and metadata.get("status") == "cleaned":
            return 0
        if metadata is None:
            raise SafeInitError("no bounded marker-owned runtime is available for cleanup")
        # Recovery for the narrow case where owned deletion completed but the
        # final cleaned-metadata write failed. Nothing is deleted here: the
        # recorded path must be an absent direct child of the private runtime
        # root, and any recorded PID must already be gone.
        run_id = metadata.get("run_id")
        runtime_value = metadata.get("runtime_dir")
        status = metadata.get("status")
        pid = metadata.get("pid")
        expected_root = private_dir / RUNTIME_DIRNAME
        if (
            not isinstance(run_id, str)
            or not re.fullmatch(r"[0-9a-f]{32}", run_id)
            or not isinstance(runtime_value, str)
            or not Path(runtime_value).is_absolute()
            or Path(runtime_value).parent != expected_root
            or not re.fullmatch(r"init-[A-Za-z0-9._-]{1,128}", Path(runtime_value).name)
            or Path(runtime_value).exists()
            or Path(runtime_value).is_symlink()
        ):
            raise SafeInitError("stale runtime metadata is not safely recoverable")
        if isinstance(pid, int) and pid > 0:
            if pid_exists(pid):
                raise SafeInitError(
                    "the recorded WeChat copy process may still be running"
                )
        elif pid is None and status in {
            "prepared",
            "prepare-error",
            "capture-error",
            "aborted-before-launch",
        }:
            pass
        else:
            raise SafeInitError("stale runtime metadata has an unsafe PID/status combination")
        reconciled = dict(metadata)
        reconciled.update(
            {
                "status": "cleaned",
                "updated_at": utc_now(),
                "pid": None,
                "runtime_dir": None,
                "app_copy_path": None,
                "executable_path": None,
                "normal_quit_required": False,
                "recovered_owned_runtime_count": 0,
            }
        )
        atomic_write_json(metadata_path, reconciled)
        return 0

    if metadata is not None and metadata.get("status") != "cleaned":
        metadata, recorded_runtime = _load_runtime_for_cleanup(private_dir)

    if recorded_runtime is not None and recorded_runtime not in {
        item.runtime_dir for item in owned_runtimes
    }:
        raise SafeInitError("recorded runtime metadata has no matching owned directory")
    if metadata is not None and metadata.get("status") != "cleaned":
        pid = metadata.get("pid")
        status = metadata.get("status")
        if isinstance(pid, int) and pid > 0:
            if pid_exists(pid):
                raise SafeInitError(
                    "the signed WeChat copy is still running; quit it normally first"
                )
        elif pid is None and status in {
            "prepared",
            "prepare-error",
            "capture-error",
            "aborted-before-launch",
        }:
            pass
        else:
            raise SafeInitError("cleanup metadata has an unsafe PID/status combination")

    for item in owned_runtimes:
        if runtime_directory_process_is_running(item.runtime_dir, runner=runner):
            raise SafeInitError(
                "a signed WeChat copy is still running; quit it normally before cleanup"
            )
    for item in owned_runtimes:
        _remove_fresh_runtime_directory(private_dir, item.runtime_dir, item.run_id)

    cleaned = dict(metadata or {})
    cleaned.update(
        {
            "schema_version": 1,
            "owner": "wechat_key_init.py",
            "status": "cleaned",
            "updated_at": utc_now(),
            "pid": None,
            "runtime_dir": None,
            "app_copy_path": None,
            "executable_path": None,
            "normal_quit_required": False,
            "recovered_owned_runtime_count": len(owned_runtimes),
        }
    )
    atomic_write_json(private_dir / RUNTIME_FILENAME, cleaned)
    return len(owned_runtimes)


def add_shared_capture_arguments(parser: argparse.ArgumentParser) -> None:
    account = parser.add_mutually_exclusive_group(required=True)
    account.add_argument(
        "--account-ref",
        help="Redacted account reference returned by setup-doctor",
    )
    account.add_argument(
        "--db-base",
        help="Development-only exact active account db_storage path",
    )
    parser.add_argument(
        "--targets",
        required=True,
        help=(
            "Exact comma-separated aliases, e.g. "
            "contact,message_0,media_0,message_resource"
        ),
    )
    parser.add_argument("--app", default=str(DEFAULT_WECHAT_APP), help="Mac WeChat .app path")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Safe one-time Mac WeChat 4.x key initializer"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor = subparsers.add_parser(
        "setup-doctor",
        aliases=["doctor"],
        help="Read-only setup diagnosis with redacted account references",
    )
    doctor.add_argument("--app", default=str(DEFAULT_WECHAT_APP), help="Mac WeChat .app path")

    dry = subparsers.add_parser(
        "dry-scan", help="Validate exact inputs without copying, launching, or writing"
    )
    add_shared_capture_arguments(dry)

    capture = subparsers.add_parser(
        "capture", help="Create a private signed copy and capture exact target keys"
    )
    add_shared_capture_arguments(capture)
    capture.add_argument(
        "--private-dir", default=str(DEFAULT_PRIVATE_DIR), help="Private 0700 state directory"
    )
    capture.add_argument("--duration", type=int, default=120, help="Capture timeout in seconds")
    capture.add_argument(
        "--approve-digest",
        required=True,
        type=parse_approval_digest,
        help="Exact 64-hex approval digest returned by the immediately preceding dry-scan",
    )

    cleanup = subparsers.add_parser(
        "cleanup", help="Remove only the recorded owned runtime after normal quit"
    )
    cleanup.add_argument(
        "--private-dir", default=str(DEFAULT_PRIVATE_DIR), help="Private 0700 state directory"
    )
    return parser


def requested_db_base(
    args: argparse.Namespace,
    *,
    xwechat_root: Path = DEFAULT_XWECHAT_ROOT,
) -> Path:
    db_base_value = getattr(args, "db_base", None)
    account_ref = getattr(args, "account_ref", None)
    if isinstance(account_ref, str) and account_ref:
        return resolve_account_ref(account_ref, xwechat_root)
    if isinstance(db_base_value, str) and db_base_value:
        return validate_db_base(Path(db_base_value), xwechat_root)
    raise SafeInitError("select one account reference returned by setup-doctor")


def run_setup_doctor(args: argparse.Namespace) -> int:
    report = build_setup_doctor_report(app_path=Path(args.app))
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return (
        0
        if report.get("ready_for_dry_scan")
        or report["ready_for_capture"]
        or report["existing_initialization_ready"]
        else 2
    )


def build_dry_scan_report(
    args: argparse.Namespace,
    *,
    xwechat_root: Path = DEFAULT_XWECHAT_ROOT,
    runner: Runner = _default_runner,
    holder_probe: Optional[Callable[[Sequence[Path]], Sequence[Any]]] = None,
) -> Mapping[str, Any]:
    """Build a no-write report and consent digest for one exact capture scope."""

    app = validate_wechat_app(Path(args.app))
    require_official_wechat_signature(app, runner=runner)
    dependencies = dict(dependency_status())
    blockers: List[Mapping[str, str]] = []
    requested_ref = getattr(args, "account_ref", None)
    explicit_db_base = getattr(args, "db_base", None)
    current_account: Mapping[str, Any]

    if isinstance(requested_ref, str) and requested_ref:
        bound_ref, current_account, routing_failure = _route_current_account(
            app_path=app.app_path,
            xwechat_root=xwechat_root,
            runner=runner,
        )
        if routing_failure is not None or bound_ref != requested_ref:
            blocker_code = routing_failure or "account-ref-mismatch"
            blockers.append(_setup_blocker(blocker_code, "account-binding"))
            return {
                "schema_version": 2,
                "command": "dry-scan",
                "mode": "read-only",
                "writes_performed": False,
                "application": {
                    "bundle_id": app.bundle_id,
                    "version": app.version,
                    "official_signature_valid": True,
                    "running": None,
                },
                "current_account": current_account,
                "account_ref": requested_ref,
                "targets": [],
                "dependencies": dependencies,
                "database_holders": {"status": "not-checked", "holder_count": None},
                "blockers": blockers,
                "prerequisites_ready": False,
                "ready_for_capture": False,
                "authorization_summary_usable": False,
                "next_action": "rerun-setup-doctor-current-account",
                "approval_digest": None,
            }
        running: Optional[bool] = True
        try:
            db_base = resolve_account_candidate(requested_ref, xwechat_root).db_base
        except SafeInitError:
            blockers.append(_setup_blocker("unstable", "account-binding"))
            return {
                "schema_version": 2,
                "command": "dry-scan",
                "mode": "read-only",
                "writes_performed": False,
                "application": {
                    "bundle_id": app.bundle_id,
                    "version": app.version,
                    "official_signature_valid": True,
                    "running": None,
                },
                "current_account": _redacted_current_account_report(
                    "unstable", samples_completed=2
                ),
                "account_ref": requested_ref,
                "targets": [],
                "dependencies": dependencies,
                "database_holders": {"status": "not-checked", "holder_count": None},
                "blockers": blockers,
                "prerequisites_ready": False,
                "ready_for_capture": False,
                "authorization_summary_usable": False,
                "next_action": "rerun-setup-doctor-current-account",
                "approval_digest": None,
            }
    elif isinstance(explicit_db_base, str) and explicit_db_base:
        db_base = validate_db_base(Path(explicit_db_base), xwechat_root)
        current_account = {
            "status": "development-explicit",
            "selected": True,
            "method": "explicit-development-path",
            "writes_performed": False,
        }
        try:
            running = original_wechat_is_running(app, runner=runner)
        except SafeInitError:
            running = None
            blockers.append(
                _setup_blocker("wechat-process-state-unavailable", "prerequisite")
            )
    else:
        raise SafeInitError("select one account reference returned by setup-doctor")

    target_names = parse_targets(args.targets)
    targets = inspect_targets(db_base, target_names)
    cdhash = official_app_cdhash(app, runner=runner)

    try:
        holder_status: Mapping[str, Any] = inspect_target_database_holders(
            targets, holder_probe=holder_probe
        )
    except SafeInitError:
        holder_status = {"status": "unavailable", "holder_count": None}
        blockers.append(_setup_blocker("database-holder-check-unavailable", "prerequisite"))

    for dependency_name, present in dependencies.items():
        if not present:
            blockers.append(
                _setup_blocker("missing-%s" % dependency_name, "prerequisite")
            )
    if running is True:
        blockers.append(_setup_blocker("official-wechat-running", "transition"))
    if holder_status["status"] == "held":
        blockers.append(_setup_blocker("target-databases-held", "transition"))

    prerequisites_ready = not any(
        item["category"] == "prerequisite" for item in blockers
    )
    ready_for_capture = bool(
        prerequisites_ready
        and running is False
        and holder_status["status"] == "clear"
    )
    blocker_codes = {item["code"] for item in blockers}
    if blocker_codes.intersection({"missing-frida", "missing-pycryptodome"}):
        next_action = "install-capture-dependencies"
    elif "wechat-process-state-unavailable" in blocker_codes:
        next_action = "resolve-process-state"
    elif "database-holder-check-unavailable" in blocker_codes:
        next_action = "resolve-database-holder-check"
    elif running is True:
        next_action = "request-consent-then-quit-official-wechat"
    elif holder_status["status"] == "held":
        next_action = "release-target-database-holders"
    else:
        next_action = "request-explicit-capture-consent"

    return {
        "schema_version": 2,
        "command": "dry-scan",
        "mode": "read-only",
        "writes_performed": False,
        "application": {
            "bundle_id": app.bundle_id,
            "version": app.version,
            "official_signature_valid": True,
            "running": running,
        },
        "current_account": current_account,
        "account_ref": getattr(args, "account_ref", None) or "development-explicit",
        "targets": [
            {
                "alias": name,
                "bytes": targets[name].size,
                "mib": round(targets[name].size / 1024 / 1024, 2),
            }
            for name in target_names
        ],
        "dependencies": dependencies,
        "database_holders": holder_status,
        "blockers": blockers,
        "prerequisites_ready": prerequisites_ready,
        "ready_for_capture": ready_for_capture,
        "authorization_summary_usable": True,
        "next_action": next_action,
        "approval_digest": capture_approval_digest(
            args, db_base, targets, app, cdhash
        ),
    }


def run_dry_scan(args: argparse.Namespace) -> int:
    report = build_dry_scan_report(args)
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["prerequisites_ready"] else 2


def run_capture(args: argparse.Namespace) -> int:
    if args.duration < 5 or args.duration > 600:
        raise SafeInitError("--duration must be between 5 and 600 seconds")
    db_base = requested_db_base(args)
    app = validate_wechat_app(Path(args.app))
    require_official_wechat_signature(app)
    cdhash = official_app_cdhash(app)
    assert_original_wechat_stopped(app)
    target_names = parse_targets(args.targets)
    targets = inspect_targets(db_base, target_names)
    assert_no_target_database_holders(targets)
    expected_digest = capture_approval_digest(args, db_base, targets, app, cdhash)
    provided_digest = getattr(args, "approve_digest", None)
    if not isinstance(provided_digest, str) or not secrets.compare_digest(
        expected_digest, provided_digest.lower()
    ):
        raise SafeInitError(
            "capture scope changed or lacks the exact dry-scan approval digest; rerun dry-scan"
        )
    frida_module = require_capture_dependencies()
    private_dir = ensure_private_dir(Path(args.private_dir), create=True)
    ensure_no_owned_runtime(private_dir)

    def recheck_quiescence() -> None:
        assert_original_wechat_stopped(app)
        assert_no_target_database_holders(targets)

    print("Preparing a random private signed copy; the original app remains read-only.")
    runtime = prepare_runtime_copy(
        app,
        private_dir,
        cdhash,
        quiescence_check=recheck_quiescence,
    )
    metadata_path = private_dir / RUNTIME_FILENAME

    current_pid: Optional[int] = None

    def record_pid(pid: int) -> None:
        nonlocal current_pid
        current_pid = pid
        atomic_write_json(
            metadata_path,
            runtime_metadata(runtime, status="capturing", pid=pid),
        )

    print("Launching the private copy and capturing exact target salts in memory only.")
    try:
        result = capture_keys(
            frida_module,
            runtime,
            targets,
            args.duration,
            pre_spawn=recheck_quiescence,
            on_pid=record_pid,
        )
    except Exception:
        atomic_write_json(
            metadata_path,
            runtime_metadata(runtime, status="capture-error", pid=current_pid),
        )
        raise

    if result.missing_targets:
        atomic_write_json(
            metadata_path,
            runtime_metadata(
                runtime,
                status="incomplete",
                pid=result.pid,
                missing_targets=result.missing_targets,
            ),
        )
        print("Capture ended without a complete key set.")
        print("  missing exact targets: %s" % ", ".join(result.missing_targets))
        print("  no keys or config were written")
        print("  runtime cleanup metadata was saved privately (path and PID redacted)")
        return 2

    capture_account_ref = getattr(args, "account_ref", None)
    write_success_files(
        private_dir,
        db_base,
        targets,
        result.matched_keys,
        account_ref=capture_account_ref if isinstance(capture_account_ref, str) else None,
    )
    atomic_write_json(
        metadata_path,
        runtime_metadata(runtime, status="complete", pid=result.pid),
    )
    print("One-time key initialization completed.")
    print("  exact keys/config: atomically saved with mode 0600")
    print("  raw PBKDF rows: memory only; none written to disk")
    print("  signed copy: still running; path and PID are only in private runtime metadata")
    print("Quit the signed copy normally, then run the cleanup subcommand.")
    return 0


def run_cleanup(args: argparse.Namespace) -> int:
    private_dir = ensure_private_dir(Path(args.private_dir), create=False)
    removed_count = cleanup_owned_runtime(private_dir)
    print(
        "Cleaned %d bounded, marker-owned private copy/copies after confirming all processes were gone."
        % removed_count
    )
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command in ("setup-doctor", "doctor"):
        return run_setup_doctor(args)
    if sys.platform != "darwin":
        raise SafeInitError("this initializer only supports macOS")
    if args.command == "dry-scan":
        return run_dry_scan(args)
    if args.command == "capture":
        return run_capture(args)
    if args.command == "cleanup":
        return run_cleanup(args)
    raise SafeInitError("unknown command")


def entrypoint() -> None:
    try:
        raise SystemExit(main())
    except SafeInitError as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    entrypoint()
