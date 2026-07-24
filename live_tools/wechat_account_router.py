"""Bind the currently running official Mac WeChat to one local account.

This module deliberately treats runtime open-file evidence as the only source
of truth.  Historical account directories are an internal search space, never
a ranking.  In particular, database mtimes, directory sizes, saved wxids and
"most recent" heuristics are not consulted.

The public API returns a binding only when two independent samples prove the
same unique account.  All error reports are redacted: no PID, filesystem path,
account directory name, database salt or key is exposed.
"""

from __future__ import annotations

import ctypes
import os
import re
import stat
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Mapping, Optional, Sequence, Set, Tuple

from live_tools.wechat_key_init import (
    AccountCandidate,
    DEFAULT_WECHAT_APP,
    DEFAULT_XWECHAT_ROOT,
    SafeInitError,
    TARGET_RE,
    WeChatApp,
    discover_account_candidates,
    target_relative_path,
    validate_wechat_app,
    verify_app_signature,
)


MAX_OFFICIAL_PROCESSES = 128
MAX_LSOF_OUTPUT_BYTES = 32 * 1024 * 1024
DEFAULT_SAMPLE_INTERVAL_SECONDS = 0.25
_ACCOUNT_REF_RE = re.compile(r"^account-[0-9a-f]{12}$")
_NUMERIC_FD_RE = re.compile(r"^[0-9]+[A-Za-z]*$")
_MESSAGE_ALIAS_RE = re.compile(r"^message_(?:0|[1-9][0-9]*)$")
_METHOD = "official-process-numeric-fd-exact-match"

Runner = Callable[..., subprocess.CompletedProcess]
PidPathProbe = Callable[[int], Path]
CandidateProvider = Callable[[Path], Sequence[AccountCandidate]]
SignatureVerifier = Callable[[WeChatApp], bool]
SleepFunction = Callable[[float], None]


class AccountRoutingError(RuntimeError):
    """A redacted, fail-closed active-account routing failure."""

    _MESSAGES = {
        "no-active-account": "no uniquely active WeChat account was proven",
        "multiple-active-accounts": "multiple active WeChat accounts were observed",
        "unstable": "the active WeChat account evidence changed during inspection",
        "unavailable": "the active WeChat account could not be inspected safely",
    }

    def __init__(self, code: str, *, samples_completed: int = 0) -> None:
        if code not in self._MESSAGES:
            code = "unavailable"
        self.code = code
        self.samples_completed = max(0, min(int(samples_completed), 2))
        super().__init__(self._MESSAGES[code])

    def public_report(self) -> Mapping[str, Any]:
        return {
            "status": self.code,
            "selected": False,
            "method": _METHOD,
            "samples_completed": self.samples_completed,
            "writes_performed": False,
        }


class ActiveAccountBinding:
    """A private account reference plus a deliberately redacted public view."""

    __slots__ = (
        "_account_ref",
        "held_categories",
        "official_process_count",
        "sample_count",
    )

    def __init__(
        self,
        account_ref: str,
        *,
        held_categories: Sequence[str],
        official_process_count: int,
    ) -> None:
        if not _ACCOUNT_REF_RE.fullmatch(account_ref):
            raise AccountRoutingError("unavailable", samples_completed=2)
        self._account_ref = account_ref
        self.held_categories = tuple(sorted(set(held_categories)))
        self.official_process_count = int(official_process_count)
        self.sample_count = 2

    @property
    def account_ref(self) -> str:
        """Return the redacted reference for internal hand-off to key-init code."""

        return self._account_ref

    def public_report(self) -> Mapping[str, Any]:
        return {
            "status": "unique",
            "selected": True,
            "method": _METHOD,
            "samples_completed": self.sample_count,
            "official_process_count": self.official_process_count,
            "held_categories": list(self.held_categories),
            "core_evidence": {"contact": True, "message": True},
            "writes_performed": False,
        }

    def __repr__(self) -> str:
        return (
            "ActiveAccountBinding(status='unique', held_categories=%r, "
            "official_process_count=%d, sample_count=2)"
            % (self.held_categories, self.official_process_count)
        )


class _ProbeFailure(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code if code in ("unstable", "unavailable") else "unavailable"
        super().__init__(self.code)


@dataclass(frozen=True)
class _PathEvidence:
    account_ref: str = field(repr=False)
    alias: str
    is_main_database: bool


@dataclass(frozen=True)
class _Sample:
    status: str
    account_refs: Tuple[str, ...] = field(repr=False)
    held_categories: Tuple[str, ...]
    official_process_count: int


def _default_runner(command: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess:
    return subprocess.run(command, **kwargs)


def proc_pidpath(pid: int) -> Path:
    """Return one macOS process executable path without invoking a shell."""

    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        raise OSError("invalid process identity")
    try:
        library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        function = library.proc_pidpath
        function.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        function.restype = ctypes.c_int
        buffer = ctypes.create_string_buffer(4096)
        length = function(pid, buffer, len(buffer))
    except (AttributeError, OSError, ValueError) as exc:
        raise OSError("process executable inspection is unavailable") from exc
    if length <= 0 or not buffer.value:
        raise OSError("process executable inspection failed")
    try:
        decoded = os.fsdecode(buffer.value)
    except (TypeError, UnicodeError) as exc:
        raise OSError("process executable inspection failed") from exc
    path = Path(decoded)
    if not path.is_absolute():
        raise OSError("process executable inspection failed")
    return path


def _enumerate_bundle_process_ids(app: WeChatApp, runner: Runner) -> Tuple[int, ...]:
    pattern = re.escape(str(app.app_path / "Contents")) + "/"
    try:
        result = runner(
            ["/usr/bin/pgrep", "-f", pattern],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        raise _ProbeFailure("unavailable") from None
    stdout = result.stdout or ""
    stderr = result.stderr or ""
    if result.returncode == 1 and not stdout.strip() and not stderr.strip():
        return ()
    if result.returncode != 0 or stderr.strip():
        raise _ProbeFailure("unavailable")
    raw = stdout.split()
    if not raw or len(raw) > MAX_OFFICIAL_PROCESSES or any(not item.isdigit() for item in raw):
        raise _ProbeFailure("unavailable")
    pids = tuple(sorted({int(item) for item in raw if int(item) > 0}))
    if not pids or len(pids) > MAX_OFFICIAL_PROCESSES:
        raise _ProbeFailure("unavailable")
    return pids


def _resolved_contents_root(app: WeChatApp) -> Path:
    try:
        contents = (app.app_path / "Contents").resolve(strict=True)
    except OSError:
        raise _ProbeFailure("unavailable") from None
    if contents.is_symlink() or not contents.is_dir():
        raise _ProbeFailure("unavailable")
    return contents


def _validated_process_paths(
    app: WeChatApp,
    pids: Sequence[int],
    pid_path_probe: PidPathProbe,
) -> Mapping[int, Path]:
    contents = _resolved_contents_root(app)
    result: Dict[int, Path] = {}
    for pid in pids:
        try:
            original = pid_path_probe(pid)
            if not isinstance(original, Path):
                original = Path(original)
            resolved = original.resolve(strict=True)
            resolved.relative_to(contents)
            file_stat = resolved.lstat()
        except (OSError, RuntimeError, TypeError, ValueError):
            raise _ProbeFailure("unstable") from None
        if not stat.S_ISREG(file_stat.st_mode):
            raise _ProbeFailure("unavailable")
        result[pid] = resolved
    return result


def _parse_numeric_open_files(
    output: str,
    requested_pids: Sequence[int],
) -> Mapping[int, Set[str]]:
    if len(output.encode("utf-8", errors="replace")) > MAX_LSOF_OUTPUT_BYTES:
        raise _ProbeFailure("unavailable")
    requested = set(requested_pids)
    seen: Set[int] = set()
    result: Dict[int, Set[str]] = {pid: set() for pid in requested}
    current_pid: Optional[int] = None
    current_fd = ""
    for raw in output.splitlines():
        if not raw:
            continue
        tag, value = raw[0], raw[1:]
        if tag == "p":
            current_fd = ""
            if not value.isdigit():
                raise _ProbeFailure("unavailable")
            current_pid = int(value)
            if current_pid not in requested:
                raise _ProbeFailure("unavailable")
            seen.add(current_pid)
        elif tag == "f":
            if current_pid is None:
                raise _ProbeFailure("unavailable")
            current_fd = value
        elif tag == "n":
            if current_pid is None or not _NUMERIC_FD_RE.fullmatch(current_fd):
                continue
            if "\x00" in value or "\n" in value or "\r" in value:
                raise _ProbeFailure("unavailable")
            result[current_pid].add(value)
    if seen != requested:
        raise _ProbeFailure("unstable")
    return result


def _numeric_open_files(
    pids: Sequence[int],
    runner: Runner,
) -> Mapping[int, Set[str]]:
    if not pids:
        return {}
    try:
        result = runner(
            [
                "/usr/sbin/lsof",
                "-nP",
                "-Fpcfn",
                "-p",
                ",".join(str(pid) for pid in pids),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        raise _ProbeFailure("unavailable") from None
    if result.returncode != 0 or (result.stderr or "").strip():
        raise _ProbeFailure("unavailable")
    return _parse_numeric_open_files(result.stdout or "", pids)


def _regular_file_identity(path: Path) -> Tuple[int, int, int]:
    try:
        if path.is_symlink():
            raise OSError("unsafe target")
        file_stat = path.lstat()
    except OSError:
        raise _ProbeFailure("unavailable") from None
    if not stat.S_ISREG(file_stat.st_mode):
        raise _ProbeFailure("unavailable")
    return (file_stat.st_dev, file_stat.st_ino, stat.S_IFMT(file_stat.st_mode))


def _target_index(
    candidates: Sequence[AccountCandidate],
    xwechat_root: Path,
) -> Tuple[Mapping[str, _PathEvidence], Mapping[str, Tuple[int, int, int]]]:
    try:
        root = xwechat_root.expanduser().resolve(strict=True)
    except OSError:
        raise _ProbeFailure("unavailable") from None
    refs: Set[str] = set()
    index: Dict[str, _PathEvidence] = {}
    identities: Dict[str, Tuple[int, int, int]] = {}
    for candidate in candidates:
        if not _ACCOUNT_REF_RE.fullmatch(candidate.account_ref) or candidate.account_ref in refs:
            raise _ProbeFailure("unavailable")
        refs.add(candidate.account_ref)
        try:
            if candidate.db_base.is_symlink():
                raise OSError("unsafe account directory")
            db_base = candidate.db_base.resolve(strict=True)
        except OSError:
            raise _ProbeFailure("unavailable") from None
        if db_base.name != "db_storage" or db_base.parent.parent != root:
            raise _ProbeFailure("unavailable")
        for alias, target in candidate.targets.items():
            if not TARGET_RE.fullmatch(alias):
                raise _ProbeFailure("unavailable")
            try:
                expected = (db_base / target_relative_path(alias)).resolve(strict=True)
                actual = target.path.resolve(strict=True)
            except (OSError, SafeInitError):
                raise _ProbeFailure("unavailable") from None
            if actual != expected or target.path.is_symlink():
                raise _ProbeFailure("unavailable")
            path_string = str(actual)
            if path_string in index:
                raise _ProbeFailure("unavailable")
            identities[path_string] = _regular_file_identity(actual)
            index[path_string] = _PathEvidence(candidate.account_ref, alias, True)
            for suffix in ("-wal", "-shm"):
                sidecar = path_string + suffix
                if sidecar in index:
                    raise _ProbeFailure("unavailable")
                index[sidecar] = _PathEvidence(candidate.account_ref, alias, False)
    return index, identities


def _assert_file_identities_unchanged(
    identities: Mapping[str, Tuple[int, int, int]],
) -> None:
    for path_string, before in identities.items():
        try:
            after = _regular_file_identity(Path(path_string))
        except _ProbeFailure:
            raise _ProbeFailure("unstable") from None
        if after != before:
            raise _ProbeFailure("unstable")


def _category(alias: str) -> str:
    if alias == "contact":
        return "contact"
    if alias == "message_resource":
        return "message_resource"
    if alias.startswith("message_"):
        return "message"
    if alias.startswith("media_"):
        return "media"
    raise _ProbeFailure("unavailable")


def _sample(
    app: WeChatApp,
    xwechat_root: Path,
    *,
    runner: Runner,
    pid_path_probe: PidPathProbe,
    candidate_provider: CandidateProvider,
) -> _Sample:
    pgrep_pids = _enumerate_bundle_process_ids(app, runner)
    if not pgrep_pids:
        return _Sample("none", (), (), 0)
    before_paths = _validated_process_paths(app, pgrep_pids, pid_path_probe)
    official_pids = tuple(sorted(before_paths))
    if not official_pids:
        return _Sample("none", (), (), 0)
    try:
        candidates = tuple(candidate_provider(xwechat_root))
    except Exception:
        raise _ProbeFailure("unavailable") from None
    if not candidates:
        return _Sample("none", (), (), len(official_pids))
    path_index, identities = _target_index(candidates, xwechat_root)
    open_files = _numeric_open_files(official_pids, runner)
    after_paths = _validated_process_paths(app, official_pids, pid_path_probe)
    if before_paths != after_paths:
        raise _ProbeFailure("unstable")
    _assert_file_identities_unchanged(identities)

    any_aliases: Dict[str, Set[str]] = {}
    main_aliases: Dict[str, Set[str]] = {}
    for names in open_files.values():
        for name in names:
            evidence = path_index.get(name)
            if evidence is None:
                continue
            any_aliases.setdefault(evidence.account_ref, set()).add(evidence.alias)
            if evidence.is_main_database:
                main_aliases.setdefault(evidence.account_ref, set()).add(evidence.alias)

    matched_refs = tuple(sorted(any_aliases))
    if not matched_refs:
        return _Sample("none", (), (), len(official_pids))
    if len(matched_refs) > 1:
        return _Sample("ambiguous", matched_refs, (), len(official_pids))

    account_ref = matched_refs[0]
    held_main = main_aliases.get(account_ref, set())
    has_contact = "contact" in held_main
    has_message = any(_MESSAGE_ALIAS_RE.fullmatch(alias) for alias in held_main)
    if not has_contact or not has_message:
        return _Sample("none", (), (), len(official_pids))
    categories = tuple(sorted({_category(alias) for alias in any_aliases[account_ref]}))
    return _Sample("unique", (account_ref,), categories, len(official_pids))


def bind_active_account(
    *,
    app_path: Path = DEFAULT_WECHAT_APP,
    xwechat_root: Path = DEFAULT_XWECHAT_ROOT,
    sample_interval_seconds: float = DEFAULT_SAMPLE_INTERVAL_SECONDS,
    runner: Runner = _default_runner,
    pid_path_probe: PidPathProbe = proc_pidpath,
    candidate_provider: CandidateProvider = discover_account_candidates,
    signature_verifier: Optional[SignatureVerifier] = None,
    sleep_function: SleepFunction = time.sleep,
) -> ActiveAccountBinding:
    """Return a binding only after two samples prove the same unique account."""

    if (
        isinstance(sample_interval_seconds, bool)
        or not isinstance(sample_interval_seconds, (int, float))
        or sample_interval_seconds < 0
        or sample_interval_seconds > 2
    ):
        raise AccountRoutingError("unavailable")
    try:
        app = validate_wechat_app(app_path)
        verifier = signature_verifier or (
            lambda value: verify_app_signature(value, runner=runner)
        )
        if not verifier(app):
            raise AccountRoutingError("unavailable")
        first = _sample(
            app,
            xwechat_root,
            runner=runner,
            pid_path_probe=pid_path_probe,
            candidate_provider=candidate_provider,
        )
    except AccountRoutingError:
        raise
    except _ProbeFailure as exc:
        raise AccountRoutingError(exc.code) from None
    except Exception:
        raise AccountRoutingError("unavailable") from None

    try:
        sleep_function(float(sample_interval_seconds))
        second = _sample(
            app,
            xwechat_root,
            runner=runner,
            pid_path_probe=pid_path_probe,
            candidate_provider=candidate_provider,
        )
    except _ProbeFailure as exc:
        raise AccountRoutingError(exc.code, samples_completed=1) from None
    except Exception:
        raise AccountRoutingError("unavailable", samples_completed=1) from None

    if first.status != second.status or first.account_refs != second.account_refs:
        raise AccountRoutingError("unstable", samples_completed=2)
    if first.status == "none":
        raise AccountRoutingError("no-active-account", samples_completed=2)
    if first.status == "ambiguous":
        raise AccountRoutingError("multiple-active-accounts", samples_completed=2)
    if first.status != "unique" or len(first.account_refs) != 1:
        raise AccountRoutingError("unavailable", samples_completed=2)

    categories = tuple(sorted(set(first.held_categories) & set(second.held_categories)))
    if "contact" not in categories or "message" not in categories:
        raise AccountRoutingError("unstable", samples_completed=2)
    return ActiveAccountBinding(
        first.account_refs[0],
        held_categories=categories,
        official_process_count=max(
            first.official_process_count,
            second.official_process_count,
        ),
    )


__all__ = [
    "AccountRoutingError",
    "ActiveAccountBinding",
    "bind_active_account",
    "proc_pidpath",
]
