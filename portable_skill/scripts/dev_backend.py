#!/usr/bin/env python3
"""Development adapter for the repository's unified content-vault backend.

This remains source development software, not a signed/notarized companion. It
accepts only high-level doctor/scan/export/direct-voice-mp4 arguments and never
accepts a key.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
from types import SimpleNamespace
from typing import Any, Callable, Mapping, Sequence


REQUEST_SCHEMA_VERSION = 1
ROUTING_SCHEMA_VERSION = 1
MAX_REQUEST_BYTES = 1_048_576
DIGEST_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
ACCOUNT_REF_PATTERN = re.compile(r"account-[0-9a-f]{12}\Z")
CURRENT_ACCOUNT_METHOD = "official-process-numeric-fd-exact-match"
PRIVATE_TASKS_RELATIVE = (
    "Library",
    "Application Support",
    "WeChatLocalExport",
    "tasks",
)
SUPPORTED_TYPES = (
    "text",
    "image",
    "voice",
    "contact_card",
    "video",
    "location",
    "file",
    "sticker",
    "link",
    "mini_program",
    "quote",
    "forwarded_record",
    "app_message",
    "call",
    "system",
    "unknown",
)


class DevelopmentBackendError(RuntimeError):
    pass


class CurrentAccountRoutingError(DevelopmentBackendError):
    """A bounded, redacted current-session routing failure."""

    _MESSAGES = {
        "no-active-account": (
            "未能证明唯一的当前微信账号；请登录目标账号、打开任意聊天并将官方微信窗口置于前台后重试"
        ),
        "multiple-active-accounts": "检测到多个当前微信账号；无法安全选择，已停止",
        "unstable": "当前微信账号在检查期间发生变化；请保持目标账号稳定后重试",
        "unavailable": "当前微信账号暂时无法安全检查；请将官方微信窗口置于前台后重试",
    }

    def __init__(self, code: str, *, samples_completed: int = 0) -> None:
        self.code = code if code in self._MESSAGES else "unavailable"
        self.samples_completed = max(0, min(int(samples_completed), 2))
        super().__init__(self._MESSAGES[self.code])

    def public_report(self) -> dict[str, Any]:
        return {
            "status": self.code,
            "selected": False,
            "method": CURRENT_ACCOUNT_METHOD,
            "samples_completed": self.samples_completed,
            "writes_performed": False,
        }


class CurrentAccountProfileError(DevelopmentBackendError):
    """The bound current account has no safe, ready schema-2 profile."""


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # noqa: ARG002
        self.print_usage(sys.stderr)
        print("参数无效；开发后端只接受受限的高层导出参数。", file=sys.stderr)
        raise SystemExit(2)


def _absolute_path(value: str) -> str:
    path = Path(value).expanduser()
    if not path.is_absolute() or any(ord(character) < 32 for character in value):
        raise argparse.ArgumentTypeError("需要绝对路径")
    return str(path)


def _positive_count(value: str) -> int:
    try:
        count = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("数量必须是正整数") from exc
    if count <= 0:
        raise argparse.ArgumentTypeError("数量必须是正整数")
    return count


def _digest(value: str) -> str:
    normalized = value.lower()
    if not DIGEST_PATTERN.fullmatch(normalized):
        raise argparse.ArgumentTypeError("摘要格式无效")
    return normalized


def build_parser() -> argparse.ArgumentParser:
    parser = SafeArgumentParser(description="WeChat Local Export 统一源码开发适配器")
    subparsers = parser.add_subparsers(dest="command", required=True)
    doctor = subparsers.add_parser("doctor")
    doctor.add_argument("--vault-dir", type=_absolute_path)
    doctor.add_argument("--account-root", type=_absolute_path)
    doctor.add_argument("--swift-bin", type=_absolute_path)
    scan = subparsers.add_parser("scan")
    scan.add_argument("--request", required=True, type=_absolute_path)
    scan.add_argument("--output", required=True, type=_absolute_path)
    export = subparsers.add_parser("export")
    export.add_argument("--vault-dir", type=_absolute_path)
    export.add_argument("--account-root", type=_absolute_path)
    export.add_argument("--plan", required=True, type=_absolute_path)
    export.add_argument("--output-dir", required=True, type=_absolute_path)
    export.add_argument("--confirm-digest", required=True, type=_digest)
    export.add_argument("--confirm-count", required=True, type=_positive_count)
    export.add_argument("--swift-bin", type=_absolute_path)
    export_mode = export.add_mutually_exclusive_group()
    export_mode.add_argument("--allow-partial", action="store_true")
    export_mode.add_argument("--voice-mp4-only", action="store_true")
    direct_voice = subparsers.add_parser("direct-voice-mp4")
    direct_voice.add_argument("--request", required=True, type=_absolute_path)
    direct_voice.add_argument("--output-dir", required=True, type=_absolute_path)
    return parser


def _candidate_roots() -> list[Path]:
    result: list[Path] = []
    seed = Path(__file__).resolve()
    result.append(seed.parent)
    result.extend(seed.parents)
    return result


def _find_project_root() -> Path:
    seen: set[Path] = set()
    for candidate in _candidate_roots():
        try:
            root = candidate.resolve(strict=True)
        except OSError:
            continue
        if root in seen:
            continue
        seen.add(root)
        if (
            (root / "content_vault" / "cli.py").is_file()
            and (root / "direct_vault" / "direct_voice_vault.py").is_file()
            and (root / "Package.swift").is_file()
        ):
            return root
    raise DevelopmentBackendError("未找到完整项目源码；无法启用开发后端")


def _load_backend(project_root: Path) -> SimpleNamespace:
    root_text = str(project_root)
    if root_text not in sys.path:
        sys.path.insert(0, root_text)
    try:
        from content_vault.archive_export import export_archive
        from content_vault.cli import doctor
        from content_vault.profile import load_account_profile
        from content_vault.scanner import (
            build_content_plan,
            find_chat_candidates,
            load_content_plan,
        )
        from direct_vault.direct_voice_vault import (
            _ensure_output_outside_vault,
            _plan_digest,
            _resolve_vault,
            _write_json_private,
        )
        from live_tools.wechat_account_router import bind_active_account
        from live_tools.wechat_online_refresh import refresh_online_snapshot
    except Exception as exc:
        raise DevelopmentBackendError("无法加载统一内容导出后端") from exc
    return SimpleNamespace(
        doctor=doctor,
        bind_active_account=bind_active_account,
        refresh_online_snapshot=refresh_online_snapshot,
        load_account_profile=load_account_profile,
        build_content_plan=build_content_plan,
        find_chat_candidates=find_chat_candidates,
        load_content_plan=load_content_plan,
        export_archive=export_archive,
        plan_digest=_plan_digest,
        resolve_vault=_resolve_vault,
        ensure_output=_ensure_output_outside_vault,
        write_json=_write_json_private,
    )


_PUBLIC_PRIVATE_FIELDS = frozenset(
    {
        "account_ref",
        "account_root",
        "chat_id",
        "manifest",
        "path",
        "pid",
        "pids",
        "plan",
        "output_dir",
        "swift_bin",
        "vault_dir",
        "wxid",
    }
)


def _redact_public_value(value: Any) -> Any:
    """Return a JSON-safe public view without local routing identifiers."""

    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                continue
            normalized = key.casefold()
            if (
                normalized in _PUBLIC_PRIVATE_FIELDS
                or normalized.endswith("_path")
                or normalized.endswith("_pid")
            ):
                continue
            result[key] = _redact_public_value(item)
        return result
    if isinstance(value, (list, tuple)):
        return [_redact_public_value(item) for item in value]
    if isinstance(value, str):
        if re.search(r"account-[0-9a-f]{12}", value):
            return "[private]"
        if re.search(r"(?i)(?:^|[^a-z0-9])wxid_[a-z0-9_-]+", value):
            return "[private]"
        if re.search(r"(?i)\bpid\s*[=:]\s*[0-9]+", value):
            return "[private]"
        if (
            value.startswith("/")
            or value.startswith("~/")
            or re.search(r"(?:[：:=<(]|\s)/(?!/)[^\s]", value)
        ):
            return "[private]"
    return value


def _json_output(value: Mapping[str, Any]) -> None:
    public = _redact_public_value(value)
    print(json.dumps(public, ensure_ascii=False, indent=2, sort_keys=True))


def _public_error_text(error: BaseException) -> str:
    """Preserve actionable errors without emitting local paths or account markers."""

    value = _redact_public_value(str(error))
    if value == "[private]" or not isinstance(value, str) or not value.strip():
        return "本地导出失败；错误详情包含私有本机标识，已隐藏"
    return value


def _read_private_json(path_value: str) -> dict[str, Any]:
    path = Path(path_value).expanduser()
    try:
        info = path.lstat()
    except OSError as exc:
        raise DevelopmentBackendError("请求文件不存在或不可读") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise DevelopmentBackendError("请求必须是普通文件且不能是符号链接")
    if info.st_size <= 0 or info.st_size > MAX_REQUEST_BYTES:
        raise DevelopmentBackendError("请求文件大小不在安全范围内")
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise DevelopmentBackendError("请求文件必须由当前用户拥有且权限为 0600 或更严格")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DevelopmentBackendError("请求文件不是有效的私有 JSON") from exc
    if not isinstance(value, dict):
        raise DevelopmentBackendError("请求 JSON 顶层必须是对象")
    return value


def _private_directory(path: Path, label: str) -> Path:
    try:
        info = path.lstat()
    except OSError as exc:
        raise DevelopmentBackendError(f"{label}不存在或不可检查") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise DevelopmentBackendError(f"{label}必须是非符号链接目录")
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise DevelopmentBackendError(
            f"{label}必须由当前用户拥有且权限为 0700 或更严格"
        )
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise DevelopmentBackendError(f"{label}无法安全解析") from exc
    if resolved != Path(os.path.abspath(os.fspath(path))):
        raise DevelopmentBackendError(f"{label}路径包含符号链接")
    return resolved


def _direct_request_path(path_value: str) -> Path:
    """Require one request directly beneath the fixed private task root."""

    requested = Path(path_value).expanduser()
    task_root = Path.home().joinpath(*PRIVATE_TASKS_RELATIVE)
    resolved_root = _private_directory(task_root, "私有任务根目录")
    resolved_parent = _private_directory(requested.parent, "私有请求目录")
    if resolved_parent.parent != resolved_root:
        raise DevelopmentBackendError(
            "直接语音导出请求必须位于固定私有任务根目录的单独目录中"
        )
    try:
        resolved = requested.resolve(strict=True)
    except OSError as exc:
        raise DevelopmentBackendError("请求文件不存在或不可安全解析") from exc
    if (
        resolved.parent != resolved_parent
        or resolved != Path(os.path.abspath(os.fspath(requested)))
    ):
        raise DevelopmentBackendError("请求文件路径包含符号链接")
    return resolved


def _private_file_identity(path: Path, label: str) -> tuple[Any, ...]:
    """Return a stable private-file identity plus a non-public content digest."""

    try:
        before = path.lstat()
    except OSError as exc:
        raise DevelopmentBackendError(f"{label}不存在或不可读") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise DevelopmentBackendError(f"{label}必须是普通文件且不能是符号链接")
    if before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) & 0o077:
        raise DevelopmentBackendError(
            f"{label}必须由当前用户拥有且权限为 0600 或更严格"
        )
    try:
        payload = path.read_bytes()
        after = path.lstat()
    except OSError as exc:
        raise DevelopmentBackendError(f"{label}读取失败") from exc
    before_fields = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_uid,
        before.st_gid,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    after_fields = (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_uid,
        after.st_gid,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if before_fields != after_fields or len(payload) != before.st_size:
        raise DevelopmentBackendError(f"{label}在读取期间发生变化")
    return (*before_fields, hashlib.sha256(payload).digest())


def _reserve_internal_plan(request_path: Path) -> Path:
    """Atomically reserve one private, unpredictable plan beside the request."""

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    for _ in range(16):
        candidate = request_path.parent / (
            f".direct-voice-plan-{secrets.token_hex(16)}.json"
        )
        try:
            descriptor = os.open(candidate, flags, 0o600)
        except FileExistsError:
            continue
        except OSError as exc:
            raise DevelopmentBackendError("无法创建私有临时扫描计划") from exc
        try:
            os.fchmod(descriptor, 0o600)
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size != 0
            ):
                raise DevelopmentBackendError("私有临时扫描计划创建验证失败")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return candidate
    raise DevelopmentBackendError("无法分配唯一的私有临时扫描计划")


def _require_reserved_plan(path: Path) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise DevelopmentBackendError("私有临时扫描计划预留文件丢失") from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_size != 0
    ):
        raise DevelopmentBackendError("私有临时扫描计划预留文件不安全")


def _cleanup_internal_plan(path: Path, request_parent: Path) -> None:
    """Remove only the exact private plan allocated by this invocation."""

    if path.parent != request_parent or not path.name.startswith(
        ".direct-voice-plan-"
    ):
        raise DevelopmentBackendError("拒绝清理非本次临时扫描计划")
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise DevelopmentBackendError("无法检查本次临时扫描计划") from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise DevelopmentBackendError("本次临时扫描计划状态不安全；拒绝误删")
    try:
        path.unlink()
    except OSError as exc:
        raise DevelopmentBackendError("无法清理本次临时扫描计划") from exc


def _validate_scan_request(value: dict[str, Any]) -> dict[str, Any]:
    allowed = {"schema_version", "vault_dir", "chat", "chat_id", "start", "end", "types"}
    if set(value) - allowed:
        raise DevelopmentBackendError("请求包含开发后端不支持的字段")
    if value.get("schema_version") != REQUEST_SCHEMA_VERSION:
        raise DevelopmentBackendError("请求 schema 版本不受支持")
    for key in ("chat", "start", "end"):
        item = value.get(key)
        if not isinstance(item, str) or not item.strip():
            raise DevelopmentBackendError(f"请求缺少有效字段：{key}")
    vault_value = value.get("vault_dir")
    vault: Path | None = None
    if vault_value is not None:
        if not isinstance(vault_value, str) or not vault_value.strip():
            raise DevelopmentBackendError("vault_dir 必须省略或为绝对路径")
        vault = Path(vault_value).expanduser()
        if not vault.is_absolute():
            raise DevelopmentBackendError("vault_dir 必须是绝对路径")
    chat_id = value.get("chat_id")
    if chat_id is not None and (not isinstance(chat_id, str) or not chat_id.strip()):
        raise DevelopmentBackendError("chat_id 必须为空或非空字符串")
    if "types" not in value:
        raise DevelopmentBackendError("请求必须明确指定 types；不得默认导出全部内容")
    types = value["types"]
    if (
        not isinstance(types, list)
        or not types
        or any(not isinstance(item, str) or not item for item in types)
        or len(set(types)) != len(types)
    ):
        raise DevelopmentBackendError("types 必须是无重复的非空字符串数组")
    if "all" in types and types != ["all"]:
        raise DevelopmentBackendError("all 不能与具体消息类型同时使用")
    unsupported = set(types) - set(SUPPORTED_TYPES) - {"all"}
    if unsupported:
        raise DevelopmentBackendError("请求含后端不支持的消息类型")
    return {
        "vault_dir": str(vault) if vault is not None else None,
        "chat": value["chat"].strip(),
        "chat_id": chat_id.strip() if isinstance(chat_id, str) else None,
        "start": value["start"].strip(),
        "end": value["end"].strip(),
        "types": types,
    }


def _plain_executable(path: Path) -> bool:
    try:
        resolved = path.resolve(strict=True)
        info = resolved.stat()
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and os.access(resolved, os.X_OK)


def _development_path_mode(
    vault_dir: str | None,
    account_root: str | None,
    swift_bin: str | None,
) -> bool:
    """Accept only a complete, explicit doctor/export development override."""

    if vault_dir and account_root:
        return True
    if vault_dir or account_root or swift_bin:
        raise DevelopmentBackendError(
            "显式开发模式必须同时提供 --vault-dir 与 --account-root；不得与当前账号 profile 混用"
        )
    return False


def _bind_current_account_or_stop(backend: SimpleNamespace) -> Any:
    try:
        binding = backend.bind_active_account()
    except Exception as exc:
        if exc.__class__.__name__ == "AccountRoutingError":
            raise CurrentAccountRoutingError(
                str(getattr(exc, "code", "unavailable")),
                samples_completed=getattr(exc, "samples_completed", 0),
            ) from exc
        raise
    account_ref = getattr(binding, "account_ref", None)
    if not isinstance(account_ref, str) or not ACCOUNT_REF_PATTERN.fullmatch(account_ref):
        raise CurrentAccountRoutingError("unavailable", samples_completed=2)
    return binding


def _public_current_account(binding: Any) -> dict[str, Any]:
    try:
        source = binding.public_report()
    except Exception as exc:
        raise CurrentAccountRoutingError("unavailable", samples_completed=2) from exc
    if not isinstance(source, Mapping) or source.get("status") != "unique":
        raise CurrentAccountRoutingError("unavailable", samples_completed=2)
    categories = source.get("held_categories")
    evidence = source.get("core_evidence")
    return {
        "status": "unique",
        "selected": True,
        "method": CURRENT_ACCOUNT_METHOD,
        "samples_completed": 2,
        "official_process_count": max(
            0, int(source.get("official_process_count", 0))
        ),
        "held_categories": (
            sorted({str(item) for item in categories})
            if isinstance(categories, (list, tuple))
            else []
        ),
        "core_evidence": {
            "contact": bool(evidence.get("contact"))
            if isinstance(evidence, Mapping)
            else True,
            "message": bool(evidence.get("message"))
            if isinstance(evidence, Mapping)
            else True,
        },
        "writes_performed": False,
    }


def _profile_or_stop(backend: SimpleNamespace, binding: Any) -> dict[str, Any]:
    account_ref = binding.account_ref
    try:
        profile = backend.load_account_profile(account_ref)
    except Exception as exc:
        if exc.__class__.__name__ == "ProfileError":
            raise CurrentAccountProfileError(
                "当前微信账号的 profile 缺失或不安全；请显式运行 $wechat-local-export-setup"
            ) from exc
        raise
    if (
        not isinstance(profile, Mapping)
        or profile.get("schema_version") != 2
        or profile.get("account_ref") != account_ref
    ):
        raise CurrentAccountProfileError(
            "当前微信账号的 profile 不匹配；请显式运行 $wechat-local-export-setup"
        )
    return dict(profile)


def _refresh_online_or_stop(
    backend: SimpleNamespace,
    binding: Any,
    profile: Mapping[str, Any],
    *,
    kinds: Sequence[str],
    chat_id: str,
) -> None:
    """Refresh one exact chat without exposing snapshot internals publicly."""

    try:
        report = backend.refresh_online_snapshot(
            binding,
            profile,
            kinds=kinds,
            chat_id=chat_id,
        )
    except Exception as exc:
        if exc.__class__.__name__ == "OnlineRefreshError":
            raise DevelopmentBackendError(f"在线快照刷新失败：{exc}") from exc
        raise
    if (
        not isinstance(report, Mapping)
        or report.get("status") != "online-refresh-complete"
        or report.get("profile_updated") is not True
    ):
        raise DevelopmentBackendError("在线快照刷新未完成；未创建扫描计划")


def _attach_plan_routing(
    plan: dict[str, Any], binding: Any, backend: SimpleNamespace
) -> None:
    plan["routing"] = {
        "schema_version": ROUTING_SCHEMA_VERSION,
        "account_ref": binding.account_ref,
    }
    plan["plan_digest"] = backend.plan_digest(plan)


def _require_plan_for_binding(plan: Mapping[str, Any], binding: Any) -> None:
    routing = plan.get("routing")
    if (
        not isinstance(routing, Mapping)
        or set(routing) != {"schema_version", "account_ref"}
        or type(routing.get("schema_version")) is not int
        or routing.get("schema_version") != ROUTING_SCHEMA_VERSION
        or not isinstance(routing.get("account_ref"), str)
        or not ACCOUNT_REF_PATTERN.fullmatch(str(routing.get("account_ref")))
    ):
        raise DevelopmentBackendError(
            "扫描计划缺少有效的当前账号路由；请重新扫描并确认"
        )
    if routing["account_ref"] != binding.account_ref:
        raise DevelopmentBackendError(
            "当前微信账号与扫描计划不一致；请重新 doctor、scan 并确认"
        )


def _find_swift_binary(project_root: Path) -> Path:
    candidates = [project_root / ".build/release/wechat-voice-mp4"]
    for candidate in candidates:
        if _plain_executable(candidate):
            return candidate.resolve()
    raise DevelopmentBackendError("未找到 Swift 媒体工具；请运行 scripts/build.sh")


def run_doctor(args: argparse.Namespace, project_root: Path, backend: SimpleNamespace) -> int:
    base: dict[str, Any] = {
        "backend": "development-source",
        "backend_version": "0.2.0-dev.7",
        "signed_companion": False,
        "notarized_companion": False,
        "product_ready": False,
        "supported_types": list(SUPPORTED_TYPES),
        "supported_message_kinds": list(SUPPORTED_TYPES),
        "exportable_asset_kinds": ["image", "voice", "file", "sticker"],
        "metadata_only_kinds": ["video"],
        "export_profile": "selected message kinds; every video is metadata-only",
        "network_required": False,
        "key_handling": "not exposed by this adapter",
        "integrity": {
            "database_page_hmac_verified": False,
            "current_checks": [
                "stable encrypted snapshot",
                "WAL/SHM gate",
                "AES-CBC structural validation",
                "SQLite quick_check",
                "expected-table gate",
            ],
        },
        "limitations": [
            "signed/notarized companion is not included",
            "wxgf conversion requires the pinned local imageio-ffmpeg dependency",
            "proprietary encrypted sticker bodies can remain metadata-only",
            "database page HMAC status comes from the source snapshot implementation",
        ],
    }
    explicit_development = _development_path_mode(
        args.vault_dir, args.account_root, args.swift_bin
    )
    profile: dict[str, Any] | None = None
    if explicit_development:
        vault_dir = args.vault_dir
        account_root = args.account_root
        swift_bin = args.swift_bin
        base["routing_mode"] = "explicit-development-paths"
        base["current_account"] = {
            "status": "bypassed-development-only",
            "selected": False,
            "writes_performed": False,
        }
        base["profile"] = {
            "status": "bypassed-development-only",
            "ready": False,
        }
    else:
        try:
            binding = _bind_current_account_or_stop(backend)
            base["current_account"] = _public_current_account(binding)
        except CurrentAccountRoutingError as exc:
            base.update(
                {
                    "routing_mode": "current-official-session",
                    "current_account": exc.public_report(),
                    "profile": {"status": "not-evaluated", "ready": False},
                    "profile_loaded": False,
                    "ready_for_scan": False,
                    "ready_for_media_export": False,
                    "ready_for_voice_mp4": False,
                    "ready_for_voice_archive": False,
                    "next_action": str(exc),
                }
            )
            _json_output(base)
            return 2
        try:
            profile = _profile_or_stop(backend, binding)
        except CurrentAccountProfileError:
            base.update(
                {
                    "routing_mode": "current-official-session",
                    "profile": {"status": "setup-required", "ready": False},
                    "profile_loaded": False,
                    "ready_for_scan": False,
                    "ready_for_media_export": False,
                    "ready_for_voice_mp4": False,
                    "ready_for_voice_archive": False,
                    "next_action": (
                        "explicitly invoke $wechat-local-export-setup for the current account"
                    ),
                }
            )
            _json_output(base)
            return 2
        vault_dir = profile["vault_dir"]
        account_root = profile["account_root"]
        swift_bin = profile.get("swift_bin")
        base["routing_mode"] = "current-official-session"
        base["profile"] = {
            "status": "ready",
            "ready": True,
            "schema_version": 2,
        }
    base["profile_loaded"] = profile is not None
    assert vault_dir is not None and account_root is not None
    report = backend.doctor(
        vault_dir, account_root=account_root, swift_bin=swift_bin
    )
    base.update(report)
    base["project_source_backend_detected"] = project_root.is_dir()
    _json_output(base)
    return 0 if base.get("ready_for_scan") else 2


def run_scan(
    args: argparse.Namespace,
    backend: SimpleNamespace,
    *,
    report_sink: Callable[[Mapping[str, Any]], None] = _json_output,
    reserved_output: bool = False,
) -> int:
    request = _validate_scan_request(_read_private_json(args.request))
    profile: dict[str, Any] | None = None
    binding: Any | None = None
    if request["vault_dir"] is None:
        binding = _bind_current_account_or_stop(backend)
        profile = _profile_or_stop(backend, binding)
    vault = backend.resolve_vault(
        request["vault_dir"] or profile["vault_dir"]
    )
    output = backend.ensure_output(Path(args.output), vault)
    if reserved_output:
        _require_reserved_plan(output)
    elif output.exists() or output.is_symlink():
        raise DevelopmentBackendError("扫描计划输出已经存在，拒绝覆盖")

    candidates = backend.find_chat_candidates(vault, request["chat"])
    if request["chat_id"] is None:
        exact = [item for item in candidates if item.get("match") == "exact"]
        if len(exact) != 1:
            public_candidates = [
                {
                    "display_name": item.get("display_name"),
                    "kind": item.get("kind"),
                    "match": item.get("match"),
                }
                for item in candidates
            ]
            report_sink(
                {
                    "status": (
                        "needs-chat-selection" if candidates else "chat-not-found"
                    ),
                    "backend": "development-source",
                    "query": request["chat"],
                    "candidate_count": len(public_candidates),
                    "candidates": public_candidates,
                    "time_range": {
                        "start_input": request["start"],
                        "end_input": request["end"],
                    },
                    "requested_types": request["types"],
                    "plan_created": False,
                }
            )
            return 3
        request["chat_id"] = exact[0]["chat_id"]
    else:
        selected = [
            item
            for item in candidates
            if item.get("match") == "exact"
            and item.get("chat_id") == request["chat_id"]
        ]
        if len(selected) != 1:
            public_candidates = [
                {
                    "display_name": item.get("display_name"),
                    "kind": item.get("kind"),
                    "match": item.get("match"),
                }
                for item in candidates
            ]
            report_sink(
                {
                    "status": (
                        "needs-chat-selection" if candidates else "chat-not-found"
                    ),
                    "backend": "development-source",
                    "query": request["chat"],
                    "candidate_count": len(public_candidates),
                    "candidates": public_candidates,
                    "time_range": {
                        "start_input": request["start"],
                        "end_input": request["end"],
                    },
                    "requested_types": request["types"],
                    "plan_created": False,
                }
            )
            return 3

    if binding is not None:
        assert profile is not None and request["chat_id"] is not None
        _refresh_online_or_stop(
            backend,
            binding,
            profile,
            kinds=request["types"],
            chat_id=request["chat_id"],
        )
        profile = _profile_or_stop(backend, binding)
        vault = backend.resolve_vault(profile["vault_dir"])
        output = backend.ensure_output(Path(args.output), vault)
        if reserved_output:
            _require_reserved_plan(output)
        elif output.exists() or output.is_symlink():
            raise DevelopmentBackendError("扫描计划输出已经存在，拒绝覆盖")

    plan = backend.build_content_plan(
        vault,
        request["chat"],
        request["start"],
        request["end"],
        expected=None,
        chat_id=request["chat_id"],
        kinds=None if request["types"] == ["all"] else request["types"],
    )
    if binding is not None:
        _attach_plan_routing(plan, binding, backend)
    backend.write_json(output, plan, vault)
    messages = plan["messages"]
    public_report = {
        "status": "dry-scan-complete",
        "backend": "development-source",
        "signed_companion": False,
        "supported_types": list(SUPPORTED_TYPES),
        "plan_digest": plan["plan_digest"],
        "message_count": plan["message_count"],
        "counts_by_kind": plan["counts_by_kind"],
        "selection": plan["selection"],
        "chat": {
            "display_name": plan["chat"]["display_name"],
            "kind": plan["chat"]["kind"],
        },
        "time_range": plan["time_range"],
        "first_create_time": messages[0]["create_time"] if messages else None,
        "last_create_time": messages[-1]["create_time"] if messages else None,
        "requires_user_confirmation": True,
        "profile_used": profile is not None,
        "routing_mode": (
            "current-official-session"
            if binding is not None
            else "explicit-development-paths"
        ),
    }
    if binding is not None:
        public_report["snapshot_mode"] = "online"
    report_sink(public_report)
    return 0


def run_export(
    args: argparse.Namespace,
    project_root: Path,
    backend: SimpleNamespace,
    *,
    report_sink: Callable[[Mapping[str, Any]], None] = _json_output,
) -> int:
    plan = backend.load_content_plan(args.plan)
    explicit_development = _development_path_mode(
        args.vault_dir, args.account_root, args.swift_bin
    )
    if explicit_development:
        if "routing" in plan:
            raise DevelopmentBackendError(
                "当前账号扫描计划不能与显式开发路径混用；请用同一模式重新扫描"
            )
        vault_dir = args.vault_dir
        account_root = args.account_root
        configured_swift = args.swift_bin
    else:
        binding = _bind_current_account_or_stop(backend)
        _require_plan_for_binding(plan, binding)
        profile = _profile_or_stop(backend, binding)
        vault_dir = profile["vault_dir"]
        account_root = profile["account_root"]
        configured_swift = profile.get("swift_bin")
    assert vault_dir is not None and account_root is not None
    if plan["plan_digest"] != args.confirm_digest:
        raise DevelopmentBackendError("确认摘要与当前计划不一致；请重新扫描并确认")
    if plan["message_count"] != args.confirm_count:
        raise DevelopmentBackendError("确认数量与当前计划不一致；请重新扫描并确认")
    has_voice = bool(plan.get("counts_by_kind", {}).get("voice"))
    swift_binary: Path | None = None
    if args.voice_mp4_only:
        # The strict MP4-only path validates and streams PCM directly into the
        # pinned local ffmpeg encoder.  Swift remains required only for the
        # readable full archive, which retains each verified M4A.
        swift_binary = None
    elif configured_swift:
        candidate = Path(configured_swift)
        if not _plain_executable(candidate):
            raise DevelopmentBackendError("--swift-bin 不可执行")
        swift_binary = candidate.resolve()
    elif has_voice:
        swift_binary = _find_swift_binary(project_root)
    report = backend.export_archive(
        vault_dir,
        account_root,
        args.plan,
        args.confirm_digest,
        args.output_dir,
        swift_bin=swift_binary,
        allow_partial=args.allow_partial,
        voice_mp4_only=args.voice_mp4_only,
    )
    report_sink(
        {
            "status": "complete",
            "backend": "development-source",
            "signed_companion": False,
            **report,
        }
    )
    return 0


def _doctor_gate_direct_voice(
    backend: SimpleNamespace,
) -> None:
    """Run the ordinary current-session doctor gates without emitting paths."""

    binding = _bind_current_account_or_stop(backend)
    _public_current_account(binding)
    profile = _profile_or_stop(backend, binding)
    report = backend.doctor(
        profile["vault_dir"],
        account_root=profile["account_root"],
        swift_bin=profile.get("swift_bin"),
    )
    if not isinstance(report, Mapping):
        raise DevelopmentBackendError("doctor 未返回可验证的能力报告")
    if report.get("ready_for_scan") is not True:
        raise DevelopmentBackendError("doctor 未确认当前账号可安全扫描")
    if report.get("ready_for_voice_mp4") is not True:
        raise DevelopmentBackendError("doctor 未确认当前账号可严格导出语音 MP4")


def run_direct_voice_mp4(
    args: argparse.Namespace,
    project_root: Path,
    backend: SimpleNamespace,
) -> int:
    """Doctor, online-scan, and strictly export one explicit voice request."""

    request_path = _direct_request_path(args.request)
    initial_identity = _private_file_identity(request_path, "私有请求文件")
    request = _validate_scan_request(_read_private_json(str(request_path)))
    if _private_file_identity(request_path, "私有请求文件") != initial_identity:
        raise DevelopmentBackendError("私有请求文件在验证期间发生变化")
    if request["vault_dir"] is not None:
        raise DevelopmentBackendError(
            "direct-voice-mp4 只允许当前官方微信会话，不接受显式开发 vault"
        )
    if request["types"] != ["voice"]:
        raise DevelopmentBackendError(
            "direct-voice-mp4 只接受明确的纯语音 types=[voice] 请求"
        )
    output = Path(args.output_dir).expanduser()
    if output.exists() or output.is_symlink():
        raise DevelopmentBackendError("导出目标已经存在，拒绝覆盖")

    _doctor_gate_direct_voice(backend)
    if _private_file_identity(request_path, "私有请求文件") != initial_identity:
        raise DevelopmentBackendError("私有请求文件在 doctor 后发生变化")

    plan_path = _reserve_internal_plan(request_path)
    public_report: dict[str, Any]
    return_code: int
    try:
        scan_reports: list[Mapping[str, Any]] = []
        scan_code = run_scan(
            SimpleNamespace(request=str(request_path), output=str(plan_path)),
            backend,
            report_sink=scan_reports.append,
            reserved_output=True,
        )
        if len(scan_reports) != 1:
            raise DevelopmentBackendError("在线扫描未返回唯一的安全结果")
        scan_report = scan_reports[0]
        if scan_code != 0:
            public_report = {
                **dict(scan_report),
                "orchestration": "direct-voice-mp4",
                "export_performed": False,
            }
            return_code = scan_code
        else:
            if _private_file_identity(
                request_path, "私有请求文件"
            ) != initial_identity:
                raise DevelopmentBackendError(
                    "私有请求文件在在线扫描期间发生变化；拒绝导出"
                )
            selection = scan_report.get("selection")
            counts = scan_report.get("counts_by_kind")
            message_count = scan_report.get("message_count")
            if (
                scan_report.get("status") != "dry-scan-complete"
                or scan_report.get("snapshot_mode") != "online"
                or scan_report.get("routing_mode")
                != "current-official-session"
                or not isinstance(selection, Mapping)
                or selection.get("types") != ["voice"]
                or not isinstance(counts, Mapping)
                or type(message_count) is not int
                or message_count < 0
                or counts.get("voice") != message_count
                or any(
                    type(value) is not int or value != 0
                    for kind, value in counts.items()
                    if kind != "voice"
                )
            ):
                raise DevelopmentBackendError(
                    "在线扫描结果不满足同请求严格纯语音导出条件"
                )
            digest = scan_report.get("plan_digest")
            if not isinstance(digest, str) or not DIGEST_PATTERN.fullmatch(digest):
                raise DevelopmentBackendError("在线扫描计划摘要无效")
            if message_count == 0:
                public_report = {
                    "status": "no-matching-voices",
                    "backend": "development-source",
                    "signed_companion": False,
                    "orchestration": "direct-voice-mp4",
                    "message_count": 0,
                    "counts_by_kind": {"voice": 0},
                    "chat": scan_report.get("chat"),
                    "time_range": scan_report.get("time_range"),
                    "snapshot_mode": "online",
                    "export_performed": False,
                    "requires_user_confirmation": False,
                }
                return_code = 3
            else:
                export_reports: list[Mapping[str, Any]] = []
                export_code = run_export(
                    SimpleNamespace(
                        vault_dir=None,
                        account_root=None,
                        plan=str(plan_path),
                        output_dir=str(output),
                        confirm_digest=digest,
                        confirm_count=message_count,
                        swift_bin=None,
                        allow_partial=False,
                        voice_mp4_only=True,
                    ),
                    project_root,
                    backend,
                    report_sink=export_reports.append,
                )
                if export_code != 0 or len(export_reports) != 1:
                    raise DevelopmentBackendError("严格语音 MP4 导出未完成")
                export_report = export_reports[0]
                verification = export_report.get("verification")
                if (
                    export_report.get("status") != "complete"
                    or export_report.get("output_mode") != "voice-mp4-only"
                    or export_report.get("message_count") != message_count
                    or export_report.get("issue_count") != 0
                    or not isinstance(verification, Mapping)
                    or verification.get("status")
                    != "verified-before-atomic-publish"
                ):
                    raise DevelopmentBackendError(
                        "严格语音 MP4 导出完成报告未通过发布校验"
                    )
                public_report = {
                    "status": "complete",
                    "backend": "development-source",
                    "signed_companion": False,
                    "orchestration": "direct-voice-mp4",
                    "output_mode": "voice-mp4-only",
                    "message_count": message_count,
                    "counts_by_kind": {"voice": message_count},
                    "chat": scan_report.get("chat"),
                    "time_range": scan_report.get("time_range"),
                    "first_create_time": scan_report.get(
                        "first_create_time"
                    ),
                    "last_create_time": scan_report.get("last_create_time"),
                    "snapshot_mode": "online",
                    "export_performed": True,
                    "requires_user_confirmation": False,
                    "verification": {
                        "status": "verified-before-atomic-publish"
                    },
                }
                return_code = 0
    finally:
        _cleanup_internal_plan(plan_path, request_path.parent)

    public_report["temporary_plan_cleaned"] = True
    _json_output(public_report)
    return return_code


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        project_root = _find_project_root()
        backend = _load_backend(project_root)
        if args.command == "doctor":
            return run_doctor(args, project_root, backend)
        if args.command == "scan":
            return run_scan(args, backend)
        if args.command == "export":
            return run_export(args, project_root, backend)
        if args.command == "direct-voice-mp4":
            return run_direct_voice_mp4(args, project_root, backend)
        raise DevelopmentBackendError("命令不受支持")
    except (DevelopmentBackendError, OSError, ValueError) as exc:
        print(f"安全停止：{_public_error_text(exc)}", file=sys.stderr)
        return 2
    except Exception as exc:
        if exc.__class__.__name__ in {
            "VaultError",
            "ImageCryptoError",
            "OnlineRefreshError",
        }:
            print(f"安全停止：{_public_error_text(exc)}", file=sys.stderr)
            return 2
        print("安全停止：开发后端发生未分类错误；未执行降级或重试。", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
