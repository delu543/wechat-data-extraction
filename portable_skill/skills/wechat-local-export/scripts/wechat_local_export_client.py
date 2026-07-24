#!/usr/bin/env python3
"""Restricted launcher for the WeChat Local Export helper.

The client deliberately knows nothing about database credentials.  It accepts
only the high-level doctor, scan, export, and direct voice-MP4 contracts,
locates either a future installed helper or this repository's development
adapter, and replaces itself with that process without capturing or rewriting
its output.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import stat
import sys
from typing import Iterable, Sequence


HELPER_ENVIRONMENT = "WECHAT_LOCAL_EXPORT_HELPER"
UNVERIFIED_HELPER_OPT_IN = "WECHAT_LOCAL_EXPORT_ALLOW_UNVERIFIED_HELPER"
ALLOWED_COMMANDS = frozenset(
    {"doctor", "scan", "export", "direct-voice-mp4"}
)
DIGEST_PATTERN = re.compile(r"[0-9a-f]{64}\Z")


class ClientError(RuntimeError):
    """A safe launcher or discovery failure."""


class SafeArgumentParser(argparse.ArgumentParser):
    """Do not echo unrecognized arguments, which could contain private text."""

    def error(self, message: str) -> None:  # noqa: ARG002 - argparse contract
        self.print_usage(sys.stderr)
        print("参数无效；请只使用帮助中列出的高层导出参数。", file=sys.stderr)
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
        raise argparse.ArgumentTypeError("摘要必须是 64 位十六进制")
    return normalized


def build_parser() -> argparse.ArgumentParser:
    parser = SafeArgumentParser(
        description="受限的本地微信导出 helper 启动器（不接收数据库凭据）"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor = subparsers.add_parser("doctor", help="只读检查后端和 vault")
    doctor.add_argument("--vault-dir", type=_absolute_path)
    doctor.add_argument("--account-root", type=_absolute_path)
    doctor.add_argument("--swift-bin", type=_absolute_path)

    scan = subparsers.add_parser("scan", help="从私有 JSON 请求生成只读计划")
    scan.add_argument("--request", required=True, type=_absolute_path)
    scan.add_argument("--output", required=True, type=_absolute_path)

    export = subparsers.add_parser("export", help="按已确认计划执行本地导出")
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

    direct_voice = subparsers.add_parser(
        "direct-voice-mp4",
        help="用同一私有请求完成检查、在线扫描和严格语音 MP4 导出",
    )
    direct_voice.add_argument("--request", required=True, type=_absolute_path)
    direct_voice.add_argument("--output-dir", required=True, type=_absolute_path)
    return parser


def _is_executable_file(path: Path) -> bool:
    try:
        resolved = path.expanduser().resolve(strict=True)
        info = resolved.stat()
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and os.access(resolved, os.X_OK)


def _unresolved_absolute_path(path: Path) -> Path:
    """Make a launcher path absolute without dereferencing its venv symlink."""
    return Path(os.path.abspath(os.fspath(path.expanduser())))


def _installed_helper_candidates() -> Iterable[Path]:
    configured = os.environ.get(HELPER_ENVIRONMENT)
    if configured and os.environ.get(UNVERIFIED_HELPER_OPT_IN) == "1":
        configured_path = Path(configured).expanduser()
        if configured_path.is_absolute():
            yield configured_path


def _candidate_roots() -> Iterable[Path]:
    seed = Path(__file__).resolve()
    yield seed.parent
    yield from seed.parents


def _development_python(project_root: Path) -> Path:
    support_override = os.environ.get("WECHAT_LOCAL_EXPORT_TOOLS_DIR")
    if support_override and os.environ.get(UNVERIFIED_HELPER_OPT_IN) == "1":
        support = Path(support_override).expanduser()
        if support.is_absolute():
            candidate = support / "python" / "bin" / "python"
            if _is_executable_file(candidate):
                return _unresolved_absolute_path(candidate)

    support = (
        Path.home()
        / "Library"
        / "Application Support"
        / "WeChatLocalExport"
        / "tools"
        / "python"
        / "bin"
        / "python"
    )
    if _is_executable_file(support):
        return _unresolved_absolute_path(support)

    project_venv = project_root / ".venv" / "bin" / "python"
    if _is_executable_file(project_venv):
        return _unresolved_absolute_path(project_venv)
    return _unresolved_absolute_path(Path(sys.executable))


def locate_backend() -> list[str]:
    seen_helpers: set[Path] = set()
    for candidate in _installed_helper_candidates():
        try:
            resolved = candidate.expanduser().resolve(strict=True)
        except OSError:
            continue
        if resolved in seen_helpers:
            continue
        seen_helpers.add(resolved)
        if _is_executable_file(resolved):
            return [str(resolved)]

    seen_roots: set[Path] = set()
    for candidate in _candidate_roots():
        try:
            root = candidate.expanduser().resolve(strict=True)
        except OSError:
            continue
        if root in seen_roots:
            continue
        seen_roots.add(root)
        adapter = root / "portable_skill" / "scripts" / "dev_backend.py"
        content_backend = root / "content_vault" / "cli.py"
        if adapter.is_file() and content_backend.is_file():
            return [str(_development_python(root)), str(adapter)]

    raise ClientError(
        "未找到已安装的本地 helper 或完整源码开发后端；请显式运行 setup Skill。"
    )


def backend_arguments(args: argparse.Namespace) -> list[str]:
    if args.command not in ALLOWED_COMMANDS:
        raise ClientError("命令不在允许列表")
    result = [args.command]
    if args.command == "doctor":
        if args.vault_dir:
            result.extend(["--vault-dir", args.vault_dir])
        if args.account_root:
            result.extend(["--account-root", args.account_root])
        if args.swift_bin:
            result.extend(["--swift-bin", args.swift_bin])
    elif args.command == "scan":
        result.extend(["--request", args.request, "--output", args.output])
    elif args.command == "export":
        result.extend(
            [
                "--plan",
                args.plan,
                "--output-dir",
                args.output_dir,
                "--confirm-digest",
                args.confirm_digest,
                "--confirm-count",
                str(args.confirm_count),
            ]
        )
        if args.vault_dir:
            result.extend(["--vault-dir", args.vault_dir])
        if args.account_root:
            result.extend(["--account-root", args.account_root])
        if args.swift_bin:
            result.extend(["--swift-bin", args.swift_bin])
        if args.allow_partial:
            result.append("--allow-partial")
        if args.voice_mp4_only:
            result.append("--voice-mp4-only")
    elif args.command == "direct-voice-mp4":
        result.extend(
            [
                "--request",
                args.request,
                "--output-dir",
                args.output_dir,
            ]
        )
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        command = [*locate_backend(), *backend_arguments(args)]
    except ClientError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    os.execv(command[0], command)
    return 127  # pragma: no cover - os.execv replaces this process


if __name__ == "__main__":
    raise SystemExit(main())
