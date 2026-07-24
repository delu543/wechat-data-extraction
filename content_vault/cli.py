#!/usr/bin/env python3
"""Command-line boundary for the unified local WeChat archive."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import sqlite3
import sys
from typing import Any, Optional

from content_vault.archive_export import _image_key_candidates, export_archive
from content_vault.profile import write_account_profile, write_profile
from content_vault.scanner import build_content_plan
from direct_vault.direct_voice_vault import (
    VaultError,
    _ensure_output_outside_vault,
    _resolve_vault,
    _write_json_private,
    doctor as voice_doctor,
)
from live_tools.wechat_key_init import SafeInitError, resolve_account_ref


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)


def doctor(
    vault_dir: str,
    *,
    account_root: Optional[str] = None,
    swift_bin: Optional[str] = None,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    macos = sys.platform == "darwin"
    checks.append(
        {
            "name": "platform",
            "ok": macos,
            "system": platform.system(),
            "machine": platform.machine(),
            "supported": "macOS only",
        }
    )
    try:
        vault_report = voice_doctor(vault_dir)
        checks.append(
            {
                "name": "decrypted_snapshot",
                "ok": vault_report["ready_for_plan"],
                "voice_ready": vault_report["ready_for_extract"],
                "detail": vault_report["checks"],
            }
        )
    except (VaultError, sqlite3.Error, OSError) as error:
        vault_report = {"ready_for_plan": False, "ready_for_extract": False}
        checks.append({"name": "decrypted_snapshot", "ok": False, "detail": str(error)})

    account_ok = False
    image_key_candidate_count = 0
    if account_root:
        requested = Path(account_root).expanduser()
        account_ok = not requested.is_symlink() and requested.is_dir() and (requested / "msg").is_dir()
        if account_ok:
            image_key_candidate_count = len(_image_key_candidates(requested.resolve()))
        checks.append(
            {
                "name": "account_media_root",
                "ok": account_ok,
                "image_key_candidate_count": image_key_candidate_count,
                "detail": None if account_ok else "账号目录不存在、是符号链接或缺少 msg/",
            }
        )
    else:
        checks.append(
            {
                "name": "account_media_root",
                "ok": False,
                "detail": "未提供 --account-root；可扫描文字，但不能正式恢复本地媒体",
            }
        )

    dependencies = {
        "imageio_ffmpeg": importlib.util.find_spec("imageio_ffmpeg") is not None,
        "zstandard": importlib.util.find_spec("zstandard") is not None,
        "pycryptodome": importlib.util.find_spec("Crypto") is not None,
        "pilk": importlib.util.find_spec("pilk") is not None,
    }
    checks.append({"name": "python_dependencies", "ok": all(dependencies.values()), **dependencies})
    swift_ok = False
    if swift_bin:
        swift = Path(swift_bin).expanduser()
        swift_ok = not swift.is_symlink() and swift.is_file() and os.access(swift, os.X_OK)
    checks.append(
        {
            "name": "voice_mp4_helper",
            "ok": swift_ok,
            "detail": (
                None
                if swift_ok
                else "未提供可执行 --swift-bin；含逐条 M4A 的完整语音归档会停止"
            ),
        }
    )
    voice_mp4_ready = (
        bool(vault_report["ready_for_extract"])
        and dependencies["pilk"]
        and dependencies["imageio_ffmpeg"]
    )
    return {
        "mode": "offline-local-read-only",
        "ready_for_scan": macos
        and bool(vault_report["ready_for_plan"])
        and dependencies["zstandard"],
        "ready_for_media_export": macos
        and account_ok
        and dependencies["pycryptodome"]
        and dependencies["imageio_ffmpeg"],
        "ready_for_voice_mp4": voice_mp4_ready,
        "ready_for_voice_archive": voice_mp4_ready and swift_ok,
        "checks": checks,
        "network_policy": "offline",
        "prohibited_actions": [
            "write_wechat_source",
            "control_wechat_ui",
            "type_or_send_messages",
            "print_or_persist_keys",
            "download_media_without_explicit_opt_in",
        ],
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="从已验证的 Mac 微信 4.x 明文快照扫描并导出本地聊天归档"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor_parser = subparsers.add_parser("doctor", help="检查快照、媒体目录和本地依赖")
    doctor_parser.add_argument("--vault-dir", required=True)
    doctor_parser.add_argument("--account-root")
    doctor_parser.add_argument("--swift-bin")

    scan_parser = subparsers.add_parser("scan", help="生成全部消息的冻结扫描计划")
    scan_parser.add_argument("--vault-dir", required=True)
    scan_parser.add_argument("--chat", required=True)
    scan_parser.add_argument("--chat-id")
    scan_parser.add_argument("--start", required=True)
    scan_parser.add_argument("--end", required=True)
    scan_parser.add_argument("--expected", type=int)
    scan_parser.add_argument(
        "--type",
        action="append",
        dest="types",
        required=True,
        help="重复指定要导出的消息 kind；全部内容也必须显式指定 all",
    )
    scan_parser.add_argument("--output", required=True)

    export_parser = subparsers.add_parser("export", help="用用户确认的计划摘要原子导出归档")
    export_parser.add_argument("--vault-dir", required=True)
    export_parser.add_argument("--account-root", required=True)
    export_parser.add_argument("--plan", required=True)
    export_parser.add_argument("--approve-digest", required=True)
    export_parser.add_argument("--output-dir", required=True)
    export_parser.add_argument("--swift-bin")
    export_parser.add_argument("--title")
    export_mode = export_parser.add_mutually_exclusive_group()
    export_mode.add_argument(
        "--allow-partial",
        action="store_true",
        help="显式允许未解决媒体以占位符进入归档；默认严格停止",
    )
    export_mode.add_argument(
        "--voice-mp4-only",
        action="store_true",
        help="仅限 voice-only 计划：严格验证后只发布合并 MP4 与精简 manifest",
    )

    profile_parser = subparsers.add_parser(
        "configure-profile",
        help="保存不含密钥的本机路径配置；仅供显式 setup 流程使用",
    )
    profile_parser.add_argument("--vault-dir", required=True)
    account = profile_parser.add_mutually_exclusive_group(required=True)
    account.add_argument("--account-ref", help="setup-doctor 返回的脱敏账号编号")
    account.add_argument("--account-root", help="仅供开发调试的明确账号媒体目录")
    profile_parser.add_argument("--swift-bin")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "doctor":
            report = doctor(
                args.vault_dir, account_root=args.account_root, swift_bin=args.swift_bin
            )
            print(_json(report))
            return 0 if report["ready_for_scan"] else 2
        if args.command == "scan":
            vault = _resolve_vault(args.vault_dir)
            plan = build_content_plan(
                vault,
                args.chat,
                args.start,
                args.end,
                expected=args.expected,
                chat_id=args.chat_id,
                kinds=args.types,
            )
            output = _ensure_output_outside_vault(Path(args.output), vault)
            _write_json_private(output, plan, vault)
            print(
                _json(
                    {
                        "plan": str(output),
                        "plan_digest": plan["plan_digest"],
                        "message_count": plan["message_count"],
                        "counts_by_kind": plan["counts_by_kind"],
                        "selection": plan["selection"],
                        "chat": {
                            "display_name": plan["chat"]["display_name"],
                            "kind": plan["chat"]["kind"],
                        },
                        "time_range": plan["time_range"],
                        "next": "确认群名、绝对时间、条数和 plan_digest 后再运行 export",
                    }
                )
            )
            return 0
        if args.command == "export":
            report = export_archive(
                args.vault_dir,
                args.account_root,
                args.plan,
                args.approve_digest,
                args.output_dir,
                swift_bin=args.swift_bin,
                title=args.title,
                allow_partial=args.allow_partial,
                voice_mp4_only=args.voice_mp4_only,
            )
            print(_json(report))
            return 0
        if args.command == "configure-profile":
            account_root = args.account_root
            if args.account_ref:
                account_root = str(resolve_account_ref(args.account_ref).parent)
            if not account_root:
                raise VaultError("缺少 setup-doctor 返回的脱敏账号编号")
            report = doctor(
                args.vault_dir,
                account_root=account_root,
                swift_bin=args.swift_bin,
            )
            checks = {item["name"]: item for item in report["checks"]}
            if not report["ready_for_scan"]:
                raise VaultError("快照尚未通过扫描 doctor，拒绝保存 profile")
            if not checks.get("account_media_root", {}).get("ok"):
                raise VaultError("账号媒体目录尚未通过 doctor，拒绝保存 profile")
            if args.swift_bin and not checks.get("voice_mp4_helper", {}).get("ok"):
                raise VaultError("Swift 媒体工具尚未通过 doctor，拒绝保存 profile")
            profile_paths = {
                "vault_dir": str(Path(args.vault_dir).expanduser().resolve()),
                "account_root": str(Path(account_root).expanduser().resolve()),
                "swift_bin": (
                    str(Path(args.swift_bin).expanduser().resolve())
                    if args.swift_bin
                    else None
                ),
            }
            if args.account_ref:
                write_account_profile(
                    args.account_ref,
                    {
                        "schema_version": 2,
                        "account_ref": args.account_ref,
                        **profile_paths,
                    },
                )
            else:
                # Preserve the explicit source-development account-root path.
                # Normal setup always supplies account-ref and therefore never
                # overwrites the legacy schema-1 profile.
                write_profile({"schema_version": 1, **profile_paths})
            print(
                _json(
                    {
                        "status": "profile-configured",
                        "contains_database_keys": False,
                        "ready_for_scan": report["ready_for_scan"],
                        "ready_for_media_export": report["ready_for_media_export"],
                        "ready_for_voice_mp4": report["ready_for_voice_mp4"],
                        "ready_for_voice_archive": bool(
                            report.get("ready_for_voice_archive")
                        ),
                    }
                )
            )
            return 0
        raise VaultError(f"未知命令：{args.command}")
    except (VaultError, SafeInitError, sqlite3.Error, OSError, ValueError) as error:
        print(f"错误：{error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
