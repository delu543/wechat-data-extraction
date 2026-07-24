#!/usr/bin/env python3
"""Static, dependency-free validation for the portable Skill/Plugin package."""

from __future__ import annotations

import json
from pathlib import Path
import re
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PLUGIN_MANIFEST = ROOT / ".codex-plugin" / "plugin.json"
MARKETPLACE = ROOT / ".agents" / "plugins" / "marketplace.json"
EXPORT_SKILL = ROOT / "skills" / "wechat-local-export"
SETUP_SKILL = ROOT / "skills" / "wechat-local-export-setup"
CLIENT = EXPORT_SKILL / "scripts" / "wechat_local_export_client.py"
DEV_BACKEND = ROOT / "scripts" / "dev_backend.py"
PRIVACY = ROOT / "PRIVACY.md"
SECURITY = ROOT / "SECURITY.md"


class ValidationError(RuntimeError):
    pass


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"invalid JSON: {path.relative_to(ROOT)}") from exc
    if not isinstance(value, dict):
        raise ValidationError(f"JSON root is not an object: {path.relative_to(ROOT)}")
    return value


def _frontmatter(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    match = re.match(r"---\n(.*?)\n---\n", text, re.DOTALL)
    if not match:
        raise ValidationError(f"missing frontmatter: {path.relative_to(ROOT)}")
    result: dict[str, str] = {}
    for line in match.group(1).splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        result[key.strip()] = value.strip()
    return result


def _yaml_policy(path: Path) -> bool:
    text = path.read_text(encoding="utf-8")
    match = re.search(
        r"(?m)^policy:\s*$[\s\S]*?^\s{2}allow_implicit_invocation:\s*(true|false)\s*$",
        text,
    )
    if not match:
        raise ValidationError(f"missing implicit policy: {path.relative_to(ROOT)}")
    return match.group(1) == "true"


def _validate_no_sensitive_literals() -> None:
    mac_home_prefix = "/" + "Users/"
    linux_home_prefix = "/" + "home/"
    local_username = "a" + "543"
    forbidden_patterns = {
        "hard-coded macOS user path": re.compile(
            re.escape(mac_home_prefix) + r"[A-Za-z0-9._-]+/"
        ),
        "hard-coded Linux user path": re.compile(
            re.escape(linux_home_prefix) + r"[A-Za-z0-9._-]+/"
        ),
        "private key block": re.compile(r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY"),
        "current-machine username": re.compile(
            rf"(?i)(?<![A-Za-z0-9]){re.escape(local_username)}(?![A-Za-z0-9])"
        ),
    }
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.suffix in {".pyc", ".png", ".zip"}:
            continue
        text = path.read_text(encoding="utf-8")
        for label, pattern in forbidden_patterns.items():
            if pattern.search(text):
                raise ValidationError(f"{label}: {path.relative_to(ROOT)}")


def _validate_client_scope() -> None:
    source = CLIENT.read_text(encoding="utf-8")
    for fragment in (
        "ALLOWED_COMMANDS = frozenset(",
        "\"direct-voice-mp4\"",
        "os.execv(",
    ):
        if fragment not in source:
            raise ValidationError(f"client scope marker missing: {fragment}")
    forbidden_options = (
        "--" + "key",
        "--" + "secret",
        "--" + "password",
        "--" + "token",
        "--" + "credential",
    )
    lowered = source.lower()
    for option in forbidden_options:
        if option in lowered:
            raise ValidationError(f"client accepts or mentions forbidden option: {option}")
    if "shell=True" in source or "os.system(" in source:
        raise ValidationError("client contains a shell execution escape")
    if "shutil.which" in source:
        raise ValidationError("client must not trust a same-named PATH executable")
    if "WECHAT_LOCAL_EXPORT_ALLOW_UNVERIFIED_HELPER" not in source:
        raise ValidationError("development helper path lacks an explicit opt-in gate")
    if "Path.cwd()" in source or "WECHAT_LOCAL_EXPORT_PROJECT_ROOT" in source:
        raise ValidationError("client must discover source only from its own real path")
    for module in ("frida", "Crypto", "keyring"):
        if re.search(rf"(?m)^\s*(?:import|from)\s+{re.escape(module)}\b", source):
            raise ValidationError(f"client imports credential/decryption module: {module}")

    backend_source = DEV_BACKEND.read_text(encoding="utf-8")
    for fragment in ("shutil.which", "Path.cwd()", "WECHAT_LOCAL_EXPORT_SWIFT_BIN"):
        if fragment in backend_source:
            raise ValidationError(f"development backend trusts ambient execution state: {fragment}")


def validate() -> dict[str, Any]:
    for required in (PRIVACY, SECURITY):
        if not required.is_file() or not required.read_text(encoding="utf-8").strip():
            raise ValidationError(f"missing release boundary document: {required.name}")
    manifest = _load_json(PLUGIN_MANIFEST)
    if manifest.get("name") != "wechat-local-export":
        raise ValidationError("unexpected plugin name")
    if manifest.get("skills") != "./skills/":
        raise ValidationError("plugin skills path must be ./skills/")
    if "mcpServers" in manifest or "apps" in manifest or "hooks" in manifest:
        raise ValidationError("local-only skills package must not declare MCP/apps/hooks")

    marketplace = _load_json(MARKETPLACE)
    entries = marketplace.get("plugins")
    if not isinstance(entries, list) or len(entries) != 1:
        raise ValidationError("local marketplace must contain exactly one plugin")
    if entries[0].get("name") != manifest["name"]:
        raise ValidationError("marketplace and plugin names differ")
    source = entries[0].get("source")
    if not isinstance(source, dict) or source.get("path") != "./":
        raise ValidationError("local marketplace source must point at ./")

    export_meta = _frontmatter(EXPORT_SKILL / "SKILL.md")
    setup_meta = _frontmatter(SETUP_SKILL / "SKILL.md")
    if export_meta.get("name") != "wechat-local-export":
        raise ValidationError("export skill name mismatch")
    if setup_meta.get("name") != "wechat-local-export-setup":
        raise ValidationError("setup skill name mismatch")
    if not export_meta.get("description") or not setup_meta.get("description"):
        raise ValidationError("both skills require descriptions")

    export_implicit = _yaml_policy(EXPORT_SKILL / "agents" / "openai.yaml")
    setup_implicit = _yaml_policy(SETUP_SKILL / "agents" / "openai.yaml")
    if not export_implicit:
        raise ValidationError("export skill must allow implicit invocation")
    if setup_implicit:
        raise ValidationError("setup skill must disable implicit invocation")

    setup_text = (SETUP_SKILL / "SKILL.md").read_text(encoding="utf-8")
    for phrase in (
        "explicit-only",
        "allow_implicit_invocation: false",
        "Do not infer consent",
        "signed_companion: false",
        "setup-doctor",
        "--account-ref",
        "pinned official Tencent signing identity",
    ):
        if phrase not in setup_text:
            raise ValidationError(f"setup safety phrase missing: {phrase}")
    if "--db-base" in setup_text:
        raise ValidationError("setup Skill must not ask ordinary users for a database path")

    _validate_client_scope()
    _validate_no_sensitive_literals()
    return {
        "status": "ok",
        "plugin": manifest["name"],
        "version": manifest["version"],
        "skills": [export_meta["name"], setup_meta["name"]],
        "export_implicit": export_implicit,
        "setup_implicit": setup_implicit,
        "client_commands": [
            "doctor",
            "scan",
            "export",
            "direct-voice-mp4",
        ],
        "signed_companion_included": False,
    }


def main() -> int:
    try:
        report = validate()
    except (ValidationError, OSError, UnicodeDecodeError) as exc:
        print(f"VALIDATION FAILED: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
