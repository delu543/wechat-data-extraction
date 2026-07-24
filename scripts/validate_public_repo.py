#!/usr/bin/env python3
"""Dependency-free release privacy and repository-shape validation."""

from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {
    "AGENTS.md",
    "PRIVACY.md",
    "README.md",
    "SECURITY.md",
    ".agents/plugins/marketplace.json",
    "portable_skill/.codex-plugin/plugin.json",
    "scripts/codex_bootstrap.sh",
    "scripts/release_check.sh",
}
FORBIDDEN_PARTS = {
    ".build",
    ".codex",
    ".git",
    "__pycache__",
    "outputs",
    "tasks",
    "work",
}
FORBIDDEN_SUFFIXES = {
    ".db",
    ".db-shm",
    ".db-wal",
    ".dylib",
    ".jsonl",
    ".key",
    ".log",
    ".m4a",
    ".mp3",
    ".mp4",
    ".mobileprovision",
    ".mov",
    ".p12",
    ".pem",
    ".pcm",
    ".pid",
    ".silk",
    ".so",
    ".sqlite",
    ".sqlite3",
    ".whl",
    ".zip",
}
TEXT_SUFFIXES = {
    "",
    ".json",
    ".md",
    ".py",
    ".sh",
    ".swift",
    ".txt",
    ".yaml",
    ".yml",
}
MAC_HOME_PREFIX = "/" + "Users" + "/"
LINUX_HOME_PREFIX = "/" + "home" + "/"
PRIVATE_PATTERNS = {
    "absolute macOS home": re.compile(
        re.escape(MAC_HOME_PREFIX) + r"[A-Za-z0-9._-]+/"
    ),
    "absolute Linux home": re.compile(
        re.escape(LINUX_HOME_PREFIX) + r"[A-Za-z0-9._-]+/"
    ),
    "private key": re.compile(r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY"),
    "GitHub token": re.compile(r"(?:gh[opsu]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
    "OpenAI token": re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
}


def candidate_files() -> list[Path]:
    tracked = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "-z"],
        capture_output=True,
        check=False,
    )
    if tracked.returncode == 0:
        return [
            ROOT / item.decode("utf-8")
            for item in tracked.stdout.split(b"\0")
            if item
        ]
    return [
        path
        for path in ROOT.rglob("*")
        if path.is_file() and not any(part in FORBIDDEN_PARTS for part in path.relative_to(ROOT).parts)
    ]


def main() -> int:
    errors: list[str] = []
    for relative in sorted(REQUIRED):
        if not (ROOT / relative).is_file():
            errors.append(f"missing required file: {relative}")

    files = candidate_files()
    for path in files:
        relative = path.relative_to(ROOT)
        if any(part in FORBIDDEN_PARTS for part in relative.parts):
            errors.append(f"tracked/generated private directory: {relative}")
            continue
        combined_suffix = "".join(path.suffixes[-2:])
        if path.suffix.lower() in FORBIDDEN_SUFFIXES or combined_suffix.lower() in FORBIDDEN_SUFFIXES:
            errors.append(f"prohibited data artifact: {relative}")
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            errors.append(f"unexpected binary text file: {relative}")
            continue
        for label, pattern in PRIVATE_PATTERNS.items():
            if pattern.search(text):
                errors.append(f"{label}: {relative}")

    marketplace_path = ROOT / ".agents/plugins/marketplace.json"
    if marketplace_path.is_file():
        try:
            marketplace = json.loads(marketplace_path.read_text(encoding="utf-8"))
            plugin = marketplace["plugins"][0]
            if plugin["source"]["path"] != "./portable_skill":
                errors.append("root marketplace must point to ./portable_skill")
        except (KeyError, IndexError, json.JSONDecodeError):
            errors.append("invalid root marketplace manifest")

    if errors:
        for error in errors:
            print(f"VALIDATION FAILED: {error}")
        return 2
    print(
        json.dumps(
            {
                "status": "ok",
                "project": "微信数据提取项目",
                "files_checked": len(files),
                "private_artifacts": 0,
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
