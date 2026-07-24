# Codex project instructions

This repository is the local macOS project “微信数据提取项目”.

## First relevant request

When the user asks to install, check, use, scan, summarize, or export WeChat data:

1. Run `./scripts/codex_bootstrap.sh doctor`.
2. If the result is `needs_install`, explain that the installer downloads pinned public Python
   packages into a private user directory and builds the local Swift helper, then run
   `./scripts/codex_bootstrap.sh install`.
3. Do not install or initialize key-capture dependencies during bootstrap.
4. After bootstrap, use the `wechat-local-export` Skill for normal natural-language requests.

Opening the repository must never execute code by itself. Installation begins only after a user
asks Codex to install or use this project.

## Account initialization boundary

- Normal export may be invoked from natural language.
- First-time database-key initialization is explicit-only. Never infer consent.
- If the current account is not initialized, ask the user to invoke
  `$wechat-local-export-setup`.
- Dependency installation, one-time key capture, and retention of a private decrypted snapshot are
  separate decisions.

## Safety boundaries

- Supported production scope is local macOS with official Mac WeChat 4.x.
- Never upload chat content, database files, keys, profiles, or exported media.
- Never commit files from `work/`, `outputs/`, `.codex/`, `.build/`, task directories, application
  support directories, or WeChat containers.
- Never send a WeChat message, type into WeChat, paste, or press Return.
- Use exact chat and absolute time boundaries. Ambiguity must stop before refresh or export.
- Keep WeChat open for the normal online snapshot path. Quitting is recovery-only.
- Run `./scripts/release_check.sh` before any public push.

## Natural-language example

```text
把“示例讨论群”2026 年 7 月 24 日 14:00 到 15:30 的所有语音直接合成 MP4。
```

Codex should perform readiness checks, resolve the exact chat and time range, and use the
high-level `direct-voice-mp4` workflow. Do not ask the user to pass database paths, plan digests, or
internal account identifiers.
