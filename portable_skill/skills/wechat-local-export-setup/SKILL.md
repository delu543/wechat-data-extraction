---
name: wechat-local-export-setup
description: Explicit-only setup for the authorized local Mac WeChat 4.x export helper, including permission diagnosis, source-development dependency checks, and a separately confirmed one-time database-key initialization. Never trigger implicitly from an ordinary export request, missing-key error, or vague request to make WeChat export work.
---

# WeChat Local Export Setup

This is a high-sensitivity, explicit-only setup workflow. `agents/openai.yaml` must keep `allow_implicit_invocation: false`.

## Entry gate

Proceed only when the user explicitly invokes `$wechat-local-export-setup` in the current task. An ordinary request to export a chat, a failed `doctor`, or the existence of encrypted databases is not authorization to initialize keys.

Setup authorization is scoped to the one account uniquely bound to the current official WeChat
session. A different account on the same Mac requires its own explicit first-time setup. Automatic
current-account binding is read-only routing evidence; it is never permission to capture a key,
create a decrypted snapshot, or reuse another account's private state.

At entry, state clearly:

- this development package does not ship a signed or notarized Companion;
- the source initializer uses a temporary private copy of the official WeChat app and observes only exact-salt PBKDF derivation results;
- the original WeChat app is never modified;
- the current development initializer stores validated keys in a private `0600` local file, not Keychain;
- the product release must move key ownership into a signed Companion and macOS Keychain;
- the user can stop before capture without changing the official app or writing keys.

## Locate the shared client

Resolve this Skill's real path, then locate the sibling export Skill client:

```text
<setup_skill_dir>/../wechat-local-export/scripts/wechat_local_export_client.py
```

Use the client only for `doctor`. It intentionally has no `init`, key, password, token, or credential option.

Resolve fixed local roots once from the current user's home with standard path APIs; never accept
them from an ordinary setup prompt and never display the resolved absolute paths:

- key state: `~/Library/Application Support/WeChatVoiceMP4/private` (the current source initializer's
  compatibility root);
- retained snapshots: `~/Library/Application Support/WeChatLocalExport/snapshots`;
- key-initializer interpreter: `~/Library/Application Support/WeChatLocalExport/key-init-tools/python/bin/python`.

Normalize `~` before passing an argument; do not pass a quoted literal tilde or derive any path from
the current working directory. Each root must pass the helper's ownership, mode and symlink gates.

## Phase 1: Read-only doctor

Resolve the full source-kit project root from this Skill's real path. First run the normal client
`doctor`. Treat setup as unnecessary only when it uniquely binds the current official WeChat session
to that same account's ready saved profile; a ready profile for another historical account must not
suppress setup. On a fresh account, run the initializer's separate read-only doctor:

Run the initializer as its package module with the process working directory set to
`<project_root>`. Do not execute `live_tools/wechat_key_init.py` as a file: direct-file execution can
load a second copy of the initializer module when the account router imports it.

```text
python3 <client> doctor [--vault-dir <absolute-existing-decrypted-vault>]
<key-init-python> -m live_tools.wechat_key_init setup-doctor
```

Prefer the fixed private interpreter at
`~/Library/Application Support/WeChatLocalExport/key-init-tools/python/bin/python` when it already
exists. Otherwise `/usr/bin/python3` may run the read-only doctor, but missing Frida must remain a
reported blocker. A setup-doctor exit code of `2` means that valid JSON was produced with blockers;
always inspect `ready_for_capture`, `existing_initialization_ready`, the complete structured
`blockers` list, and `next_action` rather than treating the exit code alone as authorization. Show
all actionable blockers in plain language. Resolve missing or unsafe prerequisites before relying on
the current-account binding; `next_action` is only a hint and must not hide another blocker.

If pinned source-development dependencies are missing, explain that installing them downloads code
from PyPI into one private virtual environment. Only after the user approves that installation, run
`<project_root>/scripts/setup_key_init_tools.sh`, then rerun setup-doctor with the fixed interpreter.
Dependency-install approval is not key-capture approval.

Check and report without mutation:

- macOS and CPU architecture;
- official Mac WeChat presence, version, bundle ID, pinned Tencent signing identity, and whether it is running;
- whether the official process family can be bound to exactly one current account using read-only,
  exact process-to-storage evidence; retain the returned opaque `account_ref` privately and never show
  it or ask the user for a filesystem path or login identifier;
- exact contact/message/media/message_resource target aliases and sizes for that current account only;
- only the Python/Frida/cryptography prerequisites needed for key initialization;
- Full Disk Access result;
- an existing owned key-init runtime that still needs normal quit and cleanup;
- whether that account's stored private salt fingerprints still match its current databases, without
  displaying a fingerprint.

Historical account directories must never be displayed as choices. Never infer the current account
from database modification time, total size, directory order, account-folder spelling, or a "most
recent" heuristic. If the binding result is zero, multiple, unstable, or unavailable, ask one
plain-language question: tell the user to sign in to the intended account in the official WeChat app,
open any chat, bring that WeChat window to the foreground, and then say it is ready. Rerun the entire
read-only setup-doctor after that response. Bringing the window forward is only a user-controlled
retry step, not account evidence and not capture consent. If the retry still cannot bind exactly one
account, stop without dry-scan or capture. Decoder and Swift/media-helper readiness are checked later
by the normal `doctor` after a snapshot exists; Phase 1 must not claim to have checked or installed
them.

Do not display raw salts, keys, PBKDF buffers, login identifiers, or chat data.

## Phase 2: Permission guidance

Full Disk Access must be granted manually in macOS System Settings. You may open the relevant settings pane, but do not use UI automation to add or toggle an entry.

In source-development mode the permission belongs to the actual host running the source, such as Terminal or Codex. Permission changes generally require that host to be fully quit and reopened. Do not ask for Accessibility, Screen Recording, or microphone access.

## Phase 3: Initialization dry run

Before choosing database targets, determine the requested content categories. If the user invoked
setup without an export goal, ask one plain-language question such as “这次以后要导出哪些内容：
文字、语音、图片、文件、表情包？可以多选。” Do not default to every type.

Build one exact target union from the uniquely bound current account's setup-doctor inventory:

- every requested category requires `contact` and **every discovered** `message_N` alias;
- `voice` additionally requires **every discovered** `media_N` alias;
- `image`, `file`, or `sticker` additionally requires `message_resource` when that alias is present;
- `text` adds nothing beyond `contact` plus every discovered `message_N`;
- a combination of categories uses the union, without duplicates.

Never substitute a wildcard, one representative shard, or an unreturned alias. If a required class
has no discovered target, report the gap and stop. A later request for a content type not covered by
the initialized target set may require this explicit setup Skill again, with a fresh dry scan and
fresh consent for the expanded exact target set.

Use the existing initializer only from the resolved source kit:

```text
<key-init-python> -m live_tools.wechat_key_init dry-scan \
  --account-ref <internally-retained-current-account-reference> \
  --targets <explicit-comma-separated-targets>
```

Requirements:

- The helper resolves `account-ref` internally to exactly one
  `xwechat_files/<account>/db_storage` directory. Do not expose or ask the user to copy that path.
- Targets must be the explicit aliases produced by the mapping above; never use a wildcard or “all”.
- The `account-ref` must be the one derived from the uniquely bound current official session in this
  setup run. Never offer historical accounts as alternatives and never treat automatic binding as
  capture approval.
- Preserve the dry-scan output as a redacted prerequisite report. Retain its 64-hex approval digest
  only in private task state for the matching capture command. Never display the digest, ask the user
  to copy it, place it in ordinary commentary, or reuse it after account, targets, app identity, or
  database metadata changes.
- The dry scan must not copy, launch, sign, attach, capture, or write files.

## Phase 4: Exact key-capture consent

Before requesting confirmation, explain that the official WeChat app must be normally quit for the
capture; a temporary private WeChat copy may then ask the user to log in or confirm on their phone,
and only the user may perform that interaction. Also state that the original app is not modified.

After showing the human-readable dry-scan result, stop and request a new explicit confirmation that
names:

- the currently signed-in account as the account uniquely bound in this setup run, without exposing
  an opaque reference, login identifier, path, modification time, size, or historical account list;
- acknowledgement that this permission is only for this account's first-time or expanded-target setup
  and does not authorize any other account on the Mac;
- the exact database target aliases, summarized in plain language;
- permission to create and locally ad-hoc-sign a temporary private WeChat copy;
- permission to observe exact-salt key derivation during this one initialization;
- acknowledgement that the development build stores validated keys in a private local file;
- acknowledgement that official WeChat must be normally quit and any temporary-copy login or phone
  confirmation remains user-controlled.

Do not infer consent from earlier conversation. Do not continue on silence, “继续看看”, or a confirmation that refers to a different target set.
This confirmation authorizes key capture for this one bound account and exact target set only. It
does **not** authorize creating or retaining a decrypted snapshot.

## Phase 5: User-controlled WeChat transition

After consent:

1. Ask the user to normally quit the official WeChat app.
2. Verify no official WeChat process still holds the selected databases.
3. Never force-quit, kill, type into, or automate login for WeChat.
4. If the temporary copy asks for login or phone confirmation, the user performs it manually for the
   same account that was bound and confirmed; a different login cannot inherit this consent.

Only then invoke the current development capture command with the exact dry-scan values and a private state directory. Never pass a raw key on the command line and never capture or echo the initializer's private JSON content.

```text
<key-init-python> -m live_tools.wechat_key_init capture \
  --account-ref <confirmed-redacted-reference> \
  --targets <confirmed-comma-separated-targets> \
  --approve-digest <privately-retained-dry-scan-digest> \
  --private-dir <fixed-private-state-directory>
```

The capture must recompute and match the retained digest before any write. A mismatch, changed
inventory, restarted official app, or account switch invalidates this consent: ask the user to sign in
to the intended account, open any chat and bring WeChat forward, then rerun setup-doctor and dry-scan,
show the new human summary, and obtain a new confirmation. Never reveal either digest.

Capture revalidates the pinned official Tencent signing identity and CDHash before any private
directory is created. After copying, it verifies the copy still satisfies the pinned official
requirement and has the same CDHash **before** ad-hoc signing. It repeats the official-process and
exact DB/WAL/SHM holder check immediately before spawning the private copy. A same-bundle-id
self-signed app, changed copy, or restarted official process must be rejected.

The source command is intentionally not routed through the thin client. This separation prevents normal export prompts from reaching key initialization.

## Phase 6: Validate, quit, and bounded cleanup

Initialization is successful only when every requested target for the confirmed current account has
an exact-salt derivation result that decrypts a structurally valid database first page. Partial key
sets must not be published or shared with another account profile.

After capture:

1. Tell the user to normally quit the temporary locally ad-hoc-signed copy.
2. Run the initializer's `cleanup` subcommand only against its fixed private state directory.
3. Cleanup must reject a live PID/process, ownership mismatch, symlink, unsafe entry, or unknown
   marker. After an interruption it may recover only bounded direct `init-*` children with valid
   owner-only initializer markers; it must never infer ownership from a name alone.
4. Never run a generic recursive deletion command.
5. Never read or print the resulting key file.

## Phase 7: Separate safe-snapshot consent and creation

After successful capture and bounded cleanup, stop again. Before creating any snapshot, request a
second explicit confirmation. In plain language, tell the user:

- the exact database categories for the same currently confirmed account that will be snapshotted,
  described simply as the account bound earlier in this setup run;
- the snapshot will be written only to WeChat Local Export's fixed, owner-private local support
  storage, separate from the downloadable export; do not expose its internal filesystem path;
- validated database keys remain in private local storage until a separate explicit removal or
  reinitialization action;
- the decrypted snapshot remains because the saved profile uses it for later exports;
- generated export outputs are never deleted automatically.

The user must expressly approve this snapshot creation and retention. Key-capture consent, dependency
installation consent, an earlier export request, silence, or “继续” is not snapshot consent. If the
user declines, keep the validated keys private, do not create a decrypted snapshot, and report that
normal export is not yet configured.

Only after that separate consent, while official WeChat remains normally exited, use the existing
`wechat_safe_snapshot.py` with:

- the confirmed redacted `account-ref`, resolved internally;
- a separate per-account private `0700` output root;
- the initializer-owned private key-file path;
- only the explicitly required contact/message/media/message_resource databases.

Passing a key-file **path** to this bounded local helper is permitted; reading or displaying its contents is not. Active WAL frames, unstable source stats, unexpected tables, failed SQLite checks, unsafe paths, or unsupported schema must stop the snapshot.

```text
<key-init-python> <project_root>/live_tools/wechat_safe_snapshot.py \
  --account-ref <confirmed-redacted-reference> \
  --output-root <fixed-private-snapshot-root> \
  --keys-file <initializer-owned-private-key-file> \
  --database <exact-alias> [--database <exact-alias> ...]
```

The current decryptor reports that page HMAC is not verified. Preserve that limitation in every status report; do not describe structural `quick_check` success as authenticated decryption.

After the snapshot succeeds, rerun `doctor` against its `decrypted` directory. The user may then reopen official WeChat.

If doctor validates the snapshot, matching account media root and optional Swift helper, save the
credential-free local profile under that account's entry through the source CLI:

```text
<project_root>/scripts/content.sh configure-profile \
  --vault-dir <absolute-decrypted-vault> \
  --account-ref <confirmed-redacted-reference> \
  [--swift-bin <absolute-media-helper>]
```

This is the final convenience step: the helper resolves the account path internally and stores only
absolute local paths under an opaque per-account profile entry, never keys, chat names, message bodies
or export consent. Report `contains_database_keys: false`. Normal export conversations may use only
the profile that matches a newly verified current official session, so the user never has to repeat
paths and switching accounts cannot reuse stale state. Another account's first setup or any later
profile change belongs to this explicit setup Skill, not to the normal export Skill.

## Product-release boundary

Do not claim that this setup is a finished cross-computer product. The release design still requires:

- a stable Developer ID-signed and notarized Companion app;
- macOS Keychain storage instead of a JSON key file;
- universal or separately verified arm64/x86_64 builds;
- an allowlisted, high-level IPC contract with no arbitrary file or SQL access;
- complete page authentication where supported;
- an updater with signature verification;
- privacy, license, support, and uninstall review.

It also requires tested per-account isolation for keys, snapshots and profiles plus a read-only,
fail-closed current-session binding contract. A foreground window alone is never sufficient evidence.

Until those exist, report the backend as `development-source` and `signed_companion: false`.
