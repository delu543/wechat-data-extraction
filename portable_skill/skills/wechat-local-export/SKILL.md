---
name: wechat-local-export
description: Export authorized local Mac WeChat 4.x chat content by chat name and time range, including a mandatory read-only dry scan before local export. Trigger for requests such as 微信导出, 微信聊天归档, 群聊文字图片语音文件导出, or combining WeChat voice messages. Do not use this skill to initialize database keys; route that separate operation to the explicitly invoked wechat-local-export-setup skill.
---

# WeChat Local Export

Use this Skill as the conversational and safety layer over a deterministic local helper. Never parse an encrypted database, handle a database key, or control the WeChat UI from the Skill itself.

## Conversational contract

The normal user interface is conversation, not commands. After the currently signed-in account has
completed its own explicit first-time setup, prefer that account's saved non-secret local profile.
The same Mac may retain separate profiles for more than one authorized account, but this Skill must
never use a profile unless a read-only doctor has bound it to the current official WeChat session.
Do not ask the user for vault paths, account directories, Swift paths, database names, technical kind
labels, opaque account references, or digests. Infer ordinary content categories from the user's
words; if no category is stated, ask one plain-language question and never default to `all`. Accept
prompts such as:

```text
把“示例讨论群”周一 9 点到 10 点的文字、图片和语音导出来。
```

Resolve everything that is deterministic, run the read-only scan, and present one compact
confirmation containing the chat, absolute interval, selected-type counts and first/last time. Ask
at most one blocking disambiguation question at a time. The user should normally
only need to say “确认导出” after the scan. A narrow exception applies when the same request
explicitly says to export voice directly: after a nonempty, unambiguous voice-only scan, continue in
that same conversation with strict MP4-only export and report the scanned count in the final result.

### Latency and delivery contract

For an ordinary explicit voice-to-MP4 request, keep the user-facing critical path to one
`direct-voice-mp4` invocation. As soon as its strict verification and atomic publication succeed,
return the file link and count to the user. Do not put repository release checks, package
installation, Swift rebuilds, Git commits, GitHub pushes or CI waits in front of that handoff.
Those are development/release work and are run only when code actually changed; their status must
be reported separately from the already verified media artifact.

Use the command's safe `stage_timing_ms` report to distinguish doctor, online snapshot, scan and
export time. Do not repeat an online snapshot for an unchanged request merely to perform additional
diagnostics. If a normal warm export exceeds 45 seconds, report the slow stage and investigate it
after handing off any already verified artifact. Never remove WAL coordination, exact counts,
hashes, duration/order checks, full MP4 decode verification or atomic publication to meet a latency
target.

## Non-negotiable boundaries

- Work only with the user's authorized, local Mac WeChat 4.x data.
- Run `doctor`, then `scan`, then wait for an exact user confirmation before `export`, except for the
  explicit same-request direct voice MP4 rule in Step 5.
- Never silently select a fuzzy chat match, change a time boundary, skip a requested item, or treat a time-group label as an exact message timestamp.
- Never send a WeChat message, type into WeChat, click a chat bubble, or request Accessibility, Screen Recording, or microphone access.
- Never request, accept, print, read, summarize, or place database keys in arguments, environment variables, logs, plans, or conversation text.
- Do not upload chat content or invoke a remote MCP service.
- Bind exactly one current account from the official WeChat process family before choosing a saved
  profile. Historical account directories are not user-facing candidates. Never select an account by
  database modification time, total size, directory order, or a "most recent" heuristic.
- If the current account is absent, multiple, unstable, or unavailable, ask the user to sign in to the
  intended account, open any chat, and bring the official WeChat window to the foreground, then rerun
  the read-only doctor. If the retry still cannot bind exactly one account, stop without scanning.
- If the helper reports that setup is required, tell the user to explicitly invoke `$wechat-local-export-setup`. Do not invoke setup implicitly.
- Treat the bundled source backend as development-only. It is not a signed or notarized product companion; trust only the capabilities returned by `doctor`.

## Locate the client

Resolve this Skill's real directory first. The client is:

```text
<skill_dir>/scripts/wechat_local_export_client.py
```

When this Skill is installed as a symlink, resolve the symlink target before deriving paths. Invoke the client with an argv array through Python; never construct a shell command from the user's chat name, path, or time text.

## Step 1: Doctor

Run, normally without paths when the current account has a matching saved local profile:

```text
python3 <client> doctor \
  [--vault-dir <absolute-decrypted-vault>] \
  [--account-root <absolute-WeChat-account-root>] \
  [--swift-bin <absolute-media-helper>]
```

Interpret the JSON result. Report separately:

- backend kind and version;
- whether a signed Companion is actually present;
- whether exactly one current official WeChat session account was bound, without displaying its
  opaque reference, login identifier, historical account directories, or filesystem path;
- whether that current account has its own ready profile and snapshot;
- supported message/media types;
- vault/schema readiness;
- missing dependencies or permissions;
- integrity limitations such as unverified page HMAC.

Do not claim product readiness when `signed_companion` is false. A profile belonging to a different
previously used account is not a fallback. If the current account cannot be uniquely bound, use the
single foreground retry described above and then stop. If the current account is uniquely bound but
has no ready decrypted vault, explain that this account requires explicit first-time setup and stop
this Skill.

Gate the actual requested categories before scanning: every request needs `ready_for_scan`; image,
file, or sticker bodies also need `ready_for_media_export`. A direct combined voice MP4 needs
`ready_for_voice_mp4`; a readable full archive that retains per-item M4A also needs
`ready_for_voice_archive`. Metadata-only video does not require a video decoder. If a required
readiness flag is false, report the single actionable setup/build issue and stop before creating a
plan or asking for export confirmation.

## Step 2: Resolve the user's natural-language request

Convert the prompt into a small structured request. Codex or macOS dictation may provide the prompt text; this Skill does not access the microphone.

Resolve all relative dates in the user's local timezone and show the absolute interval before scanning. Preserve inclusive/exclusive boundaries explicitly. Examples:

- “周一开始” means the most recent Monday in the resolved local week, not a guessed database label.
- A bare weekday such as “周一” means that most recent local calendar day, represented as
  `[00:00:00, next day 00:00:00)` unless the user gave another boundary.
- A rounded range such as “9 点到 10 点” is half-open by default: `[09:00:00, 10:00:00)`. Because
  the current source backend stores an inclusive second-resolution end, encode that request as
  `09:00:00` through `09:59:59` and show the user the original half-open interval. Explicit wording
  such as “包含 10 点整” overrides this default.
- “到昨天 00:10 那组最后一条” must be converted to actual message timestamps found by the scan; a UI grouping label is only a search clue.

For chat matching:

1. Prefer exact Unicode text.
2. Normalization may fold whitespace and full-width punctuation or omit decorative emoji only to produce candidates.
3. Fuzzy, phonetic, or multiple matches must be shown to the user; never choose one automatically.
4. Duplicate visible names require an explicit chat ID selection or another unambiguous identifier.

If `scan` returns `needs-chat-selection`, show its bounded candidates by display name and kind. Never
choose a `normalized`, `decorative-folded`, or `contains` match automatically. After the user selects
one, write its exact display name and `chat_id` into a new private request and scan again.

Compare requested types with `doctor.supported_types`. If any type is unsupported, report it before creating a plan. Do not quietly downgrade “文字、图片、语音、文件、表情” to voice-only.

Map ordinary Chinese categories to actual kinds without making the user learn them:

- 文字：`text`, `system`
- 图片：`image`
- 语音：`voice`
- 文件：`file`
- 表情包：`sticker`
- 卡片/位置/链接/小程序/引用/合并记录/通话记录等结构化内容：the corresponding supported kinds
- 全部：`all`; video messages remain metadata-only

Persist only explicitly requested kinds. Do not turn a voice-only request into an all-message plan.

## Step 3: Create a private scan request

Create a JSON file with mode `0600` under the fixed private local task root
`~/Library/Application Support/WeChatLocalExport/tasks/`,
using a fresh per-request directory. Do not ask an ordinary user to choose this path, and never put it
in Git, the project, Downloads, or a cloud-synced folder. The source-development schema is:

Create the fixed root only if absent, with mode `0700`; otherwise require a real current-user-owned
non-symlink directory with no group/other permissions. Each request directory must also be fresh and
`0700`. Stop on any ownership, permission, or symlink mismatch.

```json
{
  "schema_version": 1,
  "chat": "示例讨论群",
  "chat_id": null,
  "start": "2030-01-07 09:00:00",
  "end": "2030-01-07 09:59:59",
  "types": ["text", "system", "image", "voice"]
}
```

`vault_dir` is optional when the saved local profile belongs to the uniquely bound current account.
`all` means every locally parseable message is retained; video messages are metadata-only by policy.
Any explicit list means only those kinds are persisted in the plan and archive. Paths in the profile
are local configuration, not keys. Never add an opaque account reference, key-file path or raw secret
to this request.

## Step 4: Dry scan

For the normal confirmation flow, run:

```text
python3 <client> scan --request <absolute-request.json> --output <absolute-plan.json>
```

When the same current request explicitly asks for direct voice MP4 and already satisfies the narrow
Step 5 rule, do not manually expose or hand off a plan/digest/count between commands. Use the
single high-level command documented in Step 5; it still performs this online dry scan internally
before any export.

For the ordinary current-account path, keep official WeChat open. After the old verified vault has
resolved exactly one `chat_id`, `scan` performs a coordinated online refresh of only the initialized
database set needed by that chat and the requested types. It then reloads the updated profile and
builds the plan from that fresh verified vault. If the chat name is absent, fuzzy or ambiguous, stop
before online refresh. An explicit development `vault_dir` remains a frozen-vault path and does not
perform this refresh.

This operation never writes the live WeChat databases. Its public result may report only the safe
state `snapshot_mode: online`; it must not expose the clone directory, vault path, account reference,
database names, keys or WAL details. Present at least:

- that the source is the currently bound official WeChat session, without displaying an account
  identifier;
- exact resolved chat display name and kind;
- absolute start/end and timezone assumption;
- count by selected type and the number of in-range messages omitted by the user's type selection;
- first and last actual item timestamp;
- an internal plan digest and path retained only for the later export call.

The metadata scan does not claim that every attachment body is locally recoverable. Media bytes are
verified by the strict export gate before any final directory is published.

Do not continue if the scan reports ambiguity or an integrity failure. Do not manufacture a count when the helper fails.

If the selected count is zero, report that no matching messages were found, remove only the exact
temporary request/plan files created for this scan, and stop. Do not ask for confirmation or create an
empty archive.

Do not show the absolute plan path or full digest in normal conversation. The user sees only the
human-readable summary and confirms that current summary; reveal technical identifiers only when the
user explicitly asks for troubleshooting detail.

For daily filtering or summary requests, the same online scan is sufficient: keep WeChat open, scan
the requested chat/time/types, and summarize only after the user has asked for that content use.
Do not export or convert media merely because a metadata scan found it.

## Step 5: Confirmation or explicit direct voice instruction

Normally pause and ask the user to confirm the exact chat, absolute interval and selected-type
counts. A generic earlier request to “export everything” does not replace confirmation of the newly
generated plan.

If the current request explicitly says “直接导出”, “直接转成 MP4”, or an equally clear instruction,
the scan itself may continue to export without another turn only when all of these are true:

- the plan is nonempty and selects exactly `voice`;
- one exact chat and unchanged absolute start/end are already resolved;
- there was no candidate ambiguity, account change, unsupported type or integrity warning;
- export uses strict `--voice-mp4-only`, never `--allow-partial`;
- the scan and export occur in the same active conversation, and the final response states the exact
  scanned/exported count.

For that narrow ordinary current-account case, prefer:

```text
python3 <client> direct-voice-mp4 \
  --request <absolute-request.json> \
  --output-dir <absolute-new-output-directory>
```

This high-level command performs the current-session `doctor` gates, requires both
`ready_for_scan` and `ready_for_voice_mp4`, resolves only one exact chat, performs the coordinated
online scan, and passes that same private plan's digest/count directly into strict MP4-only export.
It accepts no development vault override and no partial-output option. A fuzzy, absent, duplicate or
otherwise ambiguous chat stops before export and returns candidates.

The helper reserves one unpredictable regular plan file with mode `0600` beside the private request.
It removes only that exact internal plan on success, zero matches, ambiguity or failure; it never
deletes the request file or another task file. Its public JSON contains the human-readable
chat/time/count result but no request path, plan path, output path, account reference or digest. The
caller already knows the requested output destination and may return that destination as a clickable
local link only after the verified completion report.

Otherwise use the normal confirmation pause. A direct-export phrase never authorizes setup, key
capture, partial output, another account, another chat/time range, or reuse of an older plan.

Accept confirmation only when it refers to the current visible summary. Internally record, without
asking the user to copy or repeat technical values:

- the exact item count;
- the exact plan digest;

Any change to the bound current account, chat, time, types, count, plan file, or digest requires a new
doctor, scan and confirmation. Never carry a plan across an account switch.

## Step 6: Export

After confirmation, run the client with the confirmed values:

```text
python3 <client> export \
  --plan <absolute-plan.json> \
  --output-dir <absolute-new-output-directory> \
  --confirm-digest <64-hex-plan-digest> \
  --confirm-count <exact-message-count> \
  [--voice-mp4-only] \
  [development-only explicit path overrides]
```

Use only the saved profile matched to the currently bound account. Explicit `--vault-dir`,
`--account-root`, or `--swift-bin` overrides are for source development and recovery only; do not
make ordinary users provide them.

The output directory must not already exist. If the user did not name a destination, create a fresh
directory beneath `~/Library/Application Support/WeChatLocalExport/exports/`, applying the same
owner/mode/symlink checks as the task root, and return a clickable result; do not ask for a filesystem
path. Do not add overwrite flags or pass raw content through the shell.

The development backend writes `index.html`, `chat.md`, `messages.json/jsonl`,
`manifest.json`, and resolved local images, voice, files, and stickers. Voice is
also assembled into MP4 when the Swift helper and decoder are ready. Conditional
or missing media must remain visible in the manifest. `--allow-partial` is a
separate, explicit user decision; never add it silently.

When the confirmed plan selects only `voice` and the user asks for only the
combined MP4, add `--voice-mp4-only` automatically. This strict mode publishes
only `voice.mp4` and a compact verification manifest; per-item SILK, PCM and M4A
artifacts remain private staging data and are removed before atomic publication.
It is mutually exclusive with `--allow-partial`. Do not use this option for a
mixed-type plan or when the user requested a readable full archive.

Always attempt strict export first. If it stops on unresolved media, no final archive is published;
show the bounded message sequence/status/reason report. Only after a new explicit acceptance of those
reported failures may the same approved plan be rerun with `--allow-partial`. This exceptional second
question is not part of the normal successful flow.

## Step 7: Verify and hand off

Require the helper's completion report and verify:

- `verification.status` is `verified-before-atomic-publish`; absence is failure, not a reason to
  inspect message bodies in the conversation;
- exported count equals confirmed count;
- plan digest matches;
- each output manifest item has a valid hash;
- missing/duplicate/failure lists are empty, or exactly match the user's explicit accepted policy;
- the final file exists outside the decrypted vault;
- development versus signed-product status is accurately stated.

The source helper performs the manifest/message re-read, relative-path containment checks and every
resolved file/MP4 SHA-256 check in staging before its atomic rename. No separate broad filesystem
`verify` command is exposed by the thin client.

After a verified strict export succeeds, remove only that task's exact regular request and plan files,
then remove the now-empty per-request directory. The high-level `direct-voice-mp4` helper has already
removed its internal plan but deliberately leaves the caller-owned request for this final bounded
cleanup. Never recursively delete the shared task root and never delete an output archive. If export
failed and a partial-export decision is pending, retain the normal-flow plan only until that decision
is resolved; otherwise clean it at task end. Explain only that temporary private task data was
cleaned, not its path. If the user explicitly asks to retain an audit plan, keep it and state that it
contains message-level private data.

Return clickable local output links. Do not automatically open or ingest exported chat content into the conversation unless the user separately asks.

## Failure behavior

Fail closed and explain the next safe action when any of these occurs:

- Full Disk Access or Codex filesystem permission is missing;
- no current official WeChat account can be uniquely and stably bound after the one guided retry;
- the current account changed or no longer matches the selected profile or approved plan;
- online SQLite coordination, the locked WAL anchor, APFS clone, committed-frame replay or new-vault
  doctor cannot be verified;
- a frozen development snapshot is unstable or contains plaintext WAL/SHM sidecars;
- a chat match is absent or ambiguous;
- the schema is unsupported;
- a media join is missing or non-unique;
- the plan digest/count differs from confirmation;
- the helper or decoder is absent;
- only remote/non-local media remains.

Never fall back to screen recording, UI clicks, CDN downloading, a third-party search service, or silent partial export.

Keeping WeChat open is the normal daily path. Ask the user to quit WeChat only as a bounded recovery
after online coordination has failed safely and a fresh retry cannot proceed; quitting is not a
routine prerequisite for scan, export, daily filtering or chat summarization.
