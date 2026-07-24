# WeChat Local Export Product Architecture

## Product boundary

The product is an offline macOS exporter for data belonging to the signed-in
user. It reads a verified decrypted WeChat 4.x snapshot and the matching account
media tree. For routine current-account work, it creates that snapshot while
official WeChat remains open by coordinating SQLite WAL locks, cloning the
minimal encrypted database set and replaying only committed frames. It never
types in WeChat, sends a message, modifies the live database, or uploads chat
data.

Video bodies are outside version 1. Video messages remain in the transcript with
`excluded_by_policy`, so their existence is never silently hidden.

## Delivery shape

The repository ships two layers:

1. A deterministic local helper implements schema checks, scan plans, digest
   approval, parsing, media recovery, manifests, and atomic output.
2. A Codex Plugin contains a normal export Skill and a separate setup Skill.
   The export Skill may match natural-language requests. Setup/key initialization
   must always be invoked explicitly.

For development, the export Skill can call the Python helper in this repository.
A public release should replace that backend with a signed and notarized
universal macOS companion app while keeping the JSON command contract stable.

## Fixed workflow

```text
explicit setup -> read-only current-session binding -> dry-scan
               -> exact per-account key-capture consent -> capture + bounded cleanup
               -> separate retained-snapshot consent -> per-account private profile

doctor -> bind current account to matching profile
       -> resolve one exact chat in old verified vault
       -> online minimal snapshot -> validate + atomically update profile -> scan
       -> show exact chat/time/counts/digest -> user confirmation
       -> export with the approved digest -> verify manifest
```

The normal scan path keeps official WeChat open. Quitting WeChat is a bounded
recovery option only when online coordination fails safely after retry; it is
not a daily prerequisite.

The setup doctor uses bounded read-only evidence from the validated official WeChat process family
to bind exactly one currently signed-in account. It may enumerate historical storage internally for
validation, but it never presents those directories as user choices and never selects by modification
time, total size, directory order or a "most recent" heuristic. The user sees only that the current
official session was uniquely bound; the Skill retains an opaque `account-ref` internally.

If binding returns zero, multiple, unstable or unavailable results, the only recovery is to ask the
user to sign in to the intended account, open any chat and bring official WeChat to the foreground,
then rerun the complete read-only doctor. Foreground state triggers a retry but is not account evidence.
A second non-unique result stops setup without dry-scan or key capture.

The same current-session reference is resolved by initialization, snapshot and profile configuration.
Capture requires Mac WeChat 4.x, rechecks a pinned Tencent signing requirement and CDHash, checks the
exact databases and any existing WAL/SHM sidecars for WeChat holders, and compares the exact dry-scan
approval digest before any private runtime or state directory is created. The copied bundle must still
satisfy the official requirement and same CDHash before it is ad-hoc signed; process/holder quiescence
is checked again immediately before spawn. A changed account binding or database inventory invalidates
the digest and requires a fresh doctor, dry-scan and consent.

Every selected content category requires `contact` and all discovered `message_N`
shards. Voice additionally requires all discovered `media_N` shards. Image, file or
sticker additionally requires `message_resource` when present. Setup never guesses a
representative shard or accepts a wildcard. The approval digest binds the selected
account, aliases, sizes, salt fingerprints and application identity; it is retained
internally and never presented as a value the user must copy.

- `doctor` diagnoses platform, snapshot, account-root and optional decoder
  readiness without exporting message content.
- `scan` resolves one exact chat and an inclusive absolute time range. It
  first uses the prior verified vault to resolve a unique exact chat ID. Only
  then does the current-account path refresh `contact`, the target message
  shard(s), and the media/resource databases required by the requested kinds.
  It reloads the validated profile, identifies kinds in memory, then persists
  only the user-requested kinds in deterministic order. Ambiguous chat
  candidates never trigger refresh. An explicit development vault remains a
  frozen input. `all` explicitly retains every message, including unknown and
  excluded types.
- `export` requires the exact scan digest. A changed plan is rejected.
- `direct-voice-mp4` is the restricted same-request shortcut for an explicit
  current-account voice-only MP4 request. It performs the doctor readiness
  gates, exact online scan and same-plan strict export in one helper call; it
  accepts no development-vault override or partial-output mode.
- Strict export is atomic. Missing, ambiguous or corrupt required media prevents
  publication. Existing `--allow-partial` mode must be separately and explicitly
  approved for the current plan.

Relative dates and voice dictation are interpreted by Codex, then converted to
absolute local timestamps before `scan`. The helper does not require microphone,
Screen Recording or Accessibility permission.

Daily filtering and summary automation uses this same online scan path and does
not convert or export media unless the user's request asks for it. The public
scan report exposes only the safe `snapshot_mode: online` state, never clone
paths, database names, account references, keys or WAL internals.

Confirmation remains the default export boundary. One narrow conversational
shortcut is supported: when the same request explicitly asks to directly export
a nonempty, unambiguous voice-only range, the verified scan may continue
immediately to strict MP4-only export. It cannot authorize partial output,
setup/key capture, a changed account, or a changed chat/time range.
The MP4-only media stage validates every extracted SILK and bounded per-item PCM,
streams the ordered PCM plus exact inter-message gaps into one local ffmpeg
encode, and then fully decodes the result to require exactly one H.264 and one
AAC track. It does not require the Swift M4A helper. The readable full archive
remains on the per-item M4A pipeline and reports a separate readiness gate.

After each account's explicit first-time setup, a private non-secret profile registry stores separate
validated vault, account-media and media-helper paths under opaque account entries. Normal
conversations should not ask the user to repeat those paths. Every doctor binds the current official
session again and may load only its exact matching entry; a profile for another account is never a
fallback. The user says chat, time and content types; chat normalization returns bounded candidates
but never silently authorizes a fuzzy match. Profiles never store a database key, chat selection or
export consent.

## Message and asset contract

The base message type is the low 32 bits of `local_type`; the upper 32 bits are
recorded only as flags. Type 49 is classified from `<appmsg><type>`, never from
those upper bits.

Version 1 covers:

- text, system and recall notices;
- contact cards and locations;
- links, mini-programs, replies and other structured app messages;
- voice BLOBs joined by `message.server_id == VoiceInfo.svr_id`;
- images bound by packed resource MD5 and the exact chat attachment tree;
- ordinary files with exact month/basename plus available size/hash evidence;
- stickers bound by exact message MD5 and exact local cache names;
- metadata placeholders for video and unsupported/unknown messages.

Every user-selected message appears in the machine-readable output; `all`
explicitly selects the entire interval. Every selected asset has one of:
`resolved`, `metadata_only`, `missing`, `ambiguous`, `corrupt`, `unsupported`,
or `excluded_by_policy`.

## Security invariants

- Decrypted vault databases are opened with SQLite `mode=ro&immutable=1`;
  plaintext WAL/SHM sidecars in a claimed frozen vault are rejected.
- Online refresh takes OFD shared locks over SQLite's WAL coordination bytes,
  validates the locked SHM/WAL anchor, APFS-clones the encrypted DB and WAL,
  replays only the committed prefix, decrypts into a fresh private vault, runs
  doctor, and only then atomically updates the non-secret account profile.
  Failure leaves the previous verified profile in place.
- Exact chat selection is mandatory. Duplicate names require an explicit chat ID.
- Media paths are constrained beneath the selected account root; symlinks and
  path traversal are rejected.
- In the development initializer, validated keys are written only to an
  owner-only `0600` local file; the normal export helper never receives or
  prints them. The public Companion must migrate key ownership to Keychain.
  Keys never enter argv, environment, stdout, manifests, Plugin caches, or
  distributable archives.
- The official app bundle ID alone is insufficient. Setup and capture also require
  a valid Apple code signature satisfying the pinned Tencent Team ID/designated
  requirement; a same-bundle-id ad-hoc app fails closed.
- Current-account binding is exact and fail-closed. Historical storage timestamps, sizes and ordering
  never select an account. Keys, snapshots and profiles are isolated per opaque account reference;
  switching accounts invalidates any plan approved for the previous account.
- Private directories use mode `0700`; private files use `0600`; output is built
  in staging and atomically renamed.
- Key-init recovery scans only a bounded set of direct `runtime/init-*` children and
  accepts only current-user, private directories with matching initializer owner markers.
  Live or unmarked entries fail closed; an explicit cleanup can recover verified orphans.
- The isolated key-initializer environment accepts only pinned binary wheels whose
  SHA-256 values match the canonical PyPI release metadata; installation never
  overwrites an existing environment.
- Before atomic archive publication, every resource and MP4 path, size, SHA-256 and
  one-to-one message reference is revalidated, and manifest statistics are recomputed.
- Default network policy is offline. Signed CDN URLs and attachment AES keys are
  not persisted by the normal parser.
- Initialization, Full Disk Access, per-account key capture, first retained-snapshot
  creation, ambiguous chat choice and scan-digest approval are explicit user boundaries. Quitting
  WeChat is requested only as recovery after safe online-refresh failure. Automatic current-account
  binding grants none of those permissions.

## Portability limits

The supported implementation boundary is macOS with official Mac WeChat 4.x.
Paths are discovered from the current user's home directory and Bundle ID, never
from a hard-coded username. Unknown WeChat versions and schemas are diagnostic
states, not assumed-compatible states. Windows, Linux and video extraction need
separate implementations.
