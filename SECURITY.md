# Security model

## Current status

This is a source-development Plugin package. It does not include a Developer ID-signed or notarized
Companion and must report `signed_companion: false` and `product_ready: false`.

## Safety invariants

- `doctor -> scan -> exact user confirmation -> export` is the default. The only shortcut is an
  explicit same-request instruction to directly export a nonempty, unambiguous voice-only range;
  `direct-voice-mp4` performs the doctor readiness gates, online scan and same-plan strict MP4-only
  export in one high-level call. It cannot authorize partial output, development-path overrides or a
  changed scope.
- Chat normalization may return candidates but never authorizes automatic fuzzy selection.
- Normal current-account scan resolves one exact chat in the prior verified vault before any online
  refresh. It then selects only the initialized database set needed by the requested kinds, takes
  SQLite WAL coordination locks, validates the locked SHM/WAL anchor, APFS-clones DB+WAL, replays
  only committed frames, validates the fresh decrypted vault, and atomically updates the profile.
  Ambiguous candidates and explicit frozen development vaults never trigger online refresh.
- Plans bind the exact chat, absolute time, selected message kinds, source-database hashes, message
  count and digest. A changed source or plan stops export.
- Strict export is atomic. Missing, ambiguous, corrupt, or unsupported requested media prevents a
  final directory unless the user separately accepts `--allow-partial`.
- The normal client exposes only `doctor`, `scan`, `export`, and the narrowly scoped
  `direct-voice-mp4`; it has no key, token, SQL, shell, WeChat UI, keyboard, or message-sending
  interface.
- Local paths are constrained, symlinks/path traversal are rejected, and private state uses `0700`
  directories plus `0600` files.
- `direct-voice-mp4` accepts one unchanged owner-only request under the fixed private task root. Its
  unpredictable `0600` internal plan is created beside that request and exactly cleaned on success,
  zero matches, ambiguity or failure; the caller-owned request and unrelated files are never removed.
  Public orchestration JSON excludes request/output/plan paths, account references and digests.
- Public online-scan JSON exposes only `snapshot_mode: online`; it does not expose clone/vault paths,
  database names, account references, keys or WAL internals.
- Fresh setup must bind exactly one account from read-only evidence belonging to the current official
  WeChat process family. Historical account directories are never offered for selection, and database
  modification time, total size, directory order or a "most recent" heuristic is never account
  evidence. The opaque `account-ref` stays internal; initialization, snapshot and profile
  configuration resolve the path without asking an ordinary user for it.
- A zero, multiple, unstable or unavailable current-account binding permits only one guided retry:
  the user signs in, opens any chat and brings official WeChat to the foreground. Foreground state is
  not sufficient evidence by itself. A second non-unique result fails closed without dry-scan or key
  capture.
- Keys, retained decrypted snapshots and non-secret profiles are isolated per account. Normal export
  may load only the profile that exactly matches a newly verified current-session binding; switching
  accounts invalidates an outstanding scan plan and cannot reuse another account's authorization.
- The source initializer requires Mac WeChat 4.x and checks the official bundle ID plus a pinned
  Apple/Tencent designated requirement during doctor and again immediately before capture; bundle
  ID alone is not trusted.
- `dry-scan` binds the account, exact database aliases, sizes, salt fingerprints and application
  identity, including the official CDHash, to an internal approval digest. Capture compares it
  before any write, verifies the copied bundle still has the official requirement and same CDHash
  before ad-hoc signing, and checks the databases plus existing WAL/SHM sidecars for WeChat process
  holders again immediately before spawn.
- Dependency installation, per-account key capture and per-account retained decrypted-snapshot
  creation are separate user decisions. Automatic account binding is routing evidence, not capture
  consent. The key-initializer environment accepts only hash-pinned binary wheels and refuses to
  overwrite an existing environment.
- Before atomic archive publication, the backend revalidates manifest/message statistics, canonical
  relative paths, sizes, hashes and one-to-one resource references.
- Interrupted key initialization is recovered only through a bounded scan of direct private
  `runtime/init-*` directories with valid owner markers. Live, unmarked or ambiguous entries are
  never deleted automatically.

## Development helper trust

An arbitrary executable from `PATH` is never trusted. An unverified helper path is available only
with the explicit source-development opt-in environment variable documented in the code. A product
release must remove that path and execute only a fixed Companion whose Developer ID, Team ID,
designated requirement, notarization and protocol version are verified by the client.

## Known integrity limitation

The current encrypted-database snapshot implementation validates AES-CBC output with a SQLite
header, `quick_check`, expected tables, locked WAL-anchor/committed-frame gates and source
fingerprints, but it does not verify the reserved-page HMAC. Status output and documentation must
preserve this limitation. Keeping WeChat open is the normal path; quitting is only a recovery option
after online coordination fails safely.

## Release blockers

Public product claims remain blocked until there is a signed/notarized universal Companion,
Keychain migration, clean-Mac compatibility testing, an owner-selected source license, a complete
third-party licensing/BOM review, signed updates, support/privacy terms, and a reviewed uninstall
flow.
