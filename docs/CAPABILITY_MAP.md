# Capability Map

“已实现”不等于“所有电脑均已适配”。下表把代码、当前机器真实证据和产品化状态分开。

| Capability | Status | Safety contract | Verification |
| --- | --- | --- | --- |
| Unified decrypted-vault doctor | active | Read-only frozen input; schema and dependency gates; no key handling | Fixtures plus current-machine real decrypted snapshot |
| Current official-session account binding | active development path | Exactly one account from read-only official-process evidence; no historical account list and no mtime/size/order guess; zero/multiple/unstable results fail closed | 17 router regressions cover multi-account, switch and race cases; current-machine double sample uniquely bound the open account with no writes |
| Exact chat/time content plan | active | Exact chat or explicit chat ID; absolute interval; every row retained; duplicate nonzero server IDs fail closed | Real plan: 34 messages in one interval; parser/scanner tests |
| Text and structured-message parsing | active | Low 32-bit type classification; bounded XML; signed URL/key/token sanitization; unknown fallback retained | Parser fixtures including type 19, legacy group sender and secret-redaction cases |
| Voice BLOB extraction and MP4 | active | Global unique `message.server_id == VoiceInfo.svr_id`; SILK/hash/duration/order validation; direct voice metadata accepts the observed frame-aligned range through 61,000 ms and rejects higher values | Real strict exports: 33/33 and 362/362 voices, 0 issues; 362-item MP4 independently decoded end-to-end; synthetic media regression |
| Voice MP4-only fast publication | active | Explicit voice-only plan; strict chat binding and source fingerprint; every SILK is revalidated and decoded to a bounded private PCM file, then hashed, sample-counted and streamed in order with exact gaps into one ffmpeg encode; one full output decode verifies exactly one H.264 and one AAC track; no partial mode. This fast path requires `pilk` plus pinned local ffmpeg, not the Swift M4A helper | Real two-item pipe integration plus process-count, ordering, timeout/BrokenPipe cleanup, no-Swift readiness, atomic-publication and full-archive compatibility regressions; full archive retains the per-item M4A path |
| Image recovery | active when local asset exists | Exact chat attachment tree and packed MD5; full > high > thumbnail; no mtime/proximity guessing; symlink/path escape rejected | Real V2 WXGF asset uniquely decoded and converted to JPEG; V1/V2/XOR fixtures |
| Ordinary file recovery | implemented, asset-dependent | Normalized exact basename, bounded month candidates and available MD5/size evidence; unresolved metadata is not success | Resolver/archive fixtures; no claim that every file body is cached locally |
| Sticker recovery | conditional | Exact message MD5 plus verified plaintext image magic/content; proprietary opaque cache stays unsupported/metadata-only | Plain-cache fixtures; one inspected proprietary encrypted cache remains unresolved |
| Video messages | metadata only by policy | Message is retained as `excluded_by_policy`; video body is never exported | Parser/archive fixtures |
| Unknown/unsupported messages | active metadata fallback | Bounded, sanitized raw preview; never silently dropped | Parser fixtures |
| Per-account one-time database-key initializer | active development path; target expansion consent pending | Current session is uniquely bound first; explicit exact targets and fresh per-account consent only; official WeChat exits normally; private random app copy; exact-salt first-page validation; keys saved owner-only `0600`; bounded cleanup | 42 initializer regressions cover scoped state, legacy exact validation, route mismatch and capture binding; existing current-account keys were revalidated read-only, with no new capture |
| `message_resource` key/snapshot target | implemented, consent pending | Exact alias only; no wildcard; `MessageResourceInfo` expected-table gate | 27 live-tools regression tests; no new real key capture performed without separate consent |
| Coordinated online snapshot/decryption | active with integrity limitation | After exact chat resolution, selects the minimal initialized DB set; OFD-locks SQLite WAL coordination bytes, validates the locked SHM/WAL anchor, APFS-clones DB+WAL, replays only committed frames, validates the decrypted vault, then atomically updates the profile; never writes live DB | 28 snapshot/online-refresh regressions, real SQLite writer-lock/APFS-clone probes, and one open-official-WeChat 362-voice scan; page HMAC is not verified |
| Source-development Codex Plugin/Skills | Plugin-ready | Normal current-account scan refreshes online only after one exact chat ID; ambiguous candidates and explicit development vaults do not refresh; profile must match the current official session; per-account setup is explicit-only; thin client preserves validated virtual-environment launchers and accepts only doctor/scan/export/direct-voice-mp4 with no secret arguments. The direct command performs the readiness gates, exact online scan and same-plan strict MP4 publication in one call | Package validator plus 29 portable routing, launcher, online-refresh, single-request orchestration, cleanup and documentation-policy tests |
| Signed/notarized universal Companion | not shipped | Future allowlisted high-level IPC, Keychain ownership, Developer ID/notarization and signed updater | Product architecture only; must not be called product-ready |
| UI/application-audio fallback | experimental | Dry scan and approval first; restricted voice `AXPress`; no keyboard; no message sending | Unit/self-tests; requires per-machine supervised calibration |
| WeChat sending/input | absent | No typing, paste, return, send or arbitrary click capability in the normal export path | Static forbidden-symbol checks |

## Change classification

The unified content archive and current-account online refresh are additive. The direct voice path,
explicit frozen development vault, and existing supervised UI/audio fallback remain available; no
prior export capability was removed. The historical-directory account choice UX is intentionally
replaced by fail-closed current official-session binding. Strict export is the default. Partial output
requires a separate `--allow-partial` decision and keeps every unresolved state visible in
`manifest.json`.
