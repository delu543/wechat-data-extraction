# Privacy boundary

WeChat Local Export is designed for authorized data already present on the user's Mac.

- Normal operation is offline. The Plugin declares no remote MCP server, telemetry service, account
  login, analytics endpoint, or background upload.
- The conversational Skill sends only high-level local commands to a local helper. It does not
  receive database keys and should not place message bodies in the AI conversation.
- A dry scan persists only the message kinds explicitly requested by the user. `all` must be an
  explicit choice.
- An explicitly requested direct voice MP4 may use the local `direct-voice-mp4` orchestration
  command. Its one internal `0600` plan is kept beside the private request only for that invocation
  and is exactly removed on every outcome. The command does not delete the request or unrelated
  files, and its public JSON omits local paths, account references and plan digests.
- Output archives can contain highly private text and media. The user chooses the destination and
  retention period; the tool never uploads or publishes them.
- The source-development initializer stores validated database keys in a local owner-only `0600`
  file. Those keys are not included in plans, archives, logs, Plugin caches, or distributable ZIPs.
- Installing capture dependencies, capturing keys, and creating a retained decrypted snapshot use
  separate confirmations. Keys remain until a separately approved removal or reinitialization;
  a decrypted snapshot remains while the saved local profile depends on it. Neither action silently
  deletes downloadable exports.
- The setup doctor uses only read-only evidence from the current official WeChat session to bind one
  account. Historical account directories, last-update times and sizes are not shown as account
  choices and are never used to guess which account the user means. If the binding is not unique and
  stable after the user signs in, opens any chat, brings WeChat forward and retries, setup stops.
- Account references and approval digests are internal control values. Normal conversations say only
  that the current signed-in account was uniquely bound and show the human-readable content scope;
  they do not expose login identifiers, account directories, opaque references or historical-account
  inventories.
- Keys, decrypted snapshots and non-secret profiles are retained separately per account. Switching
  the current login never silently loads another account's private state, and each account's first key
  capture and retained-snapshot creation require their own confirmations.
- The source/Plugin ZIPs exclude databases, decrypted snapshots, plans, manifests, logs, media,
  virtual environments, dependency wheels, and generated binaries.

The future signed Companion should keep key ownership in macOS Keychain and expose only an
allowlisted high-level protocol. Installing or uninstalling a Skill must never silently delete local
exports, snapshots, or credentials.
