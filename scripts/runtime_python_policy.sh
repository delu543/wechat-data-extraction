#!/bin/zsh

# Permit the group-writable tool cache used by GitHub-hosted macOS runners only
# when the workflow explicitly opts in and the interpreter belongs to the
# current ephemeral runner user. Normal local installation never takes this
# branch.
wechat_allow_github_hosted_python() {
  local python_path=$1
  local python_owner=$2
  local current_uid=$3
  local runner_tool_cache

  [[ "${WECHAT_LOCAL_EXPORT_ALLOW_GITHUB_HOSTED_PYTHON:-}" == "1" ]] || return 1
  [[ "${CI:-}" == "true" && "${GITHUB_ACTIONS:-}" == "true" ]] || return 1
  [[ "${RUNNER_ENVIRONMENT:-}" == "github-hosted" ]] || return 1
  [[ "${RUNNER_OS:-}" == "macOS" ]] || return 1
  [[ -n "${RUNNER_TOOL_CACHE:-}" && "$RUNNER_TOOL_CACHE" == /* ]] || return 1
  python_path=${python_path:A}
  runner_tool_cache=${RUNNER_TOOL_CACHE:A}
  [[ -d "$runner_tool_cache" && ! -L "$runner_tool_cache" ]] || return 1
  [[ "$python_owner" == "$current_uid" ]] || return 1
  [[ "$python_path" == "$runner_tool_cache"/* ]] || return 1
}
