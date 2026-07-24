#!/bin/zsh

# Permit the group-writable tool cache used by GitHub-hosted macOS runners only
# when the workflow explicitly opts in and the interpreter belongs to the
# current ephemeral runner user. Normal local installation never takes this
# branch.
wechat_allow_github_hosted_python() {
  local requested_path=$1
  local resolved_path=$2
  local python_owner=$3
  local current_uid=$4
  local runner_tool_cache_requested
  local runner_tool_cache_resolved

  [[ "${WECHAT_LOCAL_EXPORT_ALLOW_GITHUB_HOSTED_PYTHON:-}" == "1" ]] || return 1
  [[ "${CI:-}" == "true" && "${GITHUB_ACTIONS:-}" == "true" ]] || return 1
  [[ "${RUNNER_ENVIRONMENT:-}" == "github-hosted" ]] || return 1
  [[ "${RUNNER_OS:-}" == "macOS" ]] || return 1
  [[ -n "${RUNNER_TOOL_CACHE:-}" && "$RUNNER_TOOL_CACHE" == /* ]] || return 1
  requested_path=${requested_path:a}
  resolved_path=${resolved_path:A}
  runner_tool_cache_requested=${RUNNER_TOOL_CACHE:a}
  runner_tool_cache_resolved=${RUNNER_TOOL_CACHE:A}
  [[ -d "$runner_tool_cache_resolved" && ! -L "$runner_tool_cache_resolved" ]] || return 1
  [[ "$requested_path" == "$runner_tool_cache_requested"/* ]] || return 1
  [[ "$python_owner" == "$current_uid" || "$python_owner" == "0" ]] || return 1
  if [[ "$resolved_path" == "$runner_tool_cache_resolved"/* ]]; then
    return 0
  fi
  [[ "$python_owner" == "0" ]] || return 1
  [[ "$resolved_path" == /Library/Frameworks/Python.framework/Versions/*/bin/python* ]]
}
