#!/usr/bin/env bash
# Template file: identical in every repository that adopts repo-policy. Change
# it in shockstruck/agent-platform, not here.
#
# PreToolUse(Bash|Write|Edit|NotebookEdit): hand the payload to Probity, which
# applies the AI-judged rules in probity.config.ts. Deterministic checks stay in
# the sibling hooks; Probity only carries the two rules that need a judge.
# Probity answers on stdout in Claude Code's hookSpecificOutput shape and exits
# 0 either way, so this wrapper forwards its streams verbatim.
set -euo pipefail

PROJECT_DIR="${CLAUDE_PROJECT_DIR:-}"
if [[ -z "${PROJECT_DIR}" ]]; then
  PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fi

# The config is policy, so prefer the merged copy the dispatcher pinned over the
# one in the checkout the agent is editing. MULTICA_POLICY_DIR is unset outside
# the agent runtime (a workstation, the hook test suite), and a checkout created
# before probity.config.ts merged has no copy of its own -- which used to exit 2
# here and deny every Bash call in that checkout. Fall back either way.
CONFIG=""
for candidate in "${MULTICA_POLICY_DIR:-}" "${PROJECT_DIR}"; do
  if [[ -n "${candidate}" && -f "${candidate}/probity.config.ts" ]]; then
    CONFIG="${candidate}/probity.config.ts"
    break
  fi
done
if [[ -z "${CONFIG}" ]]; then
  echo "[probity] no probity.config.ts in ${MULTICA_POLICY_DIR:-<unset>} or" \
    "${PROJECT_DIR}; refusing to allow an unchecked action. Allowed next step: report the missing merged policy for reviewed repair and continue independent work; retry only after repair." >&2
  exit 2
fi

# PATH first: the multica-agent image installs @nizos/probity globally on its
# Node 22. node_modules/.bin covers a workstation that ran `npm ci` in a checkout
# that has one. `npx` is deliberately absent: it would resolve from the network.
PROBITY="$(command -v probity || true)"
if [[ -z "${PROBITY}" && -x "${PROJECT_DIR}/node_modules/.bin/probity" ]]; then
  PROBITY="${PROJECT_DIR}/node_modules/.bin/probity"
fi
if [[ -z "${PROBITY}" ]]; then
  echo "[probity] \`probity\` was not found on PATH or in ${PROJECT_DIR}/node_modules/.bin;" \
    "refusing to allow an unchecked action. Allowed next step: use the repository's documented" \
    "dependency setup to install its pinned Probity on Node 22 if authorised; otherwise report" \
    "the missing runtime dependency and continue independent work. Retry only once it is available." >&2
  exit 2
fi

exec "${PROBITY}" --agent claude-code --config "${CONFIG}"
