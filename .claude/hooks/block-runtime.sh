#!/usr/bin/env bash
# PreToolUse(Bash): block the executables this repository does not allow an
# agent to run. Reads JSON from stdin, exits 2 to block with a stderr message
# visible to Claude. Direct commands and common shell wrappers are inspected.
# This is defense in depth; Claude permission rules remain the primary
# execution boundary.
#
# The blocked set is `blockedCommands` in .claude/hooks/policy.json, this
# repository's slot. The tokenizer and wrapper unwrapping live in
# lib/shell_command.py, shared with block-git-unsafe.sh and
# require-validation-before-git.sh.
#
# Template file: identical in every repository that adopts repo-policy. Change
# it in shockstruck/agent-platform, not here.
set -euo pipefail

if ! HOOK_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/lib" && pwd)"; then
  echo "[block-runtime] hook library is missing; refusing to allow the command. Allowed next step: report the broken hook installation for reviewed repair and continue independent work; retry only after repair." >&2
  exit 2
fi
export HOOK_LIB_DIR

CLAUDE_HOOK_PAYLOAD="$(cat)"

set +e
python3 - 3<<<"${CLAUDE_HOOK_PAYLOAD}" <<'PYEOF'
import json
import os
import sys

sys.path.insert(0, os.environ["HOOK_LIB_DIR"])

from repo_policy import PolicyError, load  # noqa: E402
from shell_command import Denial, walk  # noqa: E402


def deny(message: str) -> None:
    sys.stderr.write(f"[block-runtime] {message}\n")
    sys.exit(2)


try:
    policy = load()
except PolicyError as exc:
    deny(f"{exc}; refusing to skip the runtime check. Allowed next step: report the policy load failure for reviewed repair and continue independent work; do not narrow policy slots.")

try:
    payload = json.load(os.fdopen(3))
except (json.JSONDecodeError, OSError):
    deny("hook input was not valid JSON; refusing to skip the runtime check. Allowed next step: submit a valid tool payload; if the harness generated it, report the payload failure and continue independent work.")

tool_input = payload.get("tool_input") or {}
if not isinstance(tool_input, dict):
    deny("hook tool_input was not an object; refusing to skip the runtime check. Allowed next step: submit tool_input as an object; if the harness generated it, report the payload failure and continue independent work.")
cmd = tool_input.get("command") or ""
if not isinstance(cmd, str):
    deny("Bash command was not text. Allowed next step: submit the permitted command as a text string in tool_input.command.")
if not cmd.strip():
    sys.exit(0)

blocked = policy.blocked_commands
if not blocked:
    sys.exit(0)


def visit(executable: str, arguments: list[str]) -> None:
    if executable in blocked:
        raise Denial(f"{blocked[executable]} Allowed next step: use the repository's permitted inspection or Git change flow; no agent route to run this executable here. Report the unmet need and continue independent work.")


try:
    walk(cmd, visit, blocked_names=blocked)
except Denial as denial:
    deny(denial.message)

sys.exit(0)
PYEOF
status=$?
set -e
if [[ ${status} -ne 0 && ${status} -ne 2 ]]; then
  echo "[block-runtime] internal hook failure; refusing to allow the command. Allowed next step: report the hook failure for reviewed repair and continue independent work; retry only after repair." >&2
  exit 2
fi
exit "${status}"
