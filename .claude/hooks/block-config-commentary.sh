#!/usr/bin/env bash
# PreToolUse(Write|Edit): keep change rationale and task identifiers out of the
# files this repository guards. Blocks only what the edit ADDS: a new
# non-directive `#` comment under `comments.paths`, or a new task identifier
# under `taskIdentifiers.paths`. Pre-existing lines never trip the hook. The
# identifier scan applies only to a path already in the index -- an untracked
# scratch file is never the config the rule protects -- while the comment scan
# still applies to it.
#
# Both path lists are this repository's slots in .claude/hooks/policy.json; the
# rule itself lives in lib/config_commentary.py.
#
# Template file: identical in every repository that adopts repo-policy. Change
# it in shockstruck/agent-platform, not here.
set -euo pipefail

if ! HOOK_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/lib" && pwd)"; then
  echo "[block-config-commentary BLOCK] hook library is missing; refusing to allow the write. Allowed next step: report the broken hook installation for reviewed repair and continue independent work; retry only after repair." >&2
  exit 2
fi
export HOOK_LIB_DIR

CLAUDE_HOOK_PAYLOAD="$(cat)"

set +e
python3 - 3<<<"${CLAUDE_HOOK_PAYLOAD}" <<'PYEOF'
import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, os.environ["HOOK_LIB_DIR"])

from config_commentary import in_scope, violations  # noqa: E402
from repo_policy import PolicyError, load  # noqa: E402


def path_indexed(directory: Path, relative: str) -> bool:
    """Whether `relative` is tracked in the Git index at `directory`.

    `ls-files --error-unmatch` exits 1 for a path that matches no tracked
    file; anything else -- a genuine Git error, `directory` not a checkout --
    cannot show the path is safe to exempt, so it counts as indexed.
    """
    try:
        result = subprocess.run(
            ["git", "-C", str(directory), "ls-files", "--error-unmatch", "--", relative],
            capture_output=True,
            text=True,
        )
    except OSError:
        return True
    return result.returncode != 1

DEFAULT_GUIDANCE = (
    "Change rationale belongs in the pull request body, not in a guarded file, and task "
    "identifiers never enter the repository."
)


def deny(message: str) -> None:
    sys.stderr.write(f"[block-config-commentary BLOCK] {message}\n")
    sys.exit(2)


try:
    policy = load()
except PolicyError as exc:
    deny(f"{exc}; refusing to skip the commentary check. Allowed next step: report the policy load failure for reviewed repair and continue independent work; do not narrow policy slots.")

try:
    payload = json.load(os.fdopen(3))
except (json.JSONDecodeError, OSError):
    deny("hook input was not valid JSON; refusing to skip the commentary check. Allowed next step: submit a valid tool payload; if the harness generated it, report the payload failure and continue independent work.")

tool_input = payload.get("tool_input") or {}
if not isinstance(tool_input, dict):
    deny("hook tool_input was not an object; refusing to skip the commentary check. Allowed next step: submit tool_input as an object; if the harness generated it, report the payload failure and continue independent work.")

raw_path = tool_input.get("file_path") or ""
if not isinstance(raw_path, str) or not raw_path:
    sys.exit(0)

project_root = Path(os.environ.get("CLAUDE_PROJECT_DIR", ".")).resolve()
path = Path(raw_path)
if not path.is_absolute():
    path = project_root / path
path = path.resolve()
try:
    relative = path.relative_to(project_root).as_posix()
except ValueError:
    sys.exit(0)
indexed = path_indexed(project_root, relative)
if not in_scope(relative, policy, indexed=indexed):
    sys.exit(0)

try:
    existing = path.read_text(encoding="utf-8")
except FileNotFoundError:
    existing = ""
except (OSError, UnicodeError) as exc:
    deny(f"cannot read {relative} to compare the proposed edit: {exc}. Allowed next step: verify the path and readable UTF-8 source without changing permissions; report an access or encoding gap and continue independent work if it cannot be read.")

tool_name = payload.get("tool_name") or ""
if tool_name == "Write":
    candidate = tool_input.get("content") or ""
elif tool_name == "Edit":
    old = tool_input.get("old_string") or ""
    new = tool_input.get("new_string") or ""
    if old and old in existing:
        candidate = (
            existing.replace(old, new)
            if tool_input.get("replace_all")
            else existing.replace(old, new, 1)
        )
    else:
        deny(f"cannot reconstruct the proposed edit for {relative}. Allowed next step: read the current file and submit an Edit anchored to its actual text, preserving existing work.")
else:
    deny(f"unsupported tool `{tool_name}` for the commentary check. Allowed next step: submit a reviewable Write or Edit payload with text content, subject to the same commentary rules.")

if not isinstance(candidate, str):
    deny("proposed file content was not text. Allowed next step: submit the proposed content as a text string, preserving existing work.")

found = violations(relative, existing, candidate, policy, indexed=indexed)
if found:
    for violation in found[:20]:
        sys.stderr.write(f"[block-config-commentary BLOCK] {relative}: {violation}\n")
    if len(found) > 20:
        sys.stderr.write(
            f"[block-config-commentary BLOCK] {relative}: and {len(found) - 20} more. Allowed next step: remove the added rationale comments and task identifiers throughout the proposed edit.\n"
        )
    guidance = policy.comment_guidance.strip() or DEFAULT_GUIDANCE
    allowed = ", ".join(f"`# {prefix}`" for prefix in policy.comment_directives)
    if allowed:
        guidance = f"{guidance} Only the {allowed} directives may be added here."
    sys.stderr.write(f"[block-config-commentary BLOCK] {guidance} Allowed next step: remove added rationale comments and task identifiers from the proposed content; put change context in the pull request, without narrowing policy slots.\n")
    sys.exit(2)

sys.exit(0)
PYEOF
status=$?
set -e
if [[ ${status} -ne 0 && ${status} -ne 2 ]]; then
  echo "[block-config-commentary BLOCK] internal hook failure; refusing to allow the write. Allowed next step: report the hook failure for reviewed repair and continue independent work; retry only after repair." >&2
  exit 2
fi
exit "${status}"
