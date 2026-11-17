#!/usr/bin/env bash
# PreToolUse(Bash): the one registered command for every Bash rule. It runs
# pre-bash.py and maps any status other than 0 (allow) or 2 (deny) to 2, so a
# missing python3 (127), a syntax error or a crash in the entrypoint cannot let
# a command through. Stdin and any arguments pass straight to pre-bash.py; the
# registered command passes none.
#
# Template file: identical in every repository that adopts repo-policy. Change
# it in shockstruck/agent-platform, not here.
hooks_dir="${BASH_SOURCE[0]%/*}"

python3 "${hooks_dir}/pre-bash.py" "$@"
status=$?
if [[ ${status} -ne 0 && ${status} -ne 2 ]]; then
  echo "[pre-bash] internal hook failure (status ${status}); refusing to allow the command. Allowed next step: report the hook failure for reviewed repair and continue independent work; retry only after repair." >&2
  exit 2
fi
exit "${status}"
