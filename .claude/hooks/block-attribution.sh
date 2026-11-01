#!/usr/bin/env bash
# PreToolUse(Bash): deny a `git commit` or `gh pr create`/`gh pr edit` whose
# message carries a Claude/Anthropic/agent attribution trailer, a
# "Generated with Claude Code" line, an `@anthropic.com` address, or an
# address at the committing identity's own domain. A PreToolUse hook cannot
# safely rewrite the command string it is handed, so this denies and names
# the offending line; the agent re-issues the command without it.
#
# `gh pr merge` gets a second, structural check: without an explicit
# `-b`/`--body`/`-F`/`--body-file`, GitHub composes the squash-merge message
# itself and appends a `Co-authored-by` trailer for every commit author on
# the branch who is not the merging account -- no PreToolUse hook on `git
# commit` can stop that, because the trailer is never in any command this
# session runs. The only enforcement point is the merge command itself, so an
# explicit body is required outright; when one is given, its text (and
# `--subject`/`-t`, if present) is scanned the same way a create/edit body is.
#
# The message is read from the raw command text -- not the tokenized
# arguments `lib/shell_command.py` returns -- because that tokenizer masks a
# heredoc body and a `$( … )` substitution on purpose, so that a hook judging
# *what runs* never mistakes data for code. This hook judges what a commit
# *says*, so it needs that data, not the mask. `lib/git_command.py` /
# `lib/shell_command.py` are still what tells this hook a `git commit` or
# `gh pr create`/`edit` invocation is present at all, and what resolves a
# `-F`/`--body-file` path against the command's `cd`-adjusted cwd, the same
# way `block-git-unsafe.sh` does. `-F -`/`--file=-`/`--body-file=-` names
# stdin, which this hook cannot see, so it is denied outright.
#
# Template file: identical in every repository that adopts repo-policy. Change
# it in shockstruck/agent-platform, not here.
set -euo pipefail

if ! HOOK_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/lib" && pwd)"; then
  echo "[block-attribution] hook library is missing; refusing to allow the command. Allowed next step: report the broken hook installation for reviewed repair and continue independent work; retry only after repair." >&2
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

sys.path.insert(0, os.environ["HOOK_LIB_DIR"])

from attribution import blocked_email_pattern, find_violation, owner_email_pattern  # noqa: E402
from git_command import directory_before, invocations  # noqa: E402
from repo_policy import PolicyError, load  # noqa: E402
from shell_command import Denial, walk  # noqa: E402


def deny(message: str) -> None:
    sys.stderr.write(f"[block-attribution] {message}\n")
    sys.exit(2)


def resolve_directory(cwd: str | None, cd_argument: str | None) -> str:
    if cd_argument:
        if os.path.isabs(cd_argument):
            return cd_argument
        base = cwd or os.environ.get("CLAUDE_PROJECT_DIR") or "."
        return os.path.join(base, cd_argument)
    return cwd or os.environ.get("CLAUDE_PROJECT_DIR") or "."


def commit_message_file(arguments: list[str]) -> tuple[str | None, bool]:
    """(path, is_stdin) named by `-F`/`--file` on a `git commit`, or (None, False)."""
    index = 0
    while index < len(arguments):
        token = arguments[index]
        if token == "--":
            return None, False
        if token in ("-F", "--file"):
            if index + 1 >= len(arguments):
                return None, False
            value = arguments[index + 1]
            return (None, True) if value == "-" else (value, False)
        if token.startswith("--file="):
            value = token[len("--file=") :]
            return (None, True) if value == "-" else (value, False)
        if token.startswith("-F") and len(token) > 2:
            value = token[2:]
            return (None, True) if value == "-" else (value, False)
        index += 1
    return None, False


def gh_body_file(arguments: list[str]) -> tuple[str | None, bool]:
    """(path, is_stdin) named by `-F`/`--body-file` on a `gh pr create`/`edit`."""
    value = ""
    index = 0
    while index < len(arguments):
        token = arguments[index]
        if token in ("-F", "--body-file"):
            if index + 1 < len(arguments):
                value = arguments[index + 1]
            index += 2
            continue
        if token.startswith("--body-file="):
            value = token[len("--body-file=") :]
        index += 1
    if not value:
        return None, False
    return (None, True) if value == "-" else (value, False)


def gh_has_message_flag(arguments: list[str]) -> bool:
    for token in arguments:
        name = token.split("=", 1)[0]
        if name in ("-t", "--title", "--subject", "-b", "--body", "-F", "--body-file"):
            return True
    return False


def gh_merge_has_body_flag(arguments: list[str]) -> bool:
    for token in arguments:
        name = token.split("=", 1)[0]
        if name in ("-b", "--body", "-F", "--body-file"):
            return True
    return False


def read_file(path_value: str, directory: str) -> str | None:
    import pathlib

    candidate = pathlib.Path(path_value)
    if not candidate.is_absolute():
        candidate = pathlib.Path(directory) / candidate
    try:
        return candidate.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


try:
    policy = load()
except PolicyError as exc:
    deny(f"{exc}; refusing to skip the attribution check. Allowed next step: report the policy load failure for reviewed repair and continue independent work; do not narrow policy slots.")

policy_data = {}
try:
    policy_data = json.loads(policy.source.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError):
    deny(f"{policy.source} could not be re-read; refusing to skip the attribution check. Allowed next step: report the policy read failure for reviewed repair and continue independent work; retry only after repair.")

blocked_emails_raw = ((policy_data.get("attribution") or {}).get("blockedEmails")) or []
if not isinstance(blocked_emails_raw, list) or any(
    not isinstance(item, str) for item in blocked_emails_raw
):
    deny("policy.json `attribution.blockedEmails` must be a list of strings. Allowed next step: report the policy schema failure for reviewed repair without removing blocked addresses; continue independent work.")
blocked_pattern = blocked_email_pattern(tuple(blocked_emails_raw))

try:
    payload = json.load(os.fdopen(3))
except (json.JSONDecodeError, OSError):
    deny("hook input was not valid JSON; refusing to skip the attribution check. Allowed next step: submit a valid tool payload; if the harness generated it, report the payload failure and continue independent work.")

tool_input = payload.get("tool_input") or {}
if not isinstance(tool_input, dict):
    deny("hook tool_input was not an object; refusing to skip the attribution check. Allowed next step: submit tool_input as an object; if the harness generated it, report the payload failure and continue independent work.")
cmd = tool_input.get("command") or ""
if not isinstance(cmd, str):
    deny("Bash command was not text. Allowed next step: submit the permitted command as a text string in tool_input.command.")
if not cmd.strip():
    sys.exit(0)

try:
    current = invocations(cmd)
except Denial as denial:
    deny(denial.message)

commit_invocations = [inv for inv in current if inv.subcommand == "commit"]

gh_invocations: list[list[str]] = []

# The same globals `block-gh-unsafe.sh` skips over, so a value like `-R
# shockstruck/x` is never mistaken for the `pr`/`create` subcommand words.
GH_VALUE_OPTIONS = {
    "-R", "--repo", "--hostname", "--cache",
    "-X", "--method", "-H", "--header", "-q", "--jq", "--template",
    "-F", "--field", "-f", "--raw-field", "--input",
    "-b", "--body", "--body-file", "-t", "--title", "-B", "--base",
    "--subject", "-A", "--author-email", "--match-head-commit",
}


def gh_operands(arguments: list[str]) -> list[str]:
    words = []
    index = 0
    while index < len(arguments):
        token = arguments[index]
        if token == "--":
            words.extend(arguments[index + 1 :])
            break
        if token.startswith("-") and token != "-":
            option = token.split("=", 1)[0]
            index += 1
            if option in GH_VALUE_OPTIONS and "=" not in token and index < len(arguments):
                index += 1
            continue
        words.append(token)
        index += 1
    return words


gh_merge_invocations: list[list[str]] = []
# The last literal `cd` before each create/edit/merge, keyed by identity, read
# the way `directory_before` reads it for a commit.
gh_cds: dict[int, str | None] = {}
gh_current_dir: str | None = None


def collect_gh(executable: str, arguments: list[str]) -> None:
    global gh_current_dir
    if executable == "cd":
        if len(arguments) == 1 and arguments[0] != "-" and "$" not in arguments[0]:
            gh_current_dir = arguments[0]
        return
    if executable != "gh":
        return
    words = gh_operands(arguments)
    group = words[0] if words else ""
    action = words[1] if len(words) > 1 else ""
    if group == "pr" and action in ("create", "edit"):
        gh_invocations.append(arguments)
        gh_cds[id(arguments)] = gh_current_dir
    elif group == "pr" and action == "merge":
        gh_merge_invocations.append(arguments)
        gh_cds[id(arguments)] = gh_current_dir


try:
    walk(cmd, collect_gh)
except Denial as denial:
    deny(denial.message)

if not commit_invocations and not gh_invocations and not gh_merge_invocations:
    sys.exit(0)

for args in gh_merge_invocations:
    if not gh_merge_has_body_flag(args):
        deny(
            "`gh pr merge` without an explicit body lets GitHub compose the merge commit message "
            "itself, appending a `Co-authored-by` trailer for every commit author on the branch. "
            'Allowed next step: when your role permits merging and review gates are met, supply '
            'the message explicitly: `gh pr merge <n> --squash --subject "<title> (#<n>)" '
            '--body "<body>"`; otherwise hand the PR to its merging owner.'
        )

owner_domain = os.environ.get("GIT_AUTHOR_EMAIL") or os.environ.get("GIT_COMMITTER_EMAIL") or ""
if "@" in owner_domain:
    owner_domain = owner_domain.rsplit("@", 1)[1].strip()
else:
    owner_domain = ""
if not owner_domain:
    directory = payload.get("cwd") or os.environ.get("CLAUDE_PROJECT_DIR") or "."
    try:
        result = subprocess.run(
            ["git", "-C", directory, "config", "user.email"],
            capture_output=True,
            text=True,
        )
    except OSError:
        result = None
    email = result.stdout.strip() if result and result.returncode == 0 else ""
    owner_domain = email.rsplit("@", 1)[1].strip() if "@" in email else ""
owner_pattern = owner_email_pattern(owner_domain) if owner_domain else None

# The message lives in the raw command text, not in any single invocation's
# tokenized arguments -- see the header comment. Scanning the whole command
# once, gated on a relevant invocation being present, covers every source
# named in the acceptance criteria (-m, --message=, --trailer, a heredoc
# feeding `-m "$(cat <<'EOF' … )"`, --title, --body) without depending on a
# tokenizer that deliberately cannot see inside them.
if commit_invocations or any(
    gh_has_message_flag(args) for args in (*gh_invocations, *gh_merge_invocations)
):
    violation = find_violation(cmd, owner_pattern, blocked_pattern)
    if violation:
        deny(
            f"attribution line in the command text: `{violation}`. Allowed next step: Drop that trailer or line "
            "from the message and re-run the same command without it."
        )
elif gh_invocations or gh_merge_invocations:
    sys.exit(0)

commit_cds = iter(directory_before(cmd, "commit"))
for invocation in commit_invocations:
    directory = resolve_directory(payload.get("cwd"), next(commit_cds, None))
    message_path, is_stdin = commit_message_file(invocation.arguments)
    if is_stdin:
        deny(
            "`git commit -F -`/`--file=-` reads the message from stdin, which this hook cannot "
            "inspect. Allowed next step: write a clean message to a readable file in a separate "
            "call, then use `-F <absolute-path>`."
        )
    if message_path is not None:
        content = read_file(message_path, directory)
        if content is None:
            deny(
                f"`{message_path}` named by `-F`/`--file` could not be read; refusing to skip "
                "the attribution check. Allowed next step: Write the message file in its own call first, then "
                "re-run the commit naming it by an absolute path."
            )
        violation = find_violation(content, owner_pattern, blocked_pattern)
        if violation:
            deny(
                f"attribution line in `{message_path}`: `{violation}`. Allowed next step: Delete that trailer or "
                "line from the file, then re-run the same commit."
            )

for args in (*gh_invocations, *gh_merge_invocations):
    directory = resolve_directory(payload.get("cwd"), gh_cds.get(id(args)))
    body_path, is_stdin = gh_body_file(args)
    if is_stdin:
        deny(
            "`gh pr create`/`edit`/`merge --body-file -` reads the body from stdin, which this "
            "hook cannot inspect. Allowed next step: write a clean body to a readable file in a "
            "separate call, then use `--body-file <absolute-path>`."
        )
    if body_path is not None:
        content = read_file(body_path, directory)
        if content is None:
            deny(
                f"`{body_path}` named by `--body-file` could not be read; refusing to skip the "
                "attribution check. Allowed next step: Write the body file in its own call first, then re-run the "
                "command naming it by an absolute path."
            )
        violation = find_violation(content, owner_pattern, blocked_pattern)
        if violation:
            deny(
                f"attribution line in `{body_path}`: `{violation}`. Allowed next step: Delete that trailer or line "
                "from the file, then re-run the same command."
            )

sys.exit(0)
PYEOF
status=$?
set -e
if [[ ${status} -ne 0 && ${status} -ne 2 ]]; then
  echo "[block-attribution] internal hook failure; refusing to allow the command. Allowed next step: report the hook failure for reviewed repair and continue independent work; retry only after repair." >&2
  exit 2
fi
exit "${status}"
