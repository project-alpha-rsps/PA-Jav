# PreToolUse(Bash): block the executables this repository does not allow an
# agent to run. Reads JSON from stdin, exits 2 to block with a stderr message
# visible to Claude. Direct commands and common shell wrappers are inspected.
# Native pattern rules and repository/runtime hooks enforce recognized tool calls
# as defense in depth; this parser establishes neither process containment nor target-side authorization.
#
# The blocked set is `blockedCommands` in .claude/hooks/policy.json, this
# repository's slot. The tokenizer and wrapper unwrapping live in
# lib/shell_command.py, shared with git_unsafe_rule.py and
# validation_rule.py.
#
# Rule module for pre-bash.py: `run(payload_text)` applies the rule to one
# PreToolUse payload. It returns normally to allow and calls sys.exit(2) with a
# message on stderr to deny; pre-bash.py treats anything else as a deny.


def run(payload_text: str) -> None:
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
        payload = json.loads(payload_text)
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
