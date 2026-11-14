# PreToolUse(Bash): gate `git commit` and `git push` on what the session already ran.
# Commit is gated on recorded successful validation in a status-preserving plain
# chain (unpiped, with only `&&` after validation) after the last
# write, ignoring a write under `.git/`, the pending commit's `-F` message
# file, or any path not yet in the index -- a scratch file never lands in the
# commit the gate is judging; a push to `main` or `master` is gated on a
# `git fetch` or `git pull` since the last push. A history entry counts as a
# push, fetch or pull only when its recorded result is is_error false; the
# branch a push writes to is read in the directory `cd` or `git -C` selects. Both gates read the session
# transcript through lib/transcript.py; an unreadable transcript is a block,
# because it cannot show the gate was met.
#
# Which commands count as validation is `validation.commandPattern` in
# .claude/hooks/policy.json, this repository's slot; an empty pattern turns the
# commit gate off and leaves the push-to-mainline gate in force.
# The latest matching Bash call decides: its id must have a tool_result with
# is_error exactly false. Missing evidence fails closed. A pending plain chain
# can instead carry validation before its first commit, joined only with `&&`.
# Background or interrupted calls never count; duplicate results cannot erase
# those markers or an earlier failure. `find` cannot supply validator status.
#
# Rule module for pre-bash.py: `run(payload_text)` applies the rule to one
# PreToolUse payload. It returns normally to allow and calls sys.exit(2) with a
# message on stderr to deny; pre-bash.py treats anything else as a deny.


def run(payload_text: str) -> None:
    import json
    import os
    import subprocess
    import sys
    from pathlib import Path

    sys.path.insert(0, os.environ["HOOK_LIB_DIR"])

    from git_command import contextual_invocations, directory_before, invocations, parse  # noqa: E402
    from repo_policy import PolicyError, load  # noqa: E402
    from shell_command import Denial, validation_preserves_status  # noqa: E402
    from transcript import TranscriptError, last_index, read_tool_uses, writes_under  # noqa: E402

    MAINLINE_BRANCHES = {"main", "master"}
    # The same value-taking options git_unsafe_rule.py skips for `git push`, so a
    # push refspec is never mistaken for an option's value.
    PUSH_VALUE_LONG = {"--exec", "--push-option", "--receive-pack", "--repo"}


    def deny(message: str) -> None:
        sys.stderr.write(f"[require-validation-before-git] {message}\n")
        sys.exit(2)


    def refspec_destination(refspec: str) -> str:
        """The ref a push refspec writes to, stripped to a bare branch name."""
        text = refspec[1:] if refspec.startswith("+") else refspec
        if ":" in text:
            text = text.split(":", 1)[1]
        if text.startswith("refs/heads/"):
            text = text[len("refs/heads/") :]
        return text


    def current_branch_targets_mainline(cwd: str | None) -> bool:
        """Whether the checkout at `cwd` is on `main`/`master`.

        A push with no refspec, or a bare `HEAD`, pushes whatever the current
        branch is. `symbolic-ref` fails on detached HEAD and on a path that is not
        a Git checkout; either way, with no branch name to clear it, this cannot
        be shown safe to skip the gate, so it fails closed.
        """
        directory = cwd or os.environ.get("CLAUDE_PROJECT_DIR") or "."
        try:
            result = subprocess.run(
                ["git", "-C", directory, "symbolic-ref", "--short", "-q", "HEAD"],
                capture_output=True,
                text=True,
            )
        except OSError:
            return True
        if result.returncode != 0:
            return True
        return result.stdout.strip() in MAINLINE_BRANCHES


    def resolve_push_cwd(cwd: str | None, cd_argument: str | None) -> str | None:
        """`cwd` after applying a `cd <cd_argument>` seen earlier in the command."""
        if not cd_argument:
            return cwd
        if os.path.isabs(cd_argument):
            return cd_argument
        base = cwd or os.environ.get("CLAUDE_PROJECT_DIR") or "."
        return os.path.join(base, cd_argument)


    def push_targets_mainline(arguments: list[str], cwd: str | None) -> bool:
        """Whether a `git push` invocation's arguments write to `main`/`master`.

        `git push [<repository>] [<refspec>...]`: with two or more operands the
        first is the repository and the rest are refspecs. With exactly one
        operand, Git itself disambiguates on the `:` a refspec carries and a
        repository name never does -- `git push origin` with no refspec still
        pushes the current branch, so a colon-free lone operand is the
        repository, not the destination. With none at all, the implicit refspec
        is the current branch either way.
        """
        _, _, operands = parse(arguments, "o", PUSH_VALUE_LONG)
        if len(operands) > 1:
            refspecs = operands[1:]
        elif len(operands) == 1 and ":" in operands[0]:
            refspecs = operands
        else:
            refspecs = []
        if not refspecs:
            return current_branch_targets_mainline(cwd)
        for refspec in refspecs:
            if refspec == "HEAD":
                if current_branch_targets_mainline(cwd):
                    return True
                continue
            if refspec_destination(refspec) in MAINLINE_BRANCHES:
                return True
        return False


    def commit_directory(command: str) -> str | None:
        """The last literal `cd <path>` argument before the last `git commit` in `command`."""
        directories = directory_before(command, "commit")
        return directories[-1] if directories else None


    def commit_message_file(arguments: list[str]) -> str | None:
        """The path named by `-F`/`--file` on a `git commit` invocation, or None.

        `-F -` reads the message from stdin: not a file on disk to exempt.
        """
        index = 0
        while index < len(arguments):
            token = arguments[index]
            if token == "--":
                return None
            if token in ("-F", "--file"):
                if index + 1 >= len(arguments):
                    return None
                value = arguments[index + 1]
                return None if value == "-" else value
            if token.startswith("--file="):
                value = token[len("--file=") :]
                return None if value == "-" else value
            if token.startswith("-F") and len(token) > 2:
                value = token[2:]
                return None if value == "-" else value
            index += 1
        return None


    def path_indexed(directory: str, path: Path) -> bool:
        """Whether `path` is tracked in the Git index at `directory`.

        `ls-files --error-unmatch` exits 1 for a path that matches no tracked
        file and something else for a genuine error (not a checkout, git itself
        failing); only the former can show the path is safe to exempt, so
        anything else is treated as indexed -- fail closed.
        """
        try:
            result = subprocess.run(
                ["git", "-C", directory, "ls-files", "--error-unmatch", "--", str(path)],
                capture_output=True,
                text=True,
            )
        except OSError:
            return True
        return result.returncode != 1


    try:
        policy = load()
    except PolicyError as exc:
        deny(f"{exc}; refusing to skip the validation gate. Allowed next step: report the policy load failure for reviewed repair and continue independent work; do not narrow policy slots.")

    VALIDATION_COMMAND = policy.validation_pattern
    VALIDATION_HINT = policy.validation_hint.strip() or "this repository's validation commands"

    try:
        payload = json.loads(payload_text)
    except (json.JSONDecodeError, OSError):
        deny("hook input was not valid JSON; refusing to skip the validation gate. Allowed next step: submit a valid tool payload; if the harness generated it, report the payload failure and continue independent work.")

    tool_input = payload.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        deny("hook tool_input was not an object; refusing to skip the validation gate. Allowed next step: submit tool_input as an object; if the harness generated it, report the payload failure and continue independent work.")
    cmd = tool_input.get("command") or ""
    if not isinstance(cmd, str):
        deny("Bash command was not text. Allowed next step: submit the permitted command as a text string in tool_input.command.")
    if not cmd.strip():
        sys.exit(0)

    try:
        current = invocations(cmd)
    except Denial as denial:
        deny(denial.message)

    gates = {invocation.subcommand for invocation in current}.intersection({"commit", "push"})
    if VALIDATION_COMMAND is None:
        gates.discard("commit")
    if "push" in gates:
        start = payload.get("cwd") if isinstance(payload.get("cwd"), str) else None
        start = start or os.environ.get("CLAUDE_PROJECT_DIR") or "."
        push_invocations = [
            invocation
            for invocation in contextual_invocations(cmd, start)
            if invocation.subcommand == "push"
        ]
        # A directory that cannot be derived (wrapper, `$VAR`) fails closed.
        if not any(
            invocation.directory is None
            or push_targets_mainline(invocation.arguments, invocation.directory)
            for invocation in push_invocations
        ):
            gates.discard("push")
    if not gates:
        sys.exit(0)

    # A chained command carries its own evidence: `<validation> && git commit`, or
    # `git fetch origin && git push HEAD:main`.
    def has_commit(clause: str) -> bool:
        return any(item.subcommand == "commit" for item in invocations(clause, strict=False))


    if "commit" in gates and validation_preserves_status(cmd, VALIDATION_COMMAND, has_commit):
        gates.discard("commit")
    if "push" in gates:
        order = [invocation.subcommand for invocation in current]
        if any(name in ("fetch", "pull") for name in order[: order.index("push")]):
            gates.discard("push")
    if not gates:
        sys.exit(0)

    project_root = Path(os.environ.get("CLAUDE_PROJECT_DIR", ".")).resolve()
    missing = "a validation run" if "commit" in gates else "a `git fetch`"
    try:
        uses = read_tool_uses(payload.get("transcript_path"))
    except TranscriptError as exc:
        deny(
            f"{exc}. Without the session history this hook cannot show that {missing} preceded "
            f"`git {sorted(gates)[0]}`. Allowed next step: restore a readable session transcript, "
            f"run {VALIDATION_HINT} for a commit and `git fetch origin` before a mainline push, "
            "then retry only the operation your role permits; report a harness failure and continue "
            "independent work if the transcript remains unavailable."
        )

    # The pending call is already in the transcript. Drop its last occurrence so the
    # gate is measured against what ran before it, and no earlier one is lost.
    pending = last_index(uses, lambda use: use.name == "Bash" and use.input.get("command") == cmd)
    if pending >= 0:
        uses = uses[:pending] + uses[pending + 1 :]


    def is_validation(use) -> bool:
        return (
            use.name == "Bash"
            and isinstance(use.input.get("command"), str)
            and VALIDATION_COMMAND.search(use.input["command"]) is not None
        )


    def runs_git(use, *names: str) -> bool:
        if use.name != "Bash" or not isinstance(use.input.get("command"), str):
            return False
        # A call with no recorded success never ran as far as the gate can show.
        if use.is_error is not False or use.background_or_interrupted:
            return False
        return any(
            invocation.subcommand in names
            for invocation in invocations(use.input["command"], strict=False)
        )


    if "commit" in gates:
        # The last `git commit` in `cmd` is the pending one; earlier ones in the
        # same chained command carry evidence of their own and are not judged
        # here.
        commit_arguments = next(
            (
                invocation.arguments
                for invocation in reversed(current)
                if invocation.subcommand == "commit"
            ),
            [],
        )
        message_file = commit_message_file(commit_arguments)
        commit_dir = resolve_push_cwd(payload.get("cwd"), commit_directory(cmd))
        commit_dir = commit_dir or os.environ.get("CLAUDE_PROJECT_DIR") or "."
        message_path: Path | None = None
        if message_file is not None:
            candidate = Path(message_file)
            message_path = candidate if candidate.is_absolute() else Path(commit_dir) / candidate

        def is_exempt_write(raw_path: str) -> bool:
            """A write the commit gate does not count: `.git/`, the pending
            commit's `-F` message file, or a path not yet in the index. None of
            these can land in the commit the gate is judging."""
            path = Path(raw_path)
            if not path.is_absolute():
                path = project_root / path
            try:
                resolved = path.resolve()
            except OSError:
                resolved = path
            try:
                resolved.relative_to((project_root / ".git").resolve())
                return True
            except (OSError, ValueError):
                pass
            if message_path is not None:
                try:
                    if resolved == message_path.resolve():
                        return True
                except OSError:
                    if resolved == message_path:
                        return True
            return not path_indexed(commit_dir, resolved)

        wrote = writes_under(project_root)

        def counts_against_commit(use) -> bool:
            if not wrote(use):
                return False
            raw_path = use.input.get("file_path") or use.input.get("notebook_path")
            return not is_exempt_write(raw_path)

        write_at = last_index(uses, counts_against_commit)
        validation_at = last_index(uses, is_validation, max(write_at, 0))
        reason = "no recorded result for validation after the last write"
        if VALIDATION_COMMAND.search(cmd):
            reason += "; the pending command has a shape that hides the validator's status before commit"
        valid = False
        if validation_at >= 0:
            validation = uses[validation_at]
            if validation.background_or_interrupted:
                reason = "the latest validation ran in the background or was interrupted, so its result isn't known"
            elif not validation_preserves_status(validation.input["command"], VALIDATION_COMMAND):
                reason = "the latest validation command has a shape that hides the validator's status"
            elif validation.is_error is True:
                reason = "the latest validation run failed"
            elif validation.is_error is False:
                valid = True
        if write_at >= 0 and not valid:
            written = uses[write_at].input.get("file_path") or uses[write_at].input.get("notebook_path")
            deny(
                f"`git commit` is gated: {reason}; `{written}` needs successful validation. "
                f"Allowed next step: run {VALIDATION_HINT} in the foreground with a timeout long enough "
                "to finish, alone or joined with `&&`, unpiped, "
                "redirecting to a file if the output is long; fix any failures, then commit."
            )

    if "push" in gates:
        push_at = last_index(uses, lambda use: runs_git(use, "push"))
        if last_index(uses, lambda use: runs_git(use, "fetch", "pull"), max(push_at, 0)) < 0:
            since = "since the last `git push`" if push_at >= 0 else "in this session"
            deny(
                f"`git push` to `main` or `master` is gated: no `git fetch` or `git pull` {since}. Allowed next step: fetch "
                "the default branch, integrate without force and rerun affected validation if the "
                "base moved; publish through your permitted pull-request flow, never a prohibited "
                "direct mainline push."
            )

    sys.exit(0)
