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
# *what runs* never mistakes data for code. This rule judges what a commit
# *says*, so it needs that data, not the mask. `lib/git_command.py` /
# `lib/shell_command.py` are still what tells this hook a `git commit` or
# `gh pr create`/`edit` invocation is present at all, and what resolves a
# `-F`/`--body-file` path against the command's `cd`-adjusted cwd, the same
# way `git_unsafe_rule.py` does. `-F -`/`--file=-`/`--body-file=-` names
# stdin, which this hook cannot see, so it is denied outright.
#
# Rule module for pre-bash.py: `run(payload_text)` applies the rule to one
# PreToolUse payload. It returns normally to allow and calls sys.exit(2) with a
# message on stderr to deny; pre-bash.py treats anything else as a deny.


def run(payload_text: str) -> None:
    import json
    import os
    import subprocess
    import sys

    sys.path.insert(0, os.environ["HOOK_LIB_DIR"])

    import re

    from attribution import (  # noqa: E402
        AGENT_IDENTITY_RE,
        ANTHROPIC_EMAIL_RE,
        CLAUDE_NAME_RE,
        blocked_email_pattern,
        find_violation,
        owner_email_pattern,
    )
    from git_command import contextual_invocations, directory_before, invocations, subcommand  # noqa: E402
    from repo_policy import PolicyError, load  # noqa: E402
    from shell_command import Denial, find_substitutions, split_clauses, tokenize, walk  # noqa: E402


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


    STDIN_PATHS = ("/dev/stdin", "/dev/fd/", "/proc/self/fd/", "/proc/thread-self/fd/")


    def names_stdin(value: str) -> bool:
        """`-`, a stdin or fd device path, or a process substitution (its
        placeholder after tokenizing): a source this hook cannot read."""
        return value == "-" or "$__command_substitution__" in value or value.startswith(STDIN_PATHS)


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
                return (None, True) if names_stdin(value) else (value, False)
            if token.startswith("--file="):
                value = token[len("--file=") :]
                return (None, True) if names_stdin(value) else (value, False)
            if token.startswith("-F") and len(token) > 2:
                value = token[2:]
                return (None, True) if names_stdin(value) else (value, False)
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
        return (None, True) if names_stdin(value) else (value, False)


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
        payload = json.loads(payload_text)
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


    def normalize_redirects(text: str) -> str:
        """`text` with file-descriptor redirections rewritten so the shell
        tokenizer, which reads `&` as a control operator, cannot mistake them
        for one: `N>&M`, `>&M`, `N<&M`, `>&-` are dropped (they move no file
        content), `&>file`/`&>>file`/`>&file` become `>file`/`>>file`, and `|&`
        becomes `|`. Quoted and escaped text is left alone."""
        output: list[str] = []
        quote = ""
        escaped = False
        index = 0
        length = len(text)
        while index < length:
            char = text[index]
            if escaped:
                escaped = False
                output.append(char)
                index += 1
                continue
            if char == "\\" and quote != "'":
                escaped = True
                output.append(char)
                index += 1
                continue
            if quote:
                if char == quote:
                    quote = ""
                output.append(char)
                index += 1
                continue
            if char in ("'", '"'):
                quote = char
                output.append(char)
                index += 1
                continue
            rest = text[index:]
            if rest.startswith("&>>"):
                output.append(">>")
                index += 3
                continue
            if rest.startswith("&>"):
                output.append(">")
                index += 2
                continue
            if rest.startswith("|&"):
                output.append("|")
                index += 2
                continue
            before = text[:index]
            match = re.match(r"(\d*)([<>])&(?:(\d+-?|-)|(?=[^\s;&|()]))", rest)
            if match and (not match.group(1) or not before or before[-1] in " \t\n;&|(") :
                if match.group(3):
                    index += match.end()
                    continue
                # `>&file`: both streams to a file.
                output.append(match.group(1) + ">" if match.group(2) == ">" else match.group(0))
                index += match.end()
                continue
            output.append(char)
            index += 1
        return "".join(output)


    cmd = normalize_redirects(cmd)

    try:
        current = invocations(cmd)
    except Denial as denial:
        deny(denial.message)

    commit_invocations = [inv for inv in current if inv.subcommand == "commit"]

    gh_invocations: list[list[str]] = []

    # The same globals `gh_unsafe_rule.py` skips over, so a value like `-R
    # shockstruck/x` is never mistaken for the `pr`/`create` subcommand words.
    GH_VALUE_OPTIONS = {
        "-R", "--repo", "--hostname", "--cache",
        "-X", "--method", "-H", "--header", "-q", "--jq", "--template",
        "-F", "--field", "-f", "--raw-field", "--input",
        "-b", "--body", "--body-file", "-t", "--title", "-B", "--base",
        "--subject", "-A", "--author-email", "--match-head-commit",
        "-T", "--recover",
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
        nonlocal gh_current_dir
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


    NEXT_STEP_FILE = (
        "Allowed next step: write the message with the Write tool in a separate call, then pass it "
        "with `-F <absolute path>` (git commit) or `--body-file <absolute path>` (gh pr), with "
        "nothing else rewriting that file in the same call."
    )
    NEXT_STEP_PUSH = (
        "Allowed next step: run the history-writing git step (commit, cherry-pick, revert, merge, "
        "rebase, am, amend) in its own call, then run `git push` in a later call."
    )
    HISTORY_WRITERS = {"commit", "cherry-pick", "revert", "merge", "rebase", "am"}
    # The only clauses that may run before a message-file command in the same call.
    ORDERED_BEFORE = {"cd", "test", "[", "git"}
    SAFE_GIT_BEFORE = {"add", "status", "diff", "log", "fetch"}
    MESSAGE_VALUE_LETTERS = {"commit": "m", "gh": "bt"}
    MESSAGE_LONG = {
        "commit": ("--message", "--trailer"),
        "gh": ("--body", "--title", "--subject"),
    }
    VARIABLE_RE = re.compile(r"\$(?:\{([A-Za-z_]\w*)[^}]*\}|([A-Za-z_]\w*))")


    def message_values(kind: str, arguments: list[str]) -> list[str]:
        """The values of every message argument of a `git commit` (kind
        `commit`) or `gh pr` (kind `gh`) invocation."""
        values: list[str] = []
        letters = MESSAGE_VALUE_LETTERS[kind]
        index = 0
        while index < len(arguments):
            token = arguments[index]
            index += 1
            if token == "--":
                break
            if token.startswith("--"):
                name, equals, value = token.partition("=")
                if name in MESSAGE_LONG[kind]:
                    if equals:
                        values.append(value)
                    elif index < len(arguments):
                        values.append(arguments[index])
                        index += 1
                continue
            if token.startswith("-") and len(token) > 1:
                cluster = token[1:]
                for position, letter in enumerate(cluster):
                    if letter in letters:
                        rest = cluster[position + 1 :]
                        if rest:
                            values.append(rest)
                        elif index < len(arguments):
                            values.append(arguments[index])
                            index += 1
                        break
                    if letter in "FCcStT" and kind == "commit" or letter in "FRBAXHqfT" and kind == "gh":
                        # A value-taking letter that is not a message: skip its operand.
                        if position == len(cluster) - 1:
                            index += 1
                        break
        return values


    def heredoc_form(body: str) -> bool:
        """Exactly `cat <<'X' ... X` with a quoted delimiter and nothing after it."""
        match = re.match(r"\s*cat\s+<<(-?)\s*'([A-Za-z_]\w*)'[ \t]*\n", body)
        if not match:
            return False
        dash, delimiter = match.group(1), match.group(2)
        lines = body[match.end() :].split("\n")
        for position, line in enumerate(lines):
            if (line.lstrip("\t") if dash else line).rstrip() == delimiter and not line.startswith(" ") or (
                not dash and line == delimiter
            ):
                return all(not rest.strip() for rest in lines[position + 1 :])
        return False


    HEREDOC_RE = re.compile(r"<<(-?)[ \t]*(['\"]?)([A-Za-z_]\w*)\2[^\n]*\n")


    def heredocs(text: str) -> list[tuple[bool, str]]:
        """(quoted delimiter, body) of every heredoc in `text`."""
        found = []
        position = 0
        while True:
            match = HEREDOC_RE.search(text, position)
            if not match:
                return found
            dash, quote, delimiter = match.group(1), match.group(2), match.group(3)
            end = match.end()
            body_lines = []
            closed = False
            for line in text[end:].split("\n"):
                end += len(line) + 1
                if (line.lstrip("\t") if dash else line) == delimiter:
                    closed = True
                    break
                body_lines.append(line)
            found.append((bool(quote), "\n".join(body_lines)))
            position = end if closed else len(text)


    def without_quoted_heredocs(text: str) -> str:
        for quoted, body in heredocs(text):
            if quoted and body:
                text = text.replace(body, "", 1)
        return text


    def expanded_variables(text: str) -> set[str]:
        """Names of the variables the shell expands in `text`: every `$NAME` or
        `${NAME}` outside single quotes (quoted-delimiter heredoc bodies are
        removed first)."""
        names: set[str] = set()
        single = False
        escaped = False
        stripped = without_quoted_heredocs(text)
        index = 0
        while index < len(stripped):
            char = stripped[index]
            if escaped:
                escaped = False
            elif char == "\\" and not single:
                escaped = True
            elif char == "'":
                single = not single
            elif char == "$" and not single:
                match = VARIABLE_RE.match(stripped, index)
                if match:
                    names.add(match.group(1) or match.group(2))
            index += 1
        return names


    def literal_assignments(text: str) -> set[str]:
        """Variables assigned from a plain literal anywhere in `text`."""
        pattern = re.compile(
            r"(?:^|[;&|\n]\s*|&&\s*)(?:export\s+)?([A-Za-z_]\w*)="
            r"(?:'[^']*'|\"[^\"$`\\]*\"|[^\s$`\"'\;&|<>()]*)[ \t]*(?=[;&|\n]|$)",
            re.MULTILINE,
        )
        return {match.group(1) for match in pattern.finditer(text)}


    def unresolved_expansion(text: str, shown: str) -> str | None:
        """A `$VAR` expansion in `shown` (a message argument or heredoc text)
        that is not assigned from a literal in the same command, or None."""
        assigned = literal_assignments(cmd)
        live = expanded_variables(cmd)
        for match in VARIABLE_RE.finditer(shown):
            name = match.group(1) or match.group(2)
            if name in live and name not in assigned:
                return match.group(0)
        return None


    def message_source_denial(kind: str, arguments: list[str], label: str) -> str | None:
        """Why a message argument of this invocation is not literal command text."""
        placeholder = "$__command_substitution__"
        for value in message_values(kind, arguments):
            if placeholder in value or "`" in value:
                if not all(heredoc_form(body) for body in find_substitutions(cmd)):
                    return (
                        f"the {label} message comes from a command substitution, whose output this "
                        "hook cannot see before it runs. " + NEXT_STEP_FILE
                    )
                continue
            leftover = unresolved_expansion(cmd, value)
            if leftover:
                return (
                    f"the {label} message expands `{leftover}`, which is not assigned from a "
                    "literal earlier in the same command. " + NEXT_STEP_FILE
                )
        return None


    def unquoted_heredoc_denial() -> str | None:
        for quoted, body in heredocs(cmd):
            if quoted:
                continue
            if "`" in body or "$(" in body:
                return (
                    "an unquoted-delimiter heredoc used as message text holds a command "
                    "substitution. Allowed next step: quote the delimiter (`<<'EOF'`) so the text "
                    "stays literal, or write the message with the Write tool in a separate call."
                )
            leftover = unresolved_expansion(body, body)
            if leftover:
                return (
                    f"an unquoted-delimiter heredoc used as message text expands `{leftover}`. "
                    "Allowed next step: quote the delimiter (`<<'EOF'`) so the text stays "
                    "literal, or write the message with the Write tool in a separate call."
                )
        return None


    REDIRECT_RE = re.compile(r"^(\d*)(>>|>|<)(.*)$", re.DOTALL)


    def split_redirects(arguments: list[str]) -> tuple[list[str], list[tuple[str, str, str]]]:
        """(arguments without redirections, [(fd, operator, target)]). Only an
        unquoted word is read as a redirection, so a quoted `'>x'` stays an argument."""
        clean: list[str] = []
        redirects: list[tuple[str, str, str]] = []
        index = 0
        while index < len(arguments):
            token = arguments[index]
            index += 1
            match = None if getattr(token, "literal", False) else REDIRECT_RE.match(token)
            if not match:
                clean.append(token)
                continue
            fd, operator, target = match.groups()
            if not target and index < len(arguments):
                target = arguments[index]
                index += 1
            redirects.append((fd, operator, target))
        return clean, redirects


    def file_writes(redirects: list[tuple[str, str, str]]) -> list[tuple[str, str]]:
        """(operator, target) of each redirection that writes a file other than /dev/null."""
        return [
            (operator, target)
            for _, operator, target in redirects
            if operator in (">", ">>") and not target.startswith("/dev/null")
        ]


    events: list[tuple[str, list[str]]] = []
    event_redirects: list[list[tuple[str, str, str]]] = []


    def collect_events(executable: str, arguments: list[str]) -> None:
        clean, redirects = split_redirects(arguments)
        events.append((executable, clean))
        event_redirects.append(redirects)


    try:
        walk(cmd, collect_events)
    except Denial as denial:
        deny(denial.message)

    has_push = any(
        executable == "git" and subcommand(arguments).subcommand == "push"
        for executable, arguments in events
    )
    if not commit_invocations and not gh_invocations and not gh_merge_invocations and not has_push:
        sys.exit(0)


    def event_message_file(executable: str, arguments: list[str]) -> tuple[str | None, bool] | None:
        """(path, is_stdin) when this clause names a message file, else None."""
        if executable == "git" and subcommand(arguments).subcommand == "commit":
            path, is_stdin = commit_message_file(subcommand(arguments).arguments)
            return (path, is_stdin) if path is not None or is_stdin else None
        if executable == "gh":
            words = gh_operands(arguments)
            if words[:1] == ["pr"] and words[1:2] and words[1] in ("create", "edit", "merge"):
                path, is_stdin = gh_body_file(arguments)
                if path is not None or is_stdin:
                    return path, is_stdin
                if words[1] == "create":
                    for position, token in enumerate(arguments):
                        name = token.split("=", 1)[0]
                        if name in ("-T", "--template") and ("=" in token or position + 1 < len(arguments)):
                            value = token.split("=", 1)[1] if "=" in token else arguments[position + 1]
                            return (None, True) if names_stdin(value) else (value, False)
        return None


    def check_message_order() -> set[str]:
        """Deny a message-file command that follows anything but a harmless
        clause or a literal write of that file. Returns the normalized paths
        written literally in this call."""
        written: set[str] = set()
        shell_tokens = tokenize(cmd)
        base = payload.get("cwd") or os.environ.get("CLAUDE_PROJECT_DIR") or "."
        current = base
        present = any(event_message_file(*event) is not None for event in events)
        if present:
            if re.search(r"(?<![\\$])[<>]\(", cmd):
                deny(
                    "a process substitution `<(...)` feeds a message source, and its output cannot be "
                    "read before it runs, the same as stdin. " + NEXT_STEP_FILE
                )
            for token in shell_tokens:
                if not getattr(token, "literal", False) and (token == "&" or token in ("(", ")")):
                    deny(
                        "a `&`, subshell or other unordered construct surrounds a command that reads "
                        "a message file, so the file's content at run time cannot be known. "
                        + NEXT_STEP_FILE
                    )
            reason = unquoted_heredoc_denial()
            if reason:
                deny(reason)
        for position, (executable, arguments) in enumerate(events):
            if executable == "cd":
                if len(arguments) == 1 and arguments[0] not in ("", "-") and "$" not in arguments[0]:
                    current = os.path.abspath(os.path.join(current, arguments[0]))
                continue
            named = event_message_file(executable, arguments)
            if named is None:
                writes = file_writes(event_redirects[position]) if present else []
                if (
                    len(writes) == 1
                    and writes[0][0] == ">"
                    and "$" not in writes[0][1]
                    and executable in ("cat", "printf", "echo")
                    and any(fd in ("", "1") and op == ">" for fd, op, _ in event_redirects[position])
                ):
                    target = writes[0][1]
                    literal_write = (
                        bool(heredocs(cmd)) and not arguments
                        if executable == "cat"
                        else not any("$" in token for token in arguments)
                    )
                    if literal_write:
                        written.add(os.path.normpath(os.path.join(current, target)))
                        events[position] = ("", [])
                        event_redirects[position] = []
                continue
            path, is_stdin = named
            if is_stdin or path is None:
                continue
            for before_position, (before_executable, before_arguments) in enumerate(events[:position]):
                if file_writes(event_redirects[before_position]):
                    deny(
                        f"`{before_executable}` redirects output to a file before the command that reads "
                        f"`{path}` in the same call, and could rewrite that file after this hook has read it. "
                        + NEXT_STEP_FILE
                    )
                if before_executable in ("", "cd", "test", "["):
                    continue
                if before_executable == "git" and subcommand(before_arguments).subcommand in SAFE_GIT_BEFORE:
                    continue
                deny(
                    f"`{before_executable}` runs before the command that reads `{path}` in the same "
                    "call, and could rewrite that file after this hook has read it. Only cd, git "
                    "add/status/diff/log/fetch, test, and a literal redirect to the message path may "
                    "come first. " + NEXT_STEP_FILE
                )
        return written


    written_files = check_message_order()


    def written_in_call(path_value: str, directory: str) -> bool:
        return os.path.normpath(os.path.join(directory, path_value)) in written_files


    def require_regular_file(path_value: str, directory: str) -> None:
        candidate = os.path.join(directory, path_value)
        if os.path.exists(candidate) and not os.path.isfile(candidate):
            deny(
                f"`{path_value}` is not a regular file, so its content cannot be read once. "
                + NEXT_STEP_FILE
            )


    for executable, arguments in events:
        if executable == "git":
            invocation = subcommand(arguments)
            if invocation.subcommand == "commit":
                reason = message_source_denial("commit", invocation.arguments, "`git commit`")
                if reason:
                    deny(reason)
        elif executable == "gh":
            words = gh_operands(arguments)
            if words[:1] == ["pr"] and words[1:2] and words[1] in ("create", "edit", "merge"):
                if words[1] == "create" and any(
                    token.split("=", 1)[0] == "--recover" for token in arguments
                ):
                    deny(
                        "`gh pr create --recover` restores a body from a file this hook cannot "
                        "inspect. " + NEXT_STEP_FILE
                    )
                reason = message_source_denial("gh", arguments, f"`gh pr {words[1]}`")
                if reason:
                    deny(reason)

    def author_violation(name: str, email: str) -> str | None:
        if ANTHROPIC_EMAIL_RE.search(email) or ANTHROPIC_EMAIL_RE.search(name):
            return f"{name} <{email}>"
        if CLAUDE_NAME_RE.search(name) or AGENT_IDENTITY_RE.search(name):
            return f"{name} <{email}>"
        return None


    def git_probe(directory: str, *arguments: str):
        try:
            return subprocess.run(
                ["git", "-C", directory, *arguments],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
                env={**os.environ, "LC_ALL": "C", "LANGUAGE": "C"},
            )
        except (OSError, subprocess.SubprocessError):
            return None


    def git_output(directory: str, *arguments: str) -> str | None:
        try:
            result = subprocess.run(
                ["git", "-C", directory, *arguments],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        return result.stdout if result.returncode == 0 else None


    PUSH_VALUE_OPTIONS = {"--repo", "-o", "--push-option", "--receive-pack", "--exec"}


    def check_pushes(owner_pattern, blocked_pattern) -> None:
        payload_cwd = payload.get("cwd") or os.environ.get("CLAUDE_PROJECT_DIR") or "."
        try:
            contexts = contextual_invocations(cmd, payload_cwd)
        except Denial as denial:
            deny(denial.message)
        pushes = [item for item in contexts if item.subcommand == "push"]
        if not pushes:
            return
        # A push after a history-writing step in the same call publishes commits that
        # do not exist yet when this hook runs. The one exception is a commit whose
        # message is entirely literal in the command text, which the commit check above
        # has already scanned.
        first_push = next(
            position
            for position, (executable, arguments) in enumerate(events)
            if executable == "git" and subcommand(arguments).subcommand == "push"
        )
        for executable, arguments in events[:first_push]:
            if executable != "git":
                continue
            invocation = subcommand(arguments)
            if invocation.subcommand not in HISTORY_WRITERS:
                continue
            if invocation.subcommand == "commit" and literal_commit(invocation.arguments):
                continue
            deny(
                f"`git push` follows `git {invocation.subcommand}` in the same call, so this hook "
                "cannot read the commits the push would publish. " + NEXT_STEP_PUSH
            )
        for item in pushes:
            directory = item.directory
            if directory is None:
                deny(
                    "the directory of this `git push` cannot be determined, so the commits it would "
                    "publish cannot be scanned for attribution. Allowed next step: run `git push` "
                    "directly (no wrapper, `GIT_DIR`, `--git-dir` or computed `cd`) in the repository's own "
                    "directory."
                )
            probe = git_probe(directory, "rev-parse", "--git-dir")
            if probe is None or (probe.returncode != 0 and "not a git repository" not in probe.stderr):
                deny(
                    f"git could not inspect `{directory}`, so the commits this push would publish "
                    "cannot be scanned for attribution. Allowed next step: run `git push` from an "
                    "existing repository directory where `git rev-parse --git-dir` succeeds."
                )
            if probe.returncode != 0:
                # Not inside any git repository: the push has nothing to publish.
                continue
            remote, sources = push_plan(directory, item.arguments)
            tracked = git_output(directory, "for-each-ref", "--format=%(refname)", f"refs/remotes/{remote}/")
            if not tracked or not tracked.strip():
                deny(
                    f"remote `{remote}` has no remote-tracking refs in `{directory}`, so the commits "
                    "this push would publish cannot be told from history already there. Allowed next "
                    f"step: run `git fetch {remote}` in a separate call, then push; for a brand-new remote, "
                    "hand the first push to the repository's owner."
                )
            if not sources:
                continue
            record = "%H%x1f%an%x1f%ae%x1f%cn%x1f%ce%x1f%B%x1e"
            output = git_output(
                directory, "log", f"--format={record}", *sources, "--not", f"--remotes={remote}"
            )
            if output is None:
                deny(
                    "git could not list the commits this push would publish; refusing to skip the "
                    "attribution check. Allowed next step: confirm the refs being pushed exist "
                    "locally and run `git fetch`, then push in a separate call."
                )
            for chunk in output.split("\x1e"):
                fields = chunk.strip("\n").split("\x1f")
                if len(fields) < 6:
                    continue
                sha, author, author_email, committer, committer_email, message = fields[:6]
                found = (
                    find_violation(message, owner_pattern, blocked_pattern)
                    or author_violation(author, author_email)
                    or author_violation(committer, committer_email)
                )
                if found:
                    deny(
                        f"commit {sha[:12]} that this push would publish carries an attribution: "
                        f"`{found}`. Allowed next step: do not push it; make a new commit without "
                        "the attribution (a forward fix on a new branch, never a rewrite of shared "
                        "history), then push that."
                    )


    def literal_commit(arguments: list[str]) -> bool:
        """Whether a `git commit`'s message is entirely literal in the command text."""
        has_message = False
        for token in arguments:
            if token == "--":
                break
            name = token.split("=", 1)[0]
            if name in (
                "--amend", "--reuse-message", "--reedit-message", "--file", "--template",
                "--fixup", "--squash",
            ):
                return False
            if token.startswith("--"):
                has_message = has_message or name == "--message"
            elif token.startswith("-") and len(token) > 1:
                cluster = token[1:]
                if any(letter in cluster for letter in "CcFt"):
                    return False
                has_message = has_message or "m" in cluster
        return has_message and message_source_denial("commit", arguments, "`git commit`") is None


    def push_plan(directory: str, raw_arguments: list[str]) -> tuple[str, list[str]]:
        arguments, _ = split_redirects(raw_arguments)
        operands: list[str] = []
        remote_option = ""
        sources: list[str] = []
        delete = False
        index = 0
        while index < len(arguments):
            token = arguments[index]
            index += 1
            if token == "--":
                operands.extend(arguments[index:])
                break
            if token.startswith("--repo="):
                remote_option = token.split("=", 1)[1]
            elif token in PUSH_VALUE_OPTIONS:
                if token == "--repo" and index < len(arguments):
                    remote_option = arguments[index]
                index += 1
            elif token == "--all":
                sources.append("--branches")
            elif token == "--mirror":
                sources.append("--all")
            elif token == "--tags":
                sources.append("--tags")
            elif token in ("-d", "--delete"):
                delete = True
            elif token.startswith("-"):
                continue
            else:
                operands.append(token)
        remote = remote_option or (operands.pop(0) if operands else "")
        if not remote:
            branch = (git_output(directory, "symbolic-ref", "--quiet", "--short", "HEAD") or "").strip()
            for key in (f"branch.{branch}.pushRemote", "remote.pushDefault", f"branch.{branch}.remote"):
                value = (git_output(directory, "config", "--get", key) or "").strip()
                if value:
                    remote = value
                    break
            remote = remote or "origin"
        if "/" in remote or ":" in remote:
            deny(
                f"`git push {remote}` names a URL, so the remote-tracking refs that bound the commits "
                "to scan cannot be found. Allowed next step: push to a named remote that has "
                "remote-tracking refs."
            )
        if delete:
            return remote, []
        for refspec in operands:
            source = refspec.lstrip("+").split(":", 1)[0]
            if not source:
                continue
            sources.append(f"--glob={source}" if "*" in source else source)
        if not operands and not sources:
            sources.append("HEAD")
        return remote, sources


    for args in gh_merge_invocations:
        if not gh_merge_has_body_flag(args):
            deny(
                "`gh pr merge` without an explicit body lets GitHub compose the merge commit message "
                "itself, appending a `Co-authored-by` trailer for every commit author on the branch. "
                'Allowed next step: when your role permits merging and review gates are met, supply '
                'the message explicitly: `gh pr merge <n> --squash --subject "<title> (#<n>)" '
                '--body "<body>"` by default, or `gh pr merge <n> --rebase --match-head-commit <sha> '
                '--body "<title> (#<n>)"` where the repository disables or forbids squash; otherwise '
                'hand the PR to its merging owner.'
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

    check_pushes(owner_pattern, blocked_pattern)

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
        if message_path is not None and written_in_call(message_path, directory):
            continue
        if message_path is not None:
            require_regular_file(message_path, directory)
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
        if body_path is not None and written_in_call(body_path, directory):
            continue
        if body_path is not None:
            require_regular_file(body_path, directory)
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
        for position, token in enumerate(args):
            name = token.split("=", 1)[0]
            if name not in ("-T", "--template"):
                continue
            value = token.split("=", 1)[1] if "=" in token else (args[position + 1] if position + 1 < len(args) else "")
            if written_in_call(value, directory):
                continue
            require_regular_file(value, directory)
            content = read_file(value, directory)
            violation = find_violation(content, owner_pattern, blocked_pattern) if content is not None else None
            if content is None or violation:
                deny(
                    f"`{value}` named by `--template` "
                    + (f"carries an attribution line: `{violation}`." if violation else "could not be read; refusing to skip the attribution check.")
                    + " Allowed next step: write a clean template or body file with the Write tool in a separate call, then re-run the command."
                )

    sys.exit(0)
