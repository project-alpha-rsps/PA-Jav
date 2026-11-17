"""Shared Bash command inspection for repository PreToolUse hooks.

`runtime_rule.py`, `git_unsafe_rule.py` and `validation_rule.py`
all have to see through the same wrappers -- `bash -c`, `eval`, `xargs`,
`find -exec`, `env`, `sudo`, `timeout`, command substitution -- before they can
judge what a Bash call actually runs. The tokenizer and the unwrapping live here
so every hook inspects the same set of resolved commands. Heredoc bodies are cut
out before tokenising -- they are data, not code unless fed to a shell as its script -- and only an unquoted
delimiter leaves a body whose expansions are still inspected. Command
substitutions are masked out for the same reason: each one is its own quoting
context, so its body is walked separately rather than lexed inline with the
command that contains it.

This parser does not follow pipes into a shell, script files or other interpreters.
Inside a script a shell reads from stdin, only a command it identifies is refused; a line it cannot read stays allowed.

`walk()` raises `Denial` when a command cannot be inspected safely; each hook
catches it and emits its own prefixed deny message.
"""

from __future__ import annotations

import fnmatch
import re
import shlex
import shutil
from pathlib import Path
from typing import Callable, Iterable

ENV_ASSIGN = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*=')
VARIABLE_REF = re.compile(r'^\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))$')
SHELLS = {"bash", "dash", "ksh", "sh", "zsh"}
# Tokens that stand in front of the real command, or close the construct one
# opened. Both kinds are skipped the same way: step past them and keep looking.
#
# The closing words matter because `split_clauses` breaks on `;`, so
# `mk(){ echo hi; }; mk` yields a clause that is just `}`. Without them,
# `command_index` returned that `}` as the executable and `resolve_executable`
# denied the whole command with "cannot safely resolve brace-expanded
# executable `}`" — a false positive on any shell function definition. A clause
# made only of these resolves to no command at all, which is correct: `}` runs
# nothing, and `walk` skips an index of -1.
SIMPLE_WRAPPERS = {
    "!",
    "{",
    "}",
    "command",
    "builtin",
    "do",
    "done",
    "elif",
    "else",
    "esac",
    "exec",
    "fi",
    "if",
    "nohup",
    "setsid",
    "then",
    "time",
    "until",
    "while",
}


LITERAL_SENTINEL = "\x01"
SUBSTITUTION_PLACEHOLDER = "$__command_substitution__"


class Denial(Exception):
    """A command that cannot be inspected safely, or that a visitor rejected."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class Uninspectable(Denial):
    """A command the parser cannot read, as opposed to one it identified."""


class Word(str):
    """A token, plus whether any of its characters were quoted or escaped.

    The shell brace-expands and globs an unquoted word only, so the checks that
    read `{`, `}` and `*?[` in an executable name must not fire on a word whose
    text came from inside quotes: `jq '{a: .b}'` is a literal filter, not a
    brace expansion.
    """

    __slots__ = ("literal",)

    def __new__(cls, text: str, literal: bool = False) -> "Word":
        word = super().__new__(cls, text)
        word.literal = literal
        return word


def deny(message: str) -> None:
    raise Denial(message)


def deny_dynamic_command_option(token: str) -> None:
    uninspectable(
        f"cannot safely resolve dynamic `command` option `{token}`. "
        "Allowed next step: use literal command options so the executable can be "
        "checked; no route is granted to run a blocked executable."
    )


def uninspectable(message: str) -> None:
    raise Uninspectable(message)


def normalize_newlines(command: str) -> str:
    output = []
    quote = ""
    escaped = False
    for char in command:
        if escaped:
            output.append(char)
            escaped = False
            continue
        if char == "\\" and quote != "'":
            output.append(char)
            escaped = True
            continue
        if char in ("'", '"'):
            if not quote:
                quote = char
            elif quote == char:
                quote = ""
            output.append(char)
            continue
        output.append(";" if char in "\r\n" and not quote else char)
    return "".join(output)


REDIRECT_OPERATOR = re.compile(r"(?:[0-9]+|&)?(?:>>|>\||>&|<>|>|<)")
REDIRECT_DUP_TARGET = re.compile(r"[0-9]+-?|-")


def strip_leading_redirects(command: str) -> str:
    """Drop redirections that sit where a command's name belongs.

    `>out git push --force` and `2>&1 kubectl delete ns x` run the command that
    follows the redirect; left in place, the redirect token is read as the
    executable. A redirect after the name is left alone, as are `<(`, `>(`,
    `<<<` and heredocs, which have their own handling.
    """
    output = []
    quote = ""
    escaped = False
    at_start = True
    index = 0
    length = len(command)
    while index < length:
        char = command[index]
        if escaped:
            output.append(char)
            escaped = False
            index += 1
            continue
        if char == "\\" and quote != "'":
            output.append(char)
            escaped = True
            at_start = False
            index += 1
            continue
        if char in ("'", '"') and (not quote or quote == char):
            quote = "" if quote else char
            output.append(char)
            at_start = False
            index += 1
            continue
        if quote:
            output.append(char)
            index += 1
            continue
        if char in ";&|(){\n`" and not (char == "&" and REDIRECT_OPERATOR.match(command, index)):
            at_start = True
            output.append(char)
            index += 1
            continue
        if char in " \t":
            output.append(char)
            index += 1
            continue
        if at_start:
            match = REDIRECT_OPERATOR.match(command, index)
            if match and not command.startswith(("<<", "<(", ">("), match.end() - 1):
                cursor = match.end()
                if match.group().endswith(">&"):
                    dup = REDIRECT_DUP_TARGET.match(command, cursor)
                    if dup:
                        index = dup.end()
                        output.append(" ")
                        continue
                while cursor < length and command[cursor] in " \t":
                    cursor += 1
                target_quote = ""
                while cursor < length:
                    c = command[cursor]
                    if target_quote:
                        if c == target_quote:
                            target_quote = ""
                    elif c in ("'", '"'):
                        target_quote = c
                    elif c in " \t\n;&|()":
                        break
                    cursor += 1
                index = cursor
                output.append(" ")
                continue
        at_start = False
        output.append(char)
        index += 1
    return "".join(output)


def mask_literals(command: str) -> str:
    """The command with every quoted or escaped character replaced by a
    same-width sentinel.

    Quote delimiters, escapes and unquoted whitespace keep their offsets, so
    lexing the result yields exactly the same token structure. A token that
    differs from the one the unmasked text produced carried literal text.
    """
    output = []
    quote = ""
    escaped = False
    for char in command:
        if escaped:
            output.append(LITERAL_SENTINEL)
            escaped = False
            continue
        if char == "\\" and quote != "'":
            output.append(char)
            escaped = True
            continue
        if char in ("'", '"') and (not quote or quote == char):
            quote = "" if quote else char
            output.append(char)
            continue
        output.append(LITERAL_SENTINEL if quote else char)
    return "".join(output)


def lex(command: str) -> list[str]:
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|()")
        lexer.commenters = ""
        lexer.whitespace_split = True
        return list(lexer)
    except ValueError as exc:
        uninspectable(f"could not parse Bash command safely: {exc}. Allowed next step: correct the shell syntax of a permitted command and submit a plainly inspectable call; do not change interpreters to repeat a blocked effect.")
    return []


def strip_line_continuations(command: str) -> str:
    """Turn an unescaped `\\` immediately followed by a newline into whitespace.

    Bash deletes that pair as a line continuation everywhere except inside
    single quotes, where a backslash is always literal. Left alone, the
    tokeniser reads the joined line as one word: `\\`-newline-`echo a && \\`-
    newline-`echo b` resolves to a single dynamic executable whose name
    contains a newline, denied rather than walked as the two commands it is.
    """
    output = []
    quote = ""
    escaped = False
    index = 0
    length = len(command)
    while index < length:
        char = command[index]
        if escaped:
            output.append(char)
            escaped = False
            index += 1
            continue
        if char == "\\" and quote != "'":
            if command[index + 1 : index + 2] == "\n":
                output.append(" ")
                index += 2
                continue
            output.append(char)
            escaped = True
            index += 1
            continue
        if char in ("'", '"'):
            if not quote:
                quote = char
            elif quote == char:
                quote = ""
            output.append(char)
            index += 1
            continue
        output.append(char)
        index += 1
    return "".join(output)


def tokenize(command: str) -> list[Word]:
    normalized = normalize_newlines(strip_line_continuations(command))
    plain = lex(normalized)
    masked = lex(mask_literals(normalized))
    if len(masked) != len(plain):
        return [Word(token) for token in plain]
    return [Word(token, token != mask) for token, mask in zip(plain, masked)]


def split_clauses(tokens: list[str]) -> list[list[str]]:
    clauses = []
    current: list[str] = []
    for token in tokens:
        if (
            token
            and not getattr(token, "literal", False)
            and all(char in ";&|()" for char in token)
        ):
            if current:
                clauses.append(current)
                current = []
        else:
            current.append(token)
    if current:
        clauses.append(current)
    return clauses


def validation_preserves_status(
    command: str, pattern: re.Pattern, is_commit: Callable[[str], bool] | None = None
) -> bool:
    """Additional, conservative evidence check; never broadens the policy regex.

    Keep clause text as written (including quotes and assignments). Redirection
    ampersands are not list operators. A pending commit ends the inspected
    prefix: its own result and any later recovery clause are irrelevant.
    """
    if not pattern.search(command):
        return False
    text = strip_line_continuations(command).strip()
    masked = mask_literals(text)
    # Match redirection ampersands first so `2>&1` and `&>log` stay in a clause.
    operators = list(re.finditer(r"[<>]&|&>>?|&&|\|\||[;&|()\r\n]", masked))
    clauses = []
    joins = []
    start = 0
    for match in operators:
        operator = match.group()
        if operator in (">&", "<&", "&>", "&>>"):
            continue
        clauses.append(text[start:match.start()].strip())
        joins.append(operator)
        start = match.end()
    clauses.append(text[start:].strip())
    if is_commit is not None:
        commit_at = next((i for i, clause in enumerate(clauses) if is_commit(clause)), -1)
        if commit_at < 0:
            return False
        clauses = clauses[:commit_at + 1]
        joins = joins[:commit_at]
    if any(join not in ("&&", ";", "\n", "\r") for join in joins):
        return False
    for clause in clauses:
        try:
            tokens = tokenize(clause)
        except Denial:
            return False
        if not tokens or scan_substitutions(clause)[1] or "<<" in mask_literals(clause):
            return False
        index = 0
        while index < len(tokens) and ENV_ASSIGN.match(tokens[index]):
            index += 1
        if index == len(tokens):
            return False
        executable = tokens[index].rsplit("/", 1)[-1]
        if executable in SIMPLE_WRAPPERS | {"for", "select", "case", "function", "coproc", "eval", "source", "."}:
            return False
        try:
            index = command_index(tokens)
        except Denial:
            return False
        if index < 0:
            return False
        executable = tokens[index].rsplit("/", 1)[-1]
        if executable in {"eval", "source", ".", "find"}:
            return False
        if executable in SHELLS and any(
            token.startswith("-") and "c" in token[1:] for token in tokens[index + 1:]
        ):
            return False
    candidates = clauses[:-1] if is_commit is not None else clauses
    last = max((i for i, clause in enumerate(candidates) if pattern.search(clause)), default=-1)
    return last >= 0 and all(join == "&&" for join in joins[last:])


def skip_options(tokens: list[str], index: int, value_options: set[str]) -> int:
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            return index + 1
        if not token.startswith("-") or token == "-":
            return index
        option = token.split("=", 1)[0]
        index += 1
        if option in value_options and "=" not in token and index < len(tokens):
            index += 1
    return index


def resolve_command_word(token: str, variables: dict[str, str]) -> str:
    """Expand whole-word and embedded variable references, refusing cycles."""
    def resolve_name(name: str, seen: set[str]) -> str:
        if name not in variables or name in seen:
            deny_dynamic_command_option(f"${name}")
        value = variables[name]
        match = VARIABLE_REF.fullmatch(value)
        if match:
            return resolve_name(match.group(1) or match.group(2), seen | {name})
        return value

    match = VARIABLE_REF.fullmatch(token)
    if match:
        return resolve_name(match.group(1) or match.group(2), set())

    def replace(match: re.Match[str]) -> str:
        return resolve_name(match.group(1) or match.group(2), set())

    return re.sub(
        r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)",
        replace,
        token,
    )


def command_index(tokens: list[str], variables: dict[str, str] | None = None) -> int:
    variables = variables or {}
    i = 0
    while i < len(tokens):
        token = tokens[i]
        name = token.rsplit("/", 1)[-1]
        if ENV_ASSIGN.match(token):
            i += 1
            continue
        if name == "env":
            if any(
                option in {"-S", "--split-string"} or option.startswith("--split-string=")
                for option in tokens[i + 1 :]
            ):
                uninspectable("env --split-string cannot be inspected safely. Allowed next step: write a permitted command with literal arguments rather than a split string; do not use another wrapper to repeat a blocked effect.")
            i = skip_options(tokens, i + 1, {"-C", "--chdir", "-S", "--split-string", "-u", "--unset"})
            while i < len(tokens) and ENV_ASSIGN.match(tokens[i]):
                i += 1
            continue
        if name == "sudo":
            i = skip_options(
                tokens,
                i + 1,
                {"-C", "--close-from", "-D", "--chdir", "-g", "--group", "-h", "--host", "-p", "--prompt", "-R", "--chroot", "-T", "--command-timeout", "-u", "--user"},
            )
            continue
        if name == "timeout":
            i = skip_options(
                tokens,
                i + 1,
                {"-k", "--kill-after", "-s", "--signal"},
            )
            if i < len(tokens):
                i += 1
            continue
        if name == "nice":
            i = skip_options(tokens, i + 1, {"-n", "--adjustment"})
            continue
        if name == "stdbuf":
            i = skip_options(tokens, i + 1, {"-i", "-o", "-e", "--input", "--output", "--error"})
            continue
        if name == "busybox":
            # `busybox sh -c ...` runs the applet named by the next word.
            i += 1
            continue
        if name == "command" and lookup_only(tokens[i + 1 :]):
            # `command -v NAME` and `command -V NAME` look a name up and print
            # it; nothing runs, so a loop variable there is not an executable.
            return -1
        if name in SIMPLE_WRAPPERS:
            if name == "command":
                # Resolve variable-backed option words before skipping them;
                # otherwise `command $o kubectl` treats `$o` as the executable.
                resolved = list(tokens)
                cursor = i + 1
                while cursor < len(tokens):
                    token = str(tokens[cursor])
                    if "$" in token:
                        token = resolve_command_word(token, variables)
                        if any(char.isspace() for char in token):
                            deny_dynamic_command_option(token)
                        if token.startswith("-") and token != "--" and not re.fullmatch(
                            r"-[pvV]+", token
                        ):
                            deny_dynamic_command_option(token)
                        resolved[cursor] = token
                    if token == "--" or not token.startswith("-") or token == "-":
                        break
                    cursor += 1
                i = skip_options(resolved, i + 1, set())
            else:
                i = skip_options(tokens, i + 1, set())
            continue
        return i
    return -1


def lookup_only(arguments: list[str]) -> bool:
    """True when `command`'s options make it describe NAME instead of running it."""
    for token in arguments:
        if not re.fullmatch(r"-[pvV]+", token):
            return False
        if "v" in token or "V" in token:
            return True
    return False


def record_assignments(tokens: list[str], variables: dict[str, str]) -> None:
    for token in tokens:
        if not ENV_ASSIGN.match(token):
            continue
        name, value = token.split("=", 1)
        variables[name] = value


def resolve_executable(token: str, variables: dict[str, str], blocked_names: Iterable[str]) -> str:
    blocked = frozenset(blocked_names)
    # A quoted word is neither brace-expanded nor globbed; its text is the name
    # that runs. A value that came from a variable is not quoted, so the checks
    # apply to it again.
    literal = getattr(token, "literal", False)
    seen = set()
    while True:
        match = VARIABLE_REF.fullmatch(token)
        if not match:
            break
        name = match.group(1) or match.group(2)
        if name in seen or name not in variables:
            uninspectable(f"cannot safely resolve dynamic executable `{token}`. Allowed next step: name the permitted executable literally so it can be checked; no route is granted to run a blocked executable.")
        seen.add(name)
        token = variables[name]
        literal = False
    if "$" in token or not token or any(char.isspace() for char in token):
        uninspectable(f"cannot safely resolve dynamic executable `{token}`. Allowed next step: name the permitted executable literally so it can be checked; no route is granted to run a blocked executable.")
    if not literal and ("{" in token or "}" in token):
        uninspectable(f"cannot safely resolve brace-expanded executable `{token}`. Allowed next step: name one permitted executable literally, without brace expansion, so it can be checked; no route is granted to run a blocked executable.")
    executable = token.rsplit("/", 1)[-1]
    if not literal and any(char in executable for char in "*?[") and any(
        fnmatch.fnmatchcase(name, executable) for name in blocked
    ):
        deny(f"executable glob `{executable}` can expand to a blocked cluster CLI. Allowed next step: use permitted repository inspection or a reviewed Git change; no agent route exists here to execute the blocked CLI. Report the unmet need and continue independent work.")
    resolved = shutil.which(token) if "/" not in token else token
    if resolved:
        try:
            target = Path(resolved).resolve(strict=True).name
        except OSError:
            target = ""
        if target in blocked:
            deny(f"executable `{token}` resolves to blocked cluster CLI `{target}`. Allowed next step: use permitted repository inspection or a reviewed Git change; no agent route exists here to execute the blocked CLI. Report the unmet need and continue independent work.")
    return executable


def read_heredoc_delimiter(command: str, index: int) -> tuple[str, bool, int]:
    """Read a heredoc delimiter word, returning (word, expands, next_index).

    A delimiter quoted or backslash-escaped anywhere makes the body inert; an
    unquoted one still expands `$(...)` and backticks.
    """
    delimiter = []
    expands = True
    length = len(command)
    while index < length and command[index] in " \t":
        index += 1
    while index < length:
        char = command[index]
        if char == "\\" and index + 1 < length:
            expands = False
            delimiter.append(command[index + 1])
            index += 2
            continue
        if char in ("'", '"'):
            expands = False
            index += 1
            while index < length and command[index] != char:
                if char == '"' and command[index] == "\\" and index + 1 < length:
                    delimiter.append(command[index + 1])
                    index += 2
                    continue
                delimiter.append(command[index])
                index += 1
            index += 1
            continue
        if char in " \t\r\n;&|<>()":
            break
        delimiter.append(char)
        index += 1
    return "".join(delimiter), expands, index


def read_heredoc_bodies(
    command: str,
    index: int,
    pending: list[tuple[str, bool, bool]],
    all_bodies: list[str] | None = None,
) -> tuple[int, list[str], bool]:
    """Consume the bodies of the heredocs opened on the line just ended.

    Returns (next_index, bodies as (text, expands), stripped). `stripped` is False
    when a terminator line is missing, which means the `<<` did not open a
    heredoc at all (an arithmetic shift, say) — the caller then keeps the raw
    text so it is still inspected.
    """
    bodies = []
    length = len(command)
    for delimiter, strip_tabs, expands in pending:
        body = []
        terminated = False
        while index < length:
            end = command.find("\n", index)
            line = command[index:] if end < 0 else command[index:end]
            index = length if end < 0 else end + 1
            candidate = line.lstrip("\t") if strip_tabs else line
            if candidate.rstrip("\r") == delimiter:
                terminated = True
                break
            body.append(line)
        if not terminated:
            return index, bodies, False
        if all_bodies is not None:
            all_bodies.append("\n".join(body))
        if expands and body:
            bodies.append("\n".join(body))
    return index, bodies, True


def feeds_shell(clause: str) -> bool:
    """True when a heredoc opened at the end of `clause` is a shell's script."""
    clause = re.sub(r"(?:^|(?<=\s))\d*(?:&>>?|[<>]&|>>?|<)\s*\S*", " ", clause)
    try:
        tokens = tokenize(clause)
        index = command_index(tokens)
    except Denial:
        return False
    if index < 0 or tokens[index].rsplit("/", 1)[-1] not in SHELLS:
        return False
    arguments = tokens[index + 1 :]
    if any(t.startswith("-") and not t.startswith("--") and "c" in t[1:] for t in arguments):
        return False
    if any(t.startswith("-") and not t.startswith("--") and "s" in t[1:] for t in arguments):
        return True
    return all(
        t.startswith(("-", "+")) or (arguments[i - 1][-1:] == "o" and arguments[i - 1][:1] in ("-", "+"))
        for i, t in enumerate(arguments)
    )


def strip_heredocs(
    command: str, shell_bodies: list[str] | None = None
) -> tuple[str, list[str]]:
    """Cut heredoc bodies out of the command before it is tokenised.

    A heredoc body is data, not code: tokenising it puts every line's first
    word in executable position and reads its braces, parens and backticks as
    shell syntax. Returns the command without the bodies, plus the bodies whose
    delimiter was unquoted for the caller to scan for expansions.

    A `$( … )` command substitution opens its own quoting context, so a `"`
    that opened before it does not carry inside: `"$(cat <<'EOF' … )"` still
    opens a heredoc right after `cat`. `quote_stack`/`paren_depth_stack` track
    that nesting -- push and reset the quote on `$(`, count bare parens inside
    so a literal `(...)` in ordinary (non-heredoc) substitution text does not
    close it early, and pop back to the saved quote on the matching `)`.
    """
    output = []
    expanding_bodies = []
    pending: list[tuple[str, bool, bool]] = []
    receivers: list[bool] = []
    clause_start = 0
    line_start = 0
    quote = ""
    quote_stack: list[str] = []
    paren_depth_stack: list[int] = []
    escaped = False
    index = 0
    length = len(command)
    while index < length:
        char = command[index]
        if escaped:
            output.append(char)
            escaped = False
            index += 1
            continue
        if char == "\\" and quote != "'":
            output.append(char)
            escaped = True
            index += 1
            continue
        if char in ("'", '"'):
            if not quote:
                quote = char
            elif quote == char:
                quote = ""
            output.append(char)
            index += 1
            continue
        if quote != "'" and command.startswith("$(", index):
            quote_stack.append(quote)
            paren_depth_stack.append(0)
            quote = ""
            output.append("$(")
            index += 2
            clause_start = len(output)
            continue
        if quote_stack and not quote and char == "(":
            paren_depth_stack[-1] += 1
            output.append(char)
            index += 1
            continue
        if quote_stack and not quote and char == ")":
            if paren_depth_stack[-1] > 0:
                paren_depth_stack[-1] -= 1
            else:
                quote = quote_stack.pop()
                paren_depth_stack.pop()
            output.append(char)
            index += 1
            continue
        if not quote and command.startswith("<<<", index):
            if shell_bodies is not None and feeds_shell("".join(output[clause_start:])):
                shell_bodies.append(read_heredoc_delimiter(command, index + 3)[0])
            output.append("<<<")
            index += 3
            continue
        if not quote and command.startswith("<<", index):
            strip_tabs = command.startswith("<<-", index)
            cursor = index + (3 if strip_tabs else 2)
            delimiter, expands, cursor = read_heredoc_delimiter(command, cursor)
            if delimiter:
                pending.append((delimiter, strip_tabs, expands))
                receivers.append(feeds_shell("".join(output[clause_start:])))
                output.append(" ")
                index = cursor
                continue
        if not quote and char == "\n" and pending:
            # `cat <<E | bash` pipes the body into a shell: a later pipeline
            # stage on the opening line that reads stdin as its script.
            piped = any(
                feeds_shell(stage)
                for stage in re.split(r"\|&?", "".join(output[line_start:]))[1:]
            )
            output.append("\n")
            every_body: list[str] = []
            cursor, bodies, stripped = read_heredoc_bodies(command, index + 1, pending, every_body)
            if shell_bodies is not None:
                for body, (_, _, expands), feeds in zip(every_body, pending, receivers):
                    if feeds or piped:
                        shell_bodies.append(re.sub(r"\\([$`\\])", r"\1", body) if expands else body)
            pending = []
            receivers = []
            clause_start = len(output)
            line_start = len(output)
            if not stripped:
                output.append(command[index + 1 :])
                break
            expanding_bodies.extend(bodies)
            index = cursor
            continue
        output.append(char)
        index += 1
        if char == "\n":
            line_start = len(output)
        if not quote and char in ";&|(\n" and not (
            char == "&" and index >= 2 and command[index - 2] in "<>"
        ) and not (char == "&" and command[index : index + 1] == ">"):
            clause_start = len(output)
    return "".join(output), expanding_bodies


def read_substitution(command: str, start: int) -> tuple[str, int]:
    """Read a `$(...)` body starting at its opening paren, honouring nesting."""
    depth = 0
    quote = ""
    escaped = False
    index = start
    length = len(command)
    while index < length:
        char = command[index]
        if escaped:
            escaped = False
        elif char == "\\" and quote != "'":
            escaped = True
        elif quote:
            if char == quote:
                quote = ""
        elif char in ("'", '"'):
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return command[start + 1 : index], index + 1
        index += 1
    return command[start + 1 :], length


def scan_substitutions(
    command: str,
    arithmetic_assignments: dict[str, list[str]] | None = None,
    arithmetic_seen: set[str] | None = None,
) -> tuple[str, list[str]]:
    """Replace each `$(...)` and backtick span with an inert placeholder, and
    return the bodies the shell would expand alongside it.

    Scanning the raw text rather than the tokens keeps quoting visible: a
    backtick inside single quotes is literal, so prose naming a blocked CLI in
    a single-quoted string is not a nested command.

    The replacement is what keeps a substitution's own quoting out of the outer
    token stream. `"$(cmd "arg")"` is two nested quoting contexts, and a lexer
    that reads `$(` as ordinary text closes the outer quote on the inner one:
    the body then leaks into the outer command as bare tokens, splitting on its
    `;` and `(` and putting its words in command position. The placeholder
    keeps the span dynamic -- a `$name` an unset variable cannot resolve -- so
    a substitution in command position is still refused, while the body itself
    is walked separately with its quoting intact.
    """
    arithmetic_assignments = arithmetic_assignments or {}
    if arithmetic_seen is None:
        arithmetic_seen = set()
    output = []
    found = []
    quote = ""
    escaped = False
    index = 0
    length = len(command)
    while index < length:
        char = command[index]
        if escaped:
            output.append(char)
            escaped = False
            index += 1
            continue
        if char == "\\" and quote != "'":
            output.append(char)
            escaped = True
            index += 1
            continue
        if char in ("'", '"'):
            if not quote:
                quote = char
            elif quote == char:
                quote = ""
            output.append(char)
            index += 1
            continue
        if quote != "'" and command.startswith("$(", index):
            nested, index = read_substitution(command, index + 1)
            arithmetic = arithmetic_body(nested)
            if arithmetic is not None:
                # `$(( … ))` evaluates an expression; only the command
                # substitutions inside it run anything. Arithmetic variables
                # can hold array subscripts whose text is expanded as shell
                # syntax, so inspect the recorded assignment value too.
                found.extend(find_substitutions(arithmetic))
                found.extend(
                    arithmetic_variable_substitutions(
                        arithmetic, arithmetic_assignments, arithmetic_seen
                    )
                )
            elif nested.strip():
                found.append(nested)
            output.append(SUBSTITUTION_PLACEHOLDER)
            continue
        if not quote and char in "<>" and command.startswith("(", index + 1):
            # `<( … )` and `>( … )` run their body as a command and stand in
            # for a file name, so they are walked and then read as an argument.
            nested, index = read_substitution(command, index + 1)
            if nested.strip():
                found.append(nested)
            output.append(SUBSTITUTION_PLACEHOLDER)
            continue
        if quote != "'" and char == "`":
            end = command.find("`", index + 1)
            if end < 0:
                output.append(command[index:])
                break
            nested = command[index + 1 : end]
            if nested.strip():
                found.append(nested)
            output.append(SUBSTITUTION_PLACEHOLDER)
            index = end + 1
            continue
        output.append(char)
        index += 1
    return "".join(output), found


def arithmetic_body(nested: str) -> str | None:
    """The expression of `$(( … ))`, given the text between `$(` and `)`.

    That text is `( … )` with one paren pair spanning all of it. `$( (a); (b) )`
    starts with a paren too, but its first pair closes early, so it stays a
    command substitution.
    """
    if not (nested.startswith("(") and nested.endswith(")")):
        return None
    inner, end = read_substitution(nested, 0)
    if end != len(nested):
        return None
    return inner


def arithmetic_variable_substitutions(
    expression: str,
    assignments: dict[str, list[str]],
    seen: set[str] | None = None,
) -> list[str]:
    """Inspect each assigned value reached from an arithmetic variable once."""
    if seen is None:
        seen = set()
    found = []
    pending = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", expression)
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        seen.add(name)
        for value in assignments.get(name, []):
            # A backslash preserved by a double-quoted assignment can be
            # activated by arithmetic expansion.
            arithmetic_value = value.replace(r"\$(", "$(").replace(r"\`", "`").replace("'", "")
            _, nested = scan_substitutions(
                arithmetic_value,
                arithmetic_assignments=assignments,
                arithmetic_seen=seen,
            )
            found.extend(nested)
            pending.extend(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", arithmetic_value))
    return found


def record_assignment_values(
    tokens: list[str], assignments: dict[str, list[str]]
) -> None:
    for token in tokens:
        if not ENV_ASSIGN.match(token):
            continue
        name, value = token.split("=", 1)
        values = assignments.setdefault(name, [])
        if value not in values:
            values.append(value)


def find_substitutions(command: str) -> list[str]:
    """The `$(...)` and backtick bodies the shell would expand."""
    return scan_substitutions(command)[1]


CASE_PATTERN = re.compile(r"^\s*\(?[^\s()$`'\"=]+(?:\s*\|\s*[^\s()$`'\"=]+)*\)")


def walk_script(script, visit, blocked_names, variables, assignments, seen) -> None:
    """Walk text read from shell stdin, preserving nested heredocs as data."""
    nested_scripts: list[str] = []
    text, expanding = strip_heredocs(script, nested_scripts)
    for body in expanding:
        for nested in scan_substitutions(body, assignments, seen)[1]:
            walk(nested, visit, blocked_names, variables.copy(), assignments, seen)
    kept = "\n".join(
        line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")
    )
    lines = []
    depth = 0
    for line in strip_line_continuations(kept).splitlines():
        masked = mask_literals(line)
        depth += len(re.findall(r"(?:^|[\s;])case\s", masked))
        if depth:
            line = CASE_PATTERN.sub("", line)
        depth -= len(re.findall(r"(?:^|[\s;])esac(?:$|[\s;])", masked))
        depth = max(depth, 0)
        lines.append(line)
    try:
        walk("\n".join(lines), visit, blocked_names, variables, assignments, seen)
    except Uninspectable:
        for line in lines:
            try:
                walk(line, visit, blocked_names, variables, assignments, seen)
            except Uninspectable:
                continue
    for nested in nested_scripts:
        walk_script(nested, visit, blocked_names, variables, assignments, seen)


def walk(
    command: str,
    visit: Callable[[str, list[str]], None],
    blocked_names: Iterable[str] = (),
    variables: dict[str, str] | None = None,
    arithmetic_assignments: dict[str, list[str]] | None = None,
    arithmetic_seen: set[str] | None = None,
) -> None:
    """Resolve every simple command in `command` and hand it to `visit`.

    `visit(executable, arguments)` sees the basename of each resolved
    executable and the tokens that follow it, for the top-level command and for
    every nested command string a wrapper carries.
    """
    if variables is None:
        variables = {}
    if arithmetic_assignments is None:
        arithmetic_assignments = {}
    if arithmetic_seen is None:
        arithmetic_seen = set()
    shell_bodies: list[str] = []
    command, expanding_bodies = strip_heredocs(command, shell_bodies)
    # This record is intentionally separate from `variables`: it contains all
    # assignment values for arithmetic inspection, not a simulated shell state.
    masked_command, _ = scan_substitutions(command)
    for clause in split_clauses(tokenize(masked_command)):
        record_assignment_values(clause, arithmetic_assignments)

    for body in expanding_bodies:
        _, nested_commands = scan_substitutions(body, arithmetic_assignments, arithmetic_seen)
        for nested_command in nested_commands:
            walk(
                nested_command,
                visit,
                blocked_names,
                variables.copy(),
                arithmetic_assignments,
                arithmetic_seen,
            )
    command, nested_commands = scan_substitutions(command, arithmetic_assignments, arithmetic_seen)
    for nested_command in nested_commands:
        walk(
            nested_command,
            visit,
            blocked_names,
            variables.copy(),
            arithmetic_assignments,
            arithmetic_seen,
        )
    command = strip_leading_redirects(command)

    for clause in split_clauses(tokenize(command)):
        record_assignments(clause, variables)
        index = command_index(clause, variables)
        if index < 0:
            continue
        executable = resolve_executable(clause[index], variables, blocked_names)
        remaining = clause[index + 1 :]
        visit(executable, remaining)

        if executable in SHELLS:
            for option_index, option in enumerate(remaining):
                if option == "-c" or (
                    option.startswith("-")
                    and not option.startswith("--")
                    and "c" in option[1:]
                ):
                    if option_index + 1 >= len(remaining):
                        uninspectable(f"cannot inspect `{executable}` command string. Allowed next step: submit a plainly inspectable permitted command with literal arguments; do not use another shell or interpreter to repeat a blocked effect.")
                    walk(
                        remaining[option_index + 1],
                        visit,
                        blocked_names,
                        variables.copy(),
                        arithmetic_assignments,
                        arithmetic_seen,
                    )
                    break
        elif executable == "script":
            for option_index, option in enumerate(remaining):
                if option.startswith("--command="):
                    walk(
                        option.split("=", 1)[1],
                        visit,
                        blocked_names,
                        variables.copy(),
                        arithmetic_assignments,
                        arithmetic_seen,
                    )
                    break
                if option == "--command" or (
                    option.startswith("-") and not option.startswith("--") and "c" in option[1:]
                ):
                    if option_index + 1 >= len(remaining):
                        uninspectable("cannot inspect `script` command string. Allowed next step: submit a plainly inspectable permitted command with literal arguments; do not use another shell or interpreter to repeat a blocked effect.")
                    walk(
                        remaining[option_index + 1],
                        visit,
                        blocked_names,
                        variables.copy(),
                        arithmetic_assignments,
                        arithmetic_seen,
                    )
                    break
        elif executable == "eval" and remaining:
            walk(
                " ".join(remaining),
                visit,
                blocked_names,
                variables.copy(),
                arithmetic_assignments,
                arithmetic_seen,
            )
        elif executable == "xargs":
            command_start = skip_options(
                remaining,
                0,
                {"-a", "--arg-file", "-E", "--eof", "-I", "--replace", "-L", "--max-lines", "-n", "--max-args", "-P", "--max-procs", "-s", "--max-chars"},
            )
            if command_start < len(remaining):
                nested = " ".join(shlex.quote(token) for token in remaining[command_start:])
                walk(nested, visit, blocked_names, variables.copy(), arithmetic_assignments, arithmetic_seen)
        elif executable == "find":
            for option_index, option in enumerate(remaining):
                if option in ("-exec", "-execdir") and option_index + 1 < len(remaining):
                    nested = " ".join(shlex.quote(token) for token in remaining[option_index + 1 :])
                    walk(nested, visit, blocked_names, variables.copy(), arithmetic_assignments, arithmetic_seen)

    for body in shell_bodies:
        walk_script(body, visit, blocked_names, variables.copy(), arithmetic_assignments, arithmetic_seen)
