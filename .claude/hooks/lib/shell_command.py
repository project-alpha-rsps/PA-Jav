"""Shared Bash command inspection for repository PreToolUse hooks.

`block-runtime.sh`, `block-git-unsafe.sh` and `require-validation-before-git.sh`
all have to see through the same wrappers -- `bash -c`, `eval`, `xargs`,
`find -exec`, `env`, `sudo`, `timeout`, command substitution -- before they can
judge what a Bash call actually runs. The tokenizer and the unwrapping live here
so every hook inspects the same set of resolved commands. Heredoc bodies are cut
out before tokenising -- they are data, not code -- and only an unquoted
delimiter leaves a body whose expansions are still inspected. Command
substitutions are masked out for the same reason: each one is its own quoting
context, so its body is walked separately rather than lexed inline with the
command that contains it.

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
        deny(f"could not parse Bash command safely: {exc}. Allowed next step: correct the shell syntax of a permitted command and submit a plainly inspectable call; do not change interpreters to repeat a blocked effect.")
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


def command_index(tokens: list[str]) -> int:
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
                deny("env --split-string cannot be inspected safely. Allowed next step: write a permitted command with literal arguments rather than a split string; do not use another wrapper to repeat a blocked effect.")
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
        if name in SIMPLE_WRAPPERS:
            i = skip_options(tokens, i + 1, set())
            continue
        return i
    return -1


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
            deny(f"cannot safely resolve dynamic executable `{token}`. Allowed next step: name the permitted executable literally so it can be checked; no route is granted to run a blocked executable.")
        seen.add(name)
        token = variables[name]
        literal = False
    if "$" in token or not token or any(char.isspace() for char in token):
        deny(f"cannot safely resolve dynamic executable `{token}`. Allowed next step: name the permitted executable literally so it can be checked; no route is granted to run a blocked executable.")
    if not literal and ("{" in token or "}" in token):
        deny(f"cannot safely resolve brace-expanded executable `{token}`. Allowed next step: name one permitted executable literally, without brace expansion, so it can be checked; no route is granted to run a blocked executable.")
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
    command: str, index: int, pending: list[tuple[str, bool, bool]]
) -> tuple[int, list[str], bool]:
    """Consume the bodies of the heredocs opened on the line just ended.

    Returns (next_index, bodies_that_expand, stripped). `stripped` is False
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
        if expands and body:
            bodies.append("\n".join(body))
    return index, bodies, True


def strip_heredocs(command: str) -> tuple[str, list[str]]:
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
            output.append("<<<")
            index += 3
            continue
        if not quote and command.startswith("<<", index):
            strip_tabs = command.startswith("<<-", index)
            cursor = index + (3 if strip_tabs else 2)
            delimiter, expands, cursor = read_heredoc_delimiter(command, cursor)
            if delimiter:
                pending.append((delimiter, strip_tabs, expands))
                output.append(" ")
                index = cursor
                continue
        if not quote and char == "\n" and pending:
            output.append("\n")
            cursor, bodies, stripped = read_heredoc_bodies(command, index + 1, pending)
            pending = []
            if not stripped:
                output.append(command[index + 1 :])
                break
            expanding_bodies.extend(bodies)
            index = cursor
            continue
        output.append(char)
        index += 1
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


def scan_substitutions(command: str) -> tuple[str, list[str]]:
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


def find_substitutions(command: str) -> list[str]:
    """The `$(...)` and backtick bodies the shell would expand."""
    return scan_substitutions(command)[1]


def walk(
    command: str,
    visit: Callable[[str, list[str]], None],
    blocked_names: Iterable[str] = (),
    variables: dict[str, str] | None = None,
) -> None:
    """Resolve every simple command in `command` and hand it to `visit`.

    `visit(executable, arguments)` sees the basename of each resolved
    executable and the tokens that follow it, for the top-level command and for
    every nested command string a wrapper carries.
    """
    if variables is None:
        variables = {}
    command, expanding_bodies = strip_heredocs(command)
    for body in expanding_bodies:
        for nested_command in find_substitutions(body):
            walk(nested_command, visit, blocked_names, variables.copy())
    command, nested_commands = scan_substitutions(command)
    for nested_command in nested_commands:
        walk(nested_command, visit, blocked_names, variables.copy())

    for clause in split_clauses(tokenize(command)):
        record_assignments(clause, variables)
        index = command_index(clause)
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
                        deny(f"cannot inspect `{executable}` command string. Allowed next step: submit a plainly inspectable permitted command with literal arguments; do not use another shell or interpreter to repeat a blocked effect.")
                    walk(remaining[option_index + 1], visit, blocked_names, variables.copy())
                    break
        elif executable == "eval" and remaining:
            walk(" ".join(remaining), visit, blocked_names, variables.copy())
        elif executable == "xargs":
            command_start = skip_options(
                remaining,
                0,
                {"-a", "--arg-file", "-E", "--eof", "-I", "--replace", "-L", "--max-lines", "-n", "--max-args", "-P", "--max-procs", "-s", "--max-chars"},
            )
            if command_start < len(remaining):
                nested = " ".join(shlex.quote(token) for token in remaining[command_start:])
                walk(nested, visit, blocked_names, variables.copy())
        elif executable == "find":
            for option_index, option in enumerate(remaining):
                if option in ("-exec", "-execdir") and option_index + 1 < len(remaining):
                    nested = " ".join(shlex.quote(token) for token in remaining[option_index + 1 :])
                    walk(nested, visit, blocked_names, variables.copy())
