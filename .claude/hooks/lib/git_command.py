"""Git invocation parsing shared by the Git PreToolUse hooks.

`git_unsafe_rule.py` judges the flags of the command about to run;
`validation_rule.py` needs the same parse over the session's
history to know which subcommands already ran. Both walk the shell wrappers via
`shell_command.walk`.
"""

from __future__ import annotations

import os
import shlex
from typing import NamedTuple

from shell_command import ENV_ASSIGN, Denial, deny, split_clauses, tokenize, walk

GLOBAL_VALUE_OPTIONS = {
    "--attr-source",
    "-C",
    "-c",
    "--config-env",
    "--exec-path",
    "--git-dir",
    "--namespace",
    "--super-prefix",
    "--work-tree",
}


class Invocation(NamedTuple):
    subcommand: str
    arguments: list[str]


class ContextualInvocation(NamedTuple):
    subcommand: str
    arguments: list[str]
    directory: str | None


def aliases(arguments: list[str]) -> dict[str, str]:
    """The `-c alias.NAME=VALUE` definitions among the global options."""
    found: dict[str, str] = {}
    index = 0
    while index < len(arguments):
        token = arguments[index]
        if not token.startswith("-"):
            break
        option = token.split("=", 1)[0]
        index += 1
        value = ""
        if option in GLOBAL_VALUE_OPTIONS and "=" not in token and index < len(arguments):
            value = arguments[index]
            index += 1
        elif token.startswith("-c") and not token.startswith("--") and len(token) > 2:
            option, value = "-c", token[2:]
        if option in ("-c", "--config-env"):
            if token.startswith("--config-env="):
                value = token.split("=", 1)[1]
            key, _, setting = value.partition("=")
            if key.lower().startswith("alias."):
                if option == "--config-env":
                    deny("a `git --config-env alias.*` value cannot be inspected safely. Allowed next step: name the permitted git subcommand literally instead of defining an alias.")
                found[key[len("alias.") :]] = setting
    return found


def subcommand(arguments: list[str], depth: int = 0) -> Invocation:
    """The git subcommand and its arguments, past any global options.

    A `-c alias.NAME=VALUE` that NAME resolves to is expanded, so a renamed
    `push --force` is judged as the push it is. A `!` alias runs a shell command
    and comes back as the subcommand `!`, with that command as its one argument.
    """
    index = 0
    while index < len(arguments):
        token = arguments[index]
        if not token.startswith("-"):
            result = Invocation(token, arguments[index + 1 :])
            break
        if token.startswith("-C") and token != "-C":
            index += 1
            continue
        option = token.split("=", 1)[0]
        index += 1
        if option in GLOBAL_VALUE_OPTIONS and "=" not in token and index < len(arguments):
            index += 1
    else:
        return Invocation("", [])
    defined = aliases(arguments[:index]) if depth < 8 else {}
    if result.subcommand in defined:
        value = defined[result.subcommand]
        if value.startswith("!"):
            return Invocation("!", [value[1:]] + result.arguments)
        try:
            words = shlex.split(value)
        except ValueError:
            deny(f"git alias `{result.subcommand}` cannot be inspected safely. Allowed next step: name the permitted git subcommand literally instead of defining an alias.")
        return subcommand(words + result.arguments, depth + 1)
    return result


GLOBAL_BOOLEAN_OPTIONS = {
    "--bare",
    "--literal-pathspecs",
    "--no-lazy-fetch",
    "--no-optional-locks",
    "--no-replace-objects",
    "--no-signal-handlers",
    "--no-pager",
    "--paginate",
}


def _git_context(arguments: list[str], directory: str | None) -> tuple[Invocation, str | None]:
    """Resolve Git's global directory options before the subcommand.

    Unknown global options and alternate object-directory namespaces make a
    filesystem-based policy lookup ambiguous; callers must fail closed for
    policy-sensitive operations in that case.
    """
    current = directory
    index = 0
    while index < len(arguments):
        token = arguments[index]
        if not token.startswith("-") or token == "-":
            return Invocation(token, arguments[index + 1 :]), current
        if token == "--":
            return Invocation("", []), None
        option = token.split("=", 1)[0]
        attached = token[2:] if token.startswith("-C") and token != "-C" else ""
        if token == "-C" or attached:
            index += 1
            value = attached or (arguments[index] if index < len(arguments) else "")
            if not value or current is None:
                current = None
            else:
                current = os.path.abspath(os.path.join(current, value))
                if not attached:
                    index += 1
            continue
        if option in ("--git-dir", "--namespace", "--super-prefix"):
            # These alter the repository/ref namespace without a reliably
            # derivable worktree policy location.
            return subcommand(arguments), None
        if option == "--work-tree":
            index += 1
            value = token.split("=", 1)[1] if "=" in token else (arguments[index] if index < len(arguments) else "")
            if not value:
                return subcommand(arguments), None
            current = os.path.abspath(os.path.join(current or ".", value))
            if "=" not in token:
                index += 1
            continue
        if option in GLOBAL_BOOLEAN_OPTIONS:
            index += 1
            continue
        if option in GLOBAL_VALUE_OPTIONS:
            if option in ("-c", "--config-env"):
                return subcommand(arguments), None
            index += 1
            if "=" not in token:
                if index >= len(arguments):
                    return subcommand(arguments), None
                index += 1
            continue
        # Permit the two documented short global switches with values; fail
        # closed for unknown options before a policy-sensitive command.
        if token in ("-p", "--no-pager"):
            index += 1
            continue
        return subcommand(arguments), None
    return Invocation("", []), current


CONTEXT_WRAPPERS = {"bash", "dash", "env", "eval", "find", "ksh", "nice", "sh", "sudo", "timeout", "xargs", "zsh"}


def contextual_invocations(
    command: str, directory: str | None, executable_name: str = "git"
) -> list[ContextualInvocation]:
    """Walk commands while binding literal ``cd`` and Git ``-C`` contexts.

    Commands hidden in wrappers are still found by ``walk``, but their shell
    directory scope cannot be reconstructed from the visitor stream. Mark
    those contexts unknown so policy-sensitive callers can refuse them.
    """
    initial = os.path.abspath(directory) if directory else None
    current = initial
    wrapped = _environment_context_ambiguous(command)
    found: list[ContextualInvocation] = []

    def visit(executable: str, arguments: list[str]) -> None:
        nonlocal current, wrapped
        if executable in CONTEXT_WRAPPERS:
            wrapped = True
        if executable == "cd":
            if len(arguments) == 1 and arguments[0] not in ("", "-") and "$" not in arguments[0]:
                current = os.path.abspath(os.path.join(current or ".", arguments[0]))
            else:
                current = None
            return
        if executable != executable_name:
            return
        if executable == "git":
            invocation, effective = _git_context(arguments, current)
            found.append(ContextualInvocation(invocation.subcommand, invocation.arguments, effective))
            if invocation.subcommand == "!":
                # A `!` alias runs a shell command: judge it as its own command.
                walk(invocation.arguments[0], visit)
        else:
            found.append(ContextualInvocation("gh", arguments, current))

    try:
        walk(command, visit)
    except Denial:
        raise
    if wrapped:
        found = [ContextualInvocation(item.subcommand, item.arguments, None) for item in found]
    return found


def _environment_context_ambiguous(command: str) -> bool:
    """Whether a command-prefix assignment can redirect Git/GitHub context."""
    for clause in split_clauses(tokenize(command)):
        for token in clause:
            if not ENV_ASSIGN.match(token):
                break
            key = token.split("=", 1)[0]
            if key in {"GH_REPO", "GH_HOST", "GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_NAMESPACE"}:
                return True
            if key.startswith(("GIT_CONFIG_", "GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")):
                return True
    return False


def invocations(command: str, strict: bool = True) -> list[Invocation]:
    """Every git subcommand a shell command runs, wrappers included.

    With `strict`, a command that cannot be tokenized safely raises `Denial`;
    without it -- replaying session history, where an uninspectable command
    already ran -- it contributes nothing.
    """
    found: list[Invocation] = []

    def visit(executable: str, arguments: list[str]) -> None:
        if executable == "git":
            invocation = subcommand(arguments)
            if invocation.subcommand == "!":
                found.append(invocation)
                walk(invocation.arguments[0], visit)
            else:
                found.append(invocation)

    try:
        walk(command, visit)
    except Denial:
        if strict:
            raise
        return found
    return found


def directory_before(command: str, *subcommands: str) -> list[str | None]:
    """The last literal `cd <path>` argument before each matching `git` invocation.

    One entry per invocation whose subcommand is in `subcommands`, in the
    order `invocations()` reports them, so callers that also call
    `invocations()` over the same command can zip the two together. `cd -`,
    a bare `cd`, and a `$`-expanded argument are not a literal destination,
    so they are skipped rather than clearing a path already resolved earlier
    in the same command.
    """
    names = set(subcommands)
    current_dir: str | None = None
    directories: list[str | None] = []

    def visit(executable: str, arguments: list[str]) -> None:
        nonlocal current_dir
        if executable == "cd":
            if len(arguments) == 1 and arguments[0] != "-" and "$" not in arguments[0]:
                current_dir = arguments[0]
            return
        if executable == "git" and subcommand(arguments).subcommand in names:
            directories.append(current_dir)

    try:
        walk(command, visit)
    except Denial:
        pass
    return directories


def parse(
    arguments: list[str],
    value_letters: str = "",
    value_long: set[str] | None = None,
) -> tuple[set[str], set[str], list[str]]:
    """Split subcommand arguments into short flags, long options and operands.

    A short option that takes a value consumes the rest of its cluster
    (`-mfix`) or the next token (`-m fix`), so a value is never mistaken for a
    flag.
    """
    value_long = value_long or set()
    flags: set[str] = set()
    longs: set[str] = set()
    operands: list[str] = []
    index = 0
    while index < len(arguments):
        token = arguments[index]
        if token == "--":
            operands.extend(arguments[index + 1 :])
            break
        if token.startswith("--"):
            name = token.split("=", 1)[0]
            longs.add(name)
            index += 1
            if name in value_long and "=" not in token and index < len(arguments):
                index += 1
            continue
        if token.startswith("-") and len(token) > 1:
            attached = False
            takes_value = False
            for position, letter in enumerate(token[1:]):
                flags.add(letter)
                if letter in value_letters:
                    takes_value = True
                    attached = position < len(token) - 2
                    break
            index += 1
            if takes_value and not attached and index < len(arguments):
                index += 1
            continue
        operands.append(token)
        index += 1
    return flags, longs, operands
