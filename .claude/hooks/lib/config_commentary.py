"""Diff-aware commentary and task-identifier detection for guarded files.

Change rationale belongs in the pull request body, never in the files a
reviewer reads as configuration; task identifiers never enter a repository at
all. A repository that adopts this template already carries pre-existing
comments and identifiers under the guarded paths, so the rule is enforced on
what an edit *adds*, never on what the file already holds.

Which paths are guarded, which suffixes take `#` comments and which directive
prefixes stay allowed are the repository's own slots in
`.claude/hooks/policy.json`; see `repo_policy.py`. This module holds only the
rule.

`block-config-commentary.sh` is the only caller; the module is separate so the
rule can be unit-tested and rescanned across a tree.
"""

from __future__ import annotations

import difflib

from repo_policy import Policy


def block_scalar_lines(text: str) -> set[int]:
    """Zero-based line numbers held inside a YAML block scalar.

    A `|` or `>` scalar carries verbatim application config; a `#` in there is
    data, not a comment about the change.
    """
    try:
        import yaml
        from yaml.nodes import MappingNode, ScalarNode, SequenceNode
    except ImportError:
        return set()

    lines: set[int] = set()

    def visit(node) -> None:
        if isinstance(node, ScalarNode):
            if node.style in ("|", ">"):
                lines.update(range(node.start_mark.line, node.end_mark.line + 1))
        elif isinstance(node, SequenceNode):
            for child in node.value:
                visit(child)
        elif isinstance(node, MappingNode):
            for key_node, value_node in node.value:
                visit(key_node)
                visit(value_node)

    try:
        for document in yaml.compose_all(text, Loader=yaml.SafeLoader):
            if document is not None:
                visit(document)
    except yaml.YAMLError:
        return set()
    return lines


def comment_text(line: str) -> str | None:
    """The comment body of `line`, or None when the line opens no comment.

    A `#` opens a comment at the start of the line or after whitespace, and only
    outside a quoted scalar. `image: repo/app#tag` and `url: "http://x#y"` are
    therefore not comments.
    """
    quote = ""
    escaped = False
    previous = " "
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            previous = char
            continue
        if quote == '"' and char == "\\":
            escaped = True
            previous = char
            continue
        if quote:
            if char == quote:
                quote = ""
            previous = char
            continue
        if char in ("'", '"'):
            quote = char
            previous = char
            continue
        if char == "#" and previous.isspace():
            return line[index + 1 :].strip()
        previous = char
    return None


def is_directive(comment: str, policy: Policy) -> bool:
    return bool(policy.comment_directives) and comment.startswith(policy.comment_directives)


def added_lines(old_text: str, new_text: str) -> list[tuple[int, str]]:
    """One-based line numbers and text for the lines `new_text` adds."""
    old_lines = old_text.splitlines()
    new_lines = new_text.splitlines()
    matcher = difflib.SequenceMatcher(a=old_lines, b=new_lines, autojunk=False)
    added: list[tuple[int, str]] = []
    for tag, _, _, start, end in matcher.get_opcodes():
        if tag in ("insert", "replace"):
            added.extend((index + 1, new_lines[index]) for index in range(start, end))
    return added


def in_scope(relative_path: str, policy: Policy, indexed: bool = True) -> bool:
    """True when either rule has anything to say about this path.

    The task-identifier scan only ever applies to a tracked path: an
    untracked scratch file (a commit message body, a delegation note) is
    never the committed config the rule protects.
    """
    return (indexed and policy.checks_task_identifiers(relative_path)) or policy.checks_comments(
        relative_path
    )


def violations(
    relative_path: str, old_text: str, new_text: str, policy: Policy, indexed: bool = True
) -> list[str]:
    """Commentary and task-identifier violations the edit would introduce."""
    checks_identifiers = indexed and policy.checks_task_identifiers(relative_path)
    checks_comments = policy.checks_comments(relative_path)
    if not checks_identifiers and not checks_comments:
        return []

    identifier = policy.task_identifier if checks_identifiers else None
    verbatim = block_scalar_lines(new_text) if checks_comments else set()
    found: list[str] = []
    for number, line in added_lines(old_text, new_text):
        if identifier is not None:
            for match in identifier.findall(line):
                found.append(
                    f"line {number} adds task identifier `{match}`: {line.strip()[:120]}. Allowed next step: remove the task identifier from the proposed content and put task context in the pull request."
                )
        if not checks_comments or number - 1 in verbatim:
            continue
        comment = comment_text(line)
        if comment is None or is_directive(comment, policy):
            continue
        found.append(f"line {number} adds a comment: {line.strip()[:120]}. Allowed next step: remove the added rationale comment and put the explanation in the pull request.")
    return found
