"""Loader for `.claude/hooks/policy.json`, the per-repository slots of the template.

The generic hooks are byte-identical in every repository that adopts the
template; everything a repository tunes lives in this one file, so the hooks
never have to be forked again. That is the whole point of the split, and the
drift check in agent-platform enforces it.

Fail-closed is the contract. A hook that cannot read or cannot understand its
policy has no basis to allow the action, so `load` raises `PolicyError` and
every caller turns that into exit 2.

Shape, with the defaults applied when a key is absent:

    {
      "repository": "",                 # one line, used by the Probity judge
      "blockedCommands": {},            # executable -> why it is blocked
      "taskIdentifiers": {
        "prefixes": ["SHOC", "PRO", "MUL"],
        "paths": ["**"]                 # where the identifier rule applies
      },
      "comments": {
        "paths": [],                    # where added `#` commentary is blocked
        "suffixes": [".yaml", ".yml", ".toml", ".ini", ".conf",
                     ".tf", ".tfvars", ".hcl"],
        "directives": ["yaml-language-server:", "renovate:"],
        "guidance": ""                  # the repository's own wording
      },
      "validation": {
        "commandPattern": "",           # regex; empty disables the commit gate
        "hint": ""                      # what to run, named in the denial
      }
    }

`paths` entries are gitignore-shaped globs matched against the repository-
relative POSIX path: `*` and `?` stop at a separator, `**` crosses them, and a
wildcard-free entry covers everything beneath it, so `kubernetes` matches
`kubernetes/apps/x.yaml`.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path, PurePosixPath
from typing import Any

POLICY_FILENAME = "policy.json"
DEFAULT_TASK_PREFIXES = ("SHOC", "PRO", "MUL")
DEFAULT_COMMENT_SUFFIXES = (
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".conf",
    ".tf",
    ".tfvars",
    ".hcl",
)
DEFAULT_DIRECTIVES = ("yaml-language-server:", "renovate:")

_GLOB_SPECIAL = "\\^$.|+()[]{}"


class PolicyError(Exception):
    """The repository policy could not be read or was not the expected shape."""


def _translate(pattern: str) -> str:
    """Glob to regex. `**` crosses separators, `*` and `?` do not."""
    out: list[str] = []
    index = 0
    length = len(pattern)
    while index < length:
        char = pattern[index]
        if char == "*":
            if pattern.startswith("**", index):
                index += 2
                # `a/**/b` also matches `a/b`.
                if out and out[-1] == "/" and pattern.startswith("/", index):
                    out.pop()
                    out.append("(?:/.*)?/")
                    index += 1
                else:
                    out.append(".*")
                continue
            out.append("[^/]*")
            index += 1
            continue
        if char == "?":
            out.append("[^/]")
            index += 1
            continue
        if char == "[":
            end = pattern.find("]", index + 1)
            if end > index + 1:
                body = pattern[index + 1 : end].replace("\\", "\\\\")
                if body.startswith("!"):
                    body = f"^{body[1:]}"
                out.append(f"[{body}]")
                index = end + 1
                continue
        out.append(f"\\{char}" if char in _GLOB_SPECIAL else char)
        index += 1
    return "".join(out)


def matches(pattern: str, relative_path: str) -> bool:
    """True when a repository-relative POSIX path falls under `pattern`."""
    pattern = pattern.strip().lstrip("./").rstrip("/")
    if not pattern or not relative_path:
        return False
    if re.fullmatch(_translate(pattern), relative_path) is not None:
        return True
    if not any(char in pattern for char in "*?["):
        # A wildcard-free entry names a file or a directory; a directory covers
        # everything beneath it.
        return relative_path.startswith(f"{pattern}/")
    if pattern.endswith("/**"):
        # `a/**` written without a trailing slash still covers `a` itself.
        return re.fullmatch(_translate(pattern[:-3]), relative_path) is not None
    return False


def matches_any(patterns: tuple[str, ...], relative_path: str) -> bool:
    return any(matches(pattern, relative_path) for pattern in patterns)


class Policy:
    """The repository's tuned slots, with the template's defaults filled in."""

    def __init__(self, data: dict[str, Any], source: Path) -> None:
        self.source = source
        self.repository: str = _text(data, "repository", "")
        self.blocked_commands: dict[str, str] = _blocked(data.get("blockedCommands"))

        identifiers = _section(data, "taskIdentifiers")
        self.task_prefixes: tuple[str, ...] = _strings(
            identifiers, "prefixes", DEFAULT_TASK_PREFIXES
        )
        self.task_paths: tuple[str, ...] = _strings(identifiers, "paths", ("**",))

        comments = _section(data, "comments")
        self.comment_paths: tuple[str, ...] = _strings(comments, "paths", ())
        self.comment_suffixes: tuple[str, ...] = _strings(
            comments, "suffixes", DEFAULT_COMMENT_SUFFIXES
        )
        self.comment_directives: tuple[str, ...] = _strings(
            comments, "directives", DEFAULT_DIRECTIVES
        )
        self.comment_guidance: str = _text(comments, "guidance", "")
        self.excluded_paths: tuple[str, ...] = _strings(comments, "excludedPaths", ())

        validation = _section(data, "validation")
        self.validation_pattern_source: str = _text(validation, "commandPattern", "")
        self.validation_hint: str = _text(validation, "hint", "")
        try:
            self.validation_pattern = (
                re.compile(self.validation_pattern_source)
                if self.validation_pattern_source
                else None
            )
        except re.error as exc:
            raise PolicyError(
                f"{source}: validation.commandPattern is not a valid regular expression: {exc}"
            ) from exc

    @property
    def task_identifier(self) -> re.Pattern[str] | None:
        if not self.task_prefixes:
            return None
        alternatives = "|".join(re.escape(prefix) for prefix in self.task_prefixes)
        return re.compile(rf"\b(?:{alternatives})-\d+\b")

    def checks_task_identifiers(self, relative_path: str) -> bool:
        if matches_any(self.excluded_paths, relative_path):
            return False
        return matches_any(self.task_paths, relative_path)

    def checks_comments(self, relative_path: str) -> bool:
        if matches_any(self.excluded_paths, relative_path):
            return False
        if PurePosixPath(relative_path).suffix not in self.comment_suffixes:
            return False
        return matches_any(self.comment_paths, relative_path)


def _section(data: dict[str, Any], key: str) -> dict[str, Any]:
    value = data.get(key)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise PolicyError(f"`{key}` must be an object")
    return value


def _text(data: dict[str, Any], key: str, default: str) -> str:
    value = data.get(key, default)
    if not isinstance(value, str):
        raise PolicyError(f"`{key}` must be a string")
    return value


def _strings(data: dict[str, Any], key: str, default: tuple[str, ...]) -> tuple[str, ...]:
    value = data.get(key)
    if value is None:
        return tuple(default)
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise PolicyError(f"`{key}` must be a list of strings")
    return tuple(value)


def _blocked(value: Any) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise PolicyError("`blockedCommands` must be an object of executable -> reason")
    for name, reason in value.items():
        if not isinstance(name, str) or not name:
            raise PolicyError("`blockedCommands` keys must be non-empty strings")
        if not isinstance(reason, str) or not reason.strip():
            raise PolicyError(f"`blockedCommands.{name}` must be a non-empty reason")
    return dict(value)


def policy_path(hooks_dir: Path | None = None) -> Path:
    """Where the policy lives, next to the hooks that read it."""
    if hooks_dir is None:
        hooks_dir = Path(__file__).resolve().parent.parent
    return hooks_dir / POLICY_FILENAME


def load(hooks_dir: Path | None = None) -> Policy:
    """The repository policy, or `PolicyError` when it cannot be trusted.

    The dispatcher pins policy from the default branch and points the hooks at
    that cache, so the policy read here is the merged one, not the working tree
    the agent can edit. `MULTICA_POLICY_DIR` names that cache when it is set.
    """
    candidates: list[Path] = []
    pinned = os.environ.get("MULTICA_POLICY_DIR")
    if pinned:
        candidates.append(Path(pinned) / ".claude" / "hooks" / POLICY_FILENAME)
    candidates.append(policy_path(hooks_dir))

    for candidate in candidates:
        if not candidate.is_file():
            continue
        try:
            data = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, UnicodeError) as exc:
            raise PolicyError(f"cannot read {candidate}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise PolicyError(f"{candidate} is not valid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise PolicyError(f"{candidate} must hold a JSON object")
        data.pop("$schema", None)
        try:
            return Policy(data, candidate)
        except PolicyError as exc:
            raise PolicyError(f"{candidate}: {exc}") from exc

    raise PolicyError(
        f"no {POLICY_FILENAME} beside the hooks ({candidates[-1]}); the repository policy "
        "template requires one, and a hook with no policy cannot judge the action"
    )
