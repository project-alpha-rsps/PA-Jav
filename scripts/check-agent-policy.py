#!/usr/bin/env python3
"""Check the repository's copy of the repo-policy template for the loose ends
the byte comparison in `scripts/check-repo-policy-drift.py` cannot see from
outside: this repository's own tracked tree.

Template file: identical in every repository that adopts repo-policy. Change
it in shockstruck/agent-platform, not here. It cannot import
`scripts/check-repo-policy-drift.py` to reuse `check_settings` -- that script
lives only in agent-platform -- so the settings rule is copied here instead;
keep the two in step by hand if either changes.

Checks, each reported as `path:line: problem` (or `path: problem` when no
line applies), stdlib only:

- `.claude/hooks/policy.json` still names the repository, not the template
  placeholder.
- No tracked file under `taskIdentifiers.paths` carries a task identifier.
  This scans a whole file rather than a diff, so it reuses the same
  `policy.task_identifier` regex `config_commentary.py`'s per-line scan uses,
  rather than a second one built from scratch.
- No tracked file outside `.claude/` and `AGENTS.md` carries a Multica
  `mention://` link or a UUIDv7-shaped Multica id -- the two shapes a
  committed Multica reference takes, whether typed bare or as an argument to
  `multica issue`/`multica run`.
- `.claude/settings.json` registers every template hook and carries no
  `permissions.ask`. Each template hook's PreToolUse entry sets
  `"onFailure": "block"`, and `probity.sh`'s also sets a positive `timeout`:
  without them Claude Code lets the tool call through when the hook crashes or
  times out.
- `AGENTS.md` exists and still carries every section name
  `AGENTS.md.skeleton`'s first section lists as arriving from
  `agents/shared/conduct.md` in agent-platform.

With `--commits <revision-range>`, also scans the commit messages in that
`git log` range (`base..head`, the same shape `gitleaks` takes) for the attribution patterns
`.claude/hooks/lib/attribution.py` defines -- the CI backstop for a commit
that reached the repository without going through `block-attribution.sh` at
all, such as a human push or a tool that does not run hooks. The owner domain
for each commit is its own recorded author address, not the ambient
environment `block-attribution.sh` reads.

Exit 0 only when every check holds.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOKS_DIR = ROOT / ".claude" / "hooks"
LIB_DIR = HOOKS_DIR / "lib"
POLICY_PATH = HOOKS_DIR / "policy.json"
SETTINGS_PATH = ROOT / ".claude" / "settings.json"
AGENTS_PATH = ROOT / "AGENTS.md"

sys.path.insert(0, str(LIB_DIR))

MENTION_PATTERN = re.compile(r"mention://\S+")
MULTICA_UUID_PATTERN = re.compile(
    r"\b01[0-9a-f]{6}-[0-9a-f]{4}-7[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}\b"
)

# Copied from `check_settings` in agent-platform's
# `scripts/check-repo-policy-drift.py`; see the module docstring for why this
# is a copy rather than an import.
REQUIRED_HOOKS = (
    "block-attribution.sh",
    "block-config-commentary.sh",
    "block-gh-unsafe.sh",
    "block-git-unsafe.sh",
    "block-runtime.sh",
    "probity.sh",
    "require-validation-before-git.sh",
)

# The one hook that waits on a model, so the one whose latency is sized.
PROBITY_HOOK = "probity.sh"

# The section names `AGENTS.md.skeleton`'s first section lists as arriving
# from `agents/shared/conduct.md`. Kept in step with that file by
# agent-platform's own `scripts/tests/test_repo_policy_template.py`; this
# script cannot read that file at runtime because it lives in a different
# repository.
REQUIRED_CONDUCT_SECTIONS = (
    "Work notes belong on the issue, not in the repository",
    "Work that crosses a domain becomes a sub-issue",
    "When a hook refuses you",
    "Reading a large tool response",
    "Validated work ships without a person",
    "Use Jev wherever it is good",
)

# `.claude/` and `AGENTS.md` are what the task names; this script's own
# relative path is added because its messages and regex literals have to
# spell out `mention://` and the id shape in the clear to be readable, and a
# tracked-file scan of its own source would otherwise deny itself.
SCRIPT_RELATIVE_PATH = Path(__file__).resolve().relative_to(ROOT).as_posix()
EXCLUDED_MULTICA_ID_PREFIXES = (".claude/", "AGENTS.md")


class Report:
    def __init__(self) -> None:
        self.problems: list[str] = []

    def add(self, path: str, line: int | None, message: str) -> None:
        location = f"{path}:{line}" if line is not None else path
        self.problems.append(f"{location}: {message}")


def tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "-z"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [entry for entry in out.split("\0") if entry]


def read_lines(relative: str) -> list[str] | None:
    try:
        return (ROOT / relative).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return None


def check_repository_named(policy, report: Report) -> None:
    relative = str(POLICY_PATH.relative_to(ROOT))
    if not policy.repository.strip():
        report.add(relative, None, "`repository` is empty")
    elif policy.repository.startswith("REPLACE ME"):
        report.add(relative, None, "`repository` still carries the template placeholder")


def check_task_identifiers(policy, files: list[str], report: Report) -> None:
    identifier = policy.task_identifier
    if identifier is None:
        return
    for relative in files:
        if not policy.checks_task_identifiers(relative):
            continue
        lines = read_lines(relative)
        if lines is None:
            continue
        for number, line in enumerate(lines, start=1):
            for match in identifier.findall(line):
                report.add(relative, number, f"carries task identifier `{match}`")


def check_multica_ids(files: list[str], report: Report) -> None:
    for relative in files:
        if relative == SCRIPT_RELATIVE_PATH or relative in EXCLUDED_MULTICA_ID_PREFIXES or any(
            relative.startswith(prefix) for prefix in EXCLUDED_MULTICA_ID_PREFIXES
        ):
            continue
        lines = read_lines(relative)
        if lines is None:
            continue
        for number, line in enumerate(lines, start=1):
            if MENTION_PATTERN.search(line):
                report.add(relative, number, "carries a Multica `mention://` link")
            elif MULTICA_UUID_PATTERN.search(line):
                report.add(relative, number, "carries a Multica id")


def check_settings(report: Report) -> None:
    relative = str(SETTINGS_PATH.relative_to(ROOT))
    if not SETTINGS_PATH.is_file():
        report.add(relative, None, "is missing")
        return
    try:
        settings = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        report.add(relative, None, f"is not valid JSON: {exc}")
        return
    if not isinstance(settings, dict):
        report.add(relative, None, "must hold a JSON object")
        return

    registered = {
        Path(entry["command"].strip('"')).name
        for event in (settings.get("hooks") or {}).values()
        if isinstance(event, list)
        for matcher in event
        if isinstance(matcher, dict)
        for entry in matcher.get("hooks") or []
        if isinstance(entry, dict) and isinstance(entry.get("command"), str)
    }
    missing = [name for name in REQUIRED_HOOKS if name not in registered]
    if missing:
        report.add(relative, None, f"does not register {', '.join(missing)}")
    for problem in fail_open_entries(settings):
        report.add(relative, None, problem)
    if "ask" in (settings.get("permissions") or {}):
        report.add(
            relative,
            None,
            "carries permissions.ask; no gate may wait for a person in an unattended run",
        )


def fail_open_entries(settings: dict) -> list[str]:
    """Template hook entries Claude Code would let through on a crash or timeout."""
    problems = []
    pre_tool_use = (settings.get("hooks") or {}).get("PreToolUse")
    for matcher in pre_tool_use if isinstance(pre_tool_use, list) else []:
        if not isinstance(matcher, dict):
            continue
        for entry in matcher.get("hooks") or []:
            if not isinstance(entry, dict) or not isinstance(entry.get("command"), str):
                continue
            name = Path(entry["command"].strip('"')).name
            if name not in REQUIRED_HOOKS:
                continue
            if entry.get("onFailure") != "block":
                problems.append(f'registers {name} without "onFailure": "block"')
            timeout = entry.get("timeout")
            if name == PROBITY_HOOK and (
                isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0
            ):
                problems.append(f"registers {name} without a positive `timeout`")
    return problems


def check_agents_md(report: Report) -> None:
    if not AGENTS_PATH.is_file():
        report.add("AGENTS.md", None, "is missing")
        return
    text = AGENTS_PATH.read_text(encoding="utf-8")
    missing = [section for section in REQUIRED_CONDUCT_SECTIONS if section not in text]
    if missing:
        report.add(
            "AGENTS.md",
            None,
            f"missing the shared-conduct section name(s): {', '.join(missing)}",
        )


def check_commits(range_spec: str, report: Report) -> None:
    """Every commit message in `range_spec` against the attribution patterns
    `.claude/hooks/lib/attribution.py` defines. Each commit is judged against
    its own recorded author address -- the "committing identity" for a commit
    that already landed is what it says, not the environment this check runs
    in."""
    from attribution import find_violation, owner_email_pattern

    record_sep, field_sep = "\x1e", "\x1f"
    try:
        log = subprocess.run(
            ["git", "-C", str(ROOT), "log", f"--format=%H{field_sep}%ae{field_sep}%B{record_sep}", range_spec],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except subprocess.CalledProcessError as exc:
        report.add(
            "--commits",
            None,
            f"`git log {range_spec}` failed: {exc.stderr.strip() or exc}",
        )
        return
    for record in log.split(record_sep):
        record = record.strip("\n")
        if not record:
            continue
        sha, _, rest = record.partition(field_sep)
        author_email, _, body = rest.partition(field_sep)
        domain = author_email.rsplit("@", 1)[1].strip() if "@" in author_email else ""
        owner_pattern = owner_email_pattern(domain) if domain else None
        violation = find_violation(body, owner_pattern)
        if violation:
            report.add("--commits", None, f"commit {sha[:12]} carries an attribution line: `{violation}`")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--commits",
        metavar="RANGE",
        help="also scan commit messages in this `git log` revision range for attribution lines",
    )
    args = parser.parse_args()

    from repo_policy import PolicyError, load

    try:
        policy = load(HOOKS_DIR)
    except PolicyError as exc:
        print(f"FAIL {exc}")
        return 1

    report = Report()
    check_repository_named(policy, report)

    files = tracked_files()
    check_task_identifiers(policy, files, report)
    check_multica_ids(files, report)
    check_settings(report)
    check_agents_md(report)
    if args.commits:
        check_commits(args.commits, report)

    if report.problems:
        for problem in report.problems:
            print(f"FAIL {problem}")
        print(f"\n{len(report.problems)} problem(s).")
        return 1
    print("PASS check-agent-policy")
    return 0


if __name__ == "__main__":
    sys.exit(main())
