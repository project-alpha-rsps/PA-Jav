#!/usr/bin/env python3
"""Check changed repository paths using policy and refs supplied as data.

Run this source from the trusted base commit (never from the proposed head):

    git show "$BASE_SHA:scripts/check-trusted-branch-policy.py" | python3 - \
      --repo . --base-sha "$BASE_SHA" --head-sha "$HEAD_SHA" \
      --base-branch "$BASE_BRANCH" --pr-number "$PR_NUMBER" \
      --base-ref "refs/remotes/origin/$BASE_BRANCH" \
      --head-ref "refs/pull/$PR_NUMBER/head"

The checker imports no repository code. It reads only the base policy JSON,
Git commit/ref metadata and proposed changed path names; proposed code is never
imported or executed.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
PROFILE = "project-alpha-v1"
POLICY_PATH = ".claude/hooks/policy.json"
GLOB_SPECIAL = "\\^$.|+()[]{}"
REQUIRED_PATHS = (
    ".claude/settings.json",
    ".claude/hooks/policy.json",
    ".claude/hooks/block-config-commentary.sh",
    ".claude/hooks/pre-bash.sh",
    ".claude/hooks/pre-bash.py",
    ".claude/hooks/lib/git_unsafe_rule.py",
    ".claude/hooks/lib/gh_unsafe_rule.py",
    ".claude/hooks/lib/branch_policy.py",
    ".claude/hooks/lib/repo_policy.py",
    ".claude/hooks/lib/git_command.py",
    ".claude/hooks/lib/shell_command.py",
    "scripts/check-agent-policy.py",
    "scripts/check-trusted-branch-policy.py",
    ".github/workflows/validate.yaml",
)


class CheckError(Exception):
    """Trusted inputs or the base policy could not be verified."""


def git(repo: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *arguments], capture_output=True, text=True, check=False
    )
    if result.returncode:
        raise CheckError(result.stderr.strip() or f"git {' '.join(arguments)} failed")
    return result.stdout.strip()


def translate(pattern: str) -> str:
    regex = []
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "*":
            if pattern.startswith("**", index):
                index += 2
                if regex and regex[-1] == "/" and pattern.startswith("/", index):
                    regex.pop()
                    regex.append("(?:/.*)?/")
                    index += 1
                else:
                    regex.append(".*")
                continue
            regex.append("[^/]*")
            index += 1
            continue
        if char == "?":
            regex.append("[^/]")
            index += 1
            continue
        if char == "[":
            end = pattern.find("]", index + 1)
            if end > index + 1:
                body = pattern[index + 1 : end].replace("\\", "\\\\")
                if body.startswith("!"):
                    body = f"^{body[1:]}"
                regex.append(f"[{body}]")
                index = end + 1
                continue
        regex.append(f"\\{char}" if char in GLOB_SPECIAL else char)
        index += 1
    return "".join(regex)


def matches(pattern: str, path: str) -> bool:
    pattern = pattern.strip()
    while pattern.startswith("./"):
        pattern = pattern[2:]
    pattern = pattern.rstrip("/")
    if not pattern or not path:
        return False
    if re.fullmatch(translate(pattern), path):
        return True
    if not any(char in pattern for char in "*?["):
        return path.startswith(f"{pattern}/")
    if pattern.endswith("/**"):
        return re.fullmatch(translate(pattern[:-3]), path) is not None
    return False


def validate_profile(policy: object, repo: Path) -> tuple[str, ...] | None:
    if not isinstance(policy, dict):
        raise CheckError(f"base {POLICY_PATH} must contain a JSON object")
    if "branchPolicy" not in policy:
        return None
    value = policy["branchPolicy"]
    if not isinstance(value, dict):
        raise CheckError("base branchPolicy is not an object; refusing ambiguous policy")
    if value.get("profile") != PROFILE:
        raise CheckError(f"base branchPolicy profile is not {PROFILE!r}")
    allowed = {"profile", "integrationBranch", "stableBranch", "protectedPaths"}
    if set(value) - allowed:
        raise CheckError("base branchPolicy has unknown fields")
    integration = value.get("integrationBranch")
    stable = value.get("stableBranch")
    if (
        not isinstance(integration, str)
        or not isinstance(stable, str)
        or not integration
        or not stable
        or integration == stable
    ):
        raise CheckError("base branchPolicy has invalid or equal integration/stable branches")
    for name in (integration, stable):
        checked = subprocess.run(
            ["git", "-C", str(repo), "check-ref-format", "--branch", name],
            capture_output=True,
            text=True,
            check=False,
        )
        if checked.returncode != 0:
            raise CheckError(f"base branchPolicy has unsafe branch name {name!r}")
    paths = value.get("protectedPaths")
    if not isinstance(paths, list) or any(not isinstance(item, str) or not item.strip() for item in paths):
        raise CheckError("base branchPolicy.protectedPaths is not a list of non-empty patterns")
    if any(path.startswith("/") or ".." in Path(path).parts for path in paths):
        raise CheckError("base branchPolicy.protectedPaths contains a non-relative path")
    try:
        for pattern in paths:
            matches(pattern, "")
    except re.error as exc:
        raise CheckError(f"base branchPolicy.protectedPaths contains an invalid pattern: {exc}") from exc
    if any(not any(matches(pattern, target) for pattern in paths) for target in REQUIRED_PATHS):
        raise CheckError("base branchPolicy.protectedPaths does not protect every policy/checker/guard/workflow dependency")
    return tuple(paths)


def verify_ref(repo: Path, reference: str, expected: str, label: str) -> None:
    try:
        resolved = git(repo, "rev-parse", "--verify", f"{reference}^{{commit}}")
    except CheckError as exc:
        raise CheckError(f"{label} ref {reference!r} is unavailable; required commit is missing from checkout: {exc}") from exc
    if resolved != expected:
        raise CheckError(f"{label} ref {reference!r} resolves to {resolved}, not the supplied {label} SHA")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path, help="checkout whose proposed tree is inspected as data")
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--base-branch", required=True)
    parser.add_argument("--pr-number", required=True, type=int)
    parser.add_argument("--base-ref", required=True)
    parser.add_argument("--head-ref", required=True)
    args = parser.parse_args(argv)
    repo = args.repo.resolve()

    try:
        if not SHA.fullmatch(args.base_sha) or not SHA.fullmatch(args.head_sha):
            raise CheckError("base/head must be full commit SHAs")
        if (
            not args.base_branch
            or args.pr_number < 1
            or args.base_ref != f"refs/remotes/origin/{args.base_branch}"
            or args.head_ref != f"refs/pull/{args.pr_number}/head"
        ):
            raise CheckError("base/head refs do not match the supplied pull-request base branch and PR number")
        branch_check = subprocess.run(
            ["git", "-C", str(repo), "check-ref-format", "--branch", args.base_branch],
            capture_output=True,
            text=True,
            check=False,
        )
        if branch_check.returncode:
            raise CheckError("supplied pull-request base branch is not a valid Git branch name")
        verify_ref(repo, args.base_ref, args.base_sha, "base")
        verify_ref(repo, args.head_ref, args.head_sha, "head")
        base_policy_text = git(repo, "show", f"{args.base_sha}:{POLICY_PATH}")
        try:
            base_policy = json.loads(base_policy_text)
        except json.JSONDecodeError as exc:
            raise CheckError(f"base policy is invalid JSON: {exc}") from exc
        protected = validate_profile(base_policy, repo)
        if protected is None:
            print("SKIP base policy has no branchPolicy; existing repository rules apply")
            return 0
        try:
            diff = subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "diff",
                    "--name-only",
                    "--no-renames",
                    "-z",
                    f"{args.base_ref}...{args.head_ref}",
                ],
                capture_output=True,
                check=False,
            )
            if diff.returncode:
                raise CheckError(diff.stderr.decode("utf-8", errors="replace").strip() or "git diff failed")
            changed = [path.decode("utf-8", errors="strict") for path in diff.stdout.split(b"\0") if path]
        except CheckError as exc:
            raise CheckError(
                f"cannot compare base/head refs; required merge-base history may be missing: {exc}"
            ) from exc
    except (OSError, UnicodeError, CheckError) as exc:
        print(f"FAIL trusted branch-policy check: {exc}")
        return 1

    blocked = [path for path in changed if any(matches(pattern, path) for pattern in protected)]
    if blocked:
        for path in blocked:
            print(f"FAIL {path}: protected by base branchPolicy; proposed changes cannot authorize their own maintenance")
        print(f"\n{len(blocked)} protected path(s) changed.")
        return 1
    print(f"PASS trusted base branchPolicy; checked {len(changed)} proposed path(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
