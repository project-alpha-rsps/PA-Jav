"""Fail-closed helpers for the opt-in Project Alpha branch policy."""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

from repo_policy import load

FULL_SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
BUILTIN_GIT_COMMANDS = {
    "add", "am", "annotate", "apply", "archive", "bisect", "blame", "branch",
    "bundle", "cat-file", "check-attr", "check-ignore", "check-ref-format", "checkout",
    "cherry", "cherry-pick", "clean", "clone", "commit", "config", "describe", "diff",
    "fetch", "format-patch", "gc", "grep", "help", "init", "log", "ls-files",
    "ls-remote", "merge", "merge-base", "mv", "notes", "pull", "push", "range-diff",
    "rebase", "reflog", "remote", "repack", "replace", "reset", "restore", "revert",
    "rev-list", "rev-parse", "rm", "show", "show-ref", "sparse-checkout", "stash",
    "status", "submodule", "switch", "symbolic-ref", "tag", "update-ref", "version",
    "worktree", "write-tree",
}
KNOWN_GH_GROUPS = {
    "api", "auth", "browse", "cache", "codespace", "config", "extension", "gist",
    "gpg-key", "issue", "org", "pr", "project", "release", "repo", "run", "search",
    "secret", "ssh-key", "status", "variable", "workflow",
}


def configured(hooks_dir: Path | str):
    hooks_dir = Path(hooks_dir)
    return load(hooks_dir).branch_policy


def deny_push(arguments: list[str], cwd: str | None, hooks_dir: Path) -> str | None:
    """Return a refusal for pushes into shared branches under the strict profile."""
    policy = configured(_hooks_for(cwd, hooks_dir))
    if policy is None:
        return None
    if cwd is None:
        return (
            "branchPolicy cannot bind this push to a repository directory. Allowed next step: run "
            "the explicit origin/topic or stable refspec from the checked-out repository root, "
            "without a shell wrapper or alternate Git directory."
        )

    from git_command import parse

    flags, longs, operands = parse(arguments, "o", {"--repo", "--receive-pack", "--exec"})
    if "f" in flags or "--force" in longs or "--force-with-lease" in longs:
        return (
            "force-pushing rewrites published history. Allowed next step: fetch, integrate without "
            "force, and use a reviewed PR or the documented exact-SHA fast-forward promotion."
        )
    allowed_flags = {"u"}
    allowed_longs = {"--set-upstream", "--verbose", "--quiet", "--progress", "--porcelain"}
    if flags - allowed_flags or longs - allowed_longs:
        return (
            "branchPolicy cannot safely interpret this push option form. Allowed next step: use "
            "`git push -u origin <topic-branch>` for topic work, or the documented explicit "
            "full-SHA stable refspec; do not use wildcard, matching, tag, mirror or push-option forms."
        )
    if len(operands) < 2:
        return (
            "branchPolicy requires an explicit origin and one refspec. Allowed next step: use "
            "`git push -u origin <topic-branch>` or the documented exact-SHA stable refspec."
        )
    remote, *refspecs = operands
    if remote != "origin" or len(refspecs) != 1:
        return (
            "branchPolicy requires one refspec to the repository's origin; alternate remotes and "
            "multi-ref pushes are ambiguous. Allowed next step: push one topic ref to origin or "
            "use the documented exact-SHA stable refspec."
        )
    integration = f"refs/heads/{policy['integrationBranch']}"
    stable = f"refs/heads/{policy['stableBranch']}"
    refspec = refspecs[0]
    source, separator, destination = refspec.partition(":")
    if separator and (not source or not destination or ":" in destination):
        return (
            "branchPolicy refuses deletion and malformed refspecs. Allowed next step: use one "
            "non-empty source and destination through the reviewed topic flow."
        )
    if not separator:
        source = destination = refspec
        if source == "HEAD":
            current_branch = subprocess.run(
                ["git", "-C", cwd, "branch", "--show-current"],
                capture_output=True,
                text=True,
                check=False,
            )
            if current_branch.returncode != 0 or not current_branch.stdout.strip():
                return (
                    "branchPolicy cannot resolve the destination of bare HEAD. Allowed next step: "
                    "push one explicit topic refspec, or use the documented full-SHA stable refspec."
                )
            destination = current_branch.stdout.strip()
    if not source or not destination or any(char in refspec for char in "*?[]") or refspec.startswith(("+", "-")):
        return (
            "branchPolicy refuses wildcard, matching, forced or ambiguous refspecs. Allowed next "
            "step: use one concrete topic branch name, or the documented full-SHA stable refspec."
        )
    if destination.startswith("heads/"):
        return (
            "branchPolicy refuses abbreviated `heads/` destinations because their remote ref "
            "resolution is ambiguous. Allowed next step: use `refs/heads/<topic>` or the canonical "
            "stable refspec."
        )
    if destination.startswith("refs/"):
        if not destination.startswith("refs/heads/"):
            return "branchPolicy permits branch refs only. Allowed next step: push a topic branch or use the documented stable promotion refspec."
        target = destination.removeprefix("refs/heads/")
    else:
        target = destination
    if not _safe_branch(target):
        return "branchPolicy refuses an invalid destination ref. Allowed next step: use one valid topic branch name or the documented stable refspec."
    if target == policy["integrationBranch"]:
        return (
            "direct pushes to integration are prohibited. Allowed next step: open a reviewed squash "
            "PR to integration and bind the current head."
        )
    if target != policy["stableBranch"]:
        return None

    if not separator or not FULL_SHA.fullmatch(source):
        return (
            "stable promotion requires an explicit full immutable commit SHA and destination. "
            "Allowed next step: fetch both refs and use `<full-sha>:refs/heads/<stable>`."
        )

    integration_ref = f"refs/remotes/{remote}/{policy['integrationBranch']}"
    stable_ref = f"refs/remotes/{remote}/{policy['stableBranch']}"
    try:
        subprocess.run(
            ["git", "-C", cwd, "fetch", "--no-tags", remote, f"{integration}:{integration_ref}", f"{stable}:{stable_ref}"],
            check=True,
            capture_output=True,
            text=True,
        )
        candidate = subprocess.run(
            ["git", "-C", cwd, "rev-parse", "--verify", f"{source}^{{commit}}"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        if candidate != source:
            raise ValueError("candidate SHA did not resolve to the exact commit")
        subprocess.run(
            ["git", "-C", cwd, "merge-base", "--is-ancestor", candidate, integration_ref],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", cwd, "merge-base", "--is-ancestor", stable_ref, candidate],
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError, ValueError):
        return (
            "candidate must be a full SHA reachable from freshly fetched integration, with fetched "
            "stable as its ancestor; remote refs or ancestry could not be verified. Allowed next "
            "step: inspect both refs and choose a reachable tested candidate; do not force or retry "
            "an ambiguous promotion."
        )
    return None


def _safe_branch(value: str) -> bool:
    return bool(value) and not (
        value.startswith(("-", "/"))
        or value.endswith(("/", "."))
        or "//" in value
        or ".." in value
        or "@{" in value
        or value == "@"
        or any(char in value for char in " ~^:?*[\\")
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
        or any(part.startswith(".") or part.endswith(".lock") for part in value.split("/"))
    )


def deny_git_alias(subcommand: str, cwd: str | None, hooks_dir: Path | str) -> str | None:
    """Refuse Git aliases under the profile so aliases cannot hide mutations."""
    fallback = Path(hooks_dir)
    policy = configured(_hooks_for(cwd, fallback))
    if policy is None:
        return None
    if not subcommand:
        return "branchPolicy cannot resolve a Git subcommand. Allowed next step: use a literal Git command."
    if subcommand in BUILTIN_GIT_COMMANDS:
        return None
    if cwd is None:
        return (
            "branchPolicy cannot bind an unknown Git command to its alias configuration. Allowed next "
            "step: run the literal Git subcommand from the checked-out repository without wrappers."
        )
    result = subprocess.run(
        ["git", "-C", cwd, "config", "--get", f"alias.{subcommand}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode == 0:
        return (
            f"branchPolicy refuses Git alias `{subcommand}` because its effects cannot be bound to "
            "the shared-ref rules. Allowed next step: invoke the literal documented Git command "
            "from the verified repository context."
        )
    if result.returncode != 1:
        return (
            "branchPolicy could not read the Git alias configuration safely. Allowed next step: "
            "inspect the repository configuration and use a literal Git command."
        )
    return None


def deny_gh_alias(words: list[str], cwd: str | None, hooks_dir: Path | str) -> str | None:
    """Refuse GH CLI aliases that could hide the repository or merge operation."""
    policy = configured(_hooks_for(cwd, Path(hooks_dir)))
    if policy is None:
        return None
    group = words[0] if words else ""
    if group == "alias":
        return (
            "branchPolicy does not allow GH CLI aliases because they can hide repository context "
            "and mutation commands. Allowed next step: use the explicit built-in `gh pr`, `gh repo` "
            "or read-only command and let the hook inspect it."
        )
    if group not in KNOWN_GH_GROUPS:
        return (
            f"branchPolicy cannot inspect unknown GH command/alias `{group}` safely. Allowed next "
            "step: use an explicit built-in `gh` command from the repository's origin context."
        )
    return None


def deny_local_history(
    subcommand: str, arguments: list[str], cwd: str | None, hooks_dir: Path
) -> str | None:
    """Deny local history changes while integration or stable is checked out."""
    guarded = {
        "am", "branch", "cherry-pick", "commit", "merge", "pull", "rebase",
        "reset", "revert", "update-ref",
    }
    if subcommand not in guarded:
        return None
    policy = configured(_hooks_for(cwd, hooks_dir))
    if policy is None:
        return None
    if cwd is None:
        return (
            "branchPolicy cannot bind this local history operation to a repository and branch. "
            "Allowed next step: run it directly from a checked-out repository or with a literal "
            "`git -C <path>` target; do not use an unresolved wrapper."
        )
    from git_command import parse

    shared_refs = {
        policy["integrationBranch"],
        policy["stableBranch"],
        f"refs/heads/{policy['integrationBranch']}",
        f"refs/heads/{policy['stableBranch']}",
    }
    if subcommand == "branch":
        flags, longs, operands = parse(arguments, "uUt", {"--set-upstream-to", "--sort"})
        force_update = "f" in flags or "--force" in longs
        targets = operands[1:] if operands and operands[0] in ("-f", "--force") else operands
        if force_update and shared_refs.intersection(targets):
            return (
                "branchPolicy refuses moving a local shared-branch ref directly. Allowed next step: "
                "use a feature branch and reviewed PR; stable promotion uses the exact-SHA fast-forward flow."
            )
        return None
    if subcommand == "update-ref":
        return (
            "branchPolicy refuses raw update-ref commands because their ref effects are ambiguous. "
            "Allowed next step: update through the reviewed integration PR or exact-SHA promotion route."
        )
    branch = subprocess.run(
        ["git", "-C", cwd, "branch", "--show-current"],
        capture_output=True,
        text=True,
        check=False,
    )
    if branch.returncode != 0:
        return (
            "branchPolicy cannot determine the current branch safely. Allowed next step: verify "
            "the repository and use a feature branch; do not modify shared history."
        )
    current = branch.stdout.strip()
    if current not in (policy["integrationBranch"], policy["stableBranch"]):
        return None
    return (
        f"branchPolicy forbids local {subcommand} history changes on shared branch `{current}`. "
        "Allowed next step: do feature work on a topic branch from integration and use a reviewed "
        "squash PR; stable advances only by the documented exact-SHA fast-forward promotion."
    )


def deny_pr_merge(arguments: list[str], cwd: str | None, hooks_dir: Path) -> str | None:
    """Bind an integration merge to the actual open PR and its reviewed head."""
    if cwd is None:
        if configured(hooks_dir) is None:
            return None
        return (
            "branchPolicy cannot bind this merge to a working repository directory. Allowed next "
            "step: run `gh pr merge` directly from the checked-out repository without wrappers."
        )
    hooks_dir = _hooks_for(cwd, hooks_dir)
    policy = configured(hooks_dir)
    if policy is None:
        return None
    if any(
        token in ("-R", "--repo", "-H", "--hostname")
        or token.startswith(("-R", "--repo=", "-H", "--hostname="))
        for token in arguments
    ):
        return (
            "branchPolicy requires the current checked-out repository; explicit gh repository "
            "overrides are ambiguous. Allowed next step: run the merge from the current repository "
            "without -R/--repo and inspect its attached PR."
        )
    if any(
        token in ("--delete-branch", "--auto")
        or token.startswith(("--delete-branch=", "--auto="))
        for token in arguments
    ):
        return (
            "branchPolicy does not allow automatic merge scheduling or branch deletion. Allowed "
            "next step: use an ordinary current-head reviewed PR merge without --auto or "
            "--delete-branch, and retain the source ref."
        )
    try:
        repository = _github_repository_from_origin(cwd)
        requested_repo = os.environ.get("GH_REPO")
        requested_host = os.environ.get("GH_HOST")
        if requested_repo and requested_repo.casefold() != repository.casefold():
            raise ValueError("GH_REPO does not match the checkout's origin")
        if requested_host and requested_host.casefold() != "github.com":
            raise ValueError("GH_HOST does not identify github.com")
        head = subprocess.run(
            ["git", "rev-parse", "--verify", "HEAD"],
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        branch = subprocess.run(
            ["git", "branch", "--show-current"],
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        if not branch:
            raise ValueError("checkout has no current local branch")
        repository = subprocess.run(
            ["gh", "repo", "view", repository, "--json", "nameWithOwner", "--jq", ".nameWithOwner"],
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        view = subprocess.run(
            ["gh", "pr", "view", branch, "--repo", repository, "--json", "number,baseRefName,headRefName,headRefOid,headRepository,state"],
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        metadata = json.loads(view)
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError, ValueError):
        return (
            "branchPolicy cannot bind this merge to an unambiguous current pull request and head. "
            "Allowed next step: inspect the open PR from its checked-out source branch and retry "
            "only after repository, base and full head SHA are confirmed."
        )
    head_repo = (metadata.get("headRepository") or {}).get("nameWithOwner")
    if (
        metadata.get("state") != "OPEN"
        or head_repo != repository
        or metadata.get("headRefName") != branch
        or metadata.get("headRefOid") != head
    ):
        return (
            "branchPolicy requires this repository's open PR with the current checked-out source "
            "branch and exact head SHA. Allowed next step: check out the PR source, fetch its head, "
            "and inspect the actual repository metadata before retrying."
        )
    from git_command import parse

    _, long_options, operands = parse(arguments, "", {"--match-head-commit", "--subject", "--body", "--body-file"})
    # `gh pr merge [<number>|<url>]`; an explicit target must be the actual PR
    # attached to this checked-out source branch.
    targets = [word for word in operands if word not in ("pr", "merge")]
    target_numbers = [word for word in targets if word.isdigit()]
    if len(targets) > 1 or any(not word.isdigit() for word in targets) or (
        target_numbers and any(number != str(metadata.get("number")) for number in target_numbers)
    ):
        return (
            "branchPolicy refuses a guessed or mismatched PR number. Allowed next step: omit the "
            "number to use the PR attached to this branch, then inspect the metadata and head."
        )
    match_head = ""
    for index, option in enumerate(arguments):
        if option == "--match-head-commit" and index + 1 < len(arguments):
            match_head = arguments[index + 1]
        elif option.startswith("--match-head-commit="):
            match_head = option.partition("=")[2]
    if match_head != head:
        return (
            "branchPolicy requires gh pr merge --match-head-commit bound to the actual full PR "
            "head SHA. Allowed next step: collect the current head SHA and pass it explicitly."
        )
    base = metadata.get("baseRefName")
    if base == policy["stableBranch"]:
        return (
            "all pull-request merge strategies into stable are prohibited. Allowed next step: use "
            "the documented exact-SHA non-force fast-forward promotion from integration."
        )
    if base != policy["integrationBranch"]:
        return (
            "branchPolicy permits routine feature pull requests only into integration. Allowed next "
            "step: retarget the reviewed PR to integration and rerun its checks."
        )
    if "--squash" not in arguments or any(
        option in arguments for option in ("--rebase", "--merge", "--admin")
    ):
        return (
            "feature integration requires a reviewed squash PR. Allowed next step: rerun the "
            "current-head checks and merge that PR with --squash only."
        )
    return None


def _hooks_for(cwd: str | None, fallback: Path | str) -> Path:
    if cwd is None:
        return Path(fallback)
    result = subprocess.run(
        ["git", "-C", cwd, "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return fallback
    target_hooks = Path(result.stdout.strip()) / ".claude" / "hooks"
    if os.environ.get("MULTICA_POLICY_DIR") or (target_hooks / "policy.json").is_file():
        return target_hooks
    # A separate scratch checkout without a policy inherits the hook's runtime
    # policy. The active checkout still returns its own missing path, so load()
    # fails closed rather than interpreting a broken installation as disabled.
    return Path(fallback)


def _github_repository_from_origin(cwd: str) -> str:
    result = subprocess.run(
        ["git", "-C", cwd, "remote", "get-url", "origin"],
        capture_output=True,
        text=True,
        check=True,
    )
    url = result.stdout.strip()
    match = re.fullmatch(
        r"(?:https://github\.com/|ssh://git@github\.com/|git@github\.com:)([^/]+/[^/]+?)(?:\.git)?",
        url,
        flags=re.IGNORECASE,
    )
    if not match:
        raise ValueError("origin is not a canonical github.com owner/repository URL")
    return match.group(1)
