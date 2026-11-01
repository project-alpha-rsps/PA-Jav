#!/usr/bin/env python3
"""Behavioural tests for this repository's agent safety hooks.

The generic half of this file is template scaffolding: it exercises every hook
in `repo-policy` against *this* repository's `.claude/hooks/policy.json`, so the
suite is meaningful without being rewritten. Add repository-specific tests below
the marker at the end and register them in `main`.

Run it before committing a hook or policy change:

    python3 scripts/test-agent-hooks.py

Exit 0 means every case held. Any failure raises `AssertionError` naming the
hook, the payload and what came back.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / ".claude" / "hooks"
LIB = HOOKS / "lib"
TESTS = 0
SKIPPED: list[str] = []

# Importing from LIB writes .claude/hooks/lib/__pycache__ unless this is set
# before the first import. A Lead who then stages everything commits compiled
# bytecode: that is how twenty .pyc files reached four repositories. The
# .gitignore beside the library is the second line of defence; this is the
# first, and it also keeps the tree clean for `git status`.
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

sys.path.insert(0, str(LIB))

from repo_policy import Policy, PolicyError, load  # noqa: E402


# --------------------------------------------------------------------------
# Harness
# --------------------------------------------------------------------------


def assert_refusal_hint(message: str) -> None:
    """Every exercised denial must carry a concrete, compliant corrective step."""
    assert "Allowed next step: " in message, f"refusal has no next-step hint:\n{message}"
    # Check the corrective action, not just a label appended to an old refusal.
    # Multiple reasons may occur in a commentary refusal; each must carry its hint.
    routes = {
        "hook library is missing": "report the broken hook installation for reviewed repair",
        "internal hook failure": "report the hook failure for reviewed repair",
        "hook input was not valid JSON": "submit a valid tool payload",
        "tool_input was not an object": "submit tool_input as an object",
        "Bash command was not text": "submit the permitted command as a text string",
        "policy load failure": "do not narrow policy slots",
        "cannot safely resolve dynamic executable": "name the permitted executable literally",
        "cannot safely resolve brace-expanded executable": "name one permitted executable literally",
        "could not parse Bash command safely": "correct the shell syntax of a permitted command",
        "env --split-string cannot be inspected safely": "write a permitted command with literal arguments",
        "cannot inspect `": "submit a plainly inspectable permitted command",
        "blocked cluster CLI": "no agent route exists here to execute the blocked CLI",
        "no agent route to run this executable here": "report the unmet need",
        "bypasses the pre-commit gate": "fix what the hook reports instead of skipping it",
        "force-pushing": "fetch the default branch, integrate without force",
        "deletes that ref": "explicit nonempty source and destination",
        "deletes untracked files": "remove only specific paths you own",
        "discards uncommitted work": "preserve your work in a commit",
        "discards every uncommitted change": "make a targeted forward edit",
        "one stash stack": "temporary WIP commit",
        "another session's entry": "git stash apply <sha>",
        "rewrites every commit": "make a forward fix in a new commit",
        "mutates GitHub directly": "reviewed pull request",
        "destroys the repository": "no agent route exists for repository deletion",
        "destroys a published artifact": "no agent route exists for release deletion",
        "Actions secrets outside Git review": "without exposing its value",
        "mutates CI outside review": "let its configured event trigger CI",
        "branch protection rules": "never override it",
        "session's GitHub credentials": "gh auth status",
        "attribution line in the command text": "Drop that trailer or line",
        "reads the message from stdin": "write a clean message to a readable file",
        "reads the body from stdin": "write a clean body to a readable file",
        "without an explicit body": "otherwise hand the PR to its merging owner",
        "adds task identifier": "remove the task identifier from the proposed content",
        "adds a comment": "remove the added rationale comment",
        "Without the session history": "restore a readable session transcript",
        "was written after the last validation": "fix any failures, then commit",
        "no `git fetch`": "never a prohibited direct mainline push",
        "no probity.config.ts": "report the missing merged policy for reviewed repair",
        "`probity` was not found": "repository's documented dependency setup",
        "session transcript could not be read": "retry the commit only after",
        "no AI validator available": "retry the commit only after",
        "unrelated hunks": "leave unrelated work intact for its owner",
    }
    for reason, route in routes.items():
        if reason.casefold() in message.casefold():
            assert route.casefold() in message.casefold(), (
                f"{reason!r} missing corrective action {route!r}:\n{message}"
            )


def run_hook(
    hook: str,
    payload: dict[str, object] | str,
    expected: int,
    *messages: str,
    hooks_dir: Path = HOOKS,
    project_dir: Path = ROOT,
    silent: bool = False,
    env: dict[str, str] | None = None,
) -> None:
    global TESTS
    hook_input = payload if isinstance(payload, str) else json.dumps(payload)
    env = {**os.environ, "CLAUDE_PROJECT_DIR": str(project_dir), **(env or {})}
    env.pop("MULTICA_POLICY_DIR", None)
    result = subprocess.run(
        [str(hooks_dir / hook)],
        input=hook_input,
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )
    if result.returncode != expected:
        raise AssertionError(
            f"{hook}: expected exit {expected}, got {result.returncode}\n"
            f"payload: {hook_input[:400]}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    for message in messages:
        if message not in result.stderr:
            raise AssertionError(f"{hook}: missing {message!r} in stderr:\n{result.stderr}")
    if expected == 2:
        assert_refusal_hint(result.stderr)
    if silent and result.stderr.strip():
        raise AssertionError(f"{hook}: expected no advisory, got:\n{result.stderr}")
    TESTS += 1


def bash(command: str) -> dict[str, object]:
    return {"tool_name": "Bash", "tool_input": {"command": command}}


def write(path: Path, content: str) -> dict[str, object]:
    return {"tool_name": "Write", "tool_input": {"file_path": str(path), "content": content}}


def tracked_files() -> list[str]:
    try:
        out = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files", "-z"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return []
    return [entry for entry in out.split("\0") if entry]


def transcript(directory: Path, *entries: dict[str, object]) -> str:
    path = directory / "transcript.jsonl"
    path.write_text(
        "".join(f"{json.dumps(entry)}\n" for entry in entries),
        encoding="utf-8",
    )
    return str(path)


def assistant(*tool_uses: tuple[str, dict[str, object]]) -> dict[str, object]:
    return {
        "type": "assistant",
        "message": {
            "content": [
                {"type": "tool_use", "name": name, "input": tool_input}
                for name, tool_input in tool_uses
            ]
        },
    }


# --------------------------------------------------------------------------
# Generic cases — every repository that adopts repo-policy runs these
# --------------------------------------------------------------------------


def test_policy_loads() -> Policy:
    global TESTS
    policy = load(HOOKS)
    assert policy.repository.strip(), "policy.json `repository` is still the placeholder or empty"
    assert not policy.repository.startswith("REPLACE ME"), "policy.json `repository` is unfilled"
    TESTS += 1
    return policy


def test_policy_fails_closed() -> None:
    """A hook whose policy is missing or malformed denies rather than allows."""
    with tempfile.TemporaryDirectory() as raw:
        broken = Path(raw) / "hooks"
        shutil.copytree(HOOKS, broken)
        (broken / "policy.json").write_text("{ not json", encoding="utf-8")
        run_hook("block-runtime.sh", bash("echo hi"), 2, "not valid JSON", hooks_dir=broken)
        (broken / "policy.json").unlink()
        run_hook("block-runtime.sh", bash("echo hi"), 2, "policy.json", hooks_dir=broken)
        run_hook(
            "block-config-commentary.sh",
            write(broken / "policy.json", "text\n"),
            2,
            "policy.json",
            hooks_dir=broken,
        )


def test_refusal_hints_on_failure_paths() -> None:
    """Exercise infrastructure failures as well as the ordinary policy denials."""
    bash_hooks = (
        "block-runtime.sh", "block-git-unsafe.sh", "block-gh-unsafe.sh",
        "block-attribution.sh", "require-validation-before-git.sh",
    )
    for hook in (*bash_hooks, "block-config-commentary.sh"):
        run_hook(hook, "not json", 2, "submit a valid tool payload")
        run_hook(hook, {"tool_input": ["invalid"]}, 2, "submit tool_input as an object")
    for hook in bash_hooks:
        run_hook(hook, {"tool_input": {"command": ["invalid"]}}, 2, "as a text string")

    with tempfile.TemporaryDirectory() as raw:
        directory = Path(raw)
        broken = directory / "hooks"
        shutil.copytree(HOOKS, broken)
        shutil.rmtree(broken / "lib")
        for hook in (*bash_hooks, "block-config-commentary.sh"):
            run_hook(hook, bash("echo hi"), 2, "broken hook installation", hooks_dir=broken)
        (broken / "lib").mkdir()
        for hook in (*bash_hooks, "block-config-commentary.sh"):
            run_hook(hook, bash("echo hi"), 2, "internal hook failure", hooks_dir=broken)

    # A throwaway policy exercises the template's intentionally empty commentary
    # and validation slots without editing any adopter or weakening its gates.
    with tempfile.TemporaryDirectory() as raw:
        repo = Path(raw)
        _init_repo(repo)
        hooks = repo / ".claude" / "hooks"
        shutil.copytree(HOOKS, hooks)
        policy = json.loads((hooks / "policy.json").read_text(encoding="utf-8"))
        policy["comments"]["paths"] = ["**"]
        policy["comments"]["suffixes"] = [".md"]
        policy["comments"]["excludedPaths"] = []
        policy["comments"]["guidance"] = "Repository-specific guidance."
        policy["validation"] = {"commandPattern": "python3 validate.py", "hint": "python3 validate.py"}
        (hooks / "policy.json").write_text(json.dumps(policy), encoding="utf-8")
        fixture = repo / "tracked.md"
        fixture.write_text("tracked fixture\n", encoding="utf-8")
        subprocess.run(["git", "add", "tracked.md"], cwd=repo, check=True)
        run_hook(
            "block-config-commentary.sh", write(fixture, "# rationale\n" * 25),
            2, "and 5 more", "put change context in the pull request",
            hooks_dir=hooks, project_dir=repo,
        )
        stale = {"tool_name": "Edit", "tool_input": {
            "file_path": str(fixture), "old_string": "absent", "new_string": "new",
        }}
        run_hook("block-config-commentary.sh", stale, 2, "anchored to its actual text",
                 hooks_dir=hooks, project_dir=repo)
        run_hook("block-config-commentary.sh", write(fixture, ["not text"]),
                 2, "as a text string", hooks_dir=hooks, project_dir=repo)
        run_hook("block-config-commentary.sh", {
            "tool_name": "Other", "tool_input": {"file_path": str(fixture)},
        }, 2, "reviewable Write or Edit", hooks_dir=hooks, project_dir=repo)
        run_hook("require-validation-before-git.sh", bash("git commit -m x"),
                 2, "restore a readable session transcript", hooks_dir=hooks, project_dir=repo)
        history = transcript(repo, assistant(("Write", {
            "file_path": str(fixture), "content": "changed",
        })))
        run_hook("require-validation-before-git.sh", {
            **bash("git commit -m x"), "transcript_path": history,
        }, 2, "run python3 validate.py", "fix any failures, then commit",
                 hooks_dir=hooks, project_dir=repo)


def test_shell_grammar_is_not_a_command() -> None:
    """A clause that is only shell grammar resolves to no command.

    `split_clauses` breaks on `;`, so `mk(){ echo hi; }; mk` produces a clause
    that is just `}`. That used to be handed to the resolver as the executable
    and denied the whole command with "cannot safely resolve brace-expanded
    executable `}`" — a false positive on every shell function definition.
    """
    run_hook("block-runtime.sh", bash("mk(){ echo hi; }; mk"), 0, silent=True)
    run_hook("block-runtime.sh", bash("{ echo hi; }"), 0, silent=True)
    run_hook("block-runtime.sh", bash("if true; then echo hi; fi"), 0, silent=True)
    run_hook("block-runtime.sh", bash("for f in a b; do echo $f; done"), 0, silent=True)
    run_hook("block-runtime.sh", bash("case $x in a) echo hi ;; esac"), 0, silent=True)


def test_heredoc_inside_substitution_and_line_continuations() -> None:
    """A heredoc opened inside `$( … )`, and a `\\`-newline continuation.

    Claude Code's own commit idiom is `git commit -m "$(cat <<'EOF' … EOF\n)"`:
    the `"` that opens before `$(` used to stay open across the `<<`, so
    `strip_heredocs` never recognised the heredoc and the apostrophe in the
    commit body (data, not code) reached the tokeniser as an unterminated
    quote. A `\\`-newline continuation had the same "valid Bash refused"
    shape: unstripped, it joined two commands into one dynamic executable name
    that contained a literal newline.
    """
    commit_heredoc = (
        "git commit -m \"$(cat <<'EOF'\n"
        "feat(brave): configure Brave\n"
        "\n"
        "Brave's policy today's\n"
        "EOF\n"
        ')"'
    )
    for hook in ("block-git-unsafe.sh", "block-runtime.sh", "block-gh-unsafe.sh"):
        run_hook(hook, bash(commit_heredoc), 0, silent=True)

    # The heredoc body is data: a blocked-command name inside it must not deny.
    commit_heredoc_kubectl_body = (
        "git commit -m \"$(cat <<'EOF'\n"
        "kubectl delete ns x\n"
        "EOF\n"
        ')"'
    )
    run_hook("block-runtime.sh", bash(commit_heredoc_kubectl_body), 0, silent=True)

    # Negative case: an *unquoted*-delimiter heredoc outside any quoting still
    # has its expansions walked and denied. The fix above must not blunt that.
    unquoted_heredoc_expands = "cat <<EOF\n$(kubectl get x)\nEOF"
    run_hook("block-runtime.sh", bash(unquoted_heredoc_expands), 2, "kubectl")

    run_hook("block-runtime.sh", bash("\\\necho hi"), 0, silent=True)

    # Negative case: inside single quotes, a backslash is always literal, so
    # this stays a two-character executable name, not two joined commands.
    run_hook(
        "block-runtime.sh",
        bash("'\\\n'"),
        2,
        "cannot safely resolve dynamic executable",
    )


def test_block_runtime(policy: Policy) -> None:
    run_hook("block-runtime.sh", bash("git status"), 0, silent=True)
    run_hook("block-runtime.sh", bash(""), 0, silent=True)
    run_hook("block-runtime.sh", "not json", 2, "not valid JSON")
    if not policy.blocked_commands:
        SKIPPED.append("block-runtime: policy.json blocks no executables")
        return
    for name in policy.blocked_commands:
        run_hook("block-runtime.sh", bash(f"{name} --help"), 2, name)
        run_hook("block-runtime.sh", bash(f"/usr/bin/{name} --help"), 2, name)
        run_hook("block-runtime.sh", bash(f"bash -lc '{name} --help'"), 2, name)
        run_hook("block-runtime.sh", bash(f"true && {name} --help"), 2, name)
        # A heredoc body is data, not code.
        run_hook("block-runtime.sh", bash(f"cat > n.md <<'EOF'\ndo not run {name}\nEOF"), 0)
        # Skipping the grammar must not skip the command it wraps.
        run_hook("block-runtime.sh", bash(f"if true; then {name} --help; fi"), 2, name)
        run_hook("block-runtime.sh", bash(f"run(){{ {name} --help; }}; run"), 2, name)


def _init_repo(directory: Path) -> None:
    subprocess.run(["git", "init", "-q", "."], cwd=directory, check=True)
    subprocess.run(["git", "config", "user.email", "t@example.invalid"], cwd=directory, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=directory, check=True)
    (directory / "README.md").write_text("hi\n", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=directory, check=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=directory, check=True)
    subprocess.run(["git", "remote", "add", "origin", str(directory)], cwd=directory, check=True)


def test_block_git_unsafe() -> None:
    run_hook("block-git-unsafe.sh", bash("git status --short"), 0, silent=True)
    run_hook("block-git-unsafe.sh", bash("git commit -m 'fix'"), 0, silent=True)
    run_hook("block-git-unsafe.sh", bash("git commit --no-verify -m 'fix'"), 2, "--no-verify")
    run_hook("block-git-unsafe.sh", bash("git commit -n -m 'fix'"), 2, "--no-verify")
    run_hook("block-git-unsafe.sh", bash("git push --force origin HEAD"), 2, "force-pushing")
    run_hook("block-git-unsafe.sh", bash("git push --force-with-lease"), 2, "force-pushing")
    run_hook("block-git-unsafe.sh", bash("git push origin :main"), 2, "deletes that ref")
    run_hook("block-git-unsafe.sh", bash("git clean -fd"), 2, "deletes untracked files")
    run_hook("block-git-unsafe.sh", bash("git stash"), 2, "one stash stack")
    run_hook("block-git-unsafe.sh", bash("git stash pop"), 2, "another session's entry")
    run_hook("block-git-unsafe.sh", bash("git filter-branch --all"), 2, "rewrites every commit")
    run_hook("block-git-unsafe.sh", bash("bash -c 'git push --force'"), 2, "force-pushing")

    # `reset --hard`, `checkout .` and `restore .` are allowed on a clean
    # worktree and denied otherwise -- the harness's own checkout is clean in
    # CI, so these need a dedicated repository with an actual dirty or clean
    # tree to mean anything.
    with tempfile.TemporaryDirectory() as raw:
        repo = Path(raw)
        _init_repo(repo)

        # (converted) `reset --hard`/`checkout .` still deny on a dirty tree,
        # with the same message as before this change.
        (repo / "README.md").write_text("dirty\n", encoding="utf-8")
        run_hook(
            "block-git-unsafe.sh",
            bash("git reset --hard HEAD~1"),
            2,
            "discards uncommitted work",
            project_dir=repo,
        )
        run_hook(
            "block-git-unsafe.sh",
            bash("git checkout ."),
            2,
            "discards every uncommitted change",
            project_dir=repo,
        )
        subprocess.run(["git", "checkout", "--", "README.md"], cwd=repo, check=True)

        # (1) clean tree, discard to a resolvable ref -> allowed. The hook
        # only inspects the command; it never runs it.
        run_hook(
            "block-git-unsafe.sh",
            bash("git reset --hard origin/main"),
            0,
            silent=True,
            project_dir=repo,
        )

        # (2) clean tracked tree with an untracked file -> allowed, and the
        # hook must not have touched the tree (it never runs anything).
        scratch = repo / "scratch.txt"
        scratch.write_text("keep me\n", encoding="utf-8")
        run_hook(
            "block-git-unsafe.sh", bash("git checkout -- ."), 0, silent=True, project_dir=repo
        )
        if not scratch.exists():
            raise AssertionError("block-git-unsafe.sh: untracked scratch.txt did not survive")
        scratch.unlink()

        # (3) clean tree, `restore .` -> allowed.
        run_hook("block-git-unsafe.sh", bash("git restore ."), 0, silent=True, project_dir=repo)

        # (4) clean tree, a ref before `-- .` -> allowed.
        run_hook(
            "block-git-unsafe.sh",
            bash("git checkout -q origin/main -- ."),
            0,
            silent=True,
            project_dir=repo,
        )

        # (5) a staged-only change is not a clean tree -> denied.
        (repo / "README.md").write_text("staged\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=repo, check=True)
        run_hook(
            "block-git-unsafe.sh",
            bash("git reset --hard"),
            2,
            "discards uncommitted work",
            project_dir=repo,
        )
        subprocess.run(["git", "reset", "--hard", "HEAD"], cwd=repo, check=True)

        # (6) a `cd` to the checkout earlier in the same command overrides
        # the payload `cwd`, for both a clean and a dirty tree.
        run_hook(
            "block-git-unsafe.sh",
            {
                "tool_name": "Bash",
                "tool_input": {"command": f"cd {repo} && git reset --hard origin/main"},
                "cwd": str(repo.parent),
            },
            0,
            silent=True,
            project_dir=repo.parent,
        )
        (repo / "README.md").write_text("dirty again\n", encoding="utf-8")
        run_hook(
            "block-git-unsafe.sh",
            {
                "tool_name": "Bash",
                "tool_input": {"command": f"cd {repo} && git reset --hard origin/main"},
                "cwd": str(repo.parent),
            },
            2,
            "discards uncommitted work",
            project_dir=repo.parent,
        )
        subprocess.run(["git", "checkout", "--", "README.md"], cwd=repo, check=True)

        # (8) `git clean -fd` is unconditional, clean tree or not.
        run_hook(
            "block-git-unsafe.sh",
            bash("git clean -fd"),
            2,
            "deletes untracked files",
            project_dir=repo,
        )

        # (9) bare `git stash` is unconditional, clean tree or not.
        run_hook(
            "block-git-unsafe.sh", bash("git stash"), 2, "one stash stack", project_dir=repo
        )

    # (7) `cwd` not a Git checkout at all cannot show the tree is clean, so
    # it fails closed.
    with tempfile.TemporaryDirectory() as not_a_repo:
        run_hook(
            "block-git-unsafe.sh",
            bash("git reset --hard"),
            2,
            "discards uncommitted work",
            project_dir=Path(not_a_repo),
        )


def test_block_gh_unsafe() -> None:
    run_hook("block-gh-unsafe.sh", bash("gh pr list"), 0, silent=True)
    run_hook("block-gh-unsafe.sh", bash("gh api repos/shockstruck/x"), 0, silent=True)
    run_hook("block-gh-unsafe.sh", bash("gh auth status"), 0, silent=True)
    run_hook("block-gh-unsafe.sh", bash("gh api -X DELETE repos/shockstruck/x"), 2, "mutates GitHub")
    run_hook("block-gh-unsafe.sh", bash("gh api -X PATCH repos/shockstruck/x"), 2, "mutates GitHub")
    run_hook("block-gh-unsafe.sh", bash("gh secret set FOO"), 2, "Actions secrets")
    run_hook("block-gh-unsafe.sh", bash("gh repo delete shockstruck/x"), 2, "destroys the repository")
    run_hook("block-gh-unsafe.sh", bash("gh workflow run ci.yaml"), 2, "mutates CI")
    run_hook("block-gh-unsafe.sh", bash("gh pr merge 1 --admin"), 2, "branch protection")
    run_hook("block-gh-unsafe.sh", bash("gh auth token"), 2, "GitHub credentials")


def test_block_attribution() -> None:
    run_hook("block-attribution.sh", bash("ls"), 0, silent=True)
    run_hook("block-attribution.sh", bash("git status"), 0, silent=True)
    run_hook(
        "block-attribution.sh", bash('git commit -m "Add block-attribution hook"'), 0, silent=True
    )
    run_hook(
        "block-attribution.sh",
        bash('git commit -m "Register block-attribution in .claude/settings.json"'),
        0,
        silent=True,
    )
    run_hook(
        "block-attribution.sh",
        bash(
            'git commit -m "fix" -m "Co-Authored-By: Kevin Barbieri <kevin@example.org>"'
        ),
        0,
        silent=True,
        env={"GIT_AUTHOR_EMAIL": "junior@shockstruck.example"},
    )
    run_hook(
        "block-attribution.sh",
        bash('git commit -m "x" -m "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"'),
        2,
        "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>",
        "Drop that trailer or line from the message and re-run the same command without it.",
    )
    run_hook(
        "block-attribution.sh",
        bash('git commit -m "thanks to anything@example.org"'),
        2,
        "anything@example.org",
        env={"GIT_AUTHOR_EMAIL": "someone@example.org"},
    )
    run_hook("block-attribution.sh", bash("git commit -F -"), 2, "reads the message from stdin")
    run_hook(
        "block-attribution.sh",
        bash('git commit -m "fix" -m "Claude-Session: https://claude.ai/s/abc123"'),
        2,
        "Claude-Session: https://claude.ai/s/abc123",
    )
    run_hook(
        "block-attribution.sh",
        bash('gh pr create --title t --body "Co-authored-by: Platform GitOps Junior"'),
        2,
        "Co-authored-by: Platform GitOps Junior",
    )
    run_hook("block-attribution.sh", bash("gh pr create --draft"), 0, silent=True)
    run_hook(
        "block-attribution.sh",
        bash("gh pr edit 1 --body-file -"),
        2,
        "reads the body from stdin",
    )
    run_hook(
        "block-attribution.sh",
        bash("gh pr merge 12 --squash"),
        2,
        "without an explicit body",
        'gh pr merge <n> --squash --subject "<title> (#<n>)" --body "<body>"',
    )
    run_hook(
        "block-attribution.sh",
        bash("gh pr merge 12 --squash --auto"),
        2,
        "without an explicit body",
    )
    run_hook(
        "block-attribution.sh",
        bash('gh pr merge 12 --squash --subject "Add x (#12)" --body "Adds x."'),
        0,
        silent=True,
    )
    run_hook(
        "block-attribution.sh",
        bash(
            'gh pr merge 12 --squash --body "Co-authored-by: Claude <noreply@anthropic.com>"'
        ),
        2,
        "Co-authored-by: Claude <noreply@anthropic.com>",
    )
    run_hook(
        "block-attribution.sh",
        bash("gh pr merge 12 --squash --body-file -"),
        2,
        "reads the body from stdin",
    )
    run_hook("block-attribution.sh", bash("gh pr checks 12 --watch"), 0, silent=True)

    with tempfile.TemporaryDirectory() as raw:
        directory = Path(raw)
        clean = directory / "clean.txt"
        clean.write_text("Document .claude/settings.json changes\n", encoding="utf-8")
        run_hook(
            "block-attribution.sh",
            {
                "tool_name": "Bash",
                "tool_input": {"command": "git commit -F clean.txt"},
                "cwd": str(directory),
            },
            0,
            silent=True,
        )

        message = directory / "msg.txt"
        message.write_text(
            "\U0001F916 Generated with [Claude Code](https://claude.com/claude-code)\n",
            encoding="utf-8",
        )
        run_hook(
            "block-attribution.sh",
            {
                "tool_name": "Bash",
                "tool_input": {"command": "git commit -F msg.txt"},
                "cwd": str(directory),
            },
            2,
            "Generated",
            "Delete that trailer or line from the file, then re-run the same commit.",
        )

        run_hook(
            "block-attribution.sh",
            {
                "tool_name": "Bash",
                "tool_input": {"command": "git commit -F absent.txt"},
                "cwd": str(directory),
            },
            2,
            "`absent.txt` named by `-F`/`--file` could not be read",
            "Write the message file in its own call first, then re-run the commit naming it by "
            "an absolute path.",
        )

        body = directory / "body.txt"
        body.write_text("Signed-off-by: Resolver\n", encoding="utf-8")
        run_hook(
            "block-attribution.sh",
            {
                "tool_name": "Bash",
                "tool_input": {"command": "gh pr create --title t --body-file body.txt"},
                "cwd": str(directory),
            },
            2,
            "Signed-off-by: Resolver",
            "Delete that trailer or line from the file, then re-run the same command.",
        )

        run_hook(
            "block-attribution.sh",
            {
                "tool_name": "Bash",
                "tool_input": {"command": "gh pr create --title t --body-file absent.md"},
                "cwd": str(directory),
            },
            2,
            "`absent.md` named by `--body-file` could not be read",
            "Write the body file in its own call first, then re-run the command naming it by an "
            "absolute path.",
        )

    # A relative `--body-file`/`-F` after a `cd` in the same command names a
    # path under the `cd` target, not under the payload cwd.
    with tempfile.TemporaryDirectory() as raw:
        directory = Path(raw)
        (directory / "x").mkdir()
        (directory / "b.md").write_text("Adds x.\n", encoding="utf-8")
        for command in (
            "cd x && gh pr create --title t --body-file ../b.md",
            "cd x && gh pr edit 1 -F ../b.md",
            'cd x && gh pr merge 1 --squash --subject "x (#1)" --body-file ../b.md',
        ):
            run_hook(
                "block-attribution.sh",
                {"tool_name": "Bash", "tool_input": {"command": command}, "cwd": str(directory)},
                0,
                silent=True,
            )
        (directory / "b.md").write_text("Signed-off-by: Resolver\n", encoding="utf-8")
        run_hook(
            "block-attribution.sh",
            {
                "tool_name": "Bash",
                "tool_input": {"command": "cd x && gh pr create --title t --body-file ../b.md"},
                "cwd": str(directory),
            },
            2,
            "attribution line in `../b.md`: `Signed-off-by: Resolver`",
        )
        run_hook(
            "block-attribution.sh",
            {
                "tool_name": "Bash",
                "tool_input": {"command": "cd x && gh pr create --title t --body-file b.md"},
                "cwd": str(directory),
            },
            2,
            "`b.md` named by `--body-file` could not be read",
        )

    with tempfile.TemporaryDirectory() as raw:
        broken = Path(raw) / "hooks"
        shutil.copytree(HOOKS, broken)
        (broken / "policy.json").unlink()
        run_hook("block-attribution.sh", bash("git commit -m x"), 2, "policy.json", hooks_dir=broken)


def test_block_config_commentary(policy: Policy) -> None:
    files = tracked_files()
    if not files:
        SKIPPED.append("block-config-commentary: git could not list tracked files")
        return

    identifier_target = next((f for f in files if policy.checks_task_identifiers(f)), None)
    if identifier_target and policy.task_prefixes:
        path = ROOT / identifier_target
        existing = path.read_text(encoding="utf-8", errors="replace")
        run_hook("block-config-commentary.sh", write(path, existing), 0, silent=True)
        # (8) A tracked file adding an identifier is still denied.
        run_hook(
            "block-config-commentary.sh",
            write(path, f"{existing}\n{policy.task_prefixes[0]}-1234\n"),
            2,
            "task identifier",
        )
        # (7) The same identifier in a file the index does not carry yet is
        # not the hook's business: it is not the committed config the rule
        # protects. `path.parent` keeps the same taskIdentifiers.paths scope
        # `identifier_target` matched.
        scratch = path.parent / "delegation.md"
        if scratch.relative_to(ROOT).as_posix() not in files:
            run_hook(
                "block-config-commentary.sh",
                write(scratch, f"work item {policy.task_prefixes[0]}-123 needs doing\n"),
                0,
                silent=True,
            )
    else:
        SKIPPED.append("block-config-commentary: no tracked file in taskIdentifiers.paths")

    comment_target = next((f for f in files if policy.checks_comments(f)), None)
    if comment_target:
        path = ROOT / comment_target
        existing = path.read_text(encoding="utf-8", errors="replace")
        run_hook(
            "block-config-commentary.sh",
            write(path, f"{existing}\n# why this change was made\n"),
            2,
            "adds a comment",
        )
        if policy.comment_directives:
            directive = policy.comment_directives[0]
            run_hook(
                "block-config-commentary.sh",
                write(path, f"{existing}\n# {directive} allowed\n"),
                0,
                silent=True,
            )
        # (9) The comment scan is unchanged for an untracked path under
        # comments.paths: adding a non-directive comment there still denies.
        scratch = path.with_name(f"untracked-scratch{path.suffix}")
        if scratch.relative_to(ROOT).as_posix() not in files:
            run_hook(
                "block-config-commentary.sh",
                write(scratch, f"{existing}\n# why this change was made\n"),
                2,
                "adds a comment",
            )
    else:
        SKIPPED.append("block-config-commentary: no tracked file in comments.paths")

    # A path outside every guarded list is never the hook's business.
    run_hook(
        "block-config-commentary.sh",
        write(Path("/tmp/outside-the-repository.yaml"), "# a comment\n"),
        0,
        silent=True,
    )


def test_require_validation_before_git(policy: Policy) -> None:
    with tempfile.TemporaryDirectory() as raw:
        directory = Path(raw)
        target = str(HOOKS / "policy.json")

        # Push is gated on a fetch since the last push, in every repository.
        no_fetch = transcript(directory, assistant(("Bash", {"command": "git push HEAD:main"})))
        run_hook(
            "require-validation-before-git.sh",
            {
                "tool_name": "Bash",
                "tool_input": {"command": "git push HEAD:main"},
                "transcript_path": no_fetch,
            },
            2,
            "no `git fetch`",
        )
        fetched = transcript(
            directory,
            assistant(("Bash", {"command": "git fetch origin"})),
            assistant(("Bash", {"command": "git push HEAD:main"})),
        )
        run_hook(
            "require-validation-before-git.sh",
            {
                "tool_name": "Bash",
                "tool_input": {"command": "git push HEAD:main"},
                "transcript_path": fetched,
            },
            0,
            silent=True,
        )
        run_hook(
            "require-validation-before-git.sh",
            bash("git fetch origin && git push HEAD:main"),
            0,
            silent=True,
        )

        # The gate only applies to a push that targets `main`/`master`; every
        # case below carries a transcript with no fetch, to prove the scoping
        # is what allows it, not a fetch history the gate never checked.
        no_fetch = transcript(directory, assistant(("Bash", {"command": "echo hi"})))

        run_hook(
            "require-validation-before-git.sh",
            {
                "tool_name": "Bash",
                "tool_input": {"command": "git push -u origin feature/x"},
                "transcript_path": no_fetch,
            },
            0,
            silent=True,
        )
        run_hook(
            "require-validation-before-git.sh",
            {
                "tool_name": "Bash",
                "tool_input": {"command": "git push origin +HEAD:refs/heads/main"},
                "transcript_path": no_fetch,
            },
            2,
            "no `git fetch`",
        )
        run_hook(
            "require-validation-before-git.sh",
            {
                "tool_name": "Bash",
                "tool_input": {"command": "git push origin topic:master"},
                "transcript_path": no_fetch,
            },
            2,
            "no `git fetch`",
        )

        with tempfile.TemporaryDirectory() as repo_raw:
            repo = Path(repo_raw)
            subprocess.run(
                ["git", "init", "-q", "-b", "main", "."], cwd=repo, check=True
            )
            run_hook(
                "require-validation-before-git.sh",
                {
                    "tool_name": "Bash",
                    "tool_input": {"command": "git push"},
                    "transcript_path": no_fetch,
                    "cwd": str(repo),
                },
                2,
                "no `git fetch`",
            )
            # A lone operand with no `:` is the repository, not a refspec --
            # `git push origin` still pushes the current branch.
            run_hook(
                "require-validation-before-git.sh",
                {
                    "tool_name": "Bash",
                    "tool_input": {"command": "git push origin"},
                    "transcript_path": no_fetch,
                    "cwd": str(repo),
                },
                2,
                "no `git fetch`",
            )
            subprocess.run(
                ["git", "checkout", "-q", "-b", "topic"], cwd=repo, check=True
            )
            run_hook(
                "require-validation-before-git.sh",
                {
                    "tool_name": "Bash",
                    "tool_input": {"command": "git push"},
                    "transcript_path": no_fetch,
                    "cwd": str(repo),
                },
                0,
                silent=True,
            )
            run_hook(
                "require-validation-before-git.sh",
                {
                    "tool_name": "Bash",
                    "tool_input": {"command": "git push origin"},
                    "transcript_path": no_fetch,
                    "cwd": str(repo),
                },
                0,
                silent=True,
            )
            run_hook(
                "require-validation-before-git.sh",
                {
                    "tool_name": "Bash",
                    "tool_input": {"command": "git push origin HEAD"},
                    "transcript_path": no_fetch,
                    "cwd": str(repo),
                },
                0,
                silent=True,
            )
            # A `cd` to a literal path earlier in the same command overrides
            # the payload `cwd` -- the dominant real shape is `cd <checkout> &&
            # git push`, with `cwd` at the workdir root above the checkout.
            parent = str(repo.parent)
            run_hook(
                "require-validation-before-git.sh",
                {
                    "tool_name": "Bash",
                    "tool_input": {"command": f"cd {repo} && git push -u origin HEAD"},
                    "transcript_path": no_fetch,
                    "cwd": parent,
                },
                0,
                silent=True,
            )

        with tempfile.TemporaryDirectory() as main_repo_raw:
            main_repo = Path(main_repo_raw)
            subprocess.run(
                ["git", "init", "-q", "-b", "main", "."], cwd=main_repo, check=True
            )
            run_hook(
                "require-validation-before-git.sh",
                {
                    "tool_name": "Bash",
                    "tool_input": {
                        "command": f"cd {main_repo} && git push -u origin HEAD"
                    },
                    "transcript_path": no_fetch,
                    "cwd": str(main_repo.parent),
                },
                2,
                "no `git fetch`",
            )

        with tempfile.TemporaryDirectory() as not_a_repo:
            run_hook(
                "require-validation-before-git.sh",
                {
                    "tool_name": "Bash",
                    "tool_input": {"command": "git push"},
                    "transcript_path": no_fetch,
                    "cwd": not_a_repo,
                },
                2,
                "no `git fetch`",
            )

        if policy.validation_pattern is None:
            SKIPPED.append(
                "require-validation-before-git: policy.json sets no validation.commandPattern, "
                "so the commit gate is off"
            )
            return

        sample = policy.validation_hint or ""
        command = next(
            (
                candidate
                for candidate in _validation_candidates(policy, sample)
                if policy.validation_pattern.search(candidate)
            ),
            None,
        )
        if command is None:
            raise AssertionError(
                "validation.hint names no command that validation.commandPattern matches; the "
                "denial would tell an agent to run something the gate does not recognise"
            )

        unvalidated = transcript(
            directory, assistant(("Write", {"file_path": target, "content": "x"}))
        )
        run_hook(
            "require-validation-before-git.sh",
            {
                "tool_name": "Bash",
                "tool_input": {"command": "git commit -m x"},
                "transcript_path": unvalidated,
            },
            2,
            "`git commit` is gated",
        )
        validated = transcript(
            directory,
            assistant(("Write", {"file_path": target, "content": "x"})),
            assistant(("Bash", {"command": command})),
        )
        run_hook(
            "require-validation-before-git.sh",
            {
                "tool_name": "Bash",
                "tool_input": {"command": "git commit -m x"},
                "transcript_path": validated,
            },
            0,
            silent=True,
        )
        # A write the commit gate does not count: under `.git/`, the pending
        # commit's own `-F` message file, or not yet in the index. None of
        # these can land in the commit the gate is judging, and no
        # validation ran in any of these transcripts.
        git_dir_write = transcript(
            directory,
            assistant(("Write", {"file_path": str(ROOT / ".git" / "COMMIT_MSG"), "content": "x"})),
        )
        run_hook(
            "require-validation-before-git.sh",
            {
                "tool_name": "Bash",
                "tool_input": {"command": "git commit -F .git/COMMIT_MSG"},
                "transcript_path": git_dir_write,
            },
            0,
            silent=True,
        )
        untracked_message_write = transcript(
            directory,
            assistant(("Write", {"file_path": str(ROOT / "commit-msg.txt"), "content": "x"})),
        )
        run_hook(
            "require-validation-before-git.sh",
            {
                "tool_name": "Bash",
                "tool_input": {"command": "git commit -F commit-msg.txt"},
                "transcript_path": untracked_message_write,
            },
            0,
            silent=True,
        )
        untracked_write = transcript(
            directory,
            assistant(("Write", {"file_path": str(ROOT / "pr-body.md"), "content": "x"})),
        )
        run_hook(
            "require-validation-before-git.sh",
            {
                "tool_name": "Bash",
                "tool_input": {"command": "git commit -m x"},
                "transcript_path": untracked_write,
            },
            0,
            silent=True,
        )

        # A file the session wrote and then `git add`ed is in the index by
        # commit time, so it counts against the gate like any tracked write.
        # An isolated throwaway repository, never the harness's own, so
        # `git add`/`git reset` here cannot make its real index unsafe.
        with tempfile.TemporaryDirectory() as add_repo_raw:
            add_repo = Path(add_repo_raw)
            subprocess.run(["git", "init", "-q", "."], cwd=add_repo, check=True)
            subprocess.run(
                ["git", "config", "user.email", "t@example.invalid"], cwd=add_repo, check=True
            )
            subprocess.run(["git", "config", "user.name", "t"], cwd=add_repo, check=True)
            (add_repo / "README.md").write_text("hi\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=add_repo, check=True)
            subprocess.run(["git", "commit", "-qm", "init"], cwd=add_repo, check=True)
            new_file = add_repo / "new-tracked.txt"
            new_file.write_text("z\n", encoding="utf-8")
            subprocess.run(["git", "add", "new-tracked.txt"], cwd=add_repo, check=True)
            try:
                added = transcript(
                    directory,
                    assistant(("Write", {"file_path": str(new_file), "content": "z"})),
                    assistant(("Bash", {"command": "git add new-tracked.txt"})),
                )
                run_hook(
                    "require-validation-before-git.sh",
                    {
                        "tool_name": "Bash",
                        "tool_input": {"command": "git commit -m x"},
                        "transcript_path": added,
                        "cwd": str(add_repo),
                    },
                    2,
                    "`git commit` is gated",
                    project_dir=add_repo,
                )
            finally:
                subprocess.run(["git", "reset", "new-tracked.txt"], cwd=add_repo, check=True)
                new_file.unlink()

        # `cd` to a sub-checkout before the commit changes which index and
        # which directory the `-F` path resolves against.
        with tempfile.TemporaryDirectory() as sub_raw:
            sub = Path(sub_raw) / "sub-checkout"
            sub.mkdir()
            subprocess.run(["git", "init", "-q", "."], cwd=sub, check=True)
            message_write = transcript(
                directory, assistant(("Write", {"file_path": str(sub / "msg.txt"), "content": "m"}))
            )
            run_hook(
                "require-validation-before-git.sh",
                {
                    "tool_name": "Bash",
                    "tool_input": {"command": f"cd {sub} && git commit -F msg.txt"},
                    "transcript_path": message_write,
                    "cwd": str(sub.parent),
                },
                0,
                silent=True,
                project_dir=sub.parent,
            )

        # An unreadable transcript cannot show the gate was met, so it blocks.
        run_hook(
            "require-validation-before-git.sh",
            {"tool_name": "Bash", "tool_input": {"command": "git commit -m x"}},
            2,
            "transcript",
        )


def _validation_candidates(policy: Policy, hint: str) -> list[str]:
    """Command strings drawn from the hint, longest first, plus the raw hint."""
    words = [
        token.strip("`,.;:()")
        for token in hint.replace("`", " ` ").split()
        if token.strip("`,.;:()")
    ]
    fragments = [hint]
    for size in (4, 3, 2, 1):
        fragments.extend(
            " ".join(words[start : start + size]) for start in range(0, max(len(words) - size + 1, 0))
        )
    return [fragment for fragment in fragments if fragment]


def test_probity_fails_closed() -> None:
    """No config and no `probity` on PATH is a denial, never a silent pass."""
    with tempfile.TemporaryDirectory() as raw:
        empty = Path(raw)
        run_hook(
            "probity.sh",
            bash("echo hi"),
            2,
            "probity.config.ts",
            project_dir=empty,
        )


# A stand-in for the commit-scope judge. It wraps this repository's real
# probity.config.ts and replaces only the model: the verdict is scripted from
# the `## Commit diff` section, exactly as the prompt tells the model to judge,
# so the suite proves what the config hands the judge without a live model.
# It records every prompt it saw so a case can assert on the evidence too.
PROBITY_SCRIPTED_JUDGE = """\
import base from {config!r}
import fs from 'node:fs'

const SECTION = /## Commit diff\\n\\n([\\s\\S]*?)\\n\\n## Pending command/

export default {{
  ...base,
  ai: {{
    reason: async (prompt: string) => {{
      fs.writeFileSync(process.env.PROBITY_TEST_PROMPT!, prompt)
      const section = SECTION.exec(prompt)
      if (!section) return {{ kind: 'violation', reason: 'no commit diff in the prompt' }}
      const files = section[1]
        .split('\\n')
        .filter((line) => line.includes(' | '))
        .map((line) => line.split(' | ')[0].trim())
      if (files.length > 1) {{
        return {{ kind: 'violation', reason: `unrelated hunks in ${{files.join(', ')}}` }}
      }}
      return {{ kind: 'pass', reason: '' }}
    }},
  }},
}}
"""

TRIVYIGNORE_DS0029 = """\
misconfigurations:
  - id: DS-0029
    paths:
      - apps/legacy/Dockerfile
    statement: Real hygiene debt, not a false positive
"""

TRIVYIGNORE_DS0002 = """\
  - id: DS-0002
    paths:
      - apps/fstrim/Dockerfile
    statement: The image runs as root on purpose
"""


def _judged_repo(directory: Path) -> None:
    """A throwaway adopter whose judge is scripted and whose lib is this one."""
    _init_repo(directory)
    shutil.copytree(
        LIB,
        directory / ".claude" / "hooks" / "lib",
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    (directory / "probity.config.ts").write_text(
        PROBITY_SCRIPTED_JUDGE.format(config=str(ROOT / "probity.config.ts")),
        encoding="utf-8",
    )
    (directory / ".trivyignore.yaml").write_text(TRIVYIGNORE_DS0029, encoding="utf-8")
    (directory / "apps" / "fstrim").mkdir(parents=True)
    (directory / "apps" / "fstrim" / "Dockerfile").write_text(
        "FROM alpine:3.20\n", encoding="utf-8"
    )
    subprocess.run(["git", "add", "-A"], cwd=directory, check=True)
    subprocess.run(["git", "commit", "-qm", "baseline"], cwd=directory, check=True)


def _edit(path: Path, old: str, new: str) -> tuple[str, dict[str, object]]:
    return ("Edit", {"file_path": str(path), "old_string": old, "new_string": new})


def _write_event(path: Path, content: str) -> tuple[str, dict[str, object]]:
    return ("Write", {"file_path": str(path), "content": content})


def _session(directory: Path, prompt: str, *edits: tuple[str, dict[str, object]]) -> str:
    """A transcript in the shape Probity reads: ids on tool uses, results after."""
    entries: list[dict[str, object]] = [
        {"type": "user", "message": {"content": [{"type": "text", "text": prompt}]}}
    ]
    for index, (name, tool_input) in enumerate(edits):
        entries.append(
            {
                "type": "assistant",
                "message": {
                    "content": [
                        {"type": "tool_use", "name": name, "id": f"t{index}", "input": tool_input}
                    ]
                },
            }
        )
        entries.append(
            {
                "type": "user",
                "message": {
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": f"t{index}",
                            "content": "The file has been updated successfully.",
                        }
                    ]
                },
            }
        )
    return transcript(directory, *entries)


def _judge(directory: Path, command: str, transcript_path: str) -> tuple[str, str]:
    """Run probity.sh on a commit; the decision it printed and the prompt it built."""
    global TESTS
    prompt_path = Path(transcript_path).parent / "prompt.txt"
    if prompt_path.exists():
        prompt_path.unlink()
    env = {
        **os.environ,
        "CLAUDE_PROJECT_DIR": str(directory),
        "PROBITY_TEST_PROMPT": str(prompt_path),
    }
    env.pop("MULTICA_POLICY_DIR", None)
    result = subprocess.run(
        [str(HOOKS / "probity.sh")],
        input=json.dumps(
            {
                "tool_name": "Bash",
                "tool_input": {"command": command},
                "transcript_path": transcript_path,
            }
        ),
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )
    if result.returncode != 0 or result.stderr.strip():
        raise AssertionError(
            f"probity.sh: exit {result.returncode}\nstdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    TESTS += 1
    prompt = prompt_path.read_text(encoding="utf-8") if prompt_path.exists() else ""
    return result.stdout, prompt


def _diff_files(prompt: str) -> list[str]:
    """The files the prompt's `## Commit diff` stat lists, in order."""
    section = prompt.split("## Commit diff")[1].split("## Pending command")[0]
    return [line.split(" | ")[0].strip() for line in section.splitlines() if " | " in line]


def _denial(stdout: str) -> str:
    decision = json.loads(stdout)["hookSpecificOutput"]
    assert decision["permissionDecision"] == "deny", decision
    reason = decision["permissionDecisionReason"]
    assert_refusal_hint(reason)
    return reason


def test_probity_commit_scope_judges_the_commit_diff() -> None:
    """The judge sees what the commit records, not the text of each Edit.

    An insert-before Edit has to re-emit the block it was anchored on in
    `new_string`, and Probity drops `old_string` when it canonicalises the
    event, so the writes alone show pre-existing text as if it were written.
    That refused a one-entry `.trivyignore.yaml` insert twice in
    docker-containers. The diff is what settles it.
    """
    # The same lookup probity.sh makes. A machine without Probity cannot run
    # the judge at all, and test_probity_fails_closed already proves that is a
    # denial there; this case needs the real config to run.
    local = ROOT / "node_modules" / ".bin" / "probity"
    if not (shutil.which("probity") or os.access(local, os.X_OK)):
        SKIPPED.append("probity commit scope: `probity` is not installed on this machine")
        return
    with tempfile.TemporaryDirectory() as raw:
        # The transcript and the captured prompt live beside the repository,
        # not in it: an untracked file must never reach the diff under test.
        directory = Path(raw) / "repo"
        scratch = Path(raw) / "scratch"
        directory.mkdir()
        scratch.mkdir()
        _judged_repo(directory)
        ignore = directory / ".trivyignore.yaml"
        dockerfile = directory / "apps" / "fstrim" / "Dockerfile"
        ds0029_block = TRIVYIGNORE_DS0029.split("misconfigurations:\n", 1)[1]
        insert_before = _edit(ignore, ds0029_block, TRIVYIGNORE_DS0002 + ds0029_block)
        ask = "Add a DS-0002 trivyignore entry for apps/fstrim/Dockerfile"

        # One inserted block before an existing entry: the Edit carries both
        # blocks, the diff adds one. The judge passes it.
        ignore.write_text(
            "misconfigurations:\n" + TRIVYIGNORE_DS0002 + ds0029_block, encoding="utf-8"
        )
        subprocess.run(["git", "add", ".trivyignore.yaml"], cwd=directory, check=True)
        commit = 'git commit -m "add DS-0002"'
        stdout, prompt = _judge(directory, commit, _session(scratch, ask, insert_before))
        assert stdout == "", f"single-scope insert was refused:\n{stdout}"
        assert prompt, "the judge was never consulted"
        assert "## Commit diff" in prompt and "authoritative" in prompt, prompt
        writes = prompt.split("## Commit diff")[0]
        assert "## Writes in this session" in writes and "DS-0029" in writes, (
            "the write history is context for intent and must stay in the prompt"
        )
        diff = prompt.split("## Commit diff")[1].split("## Pending command")[0]
        added = [
            line
            for line in diff.splitlines()
            if line.startswith("+") and not line.startswith("+++")
        ]
        assert added and all("DS-0029" not in line for line in added), (
            f"the re-emitted DS-0029 block must not appear as an addition:\n{diff}"
        )
        assert _diff_files(prompt) == [".trivyignore.yaml"], diff

        # The same insert plus a version bump in another file is bundled
        # scope, and the refusal names both files.
        dockerfile.write_text("FROM alpine:3.21\n", encoding="utf-8")
        subprocess.run(["git", "add", "apps/fstrim/Dockerfile"], cwd=directory, check=True)
        bump = _edit(dockerfile, "alpine:3.20", "alpine:3.21")
        bundled = _session(scratch, ask, insert_before, bump)
        stdout, prompt = _judge(directory, commit, bundled)
        reason = _denial(stdout)
        assert reason.startswith("Probity: commit scope:"), reason
        assert ".trivyignore.yaml" in reason and "apps/fstrim/Dockerfile" in reason, reason
        assert "Allowed next step: unstage what does not serve the asked-for outcome" in reason, (
            f"a scope refusal must name the allowed next step:\n{reason}"
        )
        assert _diff_files(prompt) == [".trivyignore.yaml", "apps/fstrim/Dockerfile"], prompt

        # A transcript that cannot be read is a refusal that still names the
        # allowed next step.
        stdout, _ = _judge(directory, commit, str(scratch / "absent.jsonl"))
        reason = _denial(stdout)
        assert "the session transcript could not be read" in reason, reason
        assert "preserve the change uncommitted and continue independent work" in reason, reason
        assert "re-run the same commit once" not in reason, reason

        # A change left unstaged is not in a plain `git commit`, but `-a`
        # stages every tracked change at commit time, so the diff follows
        # the command.
        subprocess.run(
            ["git", "reset", "-q", "apps/fstrim/Dockerfile"], cwd=directory, check=True
        )
        stdout, prompt = _judge(directory, commit, bundled)
        assert stdout == "", f"unstaged file counted as commit scope:\n{stdout}"
        assert _diff_files(prompt) == [".trivyignore.yaml"], prompt
        stdout, prompt = _judge(directory, 'git commit -am "add DS-0002"', bundled)
        reason = _denial(stdout)
        assert ".trivyignore.yaml" in reason and "apps/fstrim/Dockerfile" in reason, reason

        # Nothing staged is what `git add … && git commit …` looks like before
        # it runs, so the judge is handed the writes as the commit's content
        # rather than an empty commit with every write filtered out.
        subprocess.run(["git", "reset", "-q"], cwd=directory, check=True)
        stdout, prompt = _judge(
            directory,
            'git add .trivyignore.yaml && git commit -m "add DS-0002"',
            _session(scratch, ask, insert_before),
        )
        assert stdout == "", f"`git add … && git commit …` was refused:\n{stdout}"
        assert "(empty: nothing is staged yet; the command stages its changes" in prompt, prompt
        writes = prompt.split("## Commit diff")[0]
        assert "## Writes in this session\n" in writes and ".trivyignore.yaml" in writes, writes
        assert "none of this session's writes" not in writes, writes

        # A tool call issued without a path never ran; it must not crash the
        # rule (`paths[1]` undefined) and must not reach the judge.
        pathless = ("Edit", {"old_string": "a", "new_string": "b"})
        stdout, prompt = _judge(
            directory,
            'git add .trivyignore.yaml && git commit -m "add DS-0002"',
            _session(scratch, ask, pathless, insert_before),
        )
        assert stdout == "", f"a pathless write was not skipped:\n{stdout}"
        assert prompt, "the judge was never consulted"

        # A command that is not a commit never reaches the judge.
        stdout, prompt = _judge(directory, "git status", _session(scratch, ask, insert_before))
        assert stdout == "" and prompt == "", (stdout, prompt)


def test_probity_commit_scope_filters_writes_to_files_in_the_commit() -> None:
    """A write outside this commit's diff must never reach the judge.

    An Edit to a file already landed in an earlier commit of the same
    repository, and a Write to an untracked scratch file such as
    `pr-body.md`, are both things this session did that this commit does not
    record. Neither belongs in the writes section: the judge must not be
    handed a chance to read either as bundled scope.
    """
    local = ROOT / "node_modules" / ".bin" / "probity"
    if not (shutil.which("probity") or os.access(local, os.X_OK)):
        SKIPPED.append("probity commit scope: `probity` is not installed on this machine")
        return
    with tempfile.TemporaryDirectory() as raw:
        directory = Path(raw) / "repo"
        scratch = Path(raw) / "scratch"
        directory.mkdir()
        scratch.mkdir()
        _judged_repo(directory)

        # An already-landed commit: real work this session did, but it is not
        # part of the diff the pending `git commit` is about to record.
        readme = directory / "README.md"
        readme.write_text("landed earlier\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=directory, check=True)
        subprocess.run(
            ["git", "commit", "-qm", "land README update"], cwd=directory, check=True
        )

        # The pending change: a single-file, in-scope edit, staged alone.
        ignore = directory / ".trivyignore.yaml"
        ds0029_block = TRIVYIGNORE_DS0029.split("misconfigurations:\n", 1)[1]
        ignore.write_text(
            "misconfigurations:\n" + TRIVYIGNORE_DS0002 + ds0029_block, encoding="utf-8"
        )
        subprocess.run(["git", "add", ".trivyignore.yaml"], cwd=directory, check=True)

        # An untracked scratch file this session also wrote, never staged.
        pr_body = directory / "pr-body.md"
        pr_body.write_text("Adds a DS-0002 entry.\n", encoding="utf-8")

        session = _session(
            scratch,
            "Add a DS-0002 trivyignore entry",
            _edit(readme, "hi\n", "landed earlier\n"),
            _write_event(pr_body, "Adds a DS-0002 entry.\n"),
            _edit(ignore, ds0029_block, TRIVYIGNORE_DS0002 + ds0029_block),
        )
        stdout, prompt = _judge(directory, 'git commit -m "add DS-0002"', session)
        assert stdout == "", f"in-commit single-file edit was refused:\n{stdout}"
        writes = prompt.split("## Commit diff")[0]
        assert "## Writes in this session that touch files in this commit" in writes, writes
        assert "pr-body.md" not in writes, writes
        assert "README.md" not in writes, writes
        assert ".trivyignore.yaml" in writes, writes

        # The unavailable-diff fallback (all writes shown, original heading)
        # needs Git to fail to report a diff it otherwise could -- this
        # harness has no fixture for that beyond a second, dedicated one; not
        # added here.


CHANGELOG_BASE = "## Unreleased\n\n- baseline\n"
CHANGELOG_OURS = "## Unreleased\n\n- Get-CrowdStrikeDetectionInventory\n- baseline\n"
CHANGELOG_THEIRS = "## Unreleased\n\n- Get-CatoAuditFeedInventory\n- baseline\n"
CHANGELOG_RESOLVED = (
    "## Unreleased\n\n- Get-CrowdStrikeDetectionInventory\n- Get-CatoAuditFeedInventory\n"
    "- baseline\n"
)


def _git(directory: Path, *arguments: str, check: bool = True) -> None:
    subprocess.run(["git", *arguments], cwd=directory, check=check, capture_output=True)


def _diff_section(prompt: str) -> str:
    return prompt.split("## Commit diff")[1].split("## Pending command")[0]


def test_probity_commit_scope_judges_a_merge_by_its_resolution() -> None:
    """A merge commit is judged by what the session resolved by hand.

    While `.git/MERGE_HEAD` exists the index holds every change the incoming
    branch brings, so a plain `--cached` diff hands the judge another
    session's whole slice and it refuses the merge as bundled scope. That
    refused a `git merge origin/main` with one CHANGELOG conflict in
    IaC-Powershell. The diff is taken against Git's own auto-merge tree, so
    the incoming side's commits are not this commit's scope.
    """
    local = ROOT / "node_modules" / ".bin" / "probity"
    if not (shutil.which("probity") or os.access(local, os.X_OK)):
        SKIPPED.append("probity merge scope: `probity` is not installed on this machine")
        return
    with tempfile.TemporaryDirectory() as raw:
        directory = Path(raw) / "repo"
        scratch = Path(raw) / "scratch"
        directory.mkdir()
        scratch.mkdir()
        _judged_repo(directory)
        changelog = directory / "CHANGELOG.md"
        dockerfile = directory / "apps" / "fstrim" / "Dockerfile"
        changelog.write_text(CHANGELOG_BASE, encoding="utf-8")
        _git(directory, "add", "CHANGELOG.md")
        _git(directory, "commit", "-qm", "changelog")

        # The incoming side is another session's slice: its own changelog
        # bullet plus a file this session never touched.
        _git(directory, "checkout", "-qb", "incoming")
        changelog.write_text(CHANGELOG_THEIRS, encoding="utf-8")
        dockerfile.write_text("FROM alpine:3.21\n", encoding="utf-8")
        _git(directory, "commit", "-qam", "incoming slice")
        _git(directory, "checkout", "-q", "-")
        changelog.write_text(CHANGELOG_OURS, encoding="utf-8")
        _git(directory, "commit", "-qam", "our slice")

        # One conflict, one file auto-merged.
        _git(directory, "merge", "incoming", check=False)
        assert (directory / ".git" / "MERGE_HEAD").exists(), "the merge did not stop"
        changelog.write_text(CHANGELOG_RESOLVED, encoding="utf-8")
        _git(directory, "add", "CHANGELOG.md")
        ask = "Deliver Get-CrowdStrikeDetectionInventory"
        resolve = _edit(changelog, CHANGELOG_OURS, CHANGELOG_RESOLVED)
        session = _session(scratch, ask, resolve)
        commit = 'git commit -m "merge main"'

        # (a) The judge sees the hand-resolved file only, never the
        # auto-merged file the incoming side brought along.
        stdout, prompt = _judge(directory, commit, session)
        assert stdout == "", f"a hand-resolved merge was refused:\n{stdout}"
        assert "a merge is in progress" in _diff_section(prompt), prompt
        assert _diff_files(prompt) == ["CHANGELOG.md"], _diff_section(prompt)
        # Keeping both bullets is the whole resolution, so the hunks are the
        # markers the auto-merge tree carried and nothing the incoming side
        # committed.
        assert "-<<<<<<< HEAD" in _diff_section(prompt), _diff_section(prompt)
        assert "alpine" not in _diff_section(prompt), _diff_section(prompt)

        # (d) `-a` during a merge uses the same base: an unstaged tracked
        # edit joins the diff, the incoming side's commits still do not.
        dockerfile.write_text("FROM alpine:3.22\n", encoding="utf-8")
        stdout, prompt = _judge(directory, commit, session)
        assert stdout == "" and _diff_files(prompt) == ["CHANGELOG.md"], prompt
        stdout, prompt = _judge(directory, 'git commit -am "merge main"', session)
        reason = _denial(stdout)
        assert "CHANGELOG.md" in reason and "apps/fstrim/Dockerfile" in reason, reason
        assert _diff_files(prompt) == ["CHANGELOG.md", "apps/fstrim/Dockerfile"], prompt
        assert "+FROM alpine:3.22" in prompt and "+FROM alpine:3.21" not in prompt, prompt
        _git(directory, "checkout", "--", "apps/fstrim/Dockerfile")

        # (b) A merge Git settled on its own has nothing for the judge, and
        # the prompt says so rather than claiming nothing is staged.
        _git(directory, "merge", "--abort")
        _git(directory, "checkout", "-qb", "clean-incoming", "HEAD~1")
        (directory / "apps" / "fstrim" / "README.md").write_text("fstrim\n", encoding="utf-8")
        _git(directory, "add", "-A")
        _git(directory, "commit", "-qm", "clean incoming")
        _git(directory, "checkout", "-q", "-")
        _git(directory, "merge", "--no-commit", "--no-ff", "clean-incoming")
        assert (directory / ".git" / "MERGE_HEAD").exists(), "the merge did not stay open"
        stdout, prompt = _judge(directory, commit, session)
        assert stdout == "", f"an auto-resolved merge was refused:\n{stdout}"
        assert "(empty: the merge resolved every change automatically)" in prompt, prompt
        assert _diff_files(prompt) == [], prompt

        # (c) With no MERGE_HEAD the same staged content is judged against
        # HEAD, exactly as before.
        _git(directory, "merge", "--abort")
        assert not (directory / ".git" / "MERGE_HEAD").exists()
        _git(directory, "checkout", "incoming", "--", "apps/fstrim/Dockerfile")
        stdout, prompt = _judge(directory, commit, session)
        assert "a merge is in progress" not in prompt, prompt
        assert _diff_files(prompt) == ["apps/fstrim/Dockerfile"], prompt
        assert "+FROM alpine:3.21" in prompt, prompt


def test_settings_registers_every_hook() -> None:
    global TESTS
    settings = json.loads((ROOT / ".claude" / "settings.json").read_text(encoding="utf-8"))
    registered = {
        Path(entry["command"].strip('"')).name
        for event in settings.get("hooks", {}).values()
        for matcher in event
        for entry in matcher.get("hooks", [])
        if isinstance(entry.get("command"), str)
    }
    required = {
        "block-runtime.sh",
        "block-git-unsafe.sh",
        "block-gh-unsafe.sh",
        "block-attribution.sh",
        "block-config-commentary.sh",
        "require-validation-before-git.sh",
        "probity.sh",
    }
    missing = required - registered
    assert not missing, f".claude/settings.json does not register: {sorted(missing)}"
    # Claude Code lets the tool call through when a hook crashes or times out,
    # unless the entry says otherwise.
    for matcher in settings["hooks"]["PreToolUse"]:
        for entry in matcher["hooks"]:
            name = Path(entry["command"].strip('"')).name
            if name not in required:
                continue
            assert entry.get("onFailure") == "block", (
                f'{name} is registered without "onFailure": "block"'
            )
            if name == "probity.sh":
                timeout = entry.get("timeout")
                assert isinstance(timeout, (int, float)) and timeout > 0, (
                    "probity.sh waits on a model and needs an explicit `timeout`"
                )
    # No gate may wait for a person: an `ask` rule stalls an unattended run.
    assert "ask" not in settings.get("permissions", {}), (
        "permissions.ask stalls an unattended agent run; every gate must allow or deny on "
        "automated criteria"
    )
    TESTS += 1


# --------------------------------------------------------------------------
# Bridge transcripts — the OpenCode runtime writes Claude-format JSONL too
# --------------------------------------------------------------------------

# Written by the claude-hook-bridge OpenCode plugin in the multica-agent image,
# captured from a real run of the plugin (prompt, an edit, a validation run,
# then the commit the gate is asked about). Only two things were changed after
# capture: the working directory became @REPO@, and call-2's command is
# swapped for this repository's own validator at run time. The tool_result
# content is a plain string here, where Claude Code writes a block list; the
# readers must accept both.
BRIDGE_TRANSCRIPT = r'''
{"type":"user","uuid":"137ffce5-1d51-48d7-b5c7-9df69ebe592c","sessionId":"ses_bridge","cwd":"@REPO@","timestamp":"2026-10-09T01:28:41.564Z","message":{"role":"user","content":[{"type":"text","text":"Add the greeting helper to hello.py"}]}}
{"type":"assistant","uuid":"c2e9501f-f596-4db3-96b6-b37fd6918830","sessionId":"ses_bridge","cwd":"@REPO@","timestamp":"2026-10-09T01:28:41.567Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"call-1","name":"Edit","input":{"file_path":"@REPO@/hello.py","old_string":"","new_string":"def greet():\n    return 'hi'\n"}}]}}
{"type":"user","uuid":"62acf5b9-e741-43bc-9bf2-064f0d938d93","sessionId":"ses_bridge","cwd":"@REPO@","timestamp":"2026-10-09T01:28:41.568Z","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"call-1","content":"Edit applied successfully."}]}}
{"type":"assistant","uuid":"7cebda03-6c06-4452-8e6b-f4bea247e4e3","sessionId":"ses_bridge","cwd":"@REPO@","timestamp":"2026-10-09T01:28:41.568Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"call-2","name":"Bash","input":{"command":"python3 scripts/test-agent-hooks.py"}}]}}
{"type":"user","uuid":"5c0330a5-6f2d-45a2-98c8-ab464bac0f04","sessionId":"ses_bridge","cwd":"@REPO@","timestamp":"2026-10-09T01:28:41.568Z","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"call-2","content":"ok"}]}}
{"type":"assistant","uuid":"7f1cba3f-7282-4c9d-a748-9098f505876a","sessionId":"ses_bridge","cwd":"@REPO@","timestamp":"2026-10-09T01:28:41.568Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"call-3","name":"Bash","input":{"command":"git commit -am 'add greeting helper'"}}]}}
'''
BRIDGE_VALIDATION_COMMAND = "python3 scripts/test-agent-hooks.py"


def _bridge_transcript(directory: Path, repo: Path, *, validation: str | None) -> str:
    """The captured bridge session, without its validation run when `validation` is None."""
    entries = []
    for line in BRIDGE_TRANSCRIPT.strip().replace("@REPO@", str(repo)).splitlines():
        entry = json.loads(line)
        content = entry["message"]["content"][0]
        if content.get("id") == "call-2" or content.get("tool_use_id") == "call-2":
            if validation is None:
                continue
            if content.get("type") == "tool_use":
                content["input"]["command"] = validation
        entries.append(entry)
    return transcript(directory, *entries)


def test_bridge_transcript_through_the_commit_gate(policy: Policy) -> None:
    """require-validation-before-git reads a bridge transcript like a Claude Code one."""
    if policy.validation_pattern is None:
        SKIPPED.append("bridge transcript commit gate: policy.json sets no validation.commandPattern")
        return
    command = next(
        (
            candidate
            for candidate in _validation_candidates(policy, policy.validation_hint or "")
            if policy.validation_pattern.search(candidate)
        ),
        None,
    )
    assert command, "validation.hint names no command that validation.commandPattern matches"
    with tempfile.TemporaryDirectory() as raw:
        directory = Path(raw)
        repo = directory / "repo"
        repo.mkdir()
        _init_repo(repo)
        (repo / "hello.py").write_text("def greet():\n    return 'hi'\n", encoding="utf-8")
        subprocess.run(["git", "add", "hello.py"], cwd=repo, check=True)
        payload = {"tool_name": "Bash", "tool_input": {"command": "git commit -m x"}, "cwd": str(repo)}
        run_hook(
            "require-validation-before-git.sh",
            {**payload, "transcript_path": _bridge_transcript(directory, repo, validation=None)},
            2,
            "`git commit` is gated",
            project_dir=repo,
        )
        run_hook(
            "require-validation-before-git.sh",
            {**payload, "transcript_path": _bridge_transcript(directory, repo, validation=command)},
            0,
            silent=True,
            project_dir=repo,
        )


def test_bridge_transcript_through_the_commit_scope_judge() -> None:
    """Probity hands the commit-scope rule the history a bridge transcript carries."""
    local = ROOT / "node_modules" / ".bin" / "probity"
    if not (shutil.which("probity") or os.access(local, os.X_OK)):
        SKIPPED.append("bridge transcript commit scope: `probity` is not installed on this machine")
        return
    with tempfile.TemporaryDirectory() as raw:
        directory = Path(raw) / "repo"
        scratch = Path(raw) / "scratch"
        directory.mkdir()
        scratch.mkdir()
        _judged_repo(directory)
        (directory / "hello.py").write_text("def greet():\n    return 'hi'\n", encoding="utf-8")
        _git(directory, "add", "hello.py")
        path = _bridge_transcript(scratch, directory, validation=BRIDGE_VALIDATION_COMMAND)
        stdout, prompt = _judge(directory, "git commit -m 'add greeting helper'", path)
        assert stdout == "", f"a single-file bridge session was refused:\n{stdout}"
        assert prompt, "the judge was never consulted"
        history = prompt.split("## Commit diff")[0]
        assert "Add the greeting helper to hello.py" in history, history
        assert "## Writes in this session" in history and "def greet()" in history, history
        assert _diff_files(prompt) == ["hello.py"], prompt


# --------------------------------------------------------------------------
# Repository-specific cases — add yours below and register them in main()
# --------------------------------------------------------------------------


def main() -> int:
    try:
        policy = test_policy_loads()
    except PolicyError as exc:
        print(f"FAIL  .claude/hooks/policy.json: {exc}")
        return 1

    test_policy_fails_closed()
    test_refusal_hints_on_failure_paths()
    test_shell_grammar_is_not_a_command()
    test_heredoc_inside_substitution_and_line_continuations()
    test_block_runtime(policy)
    test_block_git_unsafe()
    test_block_gh_unsafe()
    test_block_attribution()
    test_block_config_commentary(policy)
    test_require_validation_before_git(policy)
    test_probity_fails_closed()
    test_probity_commit_scope_judges_the_commit_diff()
    test_probity_commit_scope_filters_writes_to_files_in_the_commit()
    test_probity_commit_scope_judges_a_merge_by_its_resolution()
    test_bridge_transcript_through_the_commit_gate(policy)
    test_bridge_transcript_through_the_commit_scope_judge()
    test_settings_registers_every_hook()

    for note in SKIPPED:
        print(f"SKIP  {note}")
    print(f"PASS  {TESTS} hook cases")
    return 0


if __name__ == "__main__":
    sys.exit(main())
