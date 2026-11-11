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
import runpy
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
        "session transcript could not be read": "retry the commit only after",
        "no AI validator available": "retry the commit only after",
        "unrelated hunks": "leave unrelated work intact for its owner",
    }
    for reason, route in routes.items():
        if reason.casefold() in message.casefold():
            assert route.casefold() in message.casefold(), (
                f"{reason!r} missing corrective action {route!r}:\n{message}"
            )


# The Bash rules run through one entrypoint. A case names a rule by its
# historical hook file name; the harness runs that rule alone through the
# registered wrapper, so a case keeps judging the rule it was written for.
BASH_RULES = {
    "block-runtime.sh": "block-runtime",
    "block-git-unsafe.sh": "block-git-unsafe",
    "block-gh-unsafe.sh": "block-gh-unsafe",
    "block-attribution.sh": "block-attribution",
    "require-validation-before-git.sh": "require-validation-before-git",
}


def hook_command(hook: str, hooks_dir: Path) -> list[str]:
    if hook in BASH_RULES:
        return [str(hooks_dir / "pre-bash.sh"), "--only", BASH_RULES[hook]]
    return [str(hooks_dir / hook)]


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
    supplied_env = env or {}
    env = {**os.environ, "CLAUDE_PROJECT_DIR": str(project_dir), **supplied_env}
    trusted_policy_dir = supplied_env.get("MULTICA_POLICY_DIR")
    env.pop("MULTICA_POLICY_DIR", None)
    if trusted_policy_dir:
        env["MULTICA_POLICY_DIR"] = trusted_policy_dir
    result = subprocess.run(
        hook_command(hook, hooks_dir),
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
    """Write a session transcript.

    Real transcripts record a `tool_result` for every call that completed, so a
    `tool_use` without an `id` gets one, followed by a result carrying the
    entry's `_result` (see `assistant`): False for is_error false (default),
    True for a failed call, None for a call with no recorded result.
    """
    lines: list[dict[str, object]] = []
    for number, source in enumerate(entries):
        entry = json.loads(json.dumps(source))
        result = entry.pop("_result", False)
        lines.append(entry)
        message = entry.get("message")
        blocks = message.get("content") if isinstance(message, dict) else None
        if entry.get("type") != "assistant" or not isinstance(blocks, list):
            continue
        results = []
        for index, block in enumerate(blocks):
            if block.get("type") != "tool_use" or block.get("id") is not None:
                continue
            block["id"] = f"auto-{number}-{index}"
            if result is not None:
                results.append(
                    {"type": "tool_result", "tool_use_id": block["id"], "content": "ok", "is_error": result}
                )
        if results:
            lines.append({"type": "user", "message": {"content": results}})
    path = directory / "transcript.jsonl"
    path.write_text("".join(f"{json.dumps(line)}\n" for line in lines), encoding="utf-8")
    return str(path)


def assistant(*tool_uses: tuple[str, dict[str, object]], result: bool | None = False) -> dict[str, object]:
    """One assistant turn; `result` is the is_error that `transcript()` records
    for its calls (None records no result)."""
    return {
        "type": "assistant",
        "_result": result,
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
    for command in (
        "for t in jq yamllint; do printf '%s: ' $t; command -v $t || echo MISSING; done",
        'for t in jq; do command -V "$t"; done',
        "(git config --worktree user.name >/dev/null 2>&1 || { git config --worktree user.name x; }) && git status",
        'end=$(( $(date +%s) + 120 )); until [ "$(date +%s)" -ge "$end" ]; do sleep 5; done; date -u',
        "P=repo; diff <(cat /tmp/a.json) $P/settings.json",
    ):
        run_hook("block-runtime.sh", bash(command), 0, silent=True)
    run_hook("block-runtime.sh", bash("git status"), 0, silent=True)
    run_hook("block-runtime.sh", bash(""), 0, silent=True)
    run_hook("block-runtime.sh", "not json", 2, "not valid JSON")
    if not policy.blocked_commands:
        SKIPPED.append("block-runtime: policy.json blocks no executables")
        return
    for name in policy.blocked_commands:
        for command in (
            f"o='-- {name}'; command $o",
            f"o='-- {name}'; command ${{o}}",
            f"o='-- {name}'; command \"$o\"",
            f"o='-p {name}'; command $o",
            f"o='-p /usr/bin/{name}'; command $o",
            f"o=' -- {name}'; command $o",
        ):
            run_hook("block-runtime.sh", bash(command), 2, "cannot safely resolve dynamic")

        run_hook("block-runtime.sh", bash(f"o=--; command $o {name}"), 2, name)
        run_hook("block-runtime.sh", bash(f"o=-p; command $o /usr/bin/{name}"), 2, name)
        run_hook(
            "block-runtime.sh",
            bash(f"x='a[$({name})]'; echo $((x))"),
            2,
            name,
        )
        run_hook(
            "block-runtime.sh",
            bash(f"x=\"a[\\$({name})]\"; echo $((x))"),
            2,
            name,
        )
        run_hook(
            "block-runtime.sh",
            bash(f"x='a[$({name})]'; y=x; echo $((y))"),
            2,
            name,
        )
        for command in (
            f"read c <<<{name}; $c; c=git",
            f"for c in {name}; do $c; done; c=git",
        ):
            run_hook(
                "block-runtime.sh",
                bash(command),
                2,
                "cannot safely resolve dynamic executable",
            )
        for command in (
            f"o=--; p=$o; command $p {name}",
            f"x=\"a['\\$({name})']\"; echo $((x))",
            f"x=1; echo $((x)); bash -c \"x='a[\\$({name})]'; echo \\$((x))\"",
            f"x=1; echo $((x)); eval \"x='a[\\$({name})]'; echo \\$((x))\"",
            f"x='a[$({name})]'; cat <<EOF\n$((x))\nEOF",
            f"x='a[$({name})]'; eval 'echo $((x))'",
            f"export x='a[$({name})]'; bash -c 'echo $((x))'",
            f"export x='a[$({name})]'; env bash -c 'echo $((x))'",
            f"export x='a[$({name})]'; xargs -I{{}} bash -c 'echo $((x))' <<<1",
            f"n='a[$({name})]'; n=${{n:-0}}; echo $((n))",
            f"x='a[$({name})]'; echo $((x)) ; x=1",
        ):
            run_hook("block-runtime.sh", bash(command), 2, name)
        run_hook("block-runtime.sh", bash(f"v=-; command -$v {name}"), 2, name)
        run_hook("block-runtime.sh", bash(f"v=-; command -${{v}} {name}"), 2, name)
        run_hook("block-runtime.sh", bash(f"v=p; command -$v /usr/bin/{name}"), 2, name)
        run_hook("block-runtime.sh", bash(f"echo $(( $({name} get pods | wc -l) + 1 ))"), 2, name)
        run_hook("block-runtime.sh", bash(f"diff <({name} list) b"), 2, name)
        run_hook("block-runtime.sh", bash(f"{name} --help"), 2, name)
        run_hook("block-runtime.sh", bash(f"/usr/bin/{name} --help"), 2, name)
        run_hook("block-runtime.sh", bash(f"bash -lc '{name} --help'"), 2, name)
        run_hook("block-runtime.sh", bash(f"true && {name} --help"), 2, name)
        # A heredoc body is data, not code.
        run_hook("block-runtime.sh", bash(f"cat > n.md <<'EOF'\ndo not run {name}\nEOF"), 0)
        # Skipping the grammar must not skip the command it wraps.
        run_hook("block-runtime.sh", bash(f"if true; then {name} --help; fi"), 2, name)
        run_hook("block-runtime.sh", bash(f"run(){{ {name} --help; }}; run"), 2, name)

    for command in (
        "n=${n:-0}; echo $((n+1))",
        "N=${N:-3}; for i in 1 2; do echo $((i*N)); done",
        "n=$n; echo $((n+1))",
        "t=git; c=$t; command $c status",
        'x="$(printf \'%s\' "it\'s")"; echo "$x"',
        'echo "$(printf \'%s\' "don\'t")"',
        'A="$(echo "a\'b")"; echo "$A"',
        'echo "$(echo "it\'s" | tr a b)" && echo ok',
    ):
        run_hook("block-runtime.sh", bash(command), 0, silent=True)
    deep_arithmetic = "; ".join(
        f"v{index}=v{index + 1}+v{index + 1}" for index in range(40)
    ) + "; echo $((v0))"
    run_hook("block-runtime.sh", bash(deep_arithmetic), 0, silent=True)
    deep_substitution_arithmetic = "; ".join(
        f"v{index}='$(echo $((v{index + 1})))'" for index in range(26)
    ) + "; echo $((v0))"
    run_hook("block-runtime.sh", bash(deep_substitution_arithmetic), 0, silent=True)
    run_hook("block-runtime.sh", bash('v="it\'s"; echo $((v))'), 0, silent=True)
    run_hook("block-runtime.sh", bash("a=b; b=a; echo $((a))"), 0, silent=True)


def _init_repo(directory: Path) -> None:
    subprocess.run(["git", "init", "-q", "."], cwd=directory, check=True)
    subprocess.run(["git", "config", "user.email", "t@example.invalid"], cwd=directory, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=directory, check=True)
    (directory / "README.md").write_text("hi\n", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=directory, check=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=directory, check=True)
    subprocess.run(["git", "remote", "add", "origin", str(directory)], cwd=directory, check=True)


def test_push_gate_directory_and_history() -> None:
    """The mainline push gate: which branch a push writes to, and what counts as history."""
    gate = "require-validation-before-git.sh"

    def check(command, entries, cwd, expected, *messages):
        with tempfile.TemporaryDirectory() as raw:
            path = transcript(Path(raw), *entries)
            payload = {
                "tool_name": "Bash",
                "tool_input": {"command": command},
                "transcript_path": path,
                "cwd": str(cwd),
            }
            run_hook(gate, payload, expected, *messages, silent=expected == 0)

    fetch = assistant(("Bash", {"command": "git fetch origin"}))
    push_main = "git push origin HEAD:main"
    with tempfile.TemporaryDirectory() as raw, tempfile.TemporaryDirectory() as raw_main, tempfile.TemporaryDirectory() as task:
        repo, main_repo = Path(raw), Path(raw_main)
        _init_repo(repo)
        subprocess.run(["git", "checkout", "-q", "-b", "agent/x"], cwd=repo, check=True)
        _init_repo(main_repo)
        subprocess.run(["git", "checkout", "-q", "-B", "main"], cwd=main_repo, check=True)
        # 1: in the checkout.
        check("git push -u origin HEAD", [], repo, 0)
        # 2: `git -C` from a directory that is not a repository.
        check(f"git -C {repo} push -u origin HEAD", [], task, 0)
        # 3: `cd` into the checkout.
        check(f"cd {repo} && git push -u origin HEAD", [], task, 0)
        # 4: `git -C` with an explicit branch.
        check(f"git -C {repo} push -u origin agent/x", [], task, 0)
        # `git -C` into a checkout on main stays gated, bare and with HEAD.
        check(f"git -C {main_repo} push -u origin HEAD", [], task, 2, "no `git fetch`", "`main` or `master`")
        check(f"git -C {main_repo} push", [], task, 2, "no `git fetch`")
        # 5: a successful fetch clears a mainline push.
        check(push_main, [fetch], repo, 0)
        # 6: a push that was refused is not "the last push".
        refused = assistant(("Bash", {"command": "git push origin HEAD:master"}), result=True)
        check(push_main, [fetch, refused], repo, 0)
        # 7: a fetch chained to a refused push never ran as far as the gate can show.
        chained = assistant(("Bash", {"command": "git fetch origin && git push --force origin HEAD"}), result=True)
        check(push_main, [chained], repo, 2, "no `git fetch`")
        # 8: a failed fetch does not count.
        check(push_main, [assistant(("Bash", {"command": "git fetch origin"}), result=True)], repo, 2, "no `git fetch`")
        # A fetch with no recorded result does not count either.
        check(push_main, [assistant(("Bash", {"command": "git fetch origin"}), result=None)], repo, 2, "no `git fetch`")
        # A successful push after the fetch still requires a newer fetch.
        pushed = assistant(("Bash", {"command": "git push origin HEAD:master"}))
        check(push_main, [fetch, pushed], repo, 2, "since the last `git push`")


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


def test_branch_policy_full_git_hook_binds_push_and_local_history() -> None:
    """Exercise the installed Bash hook with active policies in two checkouts."""
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        repo_a = root / "repo-a"
        repo_b = root / "repo-b"
        repo_a.mkdir()
        repo_b.mkdir()
        _init_repo(repo_a)
        _init_repo(repo_b)
        for repo in (repo_a, repo_b):
            hooks = repo / ".claude" / "hooks"
            hooks.parent.mkdir(parents=True)
            shutil.copytree(HOOKS, hooks)
            policy_path = hooks / "policy.json"
            policy = json.loads(policy_path.read_text(encoding="utf-8"))
            policy["repository"] = f"fixture {repo.name}"
            policy_path.write_text(json.dumps(policy, indent=2) + "\n", encoding="utf-8")

        def configure(repo: Path) -> None:
            path = repo / ".claude" / "hooks" / "policy.json"
            policy = json.loads(path.read_text(encoding="utf-8"))
            policy["branchPolicy"] = {
                "profile": "project-alpha-v1",
                "integrationBranch": "dev",
                "stableBranch": "main",
                "protectedPaths": [".claude/**", ".github/workflows/**", "scripts/**"],
            }
            path.write_text(json.dumps(policy, indent=2) + "\n", encoding="utf-8")

        def on_repo(
            repo: Path,
            command: str,
            expected: int,
            *message: str,
            cwd: Path | None = None,
            silent: bool = False,
        ) -> None:
            run_hook(
                "block-git-unsafe.sh",
                {
                    "tool_name": "Bash",
                    "tool_input": {"command": command},
                    "cwd": str(cwd or repo),
                },
                expected,
                *message,
                silent=silent,
                hooks_dir=repo / ".claude" / "hooks",
                project_dir=repo,
            )

        configure(repo_a)
        default_a = subprocess.run(
            ["git", "-C", str(repo_a), "branch", "--show-current"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        if default_a != "main":
            _git(repo_a, "checkout", "-qb", "main")
        _git(repo_a, "checkout", "-qb", "dev")
        on_repo(repo_a, "git push -u origin HEAD", 2, "direct pushes to integration", silent=False)
        _git(repo_a, "checkout", "-q", "main")
        on_repo(repo_a, "git push -u origin HEAD", 2, "full immutable commit SHA", silent=False)
        _git(repo_a, "checkout", "-qb", "feature/topic")

        on_repo(repo_a, "git push -u origin feat/example", 0, silent=True)
        on_repo(repo_a, "git push -u origin HEAD", 0, silent=True)
        on_repo(repo_a, "git push origin refs/heads/*:refs/heads/*", 2, "wildcard", silent=False)
        on_repo(repo_a, "git push origin HEAD:heads/dev", 2, "abbreviated `heads/`", silent=False)
        on_repo(repo_a, "git push --matching origin", 2, "cannot safely interpret", silent=False)
        on_repo(repo_a, "git push --all origin", 2, "cannot safely interpret", silent=False)
        on_repo(repo_a, "git push origin HEAD:refs/heads/dev", 2, "direct pushes to integration", silent=False)
        _git(repo_a, "config", "alias.ci", "commit")
        on_repo(repo_a, "git ci -m hidden-commit", 2, "Git alias `ci`", silent=False)
        on_repo(repo_a, "git -c alias.ci=commit ci -m hidden-commit", 2, "cannot bind", silent=False)
        on_repo(
            repo_a,
            f"GIT_DIR={repo_b / '.git'} git push -u origin feat/example",
            2,
            "cannot bind this push",
            silent=False,
        )
        on_repo(repo_a, "git commit -m topic", 0, silent=True)
        on_repo(repo_a, "git rebase main", 0, silent=True)
        on_repo(repo_a, "git cherry-pick HEAD", 0, silent=True)

        _git(repo_a, "checkout", "-q", "main")
        on_repo(repo_a, "git commit -m direct", 2, "shared branch `main`", silent=False)
        on_repo(repo_a, "git merge feature/topic", 2, "shared branch `main`", silent=False)
        on_repo(repo_a, "git cherry-pick HEAD", 2, "shared branch `main`", silent=False)
        on_repo(repo_a, "git rebase feature/topic", 2, "shared branch `main`", silent=False)
        on_repo(repo_a, "git branch -f main HEAD", 2, "moving a local shared-branch ref", silent=False)
        on_repo(repo_a, "git update-ref refs/heads/main HEAD", 2, "raw update-ref", silent=False)

        # `git -C` and a leading literal `cd` must bind policy to repo B, not
        # reuse repo A's branch or config. Repo B has no profile yet, so its
        # main commit remains unaffected by repo A's opt-in configuration.
        default_b = subprocess.run(
            ["git", "-C", str(repo_b), "branch", "--show-current"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        if default_b != "main":
            _git(repo_b, "checkout", "-qb", "main")
        on_repo(repo_a, f"git -C {repo_b} commit -m other-repo-default", 0, silent=True)
        on_repo(repo_a, f"cd {repo_b} && git commit -m other-repo-default", 0, silent=True, cwd=root)

        configure(repo_b)
        _git(repo_b, "checkout", "-qb", "dev")
        on_repo(repo_a, f"git -C {repo_b} commit -m other-repo-dev", 2, "shared branch `dev`", silent=False)
        on_repo(repo_a, f"cd {repo_b} && git cherry-pick HEAD", 2, "shared branch `dev`", silent=False, cwd=root)
        # Nested shells cannot preserve the caller's actual `cd` scope in the
        # visitor stream; active policy rejects rather than guessing.
        on_repo(repo_a, f"bash -c 'git -C {repo_b} commit -m wrapped'", 2, "cannot bind", silent=False)


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


def test_branch_policy_full_gh_hook_binds_origin_and_cd_context() -> None:
    """The merge hook queries the origin repo for the command's effective cwd."""
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        repo_a = root / "repo-a"
        repo_b = root / "repo-b"
        repo_a.mkdir()
        repo_b.mkdir()
        fake_bin = root / "bin"
        fake_bin.mkdir()
        _init_repo(repo_a)
        _init_repo(repo_b)

        def prepare(repo: Path, slug: str) -> str:
            _git(repo, "remote", "set-url", "origin", f"https://github.com/{slug}.git")
            branch = subprocess.run(
                ["git", "-C", str(repo), "branch", "--show-current"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            if branch != "main":
                _git(repo, "checkout", "-qb", "main")
            _git(repo, "checkout", "-qb", "feature/topic")
            (repo / "README.md").write_text(f"feature {slug}\n", encoding="utf-8")
            _git(repo, "commit", "-qam", "feature commit")
            hooks = repo / ".claude" / "hooks"
            hooks.parent.mkdir(parents=True)
            shutil.copytree(HOOKS, hooks)
            policy_path = hooks / "policy.json"
            policy = json.loads(policy_path.read_text(encoding="utf-8"))
            policy["repository"] = slug
            policy["branchPolicy"] = {
                "profile": "project-alpha-v1",
                "integrationBranch": "dev",
                "stableBranch": "main",
                "protectedPaths": [".claude/**", ".github/workflows/**", "scripts/**"],
            }
            policy_path.write_text(json.dumps(policy, indent=2) + "\n", encoding="utf-8")
            return subprocess.run(
                ["git", "-C", str(repo), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()

        head_a = prepare(repo_a, "owner/repo-a")
        head_b = prepare(repo_b, "owner/repo-b")
        gh = fake_bin / "gh"
        gh.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, sys\n"
            "args = sys.argv[1:]\n"
            "if args[:2] == ['repo', 'view']:\n"
            "    repo = args[2]\n"
            "    assert '--repo' not in args\n"
            "    print(repo)\n"
            "elif args[:2] == ['pr', 'view']:\n"
            "    assert args[2] == os.environ['BRANCH_POLICY_FAKE_BRANCH']\n"
            "    assert args[3] == '--repo'\n"
            "    repo = args[4]\n"
            "    assert '--hostname' not in args\n"
            "    print(json.dumps({'number': 41, 'state': 'OPEN', 'baseRefName': 'dev', "
            "'headRefName': os.environ['BRANCH_POLICY_FAKE_BRANCH'], "
            "'headRefOid': os.environ['BRANCH_POLICY_FAKE_HEAD'], "
            "'headRepository': {'nameWithOwner': repo}}))\n"
            "else:\n"
            "    raise SystemExit('unsupported fake gh argv: ' + repr(args))\n",
            encoding="utf-8",
        )
        gh.chmod(0o755)

        def run_merge(
            repo: Path,
            head: str,
            command: str,
            expected: int,
            *messages: str,
            env=None,
            cwd=None,
            silent: bool = False,
        ):
            run_hook(
                "block-gh-unsafe.sh",
                {
                    "tool_name": "Bash",
                    "tool_input": {"command": command},
                    "cwd": str(cwd or repo),
                },
                expected,
                *messages,
                silent=silent,
                hooks_dir=repo / ".claude" / "hooks",
                project_dir=repo,
                env={
                    "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
                    "BRANCH_POLICY_FAKE_HEAD": head,
                    "BRANCH_POLICY_FAKE_BRANCH": "feature/topic",
                    **(env or {}),
                },
            )

        merge_command = f"gh pr merge --squash --match-head-commit {head_a}"
        run_merge(repo_a, head_a, merge_command, 0, silent=True)
        run_merge(
            repo_a,
            head_a,
            merge_command,
            2,
            "cannot bind this merge",
            env={"GH_REPO": "owner/repo-b"},
        )
        run_merge(
            repo_a,
            head_a,
            "gh -R owner/repo-b pr merge --squash --match-head-commit " + head_a,
            2,
            "explicit gh repository overrides",
        )
        run_merge(
            repo_a,
            head_a,
            "gh ship --squash --match-head-commit " + head_a,
            2,
            "unknown GH command/alias",
        )
        run_merge(
            repo_a,
            head_a,
            "GH_REPO=owner/repo-b " + merge_command,
            2,
            "cannot bind this merge",
        )
        run_merge(
            repo_a,
            head_b,
            f"cd {repo_b} && gh pr merge --squash --match-head-commit {head_b}",
            0,
            silent=True,
            cwd=root,
        )


def test_branch_policy_full_git_hook_uses_pinned_policy_authoritatively() -> None:
    """A pinned policy wins over absent/changed local JSON and never fails open."""
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        repo = root / "repo"
        repo.mkdir()
        _init_repo(repo)
        branch = subprocess.run(
            ["git", "-C", str(repo), "branch", "--show-current"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        if branch != "main":
            _git(repo, "checkout", "-qb", "main")
        _git(repo, "checkout", "-qb", "dev")
        hooks = repo / ".claude" / "hooks"
        hooks.parent.mkdir(parents=True)
        shutil.copytree(HOOKS, hooks)
        local_policy_path = hooks / "policy.json"
        local_policy = json.loads(local_policy_path.read_text(encoding="utf-8"))
        pinned_root = root / "policy-cache"
        pinned_hooks = pinned_root / ".claude" / "hooks"
        pinned_hooks.mkdir(parents=True)
        strict_policy = {
            "repository": "authoritative pinned policy",
            "branchPolicy": {
                "profile": "project-alpha-v1",
                "integrationBranch": "dev",
                "stableBranch": "main",
                "protectedPaths": [".claude/**", ".github/workflows/**", "scripts/**"],
            },
        }
        pinned_policy_path = pinned_hooks / "policy.json"
        pinned_policy_path.write_text(json.dumps(strict_policy), encoding="utf-8")
        command = bash("git push -u origin dev")

        def check(
            payload,
            expected: int,
            *messages: str,
            policy_dir: Path,
            silent: bool = False,
        ) -> None:
            run_hook(
                "block-git-unsafe.sh",
                payload,
                expected,
                *messages,
                hooks_dir=hooks,
                project_dir=repo,
                silent=silent,
                env={"MULTICA_POLICY_DIR": str(policy_dir)},
            )

        # Local file absent and then changed to a profile-free JSON must not
        # override the trusted active policy.
        local_policy_path.unlink()
        check(command, 2, "direct pushes to integration", policy_dir=pinned_root)
        local_policy_path.write_text(json.dumps(local_policy), encoding="utf-8")
        check(command, 2, "direct pushes to integration", policy_dir=pinned_root)

        # A valid authoritative policy with no profile is a real default, even
        # if a working-tree policy attempts to opt in.
        pinned_policy_path.write_text(json.dumps({"repository": "pinned default"}), encoding="utf-8")
        local_policy_path.write_text(json.dumps(strict_policy), encoding="utf-8")
        check(command, 0, silent=True, policy_dir=pinned_root)

        # An explicitly missing or unreadable pinned policy is an error, never
        # evidence that the profile is absent in local JSON.
        pinned_policy_path.unlink()
        check(command, 2, "could not inspect Git aliases safely", policy_dir=pinned_root)
        pinned_policy_path.write_text("{ invalid", encoding="utf-8")
        check(command, 2, "could not inspect Git aliases safely", policy_dir=pinned_root)


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
        'gh pr merge <n> --rebase --match-head-commit <sha> --body "<title> (#<n>)"',
        "otherwise hand the PR to its merging owner",
    )
    run_hook(
        "block-attribution.sh",
        bash("gh pr merge 12 --rebase --match-head-commit abc"),
        2,
        "without an explicit body",
    )
    run_hook(
        "block-attribution.sh",
        bash('gh pr merge 12 --rebase --match-head-commit abc --body "Add x (#12)"'),
        0,
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

    # The bridge supplies the whole raw file as Edit.old_string. Preserve CRLF
    # while reading so that this exact anchor is reconstructable; the content
    # policy must still inspect the reconstructed candidate.
    with tempfile.TemporaryDirectory() as raw:
        repo = Path(raw)
        _init_repo(repo)
        hooks = repo / ".claude" / "hooks"
        hooks.parent.mkdir(parents=True)
        shutil.copytree(HOOKS, hooks)
        fixture_policy = json.loads((hooks / "policy.json").read_text(encoding="utf-8"))
        fixture_policy["taskIdentifiers"]["paths"] = ["**/*.bat"]
        fixture_policy["comments"]["paths"] = ["**/*.yaml"]
        fixture_policy["comments"]["suffixes"] = [".yaml"]
        (hooks / "policy.json").write_text(json.dumps(fixture_policy), encoding="utf-8")

        for newline in ("\n", "\r\n"):
            batch = repo / ("lf" if newline == "\n" else "crlf") / "bootstrap.bat"
            batch.parent.mkdir()
            original = newline.join(("set CLIENT_VERSION=1.12.31.1", "set CLIENT_HASH=oldhash", ""))
            candidate = newline.join(("set CLIENT_VERSION=1.13.6", "set CLIENT_HASH=newhash", ""))
            batch.write_bytes(original.encode("utf-8"))
            subprocess.run(["git", "add", str(batch.relative_to(repo))], cwd=repo, check=True)
            run_hook(
                "block-config-commentary.sh",
                {"tool_name": "Edit", "tool_input": {
                    "file_path": str(batch), "old_string": original, "new_string": candidate,
                }},
                0,
                silent=True,
                hooks_dir=hooks,
                project_dir=repo,
            )

            task_id = fixture_policy["taskIdentifiers"]["prefixes"][0] + "-123"
            denied = candidate.replace(
                "set CLIENT_HASH=newhash",
                "set CLIENT_HASH=newhash" + newline + "rem " + task_id,
            )
            run_hook(
                "block-config-commentary.sh",
                {"tool_name": "Edit", "tool_input": {
                    "file_path": str(batch), "old_string": original, "new_string": denied,
                }},
                2,
                "task identifier",
                hooks_dir=hooks,
                project_dir=repo,
            )

        bom_batch = repo / "bom" / "bootstrap.bat"
        bom_batch.parent.mkdir()
        bom_original = "\ufeff" + "set CLIENT_VERSION=1.12.31.1\r\nset CLIENT_HASH=oldhash\r\n"
        bom_candidate = "\ufeff" + "set CLIENT_VERSION=1.13.6\r\nset CLIENT_HASH=newhash\r\n"
        bom_batch.write_bytes(bom_original.encode("utf-8"))
        subprocess.run(["git", "add", str(bom_batch.relative_to(repo))], cwd=repo, check=True)
        run_hook(
            "block-config-commentary.sh",
            {"tool_name": "Edit", "tool_input": {
                "file_path": str(bom_batch), "old_string": bom_original, "new_string": bom_candidate,
            }},
            0,
            silent=True,
            hooks_dir=hooks,
            project_dir=repo,
        )

        invalid_utf8 = repo / "broken" / "bootstrap.bat"
        invalid_utf8.parent.mkdir()
        invalid_utf8.write_bytes(b"\xff\xfe")
        subprocess.run(["git", "add", str(invalid_utf8.relative_to(repo))], cwd=repo, check=True)
        run_hook(
            "block-config-commentary.sh",
            write(invalid_utf8, "set CLIENT_VERSION=1.13.6\n"),
            2,
            "cannot read",
            hooks_dir=hooks,
            project_dir=repo,
        )

        yaml_path = repo / "config" / "guarded.yaml"
        yaml_path.parent.mkdir()
        yaml_path.write_text("key: value\n", encoding="utf-8")
        run_hook(
            "block-config-commentary.sh",
            write(yaml_path, "key: value\n# rationale\n"),
            2,
            "adds a comment",
            hooks_dir=hooks,
            project_dir=repo,
        )


def test_require_validation_before_git(policy: Policy) -> None:
    def validation_call(command: str, call_id: str = "validation", **fields) -> dict:
        entry = assistant(("Bash", {"command": command, **fields}))
        entry["message"]["content"][0]["id"] = call_id
        return entry

    def validation_result(call_id: str = "validation", *, tool_use_result=None, **fields) -> dict:
        entry = {"type": "user", "message": {"content": [
            {"type": "tool_result", "tool_use_id": call_id, "content": "ok", **fields}
        ]}}
        if tool_use_result is not None:
            entry["toolUseResult"] = tool_use_result
        return entry

    # Exercise the contract even in adopters that switch their commit gate off.
    # This policy exists only in an isolated scratch checkout.
    with tempfile.TemporaryDirectory() as raw:
        repo = Path(raw)
        _init_repo(repo)
        policy_dir = repo / ".claude" / "hooks"
        shutil.copytree(HOOKS, policy_dir)
        fixture = json.loads((HOOKS / "policy.json").read_text(encoding="utf-8"))
        fixture["validation"] = {"commandPattern": "validate-surface", "hint": "validate-surface"}
        (policy_dir / "policy.json").write_text(json.dumps(fixture), encoding="utf-8")
        target = repo / "tracked.txt"
        target.write_text("x", encoding="utf-8")
        subprocess.run(["git", "add", "tracked.txt"], cwd=repo, check=True)
        wrote = assistant(("Write", {"file_path": str(target), "content": "x"}))
        v = "validate-surface"

        def check(pending: str, history: list[dict], expected: int, *messages: str) -> None:
            run_hook(
                "require-validation-before-git.sh",
                {**bash(pending), "transcript_path": transcript(repo, wrote, *history), "cwd": str(repo)},
                expected, *messages, hooks_dir=policy_dir, project_dir=repo, silent=expected == 0,
            )

        for content in ("ok", [{"type": "text", "text": "ok"}]):
            check("git commit -m x", [validation_call(v), validation_result(is_error=False, content=content)], 0)
        check("git commit -m x", [validation_call(v), validation_result(is_error=True)], 2, "failed")
        check("git commit -m x", [validation_call(v)], 2, "no recorded result")
        check("git commit -m x", [validation_call(v), validation_result()], 2, "no recorded result")
        check("git commit -m x", [validation_call(v), validation_result("other", is_error=False)], 2, "no recorded result")
        check("git commit -m x", [validation_call(v), validation_result(is_error=0)], 2, "no recorded result")
        check("git commit -m x", [validation_call(v, run_in_background=True),
              validation_result(is_error=False), validation_result(is_error=False)],
              2, "ran in the background or was interrupted", "foreground", "timeout long enough to finish")
        # Claude Code can append a duplicate success entry without metadata.
        # Cover both explicit async and timeout-to-background results, and both
        # orders, so no later duplicate can clear the unknown-status marker.
        for metadata in (
            {"interrupted": False, "backgroundTaskId": "background-validation"},
            {"interrupted": True},
        ):
            marked = validation_result(is_error=False, tool_use_result=metadata)
            duplicate = validation_result(is_error=False)
            for results in ([marked, duplicate], [duplicate, marked]):
                check("git commit -m x", [validation_call(v), *results], 2,
                      "ran in the background or was interrupted", "foreground", "timeout long enough to finish")
        check("git commit -m x", [validation_call(v), validation_result(is_error=True),
              validation_result(is_error=False)], 2, "failed")
        check("git commit -m x", [validation_call(v),
              validation_result(is_error=False, tool_use_result={"interrupted": False}),
              validation_result(is_error=False)], 0)
        for pending in (
            f"{v}; git commit", f"{v}\ngit commit", f"{v} || git commit",
            f"true || {v} && git commit", f"{v} | tail -5 && git commit",
            f"git commit -m x && {v}",
        ):
            check(pending, [], 2, "`git commit` is gated", "unpiped", "`&&`")
        for previous in (
            f"{v}; echo done", f"{v} | tail -5", f"{v} || true", f"! {v}",
            f"bash -c '{v}; true'", f"if {v}; then :; fi", f"{v} &",
            f"({v})", f"{{ {v}; }}", f"eval '{v}; true'",
            f"env bash -c '{v}; true'", f"timeout 5 bash -c '{v}; true'",
            f"find . -name '*.sh' -exec {v} {{}} \\;",
        ):
            check("git commit -m x", [validation_call(previous), validation_result(is_error=False)],
                  2, "shape that hides", "unpiped", "`&&`")
        check("git commit -m x", [validation_call(v), validation_result(is_error=False),
              validation_call(v, "latest"), validation_result("latest", is_error=True)], 2, "failed")
        for pending in (
            f"{v} && git commit", f"{v} && git add -A && git commit -m x",
            f"{v} && git commit -m x || echo failed", f"cd sub && {v} && git commit",
            f"cd sub; {v} && git commit", f"{v} 2>&1 && git commit",
        ):
            check(pending, [], 0)
        for previous in (v, f"cd sub; {v}", f"{v} 2>&1", f"{v} > log 2>&1", f"MODE=test {v}"):
            check("git commit -m x", [validation_call(previous), validation_result(is_error=False)], 0)
        check(f"{v}; git commit", [validation_call(v), validation_result(is_error=False)], 0)
        # Whole-command matching remains necessary for anchored adopter patterns.
        fixture["validation"]["commandPattern"] = "^validate-surface$"
        (policy_dir / "policy.json").write_text(json.dumps(fixture), encoding="utf-8")
        check(f"{v} && git commit", [], 2, "`git commit` is gated")
        check("git commit -m x", [validation_call(v), validation_result(is_error=False)], 0)

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
            validation_call(command),
            validation_result(is_error=False),
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
    """Prefer commands inside Markdown backticks over prose that names them."""
    words = [
        token.strip("`,.;:()")
        for token in hint.replace("`", " ` ").split()
        if token.strip("`,.;:()")
    ]
    fragments = hint.split("`")[1::2] + [hint]
    for size in (4, 3, 2, 1):
        fragments.extend(
            " ".join(words[start : start + size]) for start in range(0, max(len(words) - size + 1, 0))
        )
    return [fragment for fragment in fragments if fragment]


def _git(directory: Path, *arguments: str, check: bool = True) -> None:
    subprocess.run(["git", *arguments], cwd=directory, check=check, capture_output=True)


def test_settings_registers_every_hook() -> None:
    global TESTS
    settings = json.loads((ROOT / ".claude" / "settings.json").read_text(encoding="utf-8"))
    registered = {
        Path(entry["command"].split('"')[1]).name
        for event in settings.get("hooks", {}).values()
        for matcher in event
        for entry in matcher.get("hooks", [])
        if isinstance(entry.get("command"), str)
    }
    required = {
        "block-config-commentary.sh",
        "pre-bash.sh",
    }
    missing = required - registered
    assert not missing, f".claude/settings.json does not register: {sorted(missing)}"
    # Claude Code lets the tool call through when a hook crashes or times out,
    # unless the entry says otherwise.
    for matcher in settings["hooks"]["PreToolUse"]:
        for entry in matcher["hooks"]:
            name = Path(entry["command"].split('"')[1]).name
            if name not in required:
                continue
            assert entry.get("onFailure") == "block", (
                f'{name} is registered without "onFailure": "block"'
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
# then the commit the gate is asked about). Three things were changed after
# capture: the working directory became @REPO@, and call-2's command is
# swapped for this repository's own validator at run time, and call-2's result
# carries is_error: false to record its success. The tool_result
# content is a plain string here, where Claude Code writes a block list; the
# readers must accept both.
BRIDGE_TRANSCRIPT = r'''
{"type":"user","uuid":"137ffce5-1d51-48d7-b5c7-9df69ebe592c","sessionId":"ses_bridge","cwd":"@REPO@","timestamp":"2026-10-09T01:28:41.564Z","message":{"role":"user","content":[{"type":"text","text":"Add the greeting helper to hello.py"}]}}
{"type":"assistant","uuid":"c2e9501f-f596-4db3-96b6-b37fd6918830","sessionId":"ses_bridge","cwd":"@REPO@","timestamp":"2026-10-09T01:28:41.567Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"call-1","name":"Edit","input":{"file_path":"@REPO@/hello.py","old_string":"","new_string":"def greet():\n    return 'hi'\n"}}]}}
{"type":"user","uuid":"62acf5b9-e741-43bc-9bf2-064f0d938d93","sessionId":"ses_bridge","cwd":"@REPO@","timestamp":"2026-10-09T01:28:41.568Z","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"call-1","content":"Edit applied successfully."}]}}
{"type":"assistant","uuid":"7cebda03-6c06-4452-8e6b-f4bea247e4e3","sessionId":"ses_bridge","cwd":"@REPO@","timestamp":"2026-10-09T01:28:41.568Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"call-2","name":"Bash","input":{"command":"python3 scripts/test-agent-hooks.py"}}]}}
{"type":"user","uuid":"5c0330a5-6f2d-45a2-98c8-ab464bac0f04","sessionId":"ses_bridge","cwd":"@REPO@","timestamp":"2026-10-09T01:28:41.568Z","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"call-2","is_error":false,"content":"ok"}]}}
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


# --------------------------------------------------------------------------
# Generic cases — heredoc and here-string scripts passed to shells
# --------------------------------------------------------------------------


def test_shell_stdin_scripts(policy: Policy) -> None:
    blocked = policy.blocked_commands
    deny_shapes = (
        "bash <<EOF\n{cmd}\nEOF",
        "bash <<'EOF'\n{cmd}\nEOF",
        "bash <<\\EOF\n{cmd} get\nEOF",
        "bash <<-'EOF'\n\t{cmd}\n\tEOF",
        "sh <<EOF\n{cmd}\nEOF",
        "bash -s <<'EOF'\n{cmd}\nEOF",
        "bash -s -- a b <<'EOF'\n{cmd}\nEOF",
        "bash -euo pipefail <<'EOF'\n{cmd}\nEOF",
        "env bash <<'EOF'\n{cmd}\nEOF",
        "/bin/bash <<'EOF'\n{cmd}\nEOF",
        "timeout 5 bash <<'EOF'\n{cmd}\nEOF",
        "x=$(bash <<'EOF'\n{cmd}\nEOF\n)",
        "bash <<'EOF'\nset -e\nif true; then\n  {cmd} get\nfi\nEOF",
        "bash <<'EOF'\n# comment\n{cmd}\nEOF",
        "bash <<'A'\nbash <<'B'\n{cmd}\nB\nA",
        "bash <<EOF\necho $({cmd})\nEOF",
        "bash <<EOF\nc={cmd}; $c\nEOF",
        "bash <<<{cmd}",
        "bash -s <<<{cmd}",
        "bash <<'EOF' 2>&1\n{cmd}\nEOF",
        "bash >out <<'EOF'\n{cmd}\nEOF",
        "bash 2>&1 <<'EOF'\n{cmd}\nEOF",
        "bash 2>/dev/null <<'EOF'\n{cmd}\nEOF",
        "bash &>out <<'EOF'\n{cmd}\nEOF",
        "bash <<'EOF' 2>&1 | tee out\n{cmd}\nEOF",
        "bash <<'EOF' && echo done\n{cmd}\nEOF",
        "bash <<'EOF'\n({cmd})\nEOF",
        "bash <<'EOF'\n(cd . && {cmd})\nEOF",
        "bash <<'EOF'\necho hi; {cmd}\nEOF",
        "bash <<'EOF'\nf() {{\n  {cmd}\n}}\nf\nEOF",
        "bash --norc <<'EOF'\n{cmd}\nEOF",
        "bash - <<'EOF'\n{cmd}\nEOF",
        "bash -x -e <<'EOF'\n{cmd}\nEOF",
        "bash -o pipefail <<'EOF'\n{cmd}\nEOF",
        "echo a && bash <<'EOF'\n{cmd}\nEOF",
        "if true; then bash <<'EOF'\n{cmd}\nEOF\nfi",
        'echo "$(bash <<\'EOF\'\n{cmd}\nEOF\n)"',
        "bash <<EOF\n{cmd} $(echo a)\nEOF",
        "git status; bash <<'EOF'\ngit status\n{cmd}\nEOF",
        "bash <<'EOF'\n# comment with don't\n{cmd}\nEOF",
        "bash <<'EOF'\n# note \\\n{cmd}\nEOF",
        "bash <<'EOF'\ncase a in\n  a) {cmd} ;;\nesac\nEOF",
        "bash <<EOF\necho \\$({cmd})\nEOF",
        "bash <<EOF\nc={cmd}; \\$c\nEOF",
        "bash <<<'{cmd} get'",
        "o=--; bash <<EOF\ncommand $o {cmd}\nEOF",
        "bash <<'EOF' | tee out\n{cmd}\nEOF",
        "bash <<'EOF'\ncase a in\n  *) {cmd} ;;\nesac\nEOF",
        "bash <<'EOF'\nf() {\n  {cmd}\n}\nf\nEOF",
        "bash <<'EOF'\necho a \\\n  && {cmd}\nEOF",
        "bash <<<'{cmd} get' | tee out",
        "bash <<<'echo a; {cmd}'",
        'bash <<<"{cmd}"',
        "bash -euo pipefail <<<{cmd}",
        "bash -o pipefail <<<{cmd}",
        "bash -s a b <<<{cmd}",
        "bash 2>&1 <<<{cmd}",
        "bash >out <<<{cmd}",
        "bash &>out <<<{cmd}",
        "bash <<<{cmd} 2>&1",
        "bash <<<'echo a; {cmd}' | tee out",
        "env bash <<<{cmd}",
        "timeout 5 bash <<<{cmd}",
        "bash <<'EOF'\n$CMD arg\n{cmd}\nEOF",
        "bash <<'EOF'\nrun() { \"$@\"; }\n{cmd} get\nEOF",
        "bash <<'EOF'\n$HOME/bin/tool\n(cd . && {cmd})\nEOF",
        "bash <<'EOF'\necho \"in case of\"\n({cmd})\nEOF",
        "bash <<'EOF'\ncase a in\n  \"a b\") echo ;;\n  a) {cmd} ;;\nesac\nEOF",
    )
    for name in blocked:
        for shape in deny_shapes:
            run_hook("block-runtime.sh", bash(shape.replace("{cmd}", name)), 2, name)

    script_dynamic = (
        "bash <<'EOF'\nrun() { \"$@\"; }\nrun echo hi\nEOF",
        "bash <<'EOF'\n$HOME/bin/tool --help\nEOF",
        "bash <<'EOF'\n\"$HOME/bin/tool\" --help\nEOF",
        "bash <<'EOF'\nROOT=$(git rev-parse --show-toplevel)\n\"$ROOT/scripts/x.sh\" arg\nEOF",
        "bash <<'EOF'\ncd \"$(dirname \"$0\")\"\n./x.sh\nEOF",
        "bash <<'EOF'\n$CMD arg\nEOF",
        "bash <<'EOF'\nPY=${PYTHON:-python3}\n$PY -c 'print(1)'\nEOF",
        "bash <<'EOF'\nfor t in jq yq; do $t --version; done\nEOF",
        "bash <<'EOF'\nfor s in a.sh b.sh; do \"./$s\"; done\nEOF",
        "bash <<'EOF'\nwhile read -r c; do $c; done < list\nEOF",
        "bash <<EOF\n$HOME/bin/tool --help\nEOF",
        'bash <<<"$script"',
        "bash <<<'$CMD arg'",
        'bash -s <<<"$(cat s.sh)"',
        "bash <<'EOF'\ncase $x in\n  \"a b\") echo y ;;\n  $p) echo z ;;\n  \"$q\") echo w ;;\nesac\nEOF",
        "bash <<'EOF'\ncase $x in\n  'it''s') echo y ;;\n  a|\"b c\") echo z ;;\nesac\nEOF",
        "bash <<'EOF'\n{a,b}/x.sh\nEOF",
        "bash <<'EOF'\n[[ -n $x ]] && echo y\n[ -f f ] || echo n\nEOF",
        "bash <<'EOF'\nfunction f { echo hi; }\nf\nEOF",
        "bash <<'EOF'\nenv -S 'echo hi'\nEOF",
        "bash <<'EOF'\narr=(a b)\necho ${arr[@]}\nEOF",
        "bash <<'EOF'\nx=$(cat <<Y\nhello\nY\n)\necho $x\nEOF",
        'bash <<\'EOF\'\necho "unbalanced ( paren"\necho \'a;b\'\nEOF',
    )
    for script in script_dynamic:
        run_hook("block-runtime.sh", bash(script), 0, silent=True)

    allowed_shell_scripts = (
        "bash <<'EOF'\n# don't touch this; fakecli stays out\nset -euo pipefail\nfor f in a b; do\n echo \"$f\"\ndone\nEOF",
        "bash <<'EOF'\nif [ -f x ]; then\n echo yes\nelse\n echo no\nfi\nEOF",
        "bash <<'EOF'\ncase $1 in\n a) echo a ;;\n *) echo b ;;\nesac\nEOF",
        "bash <<'EOF'\nf() {\n echo hi\n}\nf\nEOF",
        "bash <<'EOF'\necho it's fine # trailing\nEOF",
        "bash <<'EOF'\necho hi # don't\nEOF",
        "bash <<'EOF'\ncat <<X\nfakecli in nested data\nX\nEOF",
        "bash <<'EOF'\nmsg=\"one\ntwo\"\necho \"$msg\"\nEOF",
        "bash <<EOF\necho \\$HOME \\$(date)\nEOF",
        "bash s.sh <<EOF\nfakecli as data\nEOF",
        "bash -c 'cat' <<EOF\nfakecli as data\nEOF",
        "python3 <<'EOF'\nimport os\nprint('fakecli')\nEOF",
        "cat <<'EOF' > s.sh\nfakecli get pods\nEOF",
        "git commit -m \"$(cat <<'EOF'\nfakecli body\nEOF\n)\"",
        "x=$(bash <<'EOF'\necho hi\nEOF\n); echo $x",
        "bash <<<'echo hi'",
        "bash -s <<<'echo hi'",
        "bash s.sh <<<fakecli",
        "cat <<<fakecli",
        "grep -c fakecli <<<fakecli",
        "bash -euo pipefail <<'EOF'\necho hi\nEOF",
        "bash >out <<'EOF'\necho hi\nEOF",
        "bash 2>&1 <<'EOF'\necho hi\nEOF",
        "bash <<'EOF' 2>&1 | tee out\necho hi\nEOF",
        "bash <<'EOF'\n(cd . && echo hi)\nEOF",
        "bash <<'EOF'\ncase a in\n a|b) echo x ;;\n (c) echo y ;;\n f*) echo z ;;\n *) echo w ;;\nesac\nEOF",
        "bash <<'EOF'\necho \"# not a comment\"\nEOF",
        "bash <<'EOF'\ncat > f <<'X'\nit's fakecli\nX\necho hi\nEOF",
        "bash <<'EOF'\nprintf '%s\\n' 'fakecli' | wc -l\nEOF",
        "bash <<'EOF'\nmsg='first\nfakecli named at line start\nlast'\necho \"$msg\"\nEOF",
        "echo $((1<<2)); bash <<'EOF'\necho hi\nEOF",
        "cat <<'EOF' 2>&1\nfakecli\nEOF",
        "cat 2>&1 <<'EOF'\nfakecli\nEOF",
        "tee f >/dev/null <<'EOF'\nfakecli\nEOF",
        "ssh-keygen -h 2>/dev/null <<'EOF' || true\nfakecli\nEOF",
        "bash s.sh 2>&1 <<'EOF'\nfakecli as data\nEOF",
        "bash -c 'cat' 2>&1 <<'EOF'\nfakecli as data\nEOF",
        "bash s.sh <<<fakecli",
        "bash -c cat <<<fakecli",
    )
    for name in blocked:
        for script in allowed_shell_scripts:
            run_hook(
                "block-runtime.sh", bash(script.replace("fakecli", name)), 0, silent=True
            )

    script_positive = (
        "bash <<'EOF'\ncase $t in\n  fakecli) echo y ;;\n  git|fakecli) echo z ;;\nesac\nEOF",
        "bash <<'EOF'\nif command -v fakecli >/dev/null; then echo y; fi\nEOF",
        "bash <<'EOF'\ncommand -v fakecli || echo none\nEOF",
        "bash <<'EOF'\nwhich fakecli; type fakecli\nEOF",
        "bash <<'EOF'\nfor t in fakecli git; do echo $t; done\nEOF",
        "bash <<'EOF'\necho fakecli\nprintf '%s\\n' fakecli\nEOF",
        "bash <<'EOF'\nmsg=\"run\\nfakecli later\"\necho \"$msg\"\nEOF",
        "bash <<'EOF'\nmsg='run\\nfakecli later'\n$CMD\necho \"$msg\"\nEOF",
        "bash <<'EOF'\n: <<'NOTE'\nfakecli notes\nNOTE\necho hi\nEOF",
        "bash <<'EOF'\ngrep -q fakecli f && echo y\nEOF",
        "bash <<'EOF'\nexport TOOL=fakecli\necho $TOOL\nEOF",
        "bash <<'EOF'\nTOOL=fakecli\necho $TOOL\nEOF",
        "bash <<'EOF'\necho a |\n  tr a b\nEOF",
        # Original v3 script-positive[11] and [12]: actual newlines in strings.
        "bash <<'EOF'\nmsg=\"run\nfakecli later\"\necho \"$msg\"\nEOF",
        "bash <<'EOF'\nmsg='run\nfakecli later'\n$CMD\necho \"$msg\"\nEOF",
    )
    for name in blocked:
        for script in script_positive:
            run_hook("block-runtime.sh", bash(script.replace("fakecli", name)), 0, silent=True)

    for script in (
        "bash <<'EOF'\nset -euo pipefail\nfor f in a b; do\n echo \"$f\"\ndone\nEOF",
        "bash <<'EOF'\nif [ -f x ]; then\n echo yes\nelse\n echo no\nfi\nEOF",
        "bash <<'EOF'\ncase $1 in\n a) echo a ;;\n *) echo b ;;\nesac\nEOF",
        "bash <<'EOF'\necho it's fine # trailing\nEOF",
        "bash <<'EOF'\ncat <<X\nfakecli in nested data\nX\necho hi\nEOF",
        "bash <<'EOF'\nmsg=\"one\ntwo\"\necho \"$msg\"\nEOF",
        "bash s.sh <<EOF\nfakecli as data\nEOF",
        "bash -c 'cat' <<EOF\nfakecli as data\nEOF",
        "cat <<'EOF' > s.sh\nfakecli get pods\nEOF",
        "python3 <<'EOF'\nprint('fakecli')\nEOF",
        "bash <<'EOF'\n(cd . && echo hi)\nEOF",
        "bash <<'EOF'\necho \"# not a comment\"\nEOF",
        "bash <<'EOF'\nprintf '%s\\n' 'fakecli' | wc -l\nEOF",
        "bash <<'EOF'\ncase a in\n a|b) echo x ;;\n (c) echo y ;;\n f*) echo z ;;\n *) echo w ;;\nesac\nEOF",
    ):
        run_hook("block-runtime.sh", bash(script), 0, silent=True)

    run_hook(
        "block-git-unsafe.sh",
        bash("bash <<'EOF'\ngit push --force origin main\nEOF"),
        2,
        "force-pushing",
    )
    run_hook(
        "block-git-unsafe.sh", bash("bash <<'EOF'\ngit status\nEOF"), 0, silent=True
    )


# --------------------------------------------------------------------------
# Generic cases — the single Bash entrypoint fails closed
# --------------------------------------------------------------------------


def _hooks_copy(raw: str) -> Path:
    broken = Path(raw) / "hooks"
    shutil.copytree(HOOKS, broken, ignore=shutil.ignore_patterns("__pycache__"))
    return broken


def test_pre_bash_entrypoint_runs_every_rule_and_fails_closed() -> None:
    global TESTS
    # The registered command, with no `--only`: allow and deny both come out.
    run_hook("pre-bash.sh", bash("echo hi"), 0, silent=True)
    run_hook("pre-bash.sh", bash("kubectl get pods"), 2, "kubectl")
    run_hook("pre-bash.sh", bash("git push --force origin main"), 2, "force-pushing")
    run_hook("pre-bash.sh", "not json", 2, "submit a valid tool payload")

    deny = bash("git push --force origin main")
    with tempfile.TemporaryDirectory() as raw:
        broken = _hooks_copy(raw)
        rule = broken / "lib" / "runtime_rule.py"
        original = rule.read_text(encoding="utf-8")

        rule.unlink()
        run_hook("pre-bash.sh", bash("echo hi"), 2, "internal hook failure", hooks_dir=broken)
        run_hook("pre-bash.sh", deny, 2, "force-pushing", hooks_dir=broken)

        rule.write_text("def run(payload_text):\n    raise RuntimeError('boom')\n", encoding="utf-8")
        run_hook("pre-bash.sh", bash("echo hi"), 2, "boom", hooks_dir=broken)
        run_hook("pre-bash.sh", deny, 2, "force-pushing", hooks_dir=broken)

        # An early successful exit must not stop the rules after it.
        rule.write_text("import sys\n\n\ndef run(payload_text):\n    sys.exit(0)\n", encoding="utf-8")
        run_hook("pre-bash.sh", bash("echo hi"), 0, silent=True, hooks_dir=broken)
        run_hook("pre-bash.sh", deny, 2, "force-pushing", hooks_dir=broken)

        rule.write_text("import sys\n\n\ndef run(payload_text):\n    sys.exit(1)\n", encoding="utf-8")
        run_hook("pre-bash.sh", bash("echo hi"), 2, "exited with status 1", hooks_dir=broken)

        rule.write_text(original, encoding="utf-8")
        run_hook("pre-bash.sh", bash("echo hi"), 0, silent=True, hooks_dir=broken)

        # A rule that cannot be told apart from a crash in the entrypoint itself.
        (broken / "pre-bash.py").write_text("def main(:\n", encoding="utf-8")
        run_hook("pre-bash.sh", bash("echo hi"), 2, "internal hook failure", hooks_dir=broken)

    with tempfile.TemporaryDirectory() as raw:
        broken = _hooks_copy(raw)
        empty_path = Path(raw) / "empty-path"
        empty_path.mkdir()
        bash_path = shutil.which("bash")
        assert bash_path, "bash is required to run the hook wrapper"
        result = subprocess.run(
            [bash_path, str(broken / "pre-bash.sh")],
            input=json.dumps(bash("echo hi")),
            text=True,
            capture_output=True,
            check=False,
            env={"PATH": str(empty_path), "CLAUDE_PROJECT_DIR": str(ROOT)},
        )
        assert result.returncode == 2, (
            f"a missing python3 must deny, got {result.returncode}:\n{result.stderr}"
        )
        assert "internal hook failure" in result.stderr, result.stderr
        assert_refusal_hint(result.stderr)
        TESTS += 1

    settings = json.loads((ROOT / ".claude" / "settings.json").read_text(encoding="utf-8"))
    pre_tool_use = settings["hooks"]["PreToolUse"]
    bash_entries = [
        entry["command"]
        for matcher in pre_tool_use
        if matcher["matcher"] == "Bash"
        for entry in matcher["hooks"]
    ]
    assert len(bash_entries) == 1 and bash_entries[0].split('"')[1].endswith("/pre-bash.sh"), (
        f"Bash must register exactly pre-bash.sh, got {bash_entries}"
    )
    TESTS += 1


# --------------------------------------------------------------------------
# Generic cases — tokenizer bypass forms, the ordinary-command corpus and the
# fail-closed registered command
# --------------------------------------------------------------------------


def test_tokenizer_bypass_forms() -> None:
    """Each form that hides a command from the tokenizer is denied where the plain form is."""
    force_push = "[block-git-unsafe] force-pushing"
    admin_merge = "branch protection rules"
    kubectl = "[block-runtime] kubectl is blocked"
    forms = (
        # Denied before and still denied.
        ("git \\\npush --force origin main", force_push),
        ("gh \\\npr merge 1 --admin", admin_merge),
        ("bash <<'E'\nkubectl get pods\nE", kubectl),
        ("sh <<E\ngit push --force origin main\nE", force_push),
        # A leading redirect.
        (">out git push --force", force_push),
        ("2>&1 kubectl delete ns x", kubectl),
        ("ls; >out git push --force", force_push),
        # Wrappers the walker did not know.
        ("setsid kubectl get pods", kubectl),
        ("stdbuf -o0 kubectl get pods", kubectl),
        ("stdbuf -o 0 git push --force origin main", force_push),
        ("busybox sh -c 'kubectl get pods'", kubectl),
        ("script -qc 'kubectl get pods' /dev/null", kubectl),
        ("script --command='git push --force' /dev/null", force_push),
        # A shell fed by a piped heredoc.
        ("cat <<E | bash\nkubectl get pods\nE", kubectl),
        # git's own indirection.
        ("git --attr-source HEAD push --force origin main", force_push),
        ("git -c alias.x='push --force' x origin main", force_push),
        ("git -c alias.x='!git push --force' x", force_push),
        ("git -calias.x='push --force' x origin main", force_push),
    )
    for command, message in forms:
        run_hook("pre-bash.sh", bash(command), 2, message)
    # The same forms around an allowed command stay allowed.
    for command in (
        "git \\\nstatus",
        ">out git status",
        "2>&1 ls",
        "setsid true",
        "stdbuf -o0 true",
        "busybox sh -c 'ls'",
        "script -qc 'ls' /dev/null",
        "bash <<'E'\necho hi\nE",
        "cat <<E | bash\necho hi\nE",
        "git --attr-source HEAD status",
        "git -c alias.st='status -s' st",
    ):
        run_hook("pre-bash.sh", bash(command), 0, silent=True)


def test_ordinary_command_corpus() -> None:
    """Ordinary commands keep the verdict recorded for them.

    The corpus runs in a scratch tree that is not a Git checkout, so a push of
    `HEAD` cannot resolve its branch and is judged the same wherever this suite
    runs.
    """
    corpus = json.loads((ROOT / "scripts" / "fixtures" / "agent-hooks-ordinary-commands.json").read_text())
    assert len(corpus) == 86, len(corpus)
    assert sum(1 for expected in corpus.values() if expected == 0) == 82
    assert sum(1 for expected in corpus.values() if expected == 2) == 4
    with tempfile.TemporaryDirectory() as raw:
        project = Path(raw)
        shutil.copytree(HOOKS, project / ".claude" / "hooks", ignore=shutil.ignore_patterns("__pycache__"))
        for command, expected in corpus.items():
            run_hook(
                "pre-bash.sh",
                bash(command),
                expected,
                hooks_dir=project / ".claude" / "hooks",
                project_dir=project,
            )


def _registered_commands() -> dict[str, str]:
    settings = json.loads((ROOT / ".claude" / "settings.json").read_text(encoding="utf-8"))
    return {
        Path(entry["command"].split('"')[1]).name: entry["command"]
        for matcher in settings["hooks"]["PreToolUse"]
        for entry in matcher["hooks"]
    }


def test_hook_command_suffix_contract() -> None:
    """The checker accepts the quoted path or the one fail-closed suffix, nothing else."""
    global TESTS
    checker = runpy.run_path(str(ROOT / "scripts" / "check-agent-policy.py"))
    parse = checker["hook_command_path"]
    suffix = checker["FAIL_CLOSED_SUFFIX"]
    path = "${CLAUDE_PROJECT_DIR}/.claude/hooks/pre-bash.sh"
    assert parse(f'"{path}"') == (path, "")
    assert parse(f'"{path}"{suffix}') == (path, "")
    for tail in ("; true", f"{suffix}; true", suffix.replace("-eq 2", "-eq 3"), " && true", suffix + " "):
        found, error = parse(f'"{path}"{tail}')
        assert found == path and "unexpected suffix" in error, (tail, found, error)

    def problems(command: str) -> list[str]:
        settings = {
            "hooks": {
                "PreToolUse": [
                    {"matcher": "Bash", "hooks": [{"type": "command", "command": command, "onFailure": "block"}]}
                ]
            }
        }
        return checker["fail_open_entries"](settings)

    assert problems(f'"{path}"{suffix}') == []
    assert any("fail-closed command suffix" in problem for problem in problems(f'"{path}"')), problems(f'"{path}"')
    assert any("unexpected suffix" in problem for problem in problems(f'"{path}"; true')), problems(f'"{path}"; true')
    # Both registered commands are the script path plus that one constant.
    registered = _registered_commands()
    assert set(registered) == {"pre-bash.sh", "block-config-commentary.sh"}, registered
    for name, command in registered.items():
        assert command == f'"${{CLAUDE_PROJECT_DIR}}/.claude/hooks/{name}"{suffix}', (name, command)
    TESTS += 1


def test_registered_hook_command() -> None:
    """Each command string from settings.json, run as Claude Code runs it, fails closed."""
    global TESTS
    payloads = {
        "pre-bash.sh": bash("git status"),
        "block-config-commentary.sh": {"tool_name": "Write", "tool_input": {}},
    }

    def run(project: Path, command: str, payload: dict[str, object], path: str | None = None):
        env = {**os.environ, "CLAUDE_PROJECT_DIR": str(project)}
        if path is not None:
            env["PATH"] = path
        return subprocess.run(
            ["/bin/sh", "-c", command],
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            check=False,
            env=env,
        )

    registered = _registered_commands()
    with tempfile.TemporaryDirectory() as raw:
        scratch = Path(raw)
        empty = scratch / "no-such-dir"
        empty.mkdir()
        for name, command in registered.items():
            # The commands still allow and deny: 0 and 2 pass through.
            allowed = run(ROOT, command, payloads[name])
            assert allowed.returncode == 0 and allowed.stderr == "", (name, allowed)
        denied = run(ROOT, registered["pre-bash.sh"], bash("git push --force origin main"))
        assert denied.returncode == 2 and "[block-git-unsafe] force-pushing" in denied.stderr, denied
        for name, command in registered.items():
            # No bash and no python3 on PATH: env exits 127, which the command turns into 2.
            missing = run(ROOT, command, payloads[name], path=str(empty))
            assert missing.returncode == 2 and "refusing to allow the call" in missing.stderr, (name, missing)
            assert_refusal_hint(missing.stderr)
            # A hook entrypoint that crashes (status 3) or cannot execute (126).
            for label, body, mode in (
                ("crash", "#!/usr/bin/env bash\nexit 3\n", 0o755),
                ("not executable", "#!/usr/bin/env bash\nexit 0\n", 0o644),
            ):
                project = scratch / f"{name}-{label.replace(' ', '-')}"
                shutil.copytree(HOOKS, project / ".claude" / "hooks", ignore=shutil.ignore_patterns("__pycache__"))
                entry = project / ".claude" / "hooks" / name
                entry.write_text(body, encoding="utf-8")
                entry.chmod(mode)
                broken = run(project, command, payloads[name])
                assert broken.returncode == 2 and "refusing to allow the call" in broken.stderr, (name, label, broken)
    TESTS += 1


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
    test_shell_stdin_scripts(policy)
    test_block_runtime(policy)
    test_block_git_unsafe()
    test_branch_policy_full_git_hook_binds_push_and_local_history()
    test_branch_policy_full_git_hook_uses_pinned_policy_authoritatively()
    test_block_gh_unsafe()
    test_branch_policy_full_gh_hook_binds_origin_and_cd_context()
    test_block_attribution()
    test_block_config_commentary(policy)
    test_require_validation_before_git(policy)
    test_push_gate_directory_and_history()
    test_bridge_transcript_through_the_commit_gate(policy)
    test_settings_registers_every_hook()
    test_pre_bash_entrypoint_runs_every_rule_and_fails_closed()
    test_tokenizer_bypass_forms()
    test_ordinary_command_corpus()
    test_hook_command_suffix_contract()
    test_registered_hook_command()

    for note in SKIPPED:
        print(f"SKIP  {note}")
    print(f"PASS  {TESTS} hook cases")
    return 0


if __name__ == "__main__":
    sys.exit(main())
