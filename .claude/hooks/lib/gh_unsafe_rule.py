# PreToolUse(Bash): block `gh` commands that mutate GitHub outside review.
# `Bash(gh *)` is `ask`, which a Multica agent run auto-approves, so nothing
# stood between an agent and `gh pr merge --admin`, `gh secret set` or
# `gh api -X DELETE`. Reads and the ordinary pull-request flow stay open;
# wrappers are inspected through lib/shell_command.py, the same walker the
# other Bash hooks use.
#
# Rule module for pre-bash.py: `run(payload_text)` applies the rule to one
# PreToolUse payload. It returns normally to allow and calls sys.exit(2) with a
# message on stderr to deny; pre-bash.py treats anything else as a deny.


def run(payload_text: str) -> None:
    import json
    import os
    import re
    import sys

    sys.path.insert(0, os.environ["HOOK_LIB_DIR"])

    from shell_command import Denial  # noqa: E402
    from branch_policy import deny_gh_alias, deny_pr_merge  # noqa: E402
    from git_command import contextual_invocations  # noqa: E402

    # Options that consume the next token, so an operand scan does not mistake a
    # flag's value for the subcommand.
    # Kept deliberately tight: a boolean flag listed here would swallow the
    # subcommand and turn a deny into a miss.
    VALUE_OPTIONS = {
        "-R", "--repo", "--hostname", "--cache",
        "-X", "--method", "-H", "--header", "-q", "--jq", "--template",
        "-F", "--field", "-f", "--raw-field", "--input",
        "-b", "--body", "--body-file", "-t", "--title", "-B", "--base",
    }
    FIELD_OPTIONS = {"-f", "--raw-field", "-F", "--field", "--input"}
    READ_METHODS = {"GET", "HEAD"}
    MUTATION = re.compile(r"\bmutation\b", re.IGNORECASE)


    def deny(message: str) -> None:
        sys.stderr.write(f"[block-gh-unsafe] {message}\n")
        sys.exit(2)


    try:
        payload = json.loads(payload_text)
    except (json.JSONDecodeError, OSError):
        deny("hook input was not valid JSON; refusing to skip the GitHub safety check. Allowed next step: submit a valid tool payload; if the harness generated it, report the payload failure and continue independent work.")

    tool_input = payload.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        deny("hook tool_input was not an object; refusing to skip the GitHub safety check. Allowed next step: submit tool_input as an object; if the harness generated it, report the payload failure and continue independent work.")
    cmd = tool_input.get("command") or ""
    if not isinstance(cmd, str):
        deny("Bash command was not text. Allowed next step: submit the permitted command as a text string in tool_input.command.")
    if not cmd.strip():
        sys.exit(0)


    def operands(arguments: list[str]) -> list[str]:
        words = []
        index = 0
        while index < len(arguments):
            token = arguments[index]
            if token == "--":
                words.extend(arguments[index + 1 :])
                break
            if token.startswith("-") and token != "-":
                option = token.split("=", 1)[0]
                index += 1
                if option in VALUE_OPTIONS and "=" not in token and index < len(arguments):
                    index += 1
                continue
            words.append(token)
            index += 1
        return words


    def has_flag(arguments: list[str], *names: str) -> bool:
        return any(
            token == name or token.startswith(f"{name}=") for token in arguments for name in names
        )


    def option_value(arguments: list[str], *names: str) -> str:
        """The value of the last occurrence of an option, attached or separate."""
        value = ""
        for index, token in enumerate(arguments):
            for name in names:
                if token == name and index + 1 < len(arguments):
                    value = arguments[index + 1]
                elif token.startswith(f"{name}="):
                    value = token.split("=", 1)[1]
                elif len(name) == 2 and token.startswith(name) and len(token) > 2:
                    value = token[2:]
        return value


    def check_api(arguments: list[str], words: list[str]) -> None:
        endpoint = words[1] if len(words) > 1 else ""
        method = option_value(arguments, "-X", "--method").upper()
        if endpoint == "graphql":
            # GraphQL is a POST by transport; what decides read from write is the
            # document, not the verb.
            if MUTATION.search(" ".join(arguments)):
                deny(
                    "`gh api graphql` with a mutation writes to GitHub. Allowed next step: land any "
                    "repository change through a reviewed pull request; for an API-only effect, no "
                    "agent route exists here. Report the unmet need and continue independent work."
                )
            return
        if not method and any(
            token.split("=", 1)[0] in FIELD_OPTIONS for token in arguments if token.startswith("-")
        ):
            method = "POST"
        if method and method not in READ_METHODS:
            deny(
                f"`gh api -X {method}` mutates GitHub directly and bypasses review. Only `GET` and "
                "read-only `graphql` queries are open. Allowed next step: land any repository change "
                "through a reviewed pull request; for an API-only effect, no agent route exists here. "
                "Report the unmet need and continue independent work."
            )


    def check(words: list[str], arguments: list[str], directory: str | None) -> None:
        group = words[0] if words else ""
        action = words[1] if len(words) > 1 else ""

        try:
            alias_denial = deny_gh_alias(
                words,
                directory,
                os.path.join(os.environ["HOOK_LIB_DIR"], ".."),
            )
        except Exception as exc:
            deny(
                f"branchPolicy could not evaluate the GitHub CLI context safely ({exc}). Allowed next "
                "step: use a literal built-in `gh` command from the checked-out repository."
            )
        if alias_denial:
            deny(alias_denial)

        if group == "api":
            check_api(arguments, words)
            return
        if group == "auth" and action not in ("", "status"):
            deny(
                f"`gh auth {action}` touches the session's GitHub credentials. Never harvest "
                "credentials. Allowed next step: use `gh auth status` to inspect authentication "
                "without reading credentials; report any access gap and continue independent work."
            )
        if group == "repo" and action == "delete":
            deny("`gh repo delete` destroys the repository and every review record in it. Allowed next step: no agent route exists for repository deletion; report the unmet need in your result comment and continue independent work.")
        if group == "secret" and action in ("set", "delete", "remove"):
            deny(
                f"`gh secret {action}` changes Actions secrets outside Git review. Allowed next step: "
                "report the required secret change to the repository owner without exposing its value, "
                "and continue independent work; no agent route exists here."
            )
        if group == "release" and action.startswith("delete"):
            deny(f"`gh release {action}` destroys a published artifact with no recovery path. Allowed next step: no agent route exists for release deletion; report the unmet need in your result comment and continue independent work.")
        if group == "workflow" and action in ("run", "disable"):
            deny(
                f"`gh workflow {action}` mutates CI outside review. Workflow behaviour is defined in "
                "`.github/workflows/`. Allowed next step: submit any workflow change through a reviewed "
                "pull request and let its configured event trigger CI; report an unmet manual-run need "
                "and continue independent work."
            )
        if group == "pr" and action == "merge" and has_flag(arguments, "--admin"):
            deny(
                "`gh pr merge --admin` merges past the branch protection rules and the required "
                "checks. Allowed next step: fix what the gate reports, rerun the checks, then use the "
                "ordinary reviewed merge flow only if your role permits merging; never override it."
            )
        if group == "pr" and action == "merge":
            try:
                denial = deny_pr_merge(
                    arguments,
                    directory,
                    os.path.join(os.environ["HOOK_LIB_DIR"], ".."),
                )
            except Exception as exc:
                deny(
                    f"branchPolicy could not be evaluated safely ({exc}). Allowed next step: inspect "
                    "the configured policy and actual PR metadata, then use its documented route."
                )
            if denial:
                deny(denial)


    try:
        base_directory = payload.get("cwd") or os.environ.get("CLAUDE_PROJECT_DIR") or "."
        for invocation in contextual_invocations(cmd, base_directory, executable_name="gh"):
            check(operands(invocation.arguments), invocation.arguments, invocation.directory)
    except Denial as denial:
        deny(denial.message)

    sys.exit(0)
