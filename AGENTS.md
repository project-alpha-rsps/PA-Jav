# Repository Agent Guide

Generic agent conduct arrives with the agent and must not be restated here.
`agent-platform:agents/shared/conduct.md` is composed into every agent's
instructions and carries exactly these sections:

<!-- shared-conduct-sections: kept in step with agents/shared/conduct.md by
     scripts/tests/test_repo_policy_template.py -->

- Work notes belong on the issue, not in the repository
- Work that crosses a domain becomes a sub-issue
- When a hook refuses you
- Reading a large tool response
- Validated work ships without a person
- Use Jev wherever it is good

The agent's own instructions carry the rest — evidence, secret handling and
writing style. Those are deliberately worded per domain rather than shared, so
they are not in `conduct.md`, but they still reach the agent before it reads
this file. Either way, a repository restating any of it is duplicating a live
original.

This file is only what is true of this repository.

## What this repository is

This is a public repository containing two Jav client configuration files:
`jav_config.ws` and `jav_config_mobile.ws`. It has no build system.

## Sources of truth

Git is authoritative. The repository has a single trunk, `main`.

## Hard rules

The two Jav client configuration files are the repository's content. There is
no application build or release process in this repository.

## Where enforcement lives

The generic hooks come from `repo-policy/template/` in agent-platform and are
byte-identical everywhere; anything this repository tunes lives in
`.claude/hooks/policy.json`. The repository's own lint workflow runs
`scripts/check-agent-policy.py` and a secret scan against a human commit or a
non-hooked tool.

## Validation

Run `actionlint`, `zizmor --offline .github/workflows/`,
`shellcheck .claude/hooks/*.sh`, `python3 scripts/check-agent-policy.py`, and
`python3 scripts/test-agent-hooks.py` in CI. There is no Jav build validator.

## Change workflow

Changes are proposed through pull requests to the single `main` branch.

## Skill routing

Repository policy adoption uses the `repo-policy-rollout` skill. CI workflow
changes use `ci-pipeline-design`.
