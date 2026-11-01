# Jav config candidate, publication and rollback

PA-Jav remains a single-trunk repository: short-lived feature branches propose
changes through pull requests to `main`. This is the repository's main-only
exception; it does not create a `dev` branch or adopt a two-branch profile.
The existing generic repository policy remains in force.

## Candidate validation

The `Jav config validation` check reuses `scripts/validate-jav-config.py` and
the synthetic tests in `tests/` to validate desktop/mobile syntax and the
client's startup-field and HTTP(S) codebase contract. It then creates an
offline release-manifest v1 candidate using the exact PR-head or push SHA,
SHA-256 digests of both config files, a config compatibility statement and a
rollback reference to the known-good config commit. The candidate is validated
by the canonical server manifest validator at its accepted immutable revision.
The generated JSON exists only in the runner temporary directory: candidate
validation is not config publication, and passing CI does not prove public
artifact availability or a client startup.

For a deliberate later candidate with a different rollback base, invoke
`scripts/create-jav-candidate.py` with full `--source-sha` and `--rollback-sha`
values plus the candidate ID, verification evidence URI, run ID, builder and
output path. Both SHAs must be full Git object IDs, source must resolve to a
commit, and every artifact URI names the immutable source commit. The rollback
artifact digests are read from the exact prior commit; mutable tags and branch
names are not rollback identities.

## Publication and startup evidence

Publication is a separate owner-controlled operation. Record the accepted
candidate ID and exact config artifact URI/digest for each file, then verify
the published artifact identity independently. Do not change runtime config
values or consumer startup URLs as part of candidate validation. A verified
consumer startup is a separate observation that records the client/consumer
identity, startup outcome and evidence reference; config syntax or CI alone
must never be reported as live startup verification.

## Rollback

Use the candidate manifest's `rollback.knownGoodCandidateId` and complete
`rollback.artifacts` set as the rollback identity. Restore only that reviewed,
known-good config set through the existing publication owner path, then
independently verify its published hashes and consumer startup. Correct
manifest/tooling defects with a reviewed revert or forward fix; do not rewrite
release history or treat a repository revert as proof that published config
was restored.
