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
by the byte-identical offline mirror of the server-owned canonical validator at
its accepted immutable revision. The local mirror at `tools/manifest-mirror/v1/`
contains only `schema.json` and `validate.py` from
`server/tools/release-manifest/v1/` at `0a205b8bd9f352b90e6e970e2660a42e9c50224b`.
Their approved SHA-256 digests are
`67ac06444c93598d1a94c338808f4d93fb3c8134d1f5ca0dea38aaf915797773` and
`7e1aa8590b85afcb3c41783810fe8a744a3f6da510794dc4e3483a71f6078125`. CI
verifies these hashes before invoking the validator. Server remains the
canonical owner; changes to the mirror require canonical-owner review. The
schema's `$id` is an identifier, not a claim that the URI serves a live schema.
The generated JSON exists only in the runner temporary directory: candidate
validation is not config publication, and passing CI does not prove public
artifact availability or a client startup.

For a deliberate later candidate with a different rollback base, invoke
`scripts/create-jav-candidate.py` with full `--source-sha` and `--rollback-sha`
values plus the candidate ID, verification evidence URI, run ID, builder and
output path. Both SHAs must be full Git object IDs, source must resolve to a
commit, and every artifact URI uses the immutable `raw.githubusercontent.com`
commit URL so the referenced bytes are exactly what its SHA-256 digest covers.
The rollback artifact digests are read from the exact prior commit; mutable
tags and branch names are not rollback identities. The candidate records the
immutable client startup-contract input at
`73ceac2e6ed3939e604dfc6a9f7e58230ca6b7a4` and the server manifest input at
`0a205b8bd9f352b90e6e970e2660a42e9c50224b`. Its
verified config compatibility covers syntax and startup-field contract tests
only; live startup and minimum-client-version behavior remain unverified.

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
