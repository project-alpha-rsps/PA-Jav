#!/usr/bin/env python3
"""Create an offline, immutable release-manifest candidate for PA-Jav configs."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_URI = "https://github.com/project-alpha-rsps/PA-Jav"
CONFIGS = ("jav_config.ws", "jav_config_mobile.ws")
SHA_PATTERN = re.compile(r"^(?:[a-f0-9]{40}|[a-f0-9]{64})$")


class CandidateError(ValueError):
    """A candidate cannot be identified without ambiguity."""


def git_bytes(*args: str) -> bytes:
    try:
        return subprocess.run(
            ["git", *args], cwd=ROOT, check=True, capture_output=True
        ).stdout
    except subprocess.CalledProcessError as exc:
        raise CandidateError("git could not resolve the requested immutable source") from exc


def require_sha(value: str, label: str) -> str:
    if SHA_PATTERN.fullmatch(value) is None:
        raise CandidateError(f"{label} must be a full lowercase Git object SHA")
    return value


def make_artifact(name: str, sha: str, content: bytes) -> dict[str, str]:
    digest = hashlib.sha256(content).hexdigest()
    return {
        "name": name,
        "kind": "config",
        "uri": f"{REPOSITORY_URI}/blob/{sha}/{name}",
        "digest": f"sha256:{digest}",
    }


def create_candidate(
    *, source_sha: str, rollback_sha: str, candidate_id: str,
    evidence_uri: str, run_id: str, builder: str,
) -> dict:
    source_sha = require_sha(source_sha, "source SHA")
    rollback_sha = require_sha(rollback_sha, "rollback SHA")
    if source_sha == rollback_sha:
        raise CandidateError("source and rollback SHAs must identify different candidates")
    git_bytes("cat-file", "-e", f"{source_sha}^{{commit}}")
    source_artifacts = []
    rollback_artifacts = []
    for name in CONFIGS:
        try:
            current = (ROOT / name).read_bytes()
            committed = git_bytes("show", f"{source_sha}:{name}")
            prior = git_bytes("show", f"{rollback_sha}:{name}")
        except OSError as exc:
            raise CandidateError(f"cannot read config artifact {name}") from exc
        if current != committed:
            raise CandidateError(f"working config {name} does not match the source SHA")
        source_artifacts.append(make_artifact(name, source_sha, current))
        rollback_artifacts.append(make_artifact(name, rollback_sha, prior))

    return {
        "schemaVersion": "1.0.0",
        "candidateId": candidate_id,
        "source": {"name": "project-alpha-rsps/PA-Jav", "uri": REPOSITORY_URI, "sha": source_sha},
        "inputs": [],
        "artifacts": source_artifacts,
        "build": {
            "provider": "GitHub Actions",
            "pipeline": "jav-config-candidate-validation",
            "runId": run_id,
            "builder": builder,
        },
        "verification": {"status": "verified", "evidence": [evidence_uri]},
        "compatibility": {
            "cache": {"status": "not_applicable"},
            "protocol": {"status": "not_applicable"},
            "config": {
                "status": "verified",
                "value": "PA-Jav validator and synthetic tests accept the client startup fields and HTTP(S) codebase contract",
                "evidence": [evidence_uri],
            },
            "migration": {"status": "not_applicable"},
            "minimumLauncherVersion": {"status": "not_applicable"},
            "minimumClientVersion": {"status": "not_applicable"},
        },
        "environment": "development",
        "rollback": {"knownGoodCandidateId": f"pa-jav-{rollback_sha}", "artifacts": rollback_artifacts},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--rollback-sha", required=True)
    parser.add_argument("--candidate-id", required=True)
    parser.add_argument("--evidence-uri", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--builder", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        manifest = create_candidate(
            source_sha=args.source_sha,
            rollback_sha=args.rollback_sha,
            candidate_id=args.candidate_id,
            evidence_uri=args.evidence_uri,
            run_id=args.run_id,
            builder=args.builder,
        )
        args.output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    except (CandidateError, OSError) as exc:
        print(f"invalid: {exc}", file=sys.stderr)
        return 1
    print(f"created: {args.output} ({manifest['candidateId']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
