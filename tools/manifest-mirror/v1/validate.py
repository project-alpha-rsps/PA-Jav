#!/usr/bin/env python3
"""Offline validator for Project Alpha release manifest schema v1."""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
SCHEMA_PATH = HERE / "schema.json"
SENSITIVE_KEY = re.compile(r"(secret|password|token|credential|private.?key|player|account.?data|email|phone)", re.I)


class InvalidManifest(ValueError):
    pass


def _matches_type(value, expected):
    return {
        "object": lambda: isinstance(value, dict),
        "array": lambda: isinstance(value, list),
        "string": lambda: isinstance(value, str),
        "integer": lambda: isinstance(value, int) and not isinstance(value, bool),
        "number": lambda: isinstance(value, (int, float)) and not isinstance(value, bool),
        "boolean": lambda: isinstance(value, bool),
        "null": lambda: value is None,
    }[expected]()


def _format_ok(value, fmt):
    if fmt == "uri":
        try:
            parsed = urlsplit(value)
            parsed.port  # Access validates malformed and out-of-range ports.
        except ValueError:
            return False
        return bool(
            parsed.scheme
            and parsed.path
            and not any(character.isspace() for character in value)
            and not parsed.username
            and not parsed.password
            and not parsed.query
            and not parsed.fragment
        )
    return True


def _schema_errors(value, schema, path="$", root=None):
    root = schema if root is None else root
    errors = []
    if "$ref" in schema:
        target = root
        for part in schema["$ref"].removeprefix("#/ ").replace("#/", "").split("/"):
            if part:
                target = target[part]
        return _schema_errors(value, target, path, root)
    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: expected {schema['const']!r}")
    if "allOf" in schema:
        for subschema in schema["allOf"]:
            errors.extend(_schema_errors(value, subschema, path, root))
    if "if" in schema:
        branch = "then" if not _schema_errors(value, schema["if"], path, root) else "else"
        if branch in schema:
            errors.extend(_schema_errors(value, schema[branch], path, root))
    if "not" in schema and not _schema_errors(value, schema["not"], path, root):
        errors.append(f"{path}: value must not match the prohibited schema")
    if "type" in schema and not _matches_type(value, schema["type"]):
        return [f"{path}: expected {schema['type']}"]
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: value must be one of {schema['enum']}")
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            errors.append(f"{path}: string is too short")
        if "pattern" in schema and re.fullmatch(schema["pattern"], value) is None:
            errors.append(f"{path}: value does not match required pattern")
        if "format" in schema and not _format_ok(value, schema["format"]):
            errors.append(f"{path}: invalid {schema['format']}")
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            errors.append(f"{path}: array requires at least {schema['minItems']} item(s)")
        if schema.get("uniqueItems") and len({json.dumps(item, sort_keys=True) for item in value}) != len(value):
            errors.append(f"{path}: array items must be unique")
        if "items" in schema:
            for index, item in enumerate(value):
                errors.extend(_schema_errors(item, schema["items"], f"{path}[{index}]", root))
    if isinstance(value, dict):
        for key in value:
            if SENSITIVE_KEY.search(key):
                errors.append(f"{path}.{key}: sensitive or personal-data field is prohibited")
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{path}.{key}: required property is missing")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            for key in value.keys() - properties.keys():
                errors.append(f"{path}.{key}: additional property is prohibited")
        for key, child_schema in properties.items():
            if key in value:
                errors.extend(_schema_errors(value[key], child_schema, f"{path}.{key}", root))
    return errors


def _state_errors(state, path, require_evidence=False):
    status = state.get("status")
    errors = []
    if status == "verified":
        if "value" not in state and path.startswith("$.compatibility"):
            errors.append(f"{path}: verified compatibility requires a value")
        if require_evidence or "evidence" in state:
            if not state.get("evidence"):
                errors.append(f"{path}: verified status requires evidence")
    elif status in ("unverified", "not_applicable"):
        if "value" in state:
            errors.append(f"{path}: {status} state must not assert a value")
        if state.get("evidence"):
            # Evidence can clarify why a check is unavailable or inapplicable.
            pass
    return errors


def validate(manifest):
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    errors = _schema_errors(manifest, schema)
    if errors:
        return errors
    errors.extend(_state_errors(manifest["verification"], "$.verification", require_evidence=True))
    for name, state in manifest["compatibility"].items():
        errors.extend(_state_errors(state, f"$.compatibility.{name}", require_evidence=True))
    all_artifacts = [
        *((f"$.artifacts[{index}]", artifact) for index, artifact in enumerate(manifest["artifacts"])),
        *((f"$.rollback.artifacts[{index}]", artifact) for index, artifact in enumerate(manifest["rollback"]["artifacts"])),
    ]
    for path, artifact in all_artifacts:
        if artifact.get("kind") == "container":
            parsed = urlsplit(artifact["uri"])
            reference = re.fullmatch(r"/([A-Za-z0-9][A-Za-z0-9._/-]*)@sha256:([a-f0-9]{64})", parsed.path)
            uri_digest = f"sha256:{reference.group(2)}" if reference else None
            if parsed.scheme != "oci" or not parsed.netloc or uri_digest != artifact["digest"]:
                errors.append(f"{path}: container URI digest must exactly equal digest")
        if artifact.get("kind") in ("signed-client", "signed-launcher"):
            signature = artifact.get("signature")
            if not signature:
                errors.append(f"{path}: signed artifacts require an explicit signature state")
            else:
                errors.extend(_state_errors(signature, f"{path}.signature", require_evidence=True))
        elif artifact.get("signature"):
            errors.extend(_state_errors(artifact["signature"], f"{path}.signature", require_evidence=True))
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"invalid: cannot read JSON: {exc}", file=sys.stderr)
        return 2
    errors = validate(manifest)
    if errors:
        print("invalid:")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"valid: {manifest['candidateId']} (schema {manifest['schemaVersion']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
