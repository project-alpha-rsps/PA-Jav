from __future__ import annotations

import hashlib
import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_SPEC = importlib.util.spec_from_file_location(
    "validate_jav_config", ROOT / "scripts" / "validate-jav-config.py"
)
assert MODULE_SPEC and MODULE_SPEC.loader
validator = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(validator)
CANDIDATE_SPEC = importlib.util.spec_from_file_location(
    "create_jav_candidate", ROOT / "scripts" / "create-jav-candidate.py"
)
assert CANDIDATE_SPEC and CANDIDATE_SPEC.loader
candidate_tool = importlib.util.module_from_spec(CANDIDATE_SPEC)
CANDIDATE_SPEC.loader.exec_module(candidate_tool)


class JavConfigValidationTests(unittest.TestCase):
    def test_candidate_pins_source_config_hashes_compatibility_and_rollback(self) -> None:
        source_sha = "a" * 40
        rollback_sha = "b" * 40
        original = candidate_tool.git_bytes
        candidate_tool.git_bytes = lambda *args: (
            b"" if args[0] == "cat-file" else
            b"prior config\n" if args[1].startswith(f"{rollback_sha}:") else
            (ROOT / args[1].split(":", 1)[1]).read_bytes()
        )
        try:
            manifest = candidate_tool.create_candidate(
                source_sha=source_sha,
                rollback_sha=rollback_sha,
                candidate_id=f"pa-jav-{source_sha}",
                evidence_uri="https://github.example.invalid/actions/runs/1",
                run_id="1",
                builder="fixture",
            )
        finally:
            candidate_tool.git_bytes = original

        self.assertEqual(manifest["source"]["sha"], source_sha)
        self.assertEqual(manifest["rollback"]["knownGoodCandidateId"], f"pa-jav-{rollback_sha}")
        self.assertEqual(len(manifest["artifacts"]), 2)
        for artifact in manifest["artifacts"]:
            config_bytes = (ROOT / artifact["name"]).read_bytes()
            self.assertEqual(artifact["digest"], f"sha256:{hashlib.sha256(config_bytes).hexdigest()}")
            self.assertIn(source_sha, artifact["uri"])
        for artifact in manifest["rollback"]["artifacts"]:
            self.assertEqual(artifact["digest"], f"sha256:{hashlib.sha256(b'prior config\n').hexdigest()}")
            self.assertIn(rollback_sha, artifact["uri"])
        self.assertEqual(manifest["compatibility"]["config"]["status"], "verified")

    def test_candidate_rejects_abbreviated_source_and_rollback_shas(self) -> None:
        with self.assertRaisesRegex(candidate_tool.CandidateError, "full lowercase"):
            candidate_tool.require_sha("004b007", "source SHA")

    def test_synthetic_desktop_and_mobile_configs_are_accepted(self) -> None:
        for name in ("desktop-valid.ws", "mobile-valid.ws"):
            with self.subTest(name=name):
                validator.validate_file(ROOT / "tests" / "fixtures" / name)

    def test_parameter_values_preserve_additional_equals_and_empty_values(self) -> None:
        class_loader, applet = validator.parse_config(
            "codebase=https://game.example.invalid/\n"
            "initial_jar=gamepack.jar\n"
            "initial_class=client.class\n"
            "param=key=value=with=equals\n"
            "param=optional=\n"
        )
        self.assertEqual(class_loader["initial_class"], "client.class")
        self.assertEqual(applet["key"], "value=with=equals")
        self.assertEqual(applet["optional"], "")

    def test_malformed_parameter_is_rejected(self) -> None:
        with self.assertRaisesRegex(validator.ConfigError, "expected param=name=value"):
            validator.validate_file(ROOT / "tests" / "fixtures" / "malformed-param.ws")

    def test_missing_consumer_required_field_is_rejected(self) -> None:
        fixture = ROOT / "tests" / "fixtures" / "missing-initial-class.ws"
        with self.assertRaisesRegex(validator.ConfigError, "initial_class"):
            validator.validate_file(fixture)

        for field in ("codebase", "initial_jar"):
            with self.subTest(field=field):
                text = (
                    "codebase=https://game.example.invalid/\n"
                    "initial_jar=gamepack.jar\n"
                    "initial_class=client.class\n"
                )
                broken = "\n".join(
                    line for line in text.splitlines() if not line.startswith(field + "=")
                )
                with self.assertRaisesRegex(validator.ConfigError, field):
                    validator.parse_config(broken)

    def test_invalid_codebase_is_rejected(self) -> None:
        with self.assertRaisesRegex(validator.ConfigError, r"HTTP\(S\) URL"):
            validator.validate_file(ROOT / "tests" / "fixtures" / "incompatible-codebase.ws")
        with self.assertRaisesRegex(validator.ConfigError, r"HTTP\(S\) URL"):
            validator.parse_config(
                "codebase=http://[\ninitial_jar=gamepack.jar\ninitial_class=client.class"
            )

    def test_unknown_scheme_is_rejected(self) -> None:
        with self.assertRaisesRegex(validator.ConfigError, r"HTTP\(S\) URL"):
            validator.validate_file(ROOT / "tests" / "fixtures" / "unknown-codebase-scheme.ws")

    def test_malformed_or_out_of_range_port_is_rejected(self) -> None:
        for codebase in (
            "http://fixture.invalid:not-a-port/",
            "http://fixture.invalid:65536/",
            "http://fixture.invalid:/",
            "http://fixture..invalid/",
            "http://not a host/",
            " http://fixture.invalid/",
        ):
            with self.subTest(codebase=codebase):
                with self.assertRaisesRegex(validator.ConfigError, r"HTTP\(S\) URL"):
                    validator.parse_config(
                        f"codebase={codebase}\ninitial_jar=gamepack.jar\ninitial_class=client.class"
                    )

    def test_http_and_https_with_valid_hosts_and_ports_are_accepted(self) -> None:
        for codebase in (
            "http://fixture.invalid/",
            "https://fixture.invalid:443/",
            "http://127.0.0.1:8080/",
            "https://[::1]:443/",
        ):
            with self.subTest(codebase=codebase):
                validator.parse_config(
                    f"codebase={codebase}\ninitial_jar=gamepack.jar\ninitial_class=client.class"
                )

    def test_invalid_authority_fixtures_report_validation_errors_without_tracebacks(self) -> None:
        for name in ("unknown-codebase-scheme.ws", "malformed-codebase-port.ws"):
            with self.subTest(name=name):
                result = subprocess.run(
                    [
                        sys.executable,
                        str(ROOT / "scripts" / "validate-jav-config.py"),
                        str(ROOT / "tests" / "fixtures" / name),
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("FAIL ", result.stderr)
                self.assertNotIn("Traceback", result.stderr)

    def test_non_assignment_line_is_rejected(self) -> None:
        with self.assertRaisesRegex(validator.ConfigError, "expected key=value"):
            validator.parse_config(
                "codebase=https://game.example.invalid/\n"
                "initial_jar=gamepack.jar\n"
                "initial_class=client.class\n"
                "not-an-assignment"
            )


if __name__ == "__main__":
    unittest.main()
