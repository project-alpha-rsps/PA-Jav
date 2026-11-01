from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_SPEC = importlib.util.spec_from_file_location(
    "validate_jav_config", ROOT / "scripts" / "validate-jav-config.py"
)
assert MODULE_SPEC and MODULE_SPEC.loader
validator = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(validator)


class JavConfigValidationTests(unittest.TestCase):
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
        with self.assertRaisesRegex(validator.ConfigError, "absolute URL"):
            validator.validate_file(ROOT / "tests" / "fixtures" / "incompatible-codebase.ws")
        with self.assertRaisesRegex(validator.ConfigError, "absolute URL"):
            validator.parse_config(
                "codebase=http://[\ninitial_jar=gamepack.jar\ninitial_class=client.class"
            )

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
