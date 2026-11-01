#!/usr/bin/env python3
"""Validate Jav config syntax and startup fields used by the client loader.

The accepted structure follows ClientConfigLoader.fetch in the Project Alpha
client: ordinary values use key=value, applet values use param=key=value, and
the loader requires non-empty codebase, initial_jar, and initial_class values.
RSAppletStub constructs a java.net.URL from codebase. The supported client
contract is an absolute HTTP(S) URL with a syntactically valid host and port.
This checks syntax and consumer compatibility only; it does not launch a client
or check live endpoint behavior.
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit


REQUIRED_FIELDS = ("codebase", "initial_jar", "initial_class")


class ConfigError(ValueError):
    """A Jav config cannot be consumed by the client startup loader."""


def validate_codebase(codebase: str, source: str) -> None:
    message = f"{source}: codebase must be an absolute HTTP(S) URL with a valid host and port"
    if not codebase or codebase != codebase.strip():
        raise ConfigError(message)
    try:
        parsed_url = urlsplit(codebase)
        parsed_url.port  # Validate numeric syntax and the 0..65535 range.
    except ValueError:
        raise ConfigError(message) from None

    if parsed_url.scheme.lower() not in ("http", "https") or not parsed_url.netloc:
        raise ConfigError(message)

    authority = parsed_url.netloc.rsplit("@", 1)[-1]
    if authority.startswith("["):
        closing_bracket = authority.find("]")
        if closing_bracket < 0:
            raise ConfigError(message)
        suffix = authority[closing_bracket + 1 :]
        if suffix and (
            not suffix.startswith(":") or not suffix[1:].isascii() or not suffix[1:].isdigit()
        ):
            raise ConfigError(message)
        if suffix == ":":
            raise ConfigError(message)
    elif ":" in authority:
        host_part, supplied_port = authority.rsplit(":", 1)
        if ":" in host_part or not supplied_port.isascii() or not supplied_port.isdigit():
            raise ConfigError(message)

    host = parsed_url.hostname
    if not host:
        raise ConfigError(message)
    try:
        if ":" in host:
            ipaddress.IPv6Address(host)
        else:
            try:
                ipaddress.ip_address(host)
            except ValueError:
                ascii_host = host.encode("idna").decode("ascii")
                dns_host = ascii_host[:-1] if ascii_host.endswith(".") else ascii_host
                if not dns_host or len(dns_host) > 253:
                    raise ValueError
                labels = dns_host.split(".")
                if not labels or any(
                    len(label) > 63
                    or re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label) is None
                    for label in labels
                ):
                    raise ValueError
    except (UnicodeError, ValueError):
        raise ConfigError(message) from None

def parse_config(text: str, source: str = "<config>") -> tuple[dict[str, str], dict[str, str]]:
    class_loader: dict[str, str] = {}
    applet: dict[str, str] = {}

    for number, raw_line in enumerate(text.splitlines(), start=1):
        if not raw_line.strip():
            continue
        line = raw_line
        if "=" not in line:
            raise ConfigError(f"{source}:{number}: expected key=value")

        key, value = line.split("=", 1)
        if not key:
            raise ConfigError(f"{source}:{number}: key is empty")

        if key == "param":
            if "=" not in value:
                raise ConfigError(f"{source}:{number}: expected param=name=value")
            name, parameter_value = value.split("=", 1)
            if not name:
                raise ConfigError(f"{source}:{number}: parameter name is empty")
            # Match ClientConfigLoader's map behavior: repeated parameter names
            # overwrite earlier values, and empty parameter values are allowed.
            applet[name] = parameter_value
        else:
            # The source parser stores unknown keys too, so preserve them here.
            class_loader[key] = value

    for field in REQUIRED_FIELDS:
        if not class_loader.get(field):
            raise ConfigError(f"{source}: required client field '{field}' is missing or empty")

    validate_codebase(class_loader["codebase"], source)

    return class_loader, applet


def validate_file(path: Path) -> None:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ConfigError(f"{path}: unable to read UTF-8 config ({exc.__class__.__name__})") from None
    parse_config(text, str(path))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("configs", nargs="*", type=Path, default=[
        Path("jav_config.ws"), Path("jav_config_mobile.ws")
    ])
    args = parser.parse_args()

    failed = False
    for path in args.configs:
        try:
            validate_file(path)
        except ConfigError as exc:
            print(f"FAIL {exc}", file=sys.stderr)
            failed = True
        else:
            print(f"PASS {path}: syntax and required client fields are valid")
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
