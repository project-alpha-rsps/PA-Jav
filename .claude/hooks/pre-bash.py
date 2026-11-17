#!/usr/bin/env python3
# PreToolUse(Bash): run every Bash rule in one process. The rules are modules
# under lib/, each exposing `run(payload_text)`; they run in the fixed order of
# RULES, every one of them every time. A rule allows by returning or exiting 0.
# A rule that denies, raises or exits with anything else counts as a deny, and
# so does a rule module that cannot be loaded; the remaining rules still run so
# that one call reports every reason. Exit 2 if any rule denied, else 0.
#
# `--only <rule-name>` runs one rule and exists for the test suite; the
# registered command (pre-bash.sh) never passes it.
#
# Template file: identical in every repository that adopts repo-policy. Change
# it in shockstruck/agent-platform, not here.
import importlib
import os
import sys
import traceback

HOOKS_DIR = os.path.dirname(os.path.abspath(__file__))
LIB_DIR = os.path.join(HOOKS_DIR, "lib")

RULES = (
    ("block-runtime", "runtime_rule"),
    ("block-git-unsafe", "git_unsafe_rule"),
    ("block-gh-unsafe", "gh_unsafe_rule"),
    ("block-attribution", "attribution_rule"),
    ("require-validation-before-git", "validation_rule"),
)


def fail(message: str) -> None:
    sys.stderr.write(f"[pre-bash] {message}\n")
    sys.stderr.flush()


def main(argv: list[str]) -> int:
    rules = RULES
    if argv:
        if len(argv) != 2 or argv[0] != "--only":
            fail("usage: pre-bash.py [--only <rule-name>]; refusing to allow the command.")
            return 2
        rules = tuple(rule for rule in RULES if rule[0] == argv[1])
        if not rules:
            fail(f"unknown rule `{argv[1]}`; refusing to allow the command.")
            return 2

    if not os.path.isdir(LIB_DIR):
        fail("hook library is missing; refusing to allow the command. Allowed next step: report the broken hook installation for reviewed repair and continue independent work; retry only after repair.")
        return 2

    try:
        payload_text = sys.stdin.read()
    except (OSError, UnicodeDecodeError) as exc:
        fail(f"could not read the hook payload ({exc}); refusing to allow the command. Allowed next step: submit a valid tool payload; if the harness generated it, report the payload failure and continue independent work.")
        return 2

    os.environ["HOOK_LIB_DIR"] = LIB_DIR
    sys.path.insert(0, LIB_DIR)

    denied = False
    for name, module_name in rules:
        try:
            module = importlib.import_module(module_name)
            module.run(payload_text)
        except BaseException as exc:  # noqa: BLE001 - SystemExit must be judged, not propagated
            if isinstance(exc, SystemExit) and exc.code in (None, 0):
                continue
            denied = True
            if isinstance(exc, SystemExit):
                if exc.code not in (2,):
                    fail(f"internal hook failure: rule `{name}` exited with status {exc.code!r}; refusing to allow the command. Allowed next step: report the hook failure for reviewed repair and continue independent work; retry only after repair.")
            else:
                fail(f"internal hook failure: rule `{name}` failed ({type(exc).__name__}: {exc}); refusing to allow the command. Allowed next step: report the hook failure for reviewed repair and continue independent work; retry only after repair.")
                sys.stderr.write(traceback.format_exc())
    sys.stderr.flush()
    return 2 if denied else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
