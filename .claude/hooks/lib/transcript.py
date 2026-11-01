"""Session transcript reader for hooks that gate on what the session already did.

Claude Code passes `transcript_path` in every hook payload: a JSONL file whose
`assistant` entries carry `message.content[]` blocks, and whose `tool_use`
blocks record the tool name and its input in the order the session ran them.
`require-validation-before-git.sh` needs that ordering to answer "was the
repository validated after the last write" and "was origin fetched since the
last push".

`user` entries carry the prompts. `last_prompt` returns the latest one, the
trigger this turn is answering, for any hook that needs to know who asked.

A missing or unreadable transcript raises `TranscriptError`; the caller fails
closed, because an unreadable history cannot show that a gate was satisfied.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Callable, NamedTuple

SYSTEM_REMINDER = re.compile(r"<system-reminder>.*?</system-reminder>", re.DOTALL)


class TranscriptError(Exception):
    """The session transcript could not be read."""


class ToolUse(NamedTuple):
    name: str
    input: dict


def read_entries(transcript_path: str | None) -> list[dict]:
    """Every JSONL entry in the transcript, oldest first."""
    if not transcript_path or not isinstance(transcript_path, str):
        raise TranscriptError("the hook payload carried no transcript_path")
    path = Path(transcript_path)
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError) as exc:
        raise TranscriptError(f"cannot read the session transcript {path}: {exc}") from exc

    entries: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(entry, dict):
            entries.append(entry)
    return entries


def read_prompts(transcript_path: str | None) -> list[str]:
    """Every prompt the session was given, oldest first.

    A `user` entry is either a prompt or a batch of tool results, so only its
    text blocks count. `<system-reminder>` spans are cut out: they are injected
    context -- repository instructions, recalled memory -- not what the person
    or the runtime that triggered this turn actually said.
    """
    prompts: list[str] = []
    for entry in read_entries(transcript_path):
        if entry.get("type") != "user" or entry.get("isMeta"):
            continue
        message = entry.get("message")
        if not isinstance(message, dict):
            continue
        content = message.get("content")
        if isinstance(content, str):
            blocks = [content]
        elif isinstance(content, list):
            blocks = [
                block["text"]
                for block in content
                if isinstance(block, dict)
                and block.get("type") == "text"
                and isinstance(block.get("text"), str)
            ]
        else:
            continue
        text = SYSTEM_REMINDER.sub("", "\n".join(blocks)).strip()
        if text:
            prompts.append(text)
    return prompts


def last_prompt(transcript_path: str | None) -> str:
    """The prompt that triggered the current turn."""
    prompts = read_prompts(transcript_path)
    if not prompts:
        raise TranscriptError("the session transcript carried no prompt")
    return prompts[-1]


def read_tool_uses(transcript_path: str | None) -> list[ToolUse]:
    """Every tool call in the transcript, oldest first."""
    uses: list[ToolUse] = []
    for entry in read_entries(transcript_path):
        message = entry.get("message")
        if not isinstance(message, dict):
            continue
        content = message.get("content")
        if not isinstance(content, list):
            continue
        for block in content:
            if not isinstance(block, dict) or block.get("type") != "tool_use":
                continue
            name = block.get("name")
            tool_input = block.get("input")
            if isinstance(name, str) and isinstance(tool_input, dict):
                uses.append(ToolUse(name, tool_input))
    return uses


def last_index(uses: list[ToolUse], predicate: Callable[[ToolUse], bool], start: int = 0) -> int:
    """Index of the last tool call at or after `start` that matches, else -1."""
    for index in range(len(uses) - 1, start - 1, -1):
        if predicate(uses[index]):
            return index
    return -1


def bash_commands(uses: list[ToolUse], start: int = 0) -> list[str]:
    """Every Bash command string from `start` onwards."""
    commands = []
    for use in uses[start:]:
        if use.name == "Bash" and isinstance(use.input.get("command"), str):
            commands.append(use.input["command"])
    return commands


def writes_under(root: Path) -> Callable[[ToolUse], bool]:
    """Predicate matching a file-write tool call targeting a path under `root`."""
    root = root.resolve()

    def predicate(use: ToolUse) -> bool:
        if use.name not in ("Write", "Edit", "NotebookEdit", "MultiEdit"):
            return False
        raw_path = use.input.get("file_path") or use.input.get("notebook_path")
        if not isinstance(raw_path, str) or not raw_path:
            return False
        path = Path(raw_path)
        if not path.is_absolute():
            path = root / path
        try:
            path.resolve().relative_to(root)
        except (OSError, ValueError):
            return False
        return True

    return predicate
