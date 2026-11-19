#!/usr/bin/env python3
"""Stateful prompt guard using the plugin's existing sensitive-data patterns."""

import hashlib
from contextlib import contextmanager
import json
import os
from pathlib import Path
import sys
import tempfile
import time

from check_sensitive_data import (
    block_prompt, extract_strings, resolve_prompt_file, scan_text, sensitive_spans,
)


REASON = ("Sensitive data detected. This session is quarantined. "
          "Start a new session without sensitive data; a clean follow-up does not clear context.")
ALIASES = {
    "UserPromptSubmit": "userPromptSubmitted",
    "PreToolUse": "preToolUse",
    "SessionEnd": "sessionEnd",
}


def redact(text):
    spans = [(start, end) for _, _, start, end in sensitive_spans(text)]
    merged = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    for start, end in reversed(merged):
        text = text[:start] + "[REDACTED]" + text[end:]
    return text


def state_path(event):
    session = event.get("sessionId", event.get("session_id"))
    if not isinstance(session, str) or not session.strip():
        raise ValueError("Missing session identifier")
    root = Path(os.environ.get(
        "PII_GUARD_STATE_DIR", str(Path.home() / ".copilot" / "pii-prompt-guard")))
    if not root.is_absolute():
        raise ValueError("State directory must be absolute")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    key = hashlib.sha256(session.encode("utf-8")).hexdigest()
    return root / (key + ".json")


def write_state(target, tainted):
    fd, temporary = tempfile.mkstemp(prefix=".state-", dir=str(target.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump({"tainted": tainted}, stream)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def deny(reason=REASON):
    return {
        "permissionDecision": "deny",
        "permissionDecisionReason": reason,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        },
    }


def read_state(target):
    try:
        state = json.loads(target.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    if not isinstance(state, dict) or type(state.get("tainted")) is not bool:
        raise ValueError("Invalid guard state")
    return state["tainted"]


@contextmanager
def session_lock(target):
    lock = target.with_suffix(".lock")
    deadline = time.monotonic() + 2
    while True:
        try:
            lock.mkdir(mode=0o700)
            break
        except FileExistsError:
            if time.monotonic() >= deadline:
                raise OSError("Session state lock unavailable")
            time.sleep(0.01)
    try:
        yield
    finally:
        lock.rmdir()


def handle(event, name):
    if not isinstance(event, dict):
        raise ValueError("Expected a JSON object")
    name = ALIASES.get(name, name)
    if name not in ("userPromptSubmitted", "userPromptTransformed", "preToolUse", "sessionEnd"):
        raise ValueError("Unsupported hook event")
    target = state_path(event)
    with session_lock(target):
        return handle_locked(event, name, target)


def handle_locked(event, name, target):
    if name == "sessionEnd":
        try:
            target.unlink()
        except FileNotFoundError:
            pass
        return {}
    if name == "userPromptSubmitted":
        previous = read_state(target)
        write_state(target, True)
        prompt = event.get("prompt")
        if not isinstance(prompt, str):
            raise ValueError("Expected a prompt string")
        cwd = event.get("cwd")
        body = resolve_prompt_file(prompt, cwd) if isinstance(cwd, str) and cwd else ""
        tainted = bool(previous or scan_text(prompt) or scan_text(body))
        write_state(target, tainted)
        if tainted:
            print("[pii-prompt-guard] Session quarantined; prompt submission blocked.",
                  file=sys.stderr)
            return block_prompt()
        return {}
    if name == "userPromptTransformed":
        text = event.get("transformedPrompt")
        prompt = event.get("prompt")
        if not isinstance(text, str) or not isinstance(prompt, str):
            write_state(target, True)
            raise ValueError("Expected prompt and transformedPrompt strings")
        replacement = redact(text)
        if replacement != text or scan_text(prompt):
            write_state(target, True)
        return {"modifiedTransformedPrompt": replacement} if replacement != text else {}
    args = event.get("tool_input", event.get("toolArgs", event.get("toolInput")))
    if args is None:
        raise ValueError("Missing tool arguments")
    if any(scan_text(text) for text in extract_strings(args)):
        write_state(target, True)
        return deny()
    state = read_state(target)
    if state is None:
        return deny("Prompt guard has no state for this session. Submit a fresh clean prompt.")
    return deny() if state else {}


def main():
    name = os.environ.get("PII_GUARD_EVENT", "")
    try:
        event = json.load(sys.stdin)
        if not name and isinstance(event, dict):
            name = event.get("hook_event_name", event.get("hookEventName", ""))
        if not isinstance(name, str):
            raise ValueError("Invalid hook event")
        output = handle(event, name)
    except (ValueError, OSError, UnicodeError, RecursionError):
        # Never include payloads, exception text, paths, or matched values.
        print("[pii-prompt-guard] Guard input/state failure; operation denied. "
              "Check configuration and state-directory access.", file=sys.stderr)
        json.dump(deny("Prompt guard failed; check hook diagnostics."),
                  sys.stdout)
        return 2
    json.dump(output, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
