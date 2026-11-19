#!/usr/bin/env python3
"""
Sensitive Data Guard — VS Code Copilot Hook
Scans user prompts and tool inputs for sensitive data patterns. Tool denials
use top-level permissionDecision and legacy hookSpecificOutput. Prompt
blocks use the Copilot decision/reason contract.

Categories:
  - API keys & tokens (AWS, GitHub, JWT, Bearer, generic)
  - Passwords & secrets (assignments, connection strings)
  - Private keys (RSA, DSA, EC, OPENSSH, PGP)
  - PII — General (email, credit card, SSN, IP address, phone)
  - PII — India BFSI (Aadhaar, PAN, Indian mobile, IFSC, passport, UPI)

Requires: Python 3.6+ (stdlib only — sys, re, json, os, glob)
"""

import glob
import json
import os
import re
import sys
import unicodedata

PROMPT_BLOCK_REASON = "Sensitive data detected. Start a new session without sensitive data."


def block_prompt():
    return {"decision": "block", "reason": PROMPT_BLOCK_REASON}


# ---------------------------------------------------------------------------
# Verhoeff checksum tables (used for Aadhaar validation)
# ---------------------------------------------------------------------------
_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]

_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]

_VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def _verhoeff_validate(number_str: str) -> bool:
    """Return True if *number_str* passes the Verhoeff checksum."""
    c = 0
    digits = [int(d) for d in reversed(number_str)]
    for i, digit in enumerate(digits):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][digit]]
    return c == 0


# ---------------------------------------------------------------------------
# Luhn checksum (credit-card validation)
# ---------------------------------------------------------------------------
def _luhn_validate(number_str: str) -> bool:
    """Return True if *number_str* passes the Luhn checksum."""
    digits = [int(d) for d in number_str]
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    total = sum(odd_digits)
    for d in even_digits:
        total += sum(divmod(d * 2, 10))
    return total % 10 == 0


# ---------------------------------------------------------------------------
# Pattern definitions
# Each entry: (category, label, compiled_regex, optional_validator)
#   validator is a callable(match_text) -> bool; None means regex match suffices
# ---------------------------------------------------------------------------

# Known UPI suffixes — used to separate UPI IDs from plain email addresses.
_UPI_SUFFIXES = {
    "ybl", "paytm", "oksbi", "okaxis", "okicici", "okhdfcbank",
    "upi", "apl", "axisbank", "ibl", "sbi", "icici", "hdfcbank",
    "kotak", "indus", "boi", "pnb", "rbl", "federal", "idbi",
    "citi", "sc", "hsbc", "dbs", "jio", "slice", "freecharge",
    "mobikwik", "airtel", "postbank", "dlb", "kbl", "kvb",
    "aubank", "equitas", "esaf", "jupiteraxis",
}

PATTERNS: list = []


def _p(category: str, label: str, pattern: str,
       flags: int = re.IGNORECASE, validator=None):
    """Register a pattern."""
    PATTERNS.append((category, label, re.compile(pattern, flags), validator))


# ── API Keys & Tokens ─────────────────────────────────────────────────────
_p("API Keys & Tokens", "AWS Access Key ID",
   r"\bAKIA[0-9A-Z]{16}\b", flags=0)

_p("API Keys & Tokens", "AWS Secret Access Key",
   r"(?i)(?:aws).{0,20}['\"]?([A-Za-z0-9/+=]{40})['\"]?")

_p("API Keys & Tokens", "GitHub Token",
   r"\b(ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}"
   r"|ghr_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,82})\b", flags=0)

_p("API Keys & Tokens", "Bearer Token",
   r"\bBearer\s+[A-Za-z0-9\-._~+/]{20,}=*\b")

_p("API Keys & Tokens", "JWT Token",
   r"\beyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]+\b",
   flags=0)

_p("API Keys & Tokens", "Generic API Key/Secret",
   r"(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token"
   r"|client[_-]?secret)['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9\-._~+/]{16,}['\"]?")

_p("API Keys & Tokens", "Azure/GCP/Slack/Stripe Token",
   r"\b(xox[bpsa]-[A-Za-z0-9\-]{10,}"
   r"|sk_live_[A-Za-z0-9]{20,}"
   r"|rk_live_[A-Za-z0-9]{20,}"
   r"|AIza[0-9A-Za-z\-_]{35})\b", flags=0)

# ── Passwords & Secrets ───────────────────────────────────────────────────
_p("Passwords & Secrets", "Password Assignment",
   r"(?:password|passwd|pwd|secret)['\"]?\s*[:=]\s*['\"]?(?!\s)[^\s'\"]{4,}['\"]?")

_p("Passwords & Secrets", "Connection String with Credentials",
   r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:]+:[^\s@]+@[^\s]+")

# ── Private Keys ──────────────────────────────────────────────────────────
_p("Private Keys", "Private Key Block",
   r"-----BEGIN\s+(?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"
   r"[\s\S]*?(?:-----END\s+(?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----|\Z)")

# ── PII — General ────────────────────────────────────────────────────────
_p("PII", "US Social Security Number",
   r"\b\d{3}-\d{2}-\d{4}\b")

_p("PII", "Credit Card Number (Visa)",
   r"\b4[0-9]{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}\b",
   validator=lambda m: _luhn_validate(re.sub(r"[\s\-]", "", m)))

_p("PII", "Credit Card Number (Mastercard)",
   r"\b5[1-5][0-9]{2}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}\b",
   validator=lambda m: _luhn_validate(re.sub(r"[\s\-]", "", m)))

_p("PII", "Credit Card Number (Amex)",
   r"\b3[47][0-9]{2}[\s\-]?[0-9]{6}[\s\-]?[0-9]{5}\b",
   validator=lambda m: _luhn_validate(re.sub(r"[\s\-]", "", m)))

_p("PII", "IPv4 Address",
   r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
   r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")

_p("PII", "IPv6 Address",
   r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b")

_p("PII", "International Phone Number",
   r"\+\d{1,3}[\s\-]?\(?\d{1,4}\)?[\s\-]?\d{3,4}[\s\-]?\d{3,4}\b")

# ── PII — India BFSI ─────────────────────────────────────────────────────
_p("PII — India BFSI", "Aadhaar Number",
   r"\b([2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4})\b",
   validator=lambda m: _verhoeff_validate(re.sub(r"[\s\-]", "", m)))

_p("PII — India BFSI", "PAN Number",
   r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", flags=re.IGNORECASE | re.ASCII)

_p("PII — India BFSI", "Indian Mobile Number",
   r"(?<![\w+])(?:\+91[\s\-]*|0)?[6-9](?:[\s\-]*[0-9]){9}(?!\w)")

_p("PII — India BFSI", "IFSC Code",
   r"\b[A-Z]{4}0[A-Z0-9]{6}\b", flags=re.IGNORECASE | re.ASCII)

_p("PII — India BFSI", "Indian Passport Number",
   r"\b[A-Z][0-9]{7}\b", flags=re.IGNORECASE | re.ASCII)

_p("PII — India BFSI", "UPI ID",
   r"\b[a-zA-Z0-9._\-]+@(" + "|".join(_UPI_SUFFIXES) + r")\b")

_p("PII", "Email Address",
   r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------
def sensitive_spans(text: str) -> list:
    """Find normalized matches, retaining offsets into the original text."""
    normalized = []
    offsets = []
    for index, character in enumerate(text):
        if unicodedata.category(character) == "Cf":
            continue
        for value in unicodedata.normalize("NFKC", character):
            normalized.append(value)
            offsets.append(index)
    searchable = "".join(normalized)
    findings = []
    for category, label, regex, validator in PATTERNS:
        for match in regex.finditer(searchable):
            matched_text = match.group(0)
            if validator is not None:
                if not validator(matched_text):
                    continue
            findings.append((category, label, offsets[match.start()],
                             offsets[match.end() - 1] + 1))
    return findings


def scan_text(text: str) -> list:
    """Return list of (category, label, original matched text) for all matches."""
    return [(category, label, text[start:end])
            for category, label, start, end in sensitive_spans(text)]


def extract_strings(obj) -> list:
    """Extract text, numeric values and object keys from a JSON-like object."""
    strings = []
    if isinstance(obj, (dict, list)):
        # Preserve field/value associations such as quoted password assignments.
        strings.append(json.dumps(obj, ensure_ascii=False))
    pending = [obj]
    while pending:
        value = pending.pop()
        if isinstance(value, str):
            strings.append(value)
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            strings.append(str(value))
        elif isinstance(value, dict):
            pending.extend(value.keys())
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
    return strings


def resolve_prompt_file(prompt: str, cwd: str) -> str:
    """If *prompt* is a slash command (e.g. '/test-api-keys'), find and read
    the matching .prompt.md file.  Returns the file body (without YAML
    frontmatter) or empty string if not found."""
    stripped = prompt.strip()
    # Must start with '/' and be a single token (the slash command)
    if not stripped.startswith("/"):
        return ""
    # Extract the command name — first token after '/'
    command_name = stripped.lstrip("/").split()[0] if stripped.lstrip("/") else ""
    if not command_name:
        return ""

    # Search for matching .prompt.md files in standard locations
    prompt_dirs = [
        os.path.join(cwd, ".github", "prompts"),
    ]
    for prompt_dir in prompt_dirs:
        if not os.path.isdir(prompt_dir):
            continue
        for filepath in glob.glob(os.path.join(prompt_dir, "*.prompt.md")):
            fname = os.path.splitext(os.path.splitext(os.path.basename(filepath))[0])[0]
            if fname == command_name:
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        content = f.read()
                    # Strip YAML frontmatter (--- ... ---)
                    if content.startswith("---"):
                        end = content.find("---", 3)
                        if end != -1:
                            content = content[end + 3:]
                    return content
                except (OSError, UnicodeError):
                    print("[sensitive-data-guard] Could not read slash-command prompt file.",
                          file=sys.stderr)
                    return ""
    return ""


# ---------------------------------------------------------------------------
# Format findings into a readable summary
# ---------------------------------------------------------------------------
def format_findings(findings: list) -> str:
    """Build a human-readable summary of detected sensitive data."""
    # De-duplicate by (category, label)
    seen = {}
    for category, label, matched in findings:
        key = (category, label)
        if key not in seen:
            # Mask the matched value — show first 4 and last 2 chars max
            if len(matched) > 8:
                masked = matched[:4] + "****" + matched[-2:]
            else:
                masked = matched[:2] + "****"
            seen[key] = masked

    lines = []
    for (category, label), masked in seen.items():
        lines.append(f"  • {label} ({category}): {masked}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    try:
        hook_input = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        # Cannot parse input — fail open (exit 0) per accepted risk policy
        print("[sensitive-data-guard] Invalid JSON input; scan skipped.", file=sys.stderr)
        json.dump({}, sys.stdout)
        sys.exit(0)

    if not isinstance(hook_input, dict):
        print("[sensitive-data-guard] Expected a JSON object; scan skipped.", file=sys.stderr)
        json.dump({}, sys.stdout)
        sys.exit(0)

    event = (hook_input.get("hook_event_name") or hook_input.get("hookEventName")
             or os.environ.get("SENSITIVE_DATA_HOOK_EVENT", ""))
    event = {"userPromptSubmitted": "UserPromptSubmit",
             "preToolUse": "PreToolUse"}.get(event, event) if isinstance(event, str) else ""

    # ── Determine text to scan ────────────────────────────────────────────
    texts_to_scan = []

    cwd = hook_input.get("cwd", "")

    if event == "UserPromptSubmit":
        prompt = hook_input.get("prompt", "")
        if isinstance(prompt, str) and prompt:
            texts_to_scan.append(prompt)
            # If the prompt is a slash command, also scan the prompt file body
            if isinstance(cwd, str) and cwd:
                prompt_body = resolve_prompt_file(prompt, cwd)
                if prompt_body:
                    texts_to_scan.append(prompt_body)

    elif event == "PreToolUse":
        tool_input = hook_input.get("tool_input",
                                   hook_input.get("toolArgs", hook_input.get("toolInput", {})))
        texts_to_scan.extend(extract_strings(tool_input))

    else:
        # Unknown event — nothing to scan, allow through
        json.dump({}, sys.stdout)
        sys.exit(0)

    if not texts_to_scan:
        json.dump({}, sys.stdout)
        sys.exit(0)

    # ── Scan ──────────────────────────────────────────────────────────────
    all_findings = []
    for text in texts_to_scan:
        all_findings.extend(scan_text(text))

    if not all_findings:
        json.dump({}, sys.stdout)
        sys.exit(0)

    if event == "UserPromptSubmit":
        print("[sensitive-data-guard] Sensitive prompt data detected; submission blocked.",
              file=sys.stderr)
        json.dump(block_prompt(), sys.stdout)
        sys.stdout.flush()
        sys.exit(0)

    elif event == "PreToolUse":
        summary = format_findings(all_findings)
        categories = sorted({f[0] for f in all_findings})
        cat_str = ", ".join(categories)
        tool_name = hook_input.get("tool_name") or hook_input.get("toolName", "unknown")
        reason = (
            f"Sensitive data detected in tool input for '{tool_name}'.\n"
            f"Categories: {cat_str}\n"
            f"Details:\n{summary}\n\n"
            f"The tool call has been blocked. Remove sensitive data and retry."
        )
        response = {
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }
        json.dump(response, sys.stdout)
        sys.stdout.flush()
        sys.exit(0)


if __name__ == "__main__":
    main()
