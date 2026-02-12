# -*- coding: utf-8 -*-
# secret_utils.py - JWT decode, secret masking, and context formatting
# Jython 2.7 compatible (Python 2 syntax, no external packages)

import base64
import json


# ---------------------------------------------------------------------------
# Base64URL / JWT helpers
# ---------------------------------------------------------------------------

def base64url_decode(data):
    """Decode Base64URL-encoded string (no padding required)."""
    missing_padding = len(data) % 4
    if missing_padding:
        data += "=" * (4 - missing_padding)
    data = data.replace("-", "+").replace("_", "/")
    return base64.b64decode(data)


def decode_jwt(token):
    """
    Decode a JWT into its three parts.

    Returns a dict with keys: header, payload, signature_raw
    Each of header and payload is a parsed Python dict.
    signature_raw is the raw Base64URL signature segment.
    Returns None if the token is not a valid JWT.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None

    try:
        header_json = base64url_decode(parts[0])
        header = json.loads(header_json)
    except Exception:
        return None

    try:
        payload_json = base64url_decode(parts[1])
        payload = json.loads(payload_json)
    except Exception:
        return None

    return {
        "header": header,
        "payload": payload,
        "signature_raw": parts[2],
    }


def is_valid_jwt(token):
    """Quick check: does the token decode as a valid JWT structure?"""
    return decode_jwt(token) is not None


def pretty_print_jwt(token):
    """Return a human-readable multi-line string of the decoded JWT."""
    decoded = decode_jwt(token)
    if decoded is None:
        return "(invalid JWT)"
    lines = []
    lines.append("=== HEADER ===")
    lines.append(json.dumps(decoded["header"], indent=2, sort_keys=True))
    lines.append("")
    lines.append("=== PAYLOAD ===")
    lines.append(json.dumps(decoded["payload"], indent=2, sort_keys=True))
    lines.append("")
    lines.append("=== SIGNATURE (Base64URL) ===")
    lines.append(decoded["signature_raw"])
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# JWT validator for regex_engine
# ---------------------------------------------------------------------------

def validate_jwt(match):
    """Validate a JWT by decoding the header and checking for 'alg' field."""
    try:
        header = match.split(".")[0]
        padding = 4 - len(header) % 4
        if padding != 4:
            header += "=" * padding
        header = header.replace("-", "+").replace("_", "/")
        decoded = base64.b64decode(str(header))
        parsed = json.loads(decoded)
        return "alg" in parsed
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Secret masking
# ---------------------------------------------------------------------------

def mask_secret(value, show_chars=6):
    """Show first N chars, mask the rest. E.g., 'AKIA4E...[REDACTED]'"""
    if len(value) <= show_chars:
        return value
    return value[:show_chars] + "...[REDACTED]"


# ---------------------------------------------------------------------------
# Context formatting
# ---------------------------------------------------------------------------

def format_context(context_before, match, context_after, max_width=120):
    """Format context with match highlighted for display in detail pane."""
    before = context_before[-60:]
    token_display = match[:80] if len(match) > 80 else match
    after = context_after[:60]
    return "...%s[%s]%s..." % (before, token_display, after)
