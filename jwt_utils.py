# -*- coding: utf-8 -*-
# jwt_utils.py - Base64URL decode and JWT validation helpers
# Jython 2.7 compatible (Python 2 syntax, no external packages)

import base64
import json


def base64url_decode(data):
    """Decode Base64URL-encoded string (no padding required)."""
    # Add padding if needed
    missing_padding = len(data) % 4
    if missing_padding:
        data += "=" * (4 - missing_padding)
    # Replace URL-safe characters with standard Base64 characters
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
