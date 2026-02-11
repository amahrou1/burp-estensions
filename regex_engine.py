# regex_engine.py — Pattern registry and scan logic
# Jython 2.7 compatible

import re
from jwt_utils import is_valid_jwt

# ---------------------------------------------------------------------------
# Pattern registry
# Each entry: name, compiled pattern, optional validator callable.
# To add a new secret type, just append a dict here — nothing else changes.
# ---------------------------------------------------------------------------

patterns = [
    {
        "name": "JWT",
        "pattern": re.compile(
            r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{2,}"
        ),
        "validator": is_valid_jwt,
    },
    {
        "name": "AWS Access Key",
        "pattern": re.compile(r"AKIA[0-9A-Z]{16}"),
        "validator": None,
    },
    {
        "name": "Google API Key",
        "pattern": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        "validator": None,
    },
    {
        "name": "GitHub Token",
        "pattern": re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,255}"),
        "validator": None,
    },
    {
        "name": "Slack Token",
        "pattern": re.compile(r"xox[bpras]-[0-9A-Za-z\-]{10,}"),
        "validator": None,
    },
    {
        "name": "Generic Secret (Bearer)",
        "pattern": re.compile(r"Bearer\s+[A-Za-z0-9_\-\.]{20,}"),
        "validator": None,
    },
]


def scan(text):
    """
    Run all registered patterns against *text*.

    Returns a list of dicts:
        {
            "match":        <matched string>,
            "pattern_name": <name from registry>,
            "start_pos":    <int>,
            "end_pos":      <int>,
        }
    """
    results = []
    for entry in patterns:
        for m in entry["pattern"].finditer(text):
            matched = m.group(0)
            # If a validator is defined, skip false positives
            if entry["validator"] is not None and not entry["validator"](matched):
                continue
            results.append({
                "match": matched,
                "pattern_name": entry["name"],
                "start_pos": m.start(),
                "end_pos": m.end(),
            })
    return results
