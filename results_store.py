# -*- coding: utf-8 -*-
# results_store.py - Findings storage, deduplication, and export
# Jython 2.7 compatible

import json
import time
from jwt_utils import decode_jwt, pretty_print_jwt


class ResultsStore(object):
    """In-memory store for all extracted findings with deduplication."""

    def __init__(self):
        # Main list of findings (each is a dict)
        self._findings = []
        # Set of token values already stored (for dedup)
        self._seen_tokens = {}  # token_value -> index in _findings
        self._listeners = []  # callables notified on change

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------

    def add(self, token, source_url, content_type, pattern_name):
        """
        Add a finding. If the same token was already seen, just append the
        new source_url to its sources list (dedup by token value).
        Returns True if a new entry was created, False if deduplicated.
        """
        if token in self._seen_tokens:
            idx = self._seen_tokens[token]
            if source_url not in self._findings[idx]["source_urls"]:
                self._findings[idx]["source_urls"].append(source_url)
            self._notify()
            return False

        decoded = None
        if pattern_name == "JWT":
            decoded = decode_jwt(token)

        finding = {
            "token": token,
            "source_urls": [source_url],
            "content_type": content_type,
            "pattern_name": pattern_name,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "decoded": decoded,
        }
        self._seen_tokens[token] = len(self._findings)
        self._findings.append(finding)
        self._notify()
        return True

    def clear(self):
        """Remove all findings."""
        self._findings = []
        self._seen_tokens = {}
        self._notify()

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def get_all(self):
        """Return a shallow copy of the findings list."""
        return list(self._findings)

    def get(self, index):
        """Return finding at given index."""
        return self._findings[index]

    def size(self):
        return len(self._findings)

    # ------------------------------------------------------------------
    # Change listeners (for UI refresh)
    # ------------------------------------------------------------------

    def add_listener(self, callback):
        self._listeners.append(callback)

    def _notify(self):
        for cb in self._listeners:
            try:
                cb()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_json(self):
        """Return all findings as a JSON string."""
        return json.dumps(self._findings, indent=2, sort_keys=True)

    def export_csv(self):
        """Return all findings as CSV text."""
        lines = ["token,pattern_name,source_urls,content_type,timestamp"]
        for f in self._findings:
            urls = "; ".join(f["source_urls"])
            # Escape double-quotes inside token
            tok = f["token"].replace('"', '""')
            lines.append('"%s","%s","%s","%s","%s"' % (
                tok, f["pattern_name"], urls, f["content_type"], f["timestamp"]
            ))
        return "\n".join(lines)

    def get_detail_text(self, index):
        """Return a human-readable detail string for the finding at *index*."""
        f = self._findings[index]
        parts = []
        parts.append("Pattern : %s" % f["pattern_name"])
        parts.append("Found   : %s" % f["timestamp"])
        parts.append("Type    : %s" % f["content_type"])
        parts.append("Sources :")
        for u in f["source_urls"]:
            parts.append("  - %s" % u)
        parts.append("")
        parts.append("--- Full Token ---")
        parts.append(f["token"])
        parts.append("")
        if f["decoded"] is not None:
            parts.append("--- Decoded JWT ---")
            parts.append(pretty_print_jwt(f["token"]))
        return "\n".join(parts)
