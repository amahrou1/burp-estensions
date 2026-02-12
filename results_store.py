# -*- coding: utf-8 -*-
# results_store.py - Findings storage, deduplication, filtering, and export
# Jython 2.7 compatible

import json
import time
from secret_utils import decode_jwt, pretty_print_jwt, format_context


class ResultsStore(object):
    """In-memory store for all extracted findings with deduplication."""

    def __init__(self):
        self._findings = []
        self._seen_tokens = {}  # token_value -> index in _findings
        self._listeners = []

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------

    def add(self, token, source_url, content_type, pattern_name,
            category="", severity="medium", confidence="medium",
            description="", context_hint="",
            context_before="", context_after=""):
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
        if pattern_name == "JWT Token":
            decoded = decode_jwt(token)

        finding = {
            "token": token,
            "source_urls": [source_url],
            "content_type": content_type,
            "pattern_name": pattern_name,
            "category": category,
            "severity": severity,
            "confidence": confidence,
            "description": description,
            "context_hint": context_hint,
            "context_before": context_before,
            "context_after": context_after,
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
        if 0 <= index < len(self._findings):
            return self._findings[index]
        return None

    def size(self):
        return len(self._findings)

    # ------------------------------------------------------------------
    # Filtering
    # ------------------------------------------------------------------

    def get_by_category(self, category):
        """Return all findings for a given category."""
        return [f for f in self._findings if f["category"] == category]

    def get_by_severity(self, severity):
        """Return all findings matching severity level."""
        return [f for f in self._findings if f["severity"] == severity]

    def get_by_confidence(self, confidence):
        """Return all findings matching confidence level."""
        return [f for f in self._findings if f["confidence"] == confidence]

    def get_filtered(self, category=None, severity=None, confidence=None,
                     search_text=None):
        """
        Return findings matching ALL supplied filters (AND logic).
        None means "no filter" for that dimension.
        """
        results = []
        search_lower = search_text.lower() if search_text else None
        for f in self._findings:
            if category and f["category"] != category:
                continue
            if severity and f["severity"] != severity:
                continue
            if confidence and f["confidence"] != confidence:
                continue
            if search_lower:
                searchable = (
                    f["token"].lower() + " " +
                    f["pattern_name"].lower() + " " +
                    " ".join(f["source_urls"]).lower()
                )
                if search_lower not in searchable:
                    continue
            results.append(f)
        return results

    def get_stats(self):
        """Return dict with counts: total, by_category, by_severity, by_confidence."""
        stats = {
            "total": len(self._findings),
            "by_category": {},
            "by_severity": {"high": 0, "medium": 0, "low": 0},
            "by_confidence": {"high": 0, "medium": 0, "low": 0},
        }
        for f in self._findings:
            cat = f["category"]
            if cat not in stats["by_category"]:
                stats["by_category"][cat] = 0
            stats["by_category"][cat] += 1
            sev = f["severity"]
            if sev in stats["by_severity"]:
                stats["by_severity"][sev] += 1
            conf = f["confidence"]
            if conf in stats["by_confidence"]:
                stats["by_confidence"][conf] += 1
        return stats

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
        """Return all findings as a JSON string (excluding decoded for clean export)."""
        export_list = []
        for f in self._findings:
            entry = {}
            for k, v in f.items():
                if k == "decoded" and v is not None:
                    entry[k] = {
                        "header": v.get("header"),
                        "payload": v.get("payload"),
                        "signature_raw": v.get("signature_raw"),
                    }
                else:
                    entry[k] = v
            export_list.append(entry)
        return json.dumps(export_list, indent=2, sort_keys=True)

    def export_csv(self):
        """Return all findings as CSV text."""
        lines = ["token,pattern_name,category,severity,confidence,source_urls,content_type,timestamp"]
        for f in self._findings:
            urls = "; ".join(f["source_urls"])
            tok = f["token"].replace('"', '""')
            lines.append('"%s","%s","%s","%s","%s","%s","%s","%s"' % (
                tok, f["pattern_name"], f["category"], f["severity"],
                f["confidence"], urls, f["content_type"], f["timestamp"]
            ))
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Detail text
    # ------------------------------------------------------------------

    def get_detail_text(self, index):
        """Return a human-readable detail string for the finding at *index*."""
        f = self._findings[index]
        parts = []
        parts.append("Pattern    : %s" % f["pattern_name"])
        parts.append("Category   : %s" % f["category"])
        parts.append("Severity   : %s" % f["severity"].upper())
        parts.append("Confidence : %s" % f["confidence"].upper())
        parts.append("Found      : %s" % f["timestamp"])
        parts.append("Type       : %s" % f["content_type"])
        parts.append("")
        parts.append("Description: %s" % f["description"])
        if f.get("context_hint"):
            parts.append("Hint       : %s" % f["context_hint"])
        parts.append("")

        # Context
        if f.get("context_before") or f.get("context_after"):
            parts.append("--- Context ---")
            ctx = format_context(
                f.get("context_before", ""),
                f["token"],
                f.get("context_after", ""),
            )
            parts.append(ctx)
            parts.append("")

        parts.append("--- Full Token ---")
        parts.append(f["token"])
        parts.append("")

        if f["decoded"] is not None:
            parts.append("--- Decoded JWT ---")
            parts.append(pretty_print_jwt(f["token"]))
            parts.append("")

        parts.append("Sources :")
        for u in f["source_urls"]:
            parts.append("  - %s" % u)
        return "\n".join(parts)
