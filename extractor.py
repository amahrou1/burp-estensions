# -*- coding: utf-8 -*-
# extractor.py - Main Burp extension entry point
# Jython 2.7 compatible
#
# Implements:
#   IBurpExtender          - extension lifecycle
#   IContextMenuFactory    - right-click "Send to Secret Extractor"
#   ITab                   - custom tab in Burp UI

import sys
import os

# Ensure the extension directory is on the Python path so sibling modules
# (regex_engine, results_store, etc.) can be imported.
# NOTE: __file__ is not defined when Burp loads scripts via execfile(),
# so we fall back to inspect.getfile().
try:
    _ext_dir = os.path.dirname(os.path.abspath(__file__))
except NameError:
    import inspect
    _ext_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
if _ext_dir not in sys.path:
    sys.path.insert(0, _ext_dir)

from burp import IBurpExtender, IContextMenuFactory, ITab
from javax.swing import JMenuItem, SwingUtilities
from java.awt.event import ActionListener
from java.lang import Runnable

import regex_engine
from results_store import ResultsStore
from ui_panel import UIPanel

EXTENSION_NAME = "Secret Extractor"

# Content-Type prefixes we consider worth scanning
_SCANNABLE_TYPES = (
    "text/html",
    "text/plain",
    "text/javascript",
    "application/javascript",
    "application/x-javascript",
    "application/json",
    "application/xml",
    "text/xml",
    "text/css",
    "application/x-www-form-urlencoded",
)

# Content-Type prefixes we always skip (binary)
_SKIP_TYPES = (
    "image/",
    "video/",
    "audio/",
    "application/octet-stream",
    "application/pdf",
    "font/",
)

# URL suffixes that indicate scannable content even without a matching Content-Type
_SCANNABLE_EXTENSIONS = (".js", ".json", ".html", ".xml", ".css", ".map")


class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):

    # ------------------------------------------------------------------
    # IBurpExtender
    # ------------------------------------------------------------------

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName(EXTENSION_NAME)

        # Shared data store
        self._store = ResultsStore()

        # Build UI on the Swing EDT
        SwingUtilities.invokeLater(_Runnable(self._init_ui))

        # Register context menu factory
        callbacks.registerContextMenuFactory(self)

        callbacks.printOutput("%s loaded successfully." % EXTENSION_NAME)

    def _init_ui(self):
        self._panel = UIPanel(self._store, self._callbacks)
        self._callbacks.addSuiteTab(self)

    # ------------------------------------------------------------------
    # ITab
    # ------------------------------------------------------------------

    def getTabCaption(self):
        return EXTENSION_NAME

    def getUiComponent(self):
        return self._panel

    # ------------------------------------------------------------------
    # IContextMenuFactory
    # ------------------------------------------------------------------

    def createMenuItems(self, invocation):
        menu_items = []
        ctx = invocation.getInvocationContext()

        if ctx in (
            invocation.CONTEXT_MESSAGE_EDITOR_REQUEST,
            invocation.CONTEXT_MESSAGE_VIEWER_REQUEST,
            invocation.CONTEXT_MESSAGE_EDITOR_RESPONSE,
            invocation.CONTEXT_MESSAGE_VIEWER_RESPONSE,
            invocation.CONTEXT_PROXY_HISTORY,
            invocation.CONTEXT_TARGET_SITE_MAP_TABLE,
            invocation.CONTEXT_TARGET_SITE_MAP_TREE,
        ):
            item = JMenuItem("Send to %s" % EXTENSION_NAME)
            item.addActionListener(_MenuAction(self, invocation))
            menu_items.append(item)

        return menu_items if menu_items else None

    # ------------------------------------------------------------------
    # Scanning logic
    # ------------------------------------------------------------------

    def _process_messages(self, http_messages):
        """Extract secrets from the response bodies of the given messages."""
        if not http_messages:
            return

        total = len(http_messages)
        new_count = 0

        for idx in range(total):
            msg = http_messages[idx]
            response = msg.getResponse()
            if response is None:
                continue

            # Determine source URL
            url = self._helpers.analyzeRequest(msg).getUrl()
            source_url = str(url)

            self._callbacks.printOutput(
                "[%s] Scanning %d/%d: %s" % (EXTENSION_NAME, idx + 1, total, source_url)
            )

            # Analyse response info to get Content-Type
            resp_info = self._helpers.analyzeResponse(response)
            content_type = self._get_content_type(resp_info)

            # Skip binary / non-text responses
            if not self._is_scannable(content_type, source_url):
                continue

            # Get response body as string
            body_offset = resp_info.getBodyOffset()
            body_bytes = response[body_offset:]
            body_text = self._helpers.bytesToString(body_bytes)

            # Also scan if body looks like JSON regardless of Content-Type
            # (already covered by _is_scannable URL check, but also check body start)
            if not body_text:
                continue

            # Run regex engine
            matches = regex_engine.scan(body_text)
            for m in matches:
                added = self._store.add(
                    token=m["match"],
                    source_url=source_url,
                    content_type=content_type,
                    pattern_name=m["pattern_name"],
                    category=m["category"],
                    severity=m["severity"],
                    confidence=m["confidence"],
                    description=m["description"],
                    context_hint=m["context_hint"],
                    context_before=m["context_before"],
                    context_after=m["context_after"],
                )
                if added:
                    new_count += 1

        self._callbacks.printOutput(
            "[%s] Scan complete. Found %d new secret(s) in %d response(s)."
            % (EXTENSION_NAME, new_count, total)
        )

    @staticmethod
    def _get_content_type(resp_info):
        """Extract the Content-Type header value (lowercase)."""
        for header in resp_info.getHeaders():
            lower = header.lower()
            if lower.startswith("content-type:"):
                return lower.split(":", 1)[1].strip()
        return ""

    @staticmethod
    def _is_scannable(content_type, url=""):
        """Return True if this response should be scanned for secrets."""
        # If Content-Type is missing, scan anyway
        if not content_type:
            return True

        # Skip known binary types
        for prefix in _SKIP_TYPES:
            if content_type.startswith(prefix):
                return False

        # Check against scannable Content-Types
        for scannable in _SCANNABLE_TYPES:
            if content_type.startswith(scannable):
                return True

        # Check URL extension as fallback
        url_lower = url.lower().split("?")[0]  # strip query string
        for ext in _SCANNABLE_EXTENSIONS:
            if url_lower.endswith(ext):
                return True

        return False


# -------------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------------

class _MenuAction(ActionListener):
    def __init__(self, extender, invocation):
        self._extender = extender
        self._invocation = invocation

    def actionPerformed(self, event):
        messages = self._invocation.getSelectedMessages()
        if messages:
            self._extender._process_messages(messages)


class _Runnable(Runnable):
    """Wrap a callable for SwingUtilities.invokeLater."""
    def __init__(self, fn):
        self._fn = fn

    def run(self):
        self._fn()
