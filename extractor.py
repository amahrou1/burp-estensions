# -*- coding: utf-8 -*-
# extractor.py - Main Burp extension entry point
# Jython 2.7 compatible
#
# Implements:
#   IBurpExtender          - extension lifecycle
#   IContextMenuFactory    - right-click "Send to JWT Extractor"
#   ITab                   - custom tab in Burp UI

import sys
import os

# Ensure the extension directory is on the Python path so sibling modules
# (regex_engine, results_store, etc.) can be imported.
_ext_dir = os.path.dirname(os.path.abspath(__file__))
if _ext_dir not in sys.path:
    sys.path.insert(0, _ext_dir)

from burp import IBurpExtender, IContextMenuFactory, ITab
from javax.swing import JMenuItem, SwingUtilities
from java.awt.event import ActionListener

import regex_engine
from results_store import ResultsStore
from ui_panel import UIPanel

# Content-Type prefixes we consider worth scanning
_SCANNABLE_TYPES = (
    "text/",
    "application/javascript",
    "application/json",
    "application/xml",
    "application/x-javascript",
)

EXTENSION_NAME = "JWT Extractor"


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

        # Show our menu item when user right-clicks on messages
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

        new_count = 0
        for msg in http_messages:
            response = msg.getResponse()
            if response is None:
                continue

            # Determine source URL
            service = msg.getHttpService()
            url = self._helpers.analyzeRequest(msg).getUrl()
            source_url = str(url)

            # Analyse response info to get Content-Type
            resp_info = self._helpers.analyzeResponse(response)
            content_type = self._get_content_type(resp_info)

            # Skip binary / non-text responses
            if not self._is_scannable(content_type):
                continue

            # Get response body as string
            body_offset = resp_info.getBodyOffset()
            body_bytes = response[body_offset:]
            body_text = self._helpers.bytesToString(body_bytes)

            # Run regex engine
            matches = regex_engine.scan(body_text)
            for m in matches:
                added = self._store.add(
                    token=m["match"],
                    source_url=source_url,
                    content_type=content_type,
                    pattern_name=m["pattern_name"],
                )
                if added:
                    new_count += 1

        self._callbacks.printOutput(
            "Scanned %d message(s), found %d new finding(s)."
            % (len(http_messages), new_count)
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
    def _is_scannable(content_type):
        """Return True if content_type looks like text we should scan."""
        if not content_type:
            # If unknown, scan anyway (better safe than sorry)
            return True
        for prefix in _SCANNABLE_TYPES:
            if content_type.startswith(prefix):
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


class _Runnable(object):
    """Wrap a callable for SwingUtilities.invokeLater."""
    def __init__(self, fn):
        self._fn = fn

    def run(self):
        self._fn()
