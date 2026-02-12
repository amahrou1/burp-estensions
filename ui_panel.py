# -*- coding: utf-8 -*-
# ui_panel.py - Swing UI: JTable + detail pane + action buttons
# Jython 2.7 compatible - all UI updates via SwingUtilities.invokeLater

from javax.swing import (
    JPanel, JTable, JScrollPane, JTextArea, JSplitPane,
    JButton, BoxLayout, SwingUtilities, JFileChooser,
    JOptionPane, ListSelectionModel,
)
from javax.swing.table import AbstractTableModel
from java.awt import BorderLayout, Dimension, FlowLayout, Toolkit
from java.awt.datatransfer import StringSelection
from java.awt.event import ActionListener
from java.io import File, FileWriter
from java.lang import Runnable
from javax.swing.event import ListSelectionListener


# -------------------------------------------------------------------------
# Table model backed by ResultsStore
# -------------------------------------------------------------------------

COLUMNS = ["#", "Token (truncated)", "Pattern", "Source URL", "Timestamp"]


class FindingsTableModel(AbstractTableModel):
    """Read-only table model that pulls data from a ResultsStore."""

    def __init__(self, store):
        self._store = store

    def getRowCount(self):
        return self._store.size()

    def getColumnCount(self):
        return len(COLUMNS)

    def getColumnName(self, col):
        return COLUMNS[col]

    def getValueAt(self, row, col):
        if row < 0 or row >= self._store.size():
            return ""
        f = self._store.get(row)
        if col == 0:
            return str(row + 1)
        elif col == 1:
            tok = f["token"]
            return tok if len(tok) <= 80 else tok[:77] + "..."
        elif col == 2:
            return f["pattern_name"]
        elif col == 3:
            return f["source_urls"][0]
        elif col == 4:
            return f["timestamp"]
        return ""

    def isCellEditable(self, row, col):
        return False


# -------------------------------------------------------------------------
# Main panel
# -------------------------------------------------------------------------

class UIPanel(JPanel):
    """Top-level panel registered as a Burp tab."""

    def __init__(self, store, callbacks):
        JPanel.__init__(self)
        self._store = store
        self._callbacks = callbacks
        self._init_ui()
        # Listen for store changes so we can refresh the table
        store.add_listener(self._on_store_changed)

    # ----- layout --------------------------------------------------------

    def _init_ui(self):
        self.setLayout(BorderLayout())

        # -- Table --
        self._table_model = FindingsTableModel(self._store)
        self._table = JTable(self._table_model)
        self._table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self._table.getSelectionModel().addListSelectionListener(
            _SelectionListener(self)
        )
        table_scroll = JScrollPane(self._table)
        table_scroll.setPreferredSize(Dimension(900, 300))

        # -- Detail text area --
        self._detail = JTextArea()
        self._detail.setEditable(False)
        self._detail.setLineWrap(True)
        self._detail.setWrapStyleWord(True)
        detail_scroll = JScrollPane(self._detail)
        detail_scroll.setPreferredSize(Dimension(900, 300))

        # -- Split pane --
        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, table_scroll, detail_scroll)
        split.setResizeWeight(0.5)
        self.add(split, BorderLayout.CENTER)

        # -- Button bar --
        btn_panel = JPanel(FlowLayout(FlowLayout.LEFT))

        btn_clear = JButton("Clear All")
        btn_clear.addActionListener(_ActionHandler(self._on_clear))
        btn_panel.add(btn_clear)

        btn_copy = JButton("Copy Token")
        btn_copy.addActionListener(_ActionHandler(self._on_copy_token))
        btn_panel.add(btn_copy)

        btn_export_json = JButton("Export JSON")
        btn_export_json.addActionListener(_ActionHandler(self._on_export_json))
        btn_panel.add(btn_export_json)

        btn_export_csv = JButton("Export CSV")
        btn_export_csv.addActionListener(_ActionHandler(self._on_export_csv))
        btn_panel.add(btn_export_csv)

        self.add(btn_panel, BorderLayout.SOUTH)

    # ----- callbacks -----------------------------------------------------

    def _on_store_changed(self):
        """Refresh the table on the Swing EDT."""
        model = self._table_model
        SwingUtilities.invokeLater(_Runnable(lambda: model.fireTableDataChanged()))

    def _on_row_selected(self):
        row = self._table.getSelectedRow()
        if row < 0 or row >= self._store.size():
            self._detail.setText("")
            return
        self._detail.setText(self._store.get_detail_text(row))
        self._detail.setCaretPosition(0)

    def _on_clear(self, event):
        self._store.clear()
        self._detail.setText("")

    def _on_copy_token(self, event):
        row = self._table.getSelectedRow()
        if row < 0 or row >= self._store.size():
            return
        token = self._store.get(row)["token"]
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(StringSelection(token), None)

    def _on_export_json(self, event):
        self._export_to_file(self._store.export_json(), "findings.json")

    def _on_export_csv(self, event):
        self._export_to_file(self._store.export_csv(), "findings.csv")

    def _export_to_file(self, content, default_name):
        chooser = JFileChooser()
        chooser.setSelectedFile(File(default_name))
        ret = chooser.showSaveDialog(self)
        if ret == JFileChooser.APPROVE_OPTION:
            path = chooser.getSelectedFile().getAbsolutePath()
            try:
                fw = FileWriter(path)
                fw.write(content)
                fw.close()
                self._callbacks.printOutput("Exported to %s" % path)
            except Exception as e:
                self._callbacks.printError("Export failed: %s" % str(e))


# -------------------------------------------------------------------------
# Small helper classes required by Jython / Swing
# -------------------------------------------------------------------------

class _ActionHandler(ActionListener):
    def __init__(self, fn):
        self._fn = fn

    def actionPerformed(self, event):
        self._fn(event)


class _SelectionListener(ListSelectionListener):
    def __init__(self, panel):
        self._panel = panel

    def valueChanged(self, event):
        if not event.getValueIsAdjusting():
            self._panel._on_row_selected()


class _Runnable(Runnable):
    """Wrap a callable so it can be passed to SwingUtilities.invokeLater."""

    def __init__(self, fn):
        self._fn = fn

    def run(self):
        self._fn()
