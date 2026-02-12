# -*- coding: utf-8 -*-
# ui_panel.py - Swing UI: filters, stats, JTable + detail pane + action buttons
# Jython 2.7 compatible - all UI updates via SwingUtilities.invokeLater

from javax.swing import (
    JPanel, JTable, JScrollPane, JTextArea, JSplitPane,
    JButton, JComboBox, JTextField, JLabel, BoxLayout,
    SwingUtilities, JFileChooser, JOptionPane, ListSelectionModel,
    BorderFactory,
)
from javax.swing.table import AbstractTableModel, DefaultTableCellRenderer
from java.awt import BorderLayout, Dimension, FlowLayout, Toolkit, Color, Font
from java.awt.datatransfer import StringSelection
from java.awt.event import ActionListener
from java.io import File, FileWriter
from java.lang import Runnable, String
from javax.swing.event import ListSelectionListener, DocumentListener

from regex_engine import ALL_CATEGORIES


# -------------------------------------------------------------------------
# Severity color map
# -------------------------------------------------------------------------

_SEV_COLORS = {
    "high": Color(255, 200, 200),
    "medium": Color(255, 230, 200),
    "low": Color(255, 255, 200),
}


# -------------------------------------------------------------------------
# Table columns
# -------------------------------------------------------------------------

COLUMNS = ["#", "Severity", "Confidence", "Name", "Token", "Source URL", "Category", "Timestamp"]
COL_WIDTHS = [40, 70, 80, 150, 200, 200, 150, 130]


# -------------------------------------------------------------------------
# Filtered table model
# -------------------------------------------------------------------------

class FindingsTableModel(AbstractTableModel):
    """Table model backed by a filtered view of the ResultsStore."""

    def __init__(self, store):
        self._store = store
        self._filtered = []  # list of finding dicts currently displayed
        self._refresh_filtered()

    def set_filter(self, category=None, severity=None, confidence=None,
                   search_text=None):
        """Apply filters and refresh the view."""
        self._category = category
        self._severity = severity
        self._confidence = confidence
        self._search_text = search_text
        self._refresh_filtered()

    def _refresh_filtered(self):
        cat = getattr(self, "_category", None)
        sev = getattr(self, "_severity", None)
        conf = getattr(self, "_confidence", None)
        search = getattr(self, "_search_text", None)
        self._filtered = self._store.get_filtered(
            category=cat, severity=sev, confidence=conf, search_text=search,
        )

    def refresh(self):
        """Re-apply current filters and fire table data changed."""
        self._refresh_filtered()
        self.fireTableDataChanged()

    def get_finding(self, row):
        """Return the finding dict at the given filtered row index."""
        if 0 <= row < len(self._filtered):
            return self._filtered[row]
        return None

    def get_filtered_findings(self):
        return list(self._filtered)

    # -- AbstractTableModel interface --

    def getRowCount(self):
        return len(self._filtered)

    def getColumnCount(self):
        return len(COLUMNS)

    def getColumnName(self, col):
        return COLUMNS[col]

    def getColumnClass(self, col):
        return String

    def getValueAt(self, row, col):
        if row < 0 or row >= len(self._filtered):
            return ""
        f = self._filtered[row]
        if col == 0:
            return str(row + 1)
        elif col == 1:
            return f["severity"].upper()
        elif col == 2:
            return f["confidence"].upper()
        elif col == 3:
            return f["pattern_name"]
        elif col == 4:
            tok = f["token"]
            return tok if len(tok) <= 40 else tok[:37] + "..."
        elif col == 5:
            url = f["source_urls"][0]
            return url if len(url) <= 60 else url[:57] + "..."
        elif col == 6:
            return f["category"]
        elif col == 7:
            return f["timestamp"]
        return ""

    def isCellEditable(self, row, col):
        return False


# -------------------------------------------------------------------------
# Custom cell renderer for severity column coloring
# -------------------------------------------------------------------------

class SeverityCellRenderer(DefaultTableCellRenderer):

    def getTableCellRendererComponent(self, table, value, isSelected,
                                      hasFocus, row, column):
        comp = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, column)
        if not isSelected:
            val = str(value).lower() if value else ""
            bg = _SEV_COLORS.get(val)
            if bg:
                comp.setBackground(bg)
            else:
                comp.setBackground(Color.WHITE)
        return comp


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
        store.add_listener(self._on_store_changed)

    # ----- layout --------------------------------------------------------

    def _init_ui(self):
        self.setLayout(BorderLayout())

        # -- Top area: filter bar + stats bar --
        top_panel = JPanel()
        top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))

        # Filter bar
        filter_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        filter_panel.setBorder(BorderFactory.createTitledBorder("Filters"))

        filter_panel.add(JLabel("Category:"))
        cat_options = ["All"] + list(ALL_CATEGORIES)
        self._cat_combo = JComboBox(cat_options)
        self._cat_combo.addActionListener(_ActionHandler(self._on_filter_changed))
        filter_panel.add(self._cat_combo)

        filter_panel.add(JLabel("  Severity:"))
        self._sev_combo = JComboBox(["All", "high", "medium", "low"])
        self._sev_combo.addActionListener(_ActionHandler(self._on_filter_changed))
        filter_panel.add(self._sev_combo)

        filter_panel.add(JLabel("  Confidence:"))
        self._conf_combo = JComboBox(["All", "high", "medium", "low"])
        self._conf_combo.addActionListener(_ActionHandler(self._on_filter_changed))
        filter_panel.add(self._conf_combo)

        filter_panel.add(JLabel("  Search:"))
        self._search_field = JTextField(20)
        self._search_field.getDocument().addDocumentListener(
            _DocListener(self._on_filter_changed)
        )
        filter_panel.add(self._search_field)

        top_panel.add(filter_panel)

        # Stats bar
        self._stats_label = JLabel("Total: 0 | High: 0 | Medium: 0 | Low: 0")
        stats_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        stats_panel.setBorder(BorderFactory.createTitledBorder("Statistics"))
        stats_panel.add(self._stats_label)
        top_panel.add(stats_panel)

        self.add(top_panel, BorderLayout.NORTH)

        # -- Table --
        self._table_model = FindingsTableModel(self._store)
        self._table = JTable(self._table_model)
        self._table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self._table.setAutoCreateRowSorter(True)
        self._table.getSelectionModel().addListSelectionListener(
            _SelectionListener(self)
        )

        # Set column widths
        col_model = self._table.getColumnModel()
        for i in range(min(len(COL_WIDTHS), col_model.getColumnCount())):
            col_model.getColumn(i).setPreferredWidth(COL_WIDTHS[i])

        # Severity color renderer on column 1
        self._table.getColumnModel().getColumn(1).setCellRenderer(
            SeverityCellRenderer()
        )

        table_scroll = JScrollPane(self._table)
        table_scroll.setPreferredSize(Dimension(1020, 300))

        # -- Detail text area --
        self._detail = JTextArea()
        self._detail.setEditable(False)
        self._detail.setLineWrap(True)
        self._detail.setWrapStyleWord(True)
        self._detail.setFont(Font("Monospaced", Font.PLAIN, 12))
        detail_scroll = JScrollPane(self._detail)
        detail_scroll.setPreferredSize(Dimension(1020, 300))

        # -- Split pane --
        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, table_scroll, detail_scroll)
        split.setResizeWeight(0.5)
        self.add(split, BorderLayout.CENTER)

        # -- Bottom: detail action buttons + main action bar --
        bottom_panel = JPanel()
        bottom_panel.setLayout(BoxLayout(bottom_panel, BoxLayout.Y_AXIS))

        # Detail action buttons
        detail_btn_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        btn_copy_token = JButton("Copy Token")
        btn_copy_token.addActionListener(_ActionHandler(self._on_copy_token))
        detail_btn_panel.add(btn_copy_token)

        btn_copy_context = JButton("Copy Context")
        btn_copy_context.addActionListener(_ActionHandler(self._on_copy_context))
        detail_btn_panel.add(btn_copy_context)

        btn_copy_details = JButton("Copy All Details")
        btn_copy_details.addActionListener(_ActionHandler(self._on_copy_details))
        detail_btn_panel.add(btn_copy_details)
        bottom_panel.add(detail_btn_panel)

        # Main action bar
        action_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        action_panel.setBorder(BorderFactory.createTitledBorder("Actions"))

        btn_export_json = JButton("Export JSON")
        btn_export_json.addActionListener(_ActionHandler(self._on_export_json))
        action_panel.add(btn_export_json)

        btn_export_csv = JButton("Export CSV")
        btn_export_csv.addActionListener(_ActionHandler(self._on_export_csv))
        action_panel.add(btn_export_csv)

        btn_clear = JButton("Clear All")
        btn_clear.addActionListener(_ActionHandler(self._on_clear))
        action_panel.add(btn_clear)

        btn_copy_all = JButton("Copy All Tokens")
        btn_copy_all.addActionListener(_ActionHandler(self._on_copy_all_tokens))
        action_panel.add(btn_copy_all)

        bottom_panel.add(action_panel)
        self.add(bottom_panel, BorderLayout.SOUTH)

    # ----- filter helpers ------------------------------------------------

    def _get_current_filters(self):
        """Read current filter values from the UI controls."""
        cat = str(self._cat_combo.getSelectedItem())
        sev = str(self._sev_combo.getSelectedItem())
        conf = str(self._conf_combo.getSelectedItem())
        search = self._search_field.getText().strip()
        return (
            cat if cat != "All" else None,
            sev if sev != "All" else None,
            conf if conf != "All" else None,
            search if search else None,
        )

    def _apply_filters(self):
        """Apply current filter state to the table model and refresh stats."""
        cat, sev, conf, search = self._get_current_filters()
        self._table_model.set_filter(
            category=cat, severity=sev, confidence=conf, search_text=search,
        )
        self._table_model.refresh()
        self._update_stats()

    def _update_stats(self):
        """Update the stats label based on current filtered view."""
        filtered = self._table_model.get_filtered_findings()
        total = self._store.size()
        shown = len(filtered)
        high = sum(1 for f in filtered if f["severity"] == "high")
        med = sum(1 for f in filtered if f["severity"] == "medium")
        low = sum(1 for f in filtered if f["severity"] == "low")
        self._stats_label.setText(
            "Showing %d of %d total | High: %d | Medium: %d | Low: %d"
            % (shown, total, high, med, low)
        )

    # ----- callbacks -----------------------------------------------------

    def _on_store_changed(self):
        """Refresh the table on the Swing EDT."""
        SwingUtilities.invokeLater(_Runnable(self._apply_filters))

    def _on_filter_changed(self, event=None):
        self._apply_filters()

    def _on_row_selected(self):
        row = self._table.getSelectedRow()
        if row < 0:
            self._detail.setText("")
            return
        # Convert view row to model row (in case of sorting)
        model_row = self._table.convertRowIndexToModel(row)
        finding = self._table_model.get_finding(model_row)
        if finding is None:
            self._detail.setText("")
            return
        # Find the index in the original store for get_detail_text
        all_findings = self._store.get_all()
        for i in range(len(all_findings)):
            if all_findings[i] is finding:
                self._detail.setText(self._store.get_detail_text(i))
                self._detail.setCaretPosition(0)
                return
        # Fallback: build detail from finding dict directly
        self._detail.setText(
            "Pattern: %s\nCategory: %s\nSeverity: %s\n\nToken: %s"
            % (finding["pattern_name"], finding["category"],
               finding["severity"], finding["token"])
        )
        self._detail.setCaretPosition(0)

    def _get_selected_finding(self):
        """Return the currently selected finding dict, or None."""
        row = self._table.getSelectedRow()
        if row < 0:
            return None
        model_row = self._table.convertRowIndexToModel(row)
        return self._table_model.get_finding(model_row)

    def _on_clear(self, event):
        result = JOptionPane.showConfirmDialog(
            self,
            "Clear all findings?",
            "Confirm",
            JOptionPane.YES_NO_OPTION,
        )
        if result == JOptionPane.YES_OPTION:
            self._store.clear()
            self._detail.setText("")

    def _on_copy_token(self, event):
        finding = self._get_selected_finding()
        if finding is None:
            return
        self._to_clipboard(finding["token"])

    def _on_copy_context(self, event):
        finding = self._get_selected_finding()
        if finding is None:
            return
        from secret_utils import format_context
        ctx = format_context(
            finding.get("context_before", ""),
            finding["token"],
            finding.get("context_after", ""),
        )
        self._to_clipboard(ctx)

    def _on_copy_details(self, event):
        text = self._detail.getText()
        if text:
            self._to_clipboard(text)

    def _on_copy_all_tokens(self, event):
        findings = self._table_model.get_filtered_findings()
        if not findings:
            return
        tokens = [f["token"] for f in findings]
        self._to_clipboard("\n".join(tokens))

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

    @staticmethod
    def _to_clipboard(text):
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(StringSelection(text), None)


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


class _DocListener(DocumentListener):
    """Fires callback on any document change (for JTextField search)."""
    def __init__(self, fn):
        self._fn = fn

    def insertUpdate(self, event):
        self._fn()

    def removeUpdate(self, event):
        self._fn()

    def changedUpdate(self, event):
        self._fn()


class _Runnable(Runnable):
    """Wrap a callable so it can be passed to SwingUtilities.invokeLater."""

    def __init__(self, fn):
        self._fn = fn

    def run(self):
        self._fn()
