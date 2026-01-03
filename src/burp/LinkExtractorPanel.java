package burp;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Map;
import java.util.Set;

public class LinkExtractorPanel extends JPanel {

    private BurpExtender extender;
    private JTextArea displayArea;
    private JCheckBox scopeFilterCheckbox;
    private JButton exportButton;
    private JButton clearButton;
    private JLabel statsLabel;

    public LinkExtractorPanel(BurpExtender extender) {
        this.extender = extender;
        initComponents();
    }

    private void initComponents() {
        setLayout(new BorderLayout(10, 10));
        setBorder(new EmptyBorder(10, 10, 10, 10));

        // Top panel with controls
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        scopeFilterCheckbox = new JCheckBox("Only show in-scope URLs", false);
        topPanel.add(scopeFilterCheckbox);

        exportButton = new JButton("Export to File");
        exportButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                exportLinks();
            }
        });
        topPanel.add(exportButton);

        clearButton = new JButton("Clear All");
        clearButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                clearLinks();
            }
        });
        topPanel.add(clearButton);

        statsLabel = new JLabel("Sources: 0 | Total Links: 0");
        topPanel.add(Box.createHorizontalStrut(20));
        topPanel.add(statsLabel);

        add(topPanel, BorderLayout.NORTH);

        // Center panel with text area
        displayArea = new JTextArea();
        displayArea.setEditable(false);
        displayArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        displayArea.setLineWrap(false);
        displayArea.setText("Waiting for HTTP traffic...\n\nLinks will appear here as requests are captured.");

        JScrollPane scrollPane = new JScrollPane(displayArea);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        add(scrollPane, BorderLayout.CENTER);

        // Bottom info panel
        JPanel bottomPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel infoLabel = new JLabel("Links are automatically captured from all HTTP responses | Duplicates are removed globally");
        infoLabel.setFont(new Font("Arial", Font.ITALIC, 11));
        infoLabel.setForeground(Color.GRAY);
        bottomPanel.add(infoLabel);

        add(bottomPanel, BorderLayout.SOUTH);
    }

    public void updateDisplay() {
        Map<String, Set<String>> linkMap = extender.getLinkMap();

        if (linkMap.isEmpty()) {
            displayArea.setText("No links found yet.\n\nLinks will appear here as requests are captured.");
            statsLabel.setText("Sources: 0 | Total Links: 0");
            return;
        }

        StringBuilder sb = new StringBuilder();
        int totalLinks = 0;

        sb.append("═══════════════════════════════════════════════════════════════════════════\n");
        sb.append("                          EXTRACTED LINKS\n");
        sb.append("═══════════════════════════════════════════════════════════════════════════\n\n");

        for (Map.Entry<String, Set<String>> entry : linkMap.entrySet()) {
            String sourceUrl = entry.getKey();
            Set<String> links = entry.getValue();

            if (links.isEmpty()) {
                continue;
            }

            sb.append("┌─ SOURCE URL:\n");
            sb.append("│  ").append(sourceUrl).append("\n");
            sb.append("│\n");
            sb.append("└─ DISCOVERED LINKS (").append(links.size()).append("):\n");

            for (String link : links) {
                sb.append("   • ").append(link).append("\n");
                totalLinks++;
            }

            sb.append("\n");
            sb.append("───────────────────────────────────────────────────────────────────────────\n\n");
        }

        sb.append("═══════════════════════════════════════════════════════════════════════════\n");
        sb.append("Total: ").append(linkMap.size()).append(" source(s) | ").append(totalLinks).append(" unique link(s)\n");
        sb.append("═══════════════════════════════════════════════════════════════════════════\n");

        displayArea.setText(sb.toString());
        displayArea.setCaretPosition(0); // Scroll to top

        // Update stats
        statsLabel.setText("Sources: " + linkMap.size() + " | Total Links: " + totalLinks);
    }

    private void exportLinks() {
        Map<String, Set<String>> linkMap = extender.getLinkMap();

        if (linkMap.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                "No links to export!",
                "Export",
                JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Export Links");
        fileChooser.setSelectedFile(new File("extracted_links.txt"));

        int userSelection = fileChooser.showSaveDialog(this);

        if (userSelection == JFileChooser.APPROVE_OPTION) {
            File fileToSave = fileChooser.getSelectedFile();

            try (FileWriter writer = new FileWriter(fileToSave)) {
                writer.write("═══════════════════════════════════════════════════════════════════════════\n");
                writer.write("                     BURP LINK EXTRACTOR - EXPORT\n");
                writer.write("═══════════════════════════════════════════════════════════════════════════\n\n");

                int totalLinks = 0;

                for (Map.Entry<String, Set<String>> entry : linkMap.entrySet()) {
                    String sourceUrl = entry.getKey();
                    Set<String> links = entry.getValue();

                    if (links.isEmpty()) {
                        continue;
                    }

                    writer.write("┌─ SOURCE URL:\n");
                    writer.write("│  " + sourceUrl + "\n");
                    writer.write("│\n");
                    writer.write("└─ DISCOVERED LINKS (" + links.size() + "):\n");

                    for (String link : links) {
                        writer.write("   • " + link + "\n");
                        totalLinks++;
                    }

                    writer.write("\n───────────────────────────────────────────────────────────────────────────\n\n");
                }

                writer.write("═══════════════════════════════════════════════════════════════════════════\n");
                writer.write("Total: " + linkMap.size() + " source(s) | " + totalLinks + " unique link(s)\n");
                writer.write("═══════════════════════════════════════════════════════════════════════════\n");

                JOptionPane.showMessageDialog(this,
                    "Links exported successfully to:\n" + fileToSave.getAbsolutePath(),
                    "Export Successful",
                    JOptionPane.INFORMATION_MESSAGE);

                extender.getCallbacks().printOutput("Links exported to: " + fileToSave.getAbsolutePath());

            } catch (IOException e) {
                JOptionPane.showMessageDialog(this,
                    "Error exporting links:\n" + e.getMessage(),
                    "Export Error",
                    JOptionPane.ERROR_MESSAGE);

                extender.getCallbacks().printError("Export error: " + e.getMessage());
            }
        }
    }

    private void clearLinks() {
        int result = JOptionPane.showConfirmDialog(this,
            "Are you sure you want to clear all extracted links?",
            "Clear All Links",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.WARNING_MESSAGE);

        if (result == JOptionPane.YES_OPTION) {
            extender.clearLinks();
            displayArea.setText("All links cleared.\n\nLinks will appear here as new requests are captured.");
            statsLabel.setText("Sources: 0 | Total Links: 0");
            extender.getCallbacks().printOutput("All links cleared by user.");
        }
    }

    public boolean isScopeFilterEnabled() {
        return scopeFilterCheckbox.isSelected();
    }
}
