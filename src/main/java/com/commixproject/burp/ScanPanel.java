/*
 * This file is part of the commix-to-burp extension (https://github.com/commixproject/commix-to-burp).
 * Copyright 2026 Anastasios Stasinopoulos (@ancst).
 *
 * Licensed under the Apache License, Version 2.0; see the LICENSE file for details.
 */

package com.commixproject.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.text.BadLocationException;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * One scan's own tab: status, the log as it is said, and the findings table once there are any -
 * all three read off the same task id, polled on a timer so the UI never blocks on the network.
 * Each new finding is also raised as a Burp audit issue, once, the first time it is seen.
 */
public class ScanPanel extends JPanel {

    private static final Set<String> RUNNING_STATUSES = Set.of("not started", "running");
    // commix's log says a technique is confirmed the moment it happens, during the scan - the
    // structured report read back at the end can end up with fewer entries than that (seemingly
    // just one finding per parameter once something is already confirmed), so this is also parsed
    // out of the log itself as a fallback, to stop a confirmed technique being silently dropped.
    private static final Pattern INJECTABLE_LOG_LINE = Pattern.compile(
            "^(\\w+) parameter '(.+)' appears to be injectable via (\\w+)-based (.+) command injection technique\\.$");
    private static final Color BAD = new Color(0xC6, 0x28, 0x28);
    private static final Color WARN = new Color(0xB2, 0x6A, 0x00);
    private static final Color MUTED = new Color(0x75, 0x75, 0x75);
    private static final Color GOOD = new Color(0x2E, 0x7D, 0x32);
    private static final Color RUNNING_COLOR = new Color(0x42, 0x85, 0xF4);

    private final MontoyaApi api;
    private final CommixApiClient client;
    private final Logging logging;
    private final String taskId;
    private final String targetUrl;
    private final HttpRequestResponse originalRequestResponse;
    private final Runnable retryHandler;
    private Consumer<Color> onStatusChange;

    private final JLabel statusLabel = new JLabel("status: not started");
    private final Color statusDefaultColor = statusLabel.getForeground();
    private final JProgressBar progressBar = new JProgressBar();
    private final JTextPane logArea = new JTextPane();
    private final JTable findingsTable;
    private final JScrollPane findingsScroll;
    private final JLabel noFindingsLabel = new JLabel("No command injection confirmed.", SwingConstants.CENTER);
    private final DefaultTableModel findingsModel = new DefaultTableModel(
            new Object[]{"Parameter", "Method", "Technique", "Type", "Payload"}, 0) {
        @Override
        public boolean isCellEditable(int row, int column) {
            return false;
        }
    };
    private final List<JsonObject> findingsData = new ArrayList<>();
    private final JButton stopButton = new JButton("Stop");
    private final JButton killButton = new JButton("Kill");
    private final JButton retryButton = new JButton("Edit options & scan again");

    private final Timer pollTimer;
    private final Set<String> raisedFindings = new HashSet<>();
    private final Map<String, JsonObject> logConfirmedFindings = new LinkedHashMap<>();
    private int logCursor = 0;
    private boolean finished = false;
    private boolean hasCritical = false;

    public ScanPanel(MontoyaApi api, CommixApiClient client, String taskId, String targetUrl,
                      HttpRequestResponse originalRequestResponse, Runnable retryHandler) {
        super(new BorderLayout(8, 8));
        this.api = api;
        this.client = client;
        this.logging = api.logging();
        this.taskId = taskId;
        this.targetUrl = targetUrl;
        this.originalRequestResponse = originalRequestResponse;
        this.retryHandler = retryHandler;

        progressBar.setIndeterminate(true);
        progressBar.setPreferredSize(new Dimension(90, statusLabel.getPreferredSize().height));

        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));
        top.add(new JLabel("Target: " + targetUrl));
        top.add(Box.createHorizontalStrut(16));
        top.add(statusLabel);
        top.add(Box.createHorizontalStrut(8));
        top.add(progressBar);

        JPanel north = new JPanel(new BorderLayout());
        north.add(CommixLogo.header(22, null), BorderLayout.NORTH);
        north.add(top, BorderLayout.CENTER);
        add(north, BorderLayout.NORTH);

        logArea.setEditable(false);
        logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane logScroll = new JScrollPane(logArea);
        logScroll.setBorder(BorderFactory.createTitledBorder("Log"));

        findingsTable = new JTable(findingsModel);
        findingsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() != 2) {
                    return;
                }
                int viewRow = findingsTable.rowAtPoint(e.getPoint());
                if (viewRow < 0) {
                    return;
                }
                int modelRow = findingsTable.convertRowIndexToModel(viewRow);
                if (modelRow >= 0 && modelRow < findingsData.size()) {
                    showFindingDetail(findingsData.get(modelRow));
                }
            }
        });
        findingsScroll = new JScrollPane(findingsTable);
        findingsScroll.setBorder(BorderFactory.createTitledBorder("Findings (also raised under Target → Issues)"));
        noFindingsLabel.setForeground(MUTED);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, logScroll, findingsScroll);
        split.setResizeWeight(0.6);
        add(split, BorderLayout.CENTER);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        stopButton.addActionListener(e -> stop());
        killButton.addActionListener(e -> kill());
        retryButton.addActionListener(e -> retryHandler.run());
        buttons.add(stopButton);
        buttons.add(killButton);
        buttons.add(retryButton);
        add(buttons, BorderLayout.SOUTH);

        this.pollTimer = new Timer(2000, e -> poll());
        pollTimer.setInitialDelay(0);
        pollTimer.start();
    }

    /**
     * Stops this scan's own polling - called for every open scan when the extension unloads, since
     * a Swing Timer nobody told to stop keeps firing (and keeps this object alive) long after.
     */
    public void stopPolling() {
        pollTimer.stop();
    }

    /**
     * Called with this scan's status color (running/finished/critical) each time it changes, so
     * whoever owns this tab can reflect it in the tab itself - set after construction, since the
     * caller needs this panel to already exist (e.g. to look up its own tab index) before it can
     * do anything useful with the color.
     */
    public void setOnStatusChange(Consumer<Color> onStatusChange) {
        this.onStatusChange = onStatusChange;
    }

    private void stop() {
        new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() {
                try {
                    client.stopScan(taskId);
                } catch (CommixApiClient.ApiException e) {
                    logging.logToError("Could not stop task " + taskId + ": " + e.getMessage());
                }
                return null;
            }
        }.execute();
    }

    private void kill() {
        new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() {
                try {
                    client.killScan(taskId);
                } catch (CommixApiClient.ApiException e) {
                    logging.logToError("Could not kill task " + taskId + ": " + e.getMessage());
                }
                return null;
            }
        }.execute();
    }

    private void poll() {
        if (finished) {
            pollTimer.stop();
            return;
        }
        new SwingWorker<PollResult, Void>() {
            @Override
            protected PollResult doInBackground() throws Exception {
                JsonObject status = client.status(taskId);
                JsonObject log = client.log(taskId, logCursor);
                JsonObject data = null;
                String statusValue = status.has("status") ? status.get("status").getAsString() : "unknown";
                if (!RUNNING_STATUSES.contains(statusValue)) {
                    data = client.data(taskId);
                }
                return new PollResult(statusValue, log, data);
            }

            @Override
            protected void done() {
                try {
                    applyPoll(get());
                } catch (Exception e) {
                    logging.logToError("Polling task " + taskId + " failed: " + e.getMessage());
                }
            }
        }.execute();
    }

    private void applyPoll(PollResult result) {
        if (result.log != null && result.log.has("log")) {
            JsonArray lines = result.log.getAsJsonArray("log");
            for (JsonElement element : lines) {
                JsonObject line = element.getAsJsonObject();
                String level = line.get("level").getAsString();
                String message = line.get("message").getAsString();
                if ("critical".equalsIgnoreCase(level)) {
                    hasCritical = true;
                }
                recordIfConfirmation(message);
                appendLogLine("[" + line.get("time").getAsString() + "] "
                        + level + ": "
                        + message + "\n", colorFor(level));
                logCursor++;
            }
            logArea.setCaretPosition(logArea.getDocument().getLength());
        }

        if (result.data != null) {
            renderFindings(result.data);
            finished = true;
            stopButton.setEnabled(false);
            killButton.setEnabled(false);
            progressBar.setVisible(false);
            findingsScroll.setViewportView(findingsModel.getRowCount() == 0 ? noFindingsLabel : findingsTable);
        }

        if (hasCritical) {
            statusLabel.setText("status: " + result.status + " - critical error, see log below");
            statusLabel.setForeground(BAD);
        } else if (finished) {
            statusLabel.setText("status: " + result.status);
            statusLabel.setForeground(GOOD);
        } else {
            statusLabel.setText("status: " + result.status);
            statusLabel.setForeground(statusDefaultColor);
        }

        if (onStatusChange != null) {
            onStatusChange.accept(hasCritical ? BAD : finished ? GOOD : RUNNING_COLOR);
        }
    }

    private void renderFindings(JsonObject data) {
        if (!data.has("data")) {
            return;
        }
        JsonObject report = data.getAsJsonObject("data");
        findingsModel.setRowCount(0);
        findingsData.clear();

        Set<String> covered = new HashSet<>();
        if (report.has("findings")) {
            addFindingRows(report.getAsJsonArray("findings"), covered);
        } else if (report.has("targets")) {
            for (JsonElement targetElement : report.getAsJsonArray("targets")) {
                JsonObject target = targetElement.getAsJsonObject();
                if (target.has("findings")) {
                    addFindingRows(target.getAsJsonArray("findings"), covered);
                }
            }
        }

        // Anything the log already said was confirmed, but that isn't covered by the structured
        // report above, still gets a row - see the comment on logConfirmedFindings/INJECTABLE_LOG_LINE.
        for (Map.Entry<String, JsonObject> entry : logConfirmedFindings.entrySet()) {
            if (!covered.contains(entry.getKey())) {
                addOneFinding(entry.getValue(), covered);
            }
        }
    }

    private void addFindingRows(JsonArray findings, Set<String> covered) {
        for (JsonElement element : findings) {
            addOneFinding(element.getAsJsonObject(), covered);
        }
    }

    private void addOneFinding(JsonObject finding, Set<String> covered) {
        covered.add(findingKey(finding));
        findingsModel.addRow(new Object[]{
                text(finding, "parameter"),
                text(finding, "http_method"),
                text(finding, "technique"),
                text(finding, "type"),
                text(finding, "payload")
        });
        findingsData.add(finding);
        raiseIssueOnce(finding);
    }

    /**
     * commix's own log announces a technique as confirmed the moment it happens - kept here (keyed
     * the same way as a structured finding, parameter+method+technique) so it can still be shown
     * even if the final report doesn't carry it through.
     */
    private void recordIfConfirmation(String message) {
        Matcher matcher = INJECTABLE_LOG_LINE.matcher(message);
        if (!matcher.matches()) {
            return;
        }
        String method = matcher.group(1);
        String parameter = matcher.group(2);
        String technique = capitalize(matcher.group(3)) + "-based";
        String type = capitalize(matcher.group(4)) + " command injection";

        JsonObject finding = new JsonObject();
        finding.addProperty("parameter", parameter);
        finding.addProperty("http_method", method);
        finding.addProperty("technique", technique);
        finding.addProperty("type", type);
        finding.addProperty("payload", "(not included in commix's own report for this technique - see the log above)");
        finding.addProperty("boundary", "");

        logConfirmedFindings.putIfAbsent(findingKey(finding), finding);
    }

    private static String findingKey(JsonObject finding) {
        return text(finding, "parameter") + "\u0000" + text(finding, "http_method") + "\u0000" + text(finding, "technique");
    }

    private static String capitalize(String word) {
        return word.isEmpty() ? word : Character.toUpperCase(word.charAt(0)) + word.substring(1);
    }

    /** Full detail for a finding, including the whole payload - the table's own column truncates it. */
    private void showFindingDetail(JsonObject finding) {
        String boundary = text(finding, "boundary");
        String detail = "Parameter: " + text(finding, "parameter") + "\n"
                + "Method: " + text(finding, "http_method") + "\n"
                + "Technique: " + text(finding, "technique") + "\n"
                + "Type: " + text(finding, "type") + "\n"
                + (boundary.isEmpty() ? "" : "Boundary: " + boundary + "\n")
                + "Payload:\n" + text(finding, "payload");

        JTextArea area = new JTextArea(detail, 10, 50);
        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JOptionPane.showMessageDialog(api.userInterface().swingUtils().suiteFrame(), new JScrollPane(area),
                "Finding detail", JOptionPane.PLAIN_MESSAGE);
    }

    /**
     * Raises a Burp audit issue for 'finding', the first time this exact finding is seen - a single
     * report can list the same finding more than once (one entry per matching boundary or
     * technique pass), which would otherwise raise the same issue again for each repeat.
     */
    private void raiseIssueOnce(JsonObject finding) {
        String parameter = text(finding, "parameter");
        String httpMethod = text(finding, "http_method");
        String technique = text(finding, "technique");
        String type = text(finding, "type");
        String boundary = text(finding, "boundary");
        String payload = text(finding, "payload");

        String key = parameter + "\u0000" + httpMethod + "\u0000" + technique + "\u0000" + payload;
        if (!raisedFindings.add(key)) {
            return;
        }

        String name = "OS command injection (commix: " + type + ")";
        String detail = "<p>commix confirmed OS command injection on the <b>" + escape(parameter)
                + "</b> parameter (" + escape(httpMethod) + ").</p>"
                + "<ul>"
                + "<li><b>Technique:</b> " + escape(technique) + "</li>"
                + "<li><b>Type:</b> " + escape(type) + "</li>"
                + (boundary.isEmpty() ? "" : "<li><b>Boundary:</b> " + escape(boundary) + "</li>")
                + "<li><b>Payload:</b> <code>" + escape(payload) + "</code></li>"
                + "</ul>"
                + "<p>commix task id: " + escape(taskId) + "</p>";
        String remediation = "<p>Avoid passing user-controlled input to a function that invokes a system "
                + "shell. Where a command must be run, use an API that takes the program and its arguments "
                + "separately (never a single shell string), and validate the input against a strict "
                + "allow-list rather than a blacklist of dangerous characters.</p>";

        AuditIssue issue = AuditIssue.auditIssue(
                name,
                detail,
                remediation,
                targetUrl,
                AuditIssueSeverity.HIGH,
                AuditIssueConfidence.CERTAIN,
                "OS command injection allows an attacker to execute arbitrary operating system commands "
                        + "on the server, typically leading to full compromise of the application and often "
                        + "the underlying host.",
                null,
                AuditIssueSeverity.HIGH,
                originalRequestResponse
        );
        api.siteMap().add(issue);
    }

    private Color colorFor(String level) {
        switch (level.toLowerCase(Locale.ROOT)) {
            case "critical":
            case "error":
                return BAD;
            case "warning":
                return WARN;
            case "debug":
                return MUTED;
            default:
                // "info", and anything else commix might send, in the log's own default color.
                return statusDefaultColor;
        }
    }

    private void appendLogLine(String line, Color color) {
        StyledDocument document = logArea.getStyledDocument();
        SimpleAttributeSet attributes = new SimpleAttributeSet();
        StyleConstants.setForeground(attributes, color);
        try {
            document.insertString(document.getLength(), line, attributes);
        } catch (BadLocationException e) {
            // The insertion point is always document.getLength(), which is always a valid offset.
            throw new AssertionError(e);
        }
    }

    private static String escape(String value) {
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private static String text(JsonObject object, String field) {
        return object.has(field) && !object.get(field).isJsonNull() ? object.get(field).getAsString() : "";
    }

    private static final class PollResult {
        final String status;
        final JsonObject log;
        final JsonObject data;

        PollResult(String status, JsonObject log, JsonObject data) {
            this.status = status;
            this.log = log;
            this.data = data;
        }
    }
}
