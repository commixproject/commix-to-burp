/*
 * This file is part of the commix-to-burp extension (https://github.com/commixproject/commix-to-burp).
 * Copyright 2026 Anastasios Stasinopoulos (@ancst).
 *
 * Licensed under the Apache License, Version 2.0; see the LICENSE file for details.
 */

package com.commixproject.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;

import javax.swing.*;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Insets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The one suite tab this extension registers: a settings page, and one more tab per scan started
 * from the context menu, added as they begin rather than all laid out up front. Also the one place
 * that actually launches a scan, so both the context menu and a failed scan's "retry" button go
 * through the same path.
 */
public class MainPanel extends JTabbedPane {

    private final MontoyaApi api;
    private final CommixSettings settings;
    private final CommixApiClient client;
    private final List<ScanPanel> scans = new ArrayList<>();

    public MainPanel(MontoyaApi api, CommixSettings settings, CommixApiClient client) {
        this.api = api;
        this.settings = settings;
        this.client = client;
        addTab("Settings", new SettingsPanel(settings, client, api.logging()));
    }

    /**
     * Shows the options dialog for 'requestResponse' and, unless the user cancels, starts a scan
     * and adds its tab. On failure, offers to reopen the dialog (pre-filled with what was just
     * chosen) rather than leaving the user to start over from the context menu.
     */
    public void launchScan(HttpRequestResponse requestResponse) {
        RequestToOptions.Result extracted = RequestToOptions.from(requestResponse.request());

        Optional<Map<String, Object>> chosen = ScanOptionsDialog.show(
                api.userInterface().swingUtils().suiteFrame(), settings, extracted.markedParameters);
        if (chosen.isEmpty()) {
            return;
        }

        Map<String, Object> options = new LinkedHashMap<>(extracted.options);
        options.putAll(chosen.get());
        if (Boolean.TRUE.equals(options.get("random_agent")) || Boolean.TRUE.equals(options.get("mobile"))) {
            // commix rejects a fixed User-Agent read off the original request together with either
            // --random-agent or --mobile - only one User-Agent can apply to a given scan.
            options.remove("agent");
        }
        String targetUrl = String.valueOf(options.get("url"));

        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() throws Exception {
                String taskId = client.newTask();
                client.setOptions(taskId, options);
                client.startScan(taskId);
                return taskId;
            }

            @Override
            protected void done() {
                try {
                    String taskId = get();
                    SwingUtilities.invokeLater(() -> addScan(taskId, targetUrl, requestResponse));
                } catch (Exception e) {
                    String message = "Could not start a commix scan: " + rootMessage(e);
                    api.logging().logToError(message);
                    SwingUtilities.invokeLater(() -> offerRetry(message, requestResponse));
                }
            }
        }.execute();
    }

    private void offerRetry(String message, HttpRequestResponse requestResponse) {
        Object[] choices = {"Edit options and retry", "Cancel"};
        int choice = JOptionPane.showOptionDialog(
                api.userInterface().swingUtils().suiteFrame(),
                message,
                "commix",
                JOptionPane.DEFAULT_OPTION,
                JOptionPane.ERROR_MESSAGE,
                null,
                choices,
                choices[0]);
        if (choice == 0) {
            launchScan(requestResponse);
        }
    }

    private static String rootMessage(Throwable t) {
        Throwable cause = t.getCause();
        return cause != null ? cause.getMessage() : t.getMessage();
    }

    /** Adds a tab for a just-started scan, and brings it to the front. */
    private void addScan(String taskId, String targetUrl, HttpRequestResponse originalRequestResponse) {
        ScanPanel panel = new ScanPanel(api, client, taskId, targetUrl, originalRequestResponse,
                () -> launchScan(originalRequestResponse));
        scans.add(panel);
        String title = targetUrl.length() > 40 ? targetUrl.substring(0, 37) + "..." : targetUrl;
        addTab(null, panel);
        int index = getTabCount() - 1;
        ScanTabHeader header = new ScanTabHeader(title, () -> closeScan(panel));
        setTabComponentAt(index, header);
        setSelectedIndex(index);
        panel.setOnStatusChange(header::setDotColor);
    }

    /** Stops the scan's polling and removes its tab - the close (×) button's own action. */
    private void closeScan(ScanPanel panel) {
        panel.stopPolling();
        scans.remove(panel);
        int index = indexOfComponent(panel);
        if (index >= 0) {
            removeTabAt(index);
        }
    }

    /** Stops every open scan's polling - called once, when the extension unloads. */
    public void stopAllScans() {
        for (ScanPanel panel : scans) {
            panel.stopPolling();
        }
    }

    /** A scan tab's own title bar: the status dot, the target title, and a close (×) button. */
    private static final class ScanTabHeader extends JPanel {
        private final JLabel dot = new JLabel();

        ScanTabHeader(String title, Runnable onClose) {
            super(new FlowLayout(FlowLayout.LEFT, 4, 0));
            setOpaque(false);
            add(dot);
            add(new JLabel(title));

            JButton close = new JButton("×");
            close.setToolTipText("Close");
            close.setMargin(new Insets(0, 4, 0, 4));
            close.setBorderPainted(false);
            close.setContentAreaFilled(false);
            close.setFocusable(false);
            close.setFont(close.getFont().deriveFont(Font.BOLD));
            close.addActionListener(e -> onClose.run());
            add(close);
        }

        void setDotColor(Color color) {
            dot.setIcon(new DotIcon(color));
        }
    }

    /** A small filled circle, used in a scan tab's title to show its status at a glance. */
    private static final class DotIcon implements Icon {
        private final Color color;

        DotIcon(Color color) {
            this.color = color;
        }

        @Override
        public void paintIcon(Component c, Graphics g, int x, int y) {
            g.setColor(color);
            g.fillOval(x, y + 3, 8, 8);
        }

        @Override
        public int getIconWidth() {
            return 10;
        }

        @Override
        public int getIconHeight() {
            return 14;
        }
    }
}
