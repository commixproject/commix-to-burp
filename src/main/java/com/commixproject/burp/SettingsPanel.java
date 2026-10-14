/*
 * This file is part of the commix-to-burp extension (https://github.com/commixproject/commix-to-burp).
 * Copyright 2026 Anastasios Stasinopoulos (@ancst).
 *
 * Licensed under the Apache License, Version 2.0; see the LICENSE file for details.
 */

package com.commixproject.burp;

import burp.api.montoya.logging.Logging;
import com.google.gson.JsonObject;

import javax.swing.*;
import java.awt.*;

/**
 * Where the commixapi.py server is, and the token it wants - a thin editor over CommixSettings,
 * with a button to prove the two sides can actually talk before a scan is ever started. Leads with
 * what has to happen first, since nothing below it works until a commixapi.py is actually running,
 * and checks the saved connection itself on load so the status is visible before the user clicks anything.
 */
public class SettingsPanel extends JPanel {

    private static final Color ACCENT = new Color(0x2E, 0x7D, 0x32);
    private static final Color BAD = new Color(0xC6, 0x28, 0x28);
    private static final Color MUTED = new Color(0x75, 0x75, 0x75);

    public SettingsPanel(CommixSettings settings, CommixApiClient client, Logging logging) {
        super(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        add(CommixLogo.header(36, "Burp extension, driven by commix's own REST API"), BorderLayout.NORTH);

        JPanel body = new JPanel();
        body.setLayout(new BoxLayout(body, BoxLayout.Y_AXIS));
        body.add(gettingStartedPanel());
        body.add(Box.createVerticalStrut(10));
        body.add(connectionPanel(settings, client, logging));
        body.add(Box.createVerticalStrut(10));
        body.add(nextStepsPanel());
        // NORTH, not CENTER: otherwise the tab's leftover height gets split between the boxes
        // above, and a GridBagLayout panel centers itself inside space wider than it needs.
        add(body, BorderLayout.NORTH);
    }

    private JPanel gettingStartedPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createTitledBorder("Getting started"));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);

        panel.add(stepLabel("1. Clone commix, if you don't have it already:"));
        panel.add(codeLabel("git clone https://github.com/commixproject/commix.git"));
        panel.add(Box.createVerticalStrut(8));
        panel.add(stepLabel("2. From that checkout, run:"));
        panel.add(codeLabel("python commixapi.py"));
        panel.add(Box.createVerticalStrut(8));
        panel.add(stepLabel("3. It prints a host, a port and a token, e.g.:"));
        panel.add(codeLabel("Serving the commix API at 'http://127.0.0.1:8775'."));
        panel.add(codeLabel("Send the token 's3cr3t' as the 'X-Api-Token' header."));
        return panel;
    }

    private JPanel nextStepsPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createTitledBorder("Next steps"));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);

        panel.add(stepLabel("4. Enter those three above and click \"Save & test\"."));
        panel.add(Box.createVerticalStrut(8));
        panel.add(stepLabel("5. Right-click any request in Burp and choose \"Scan\"."));
        return panel;
    }

    private static JLabel stepLabel(String text) {
        JLabel label = new JLabel(text);
        label.setAlignmentX(Component.LEFT_ALIGNMENT);
        label.setBorder(BorderFactory.createEmptyBorder(2, 4, 2, 4));
        return label;
    }

    private static JLabel codeLabel(String text) {
        JLabel label = new JLabel(text);
        label.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        label.setForeground(MUTED);
        label.setAlignmentX(Component.LEFT_ALIGNMENT);
        label.setBorder(BorderFactory.createEmptyBorder(1, 22, 1, 4));
        return label;
    }

    private JPanel connectionPanel(CommixSettings settings, CommixApiClient client, Logging logging) {
        JPanel outer = new JPanel(new BorderLayout());
        outer.setBorder(BorderFactory.createTitledBorder("Connection"));
        outer.setAlignmentX(Component.LEFT_ALIGNMENT);

        JPanel panel = new JPanel(new GridBagLayout());
        outer.add(panel, BorderLayout.WEST);

        JTextField hostField = new JTextField(settings.host(), 16);
        JTextField portField = new JTextField(String.valueOf(settings.port()), 6);
        JTextField tokenField = new JTextField(settings.token(), 24);
        JLabel statusDot = new JLabel("●");
        statusDot.setForeground(MUTED);
        JLabel resultLabel = new JLabel("Not checked yet.");
        resultLabel.setForeground(MUTED);
        JButton saveButton = new JButton("Save & test");

        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(5, 5, 5, 5);
        c.anchor = GridBagConstraints.WEST;

        c.gridx = 0;
        c.gridy = 0;
        panel.add(new JLabel("Host"), c);
        c.gridx = 1;
        c.gridwidth = 2;
        panel.add(hostField, c);
        c.gridwidth = 1;

        c.gridx = 0;
        c.gridy = 1;
        panel.add(new JLabel("Port"), c);
        c.gridx = 1;
        c.gridwidth = 2;
        panel.add(portField, c);
        c.gridwidth = 1;

        c.gridx = 0;
        c.gridy = 2;
        panel.add(new JLabel("Token"), c);
        c.gridx = 1;
        c.gridwidth = 2;
        panel.add(tokenField, c);
        c.gridwidth = 1;

        c.gridx = 1;
        c.gridy = 3;
        c.gridwidth = 2;
        JLabel tokenHint = new JLabel("the server prints this on startup, as 'X-Api-Token'");
        tokenHint.setForeground(MUTED);
        tokenHint.setFont(tokenHint.getFont().deriveFont(Font.ITALIC, 11f));
        panel.add(tokenHint, c);
        c.gridwidth = 1;

        c.gridx = 0;
        c.gridy = 4;
        c.gridwidth = 3;
        panel.add(saveButton, c);

        c.gridy = 5;
        JPanel statusRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        statusRow.setOpaque(false);
        statusRow.add(statusDot);
        statusRow.add(resultLabel);
        panel.add(statusRow, c);

        Runnable save = () -> {
            settings.setHost(hostField.getText().trim());
            try {
                settings.setPort(Integer.parseInt(portField.getText().trim()));
            } catch (NumberFormatException e) {
                statusDot.setForeground(BAD);
                resultLabel.setForeground(BAD);
                resultLabel.setText("Port must be a number.");
                return;
            }
            settings.setToken(tokenField.getText());
        };

        Runnable test = () -> {
            statusDot.setForeground(MUTED);
            resultLabel.setForeground(MUTED);
            resultLabel.setText("Checking...");
            new SwingWorker<String, Void>() {
                private boolean ok;

                @Override
                protected String doInBackground() {
                    try {
                        JsonObject version = client.version();
                        ok = true;
                        return "Connected using commix REST API (" + version.get("api").getAsString() + ").";
                    } catch (CommixApiClient.ApiException ex) {
                        ok = false;
                        return "Not connected: " + ex.getMessage();
                    }
                }

                @Override
                protected void done() {
                    try {
                        String message = get();
                        statusDot.setForeground(ok ? ACCENT : BAD);
                        resultLabel.setForeground(ok ? ACCENT : BAD);
                        resultLabel.setText(message);
                        logging.logToOutput(message);
                    } catch (Exception ex) {
                        statusDot.setForeground(BAD);
                        resultLabel.setForeground(BAD);
                        resultLabel.setText("Failed: " + ex.getMessage());
                    }
                }
            }.execute();
        };

        saveButton.addActionListener(e -> {
            save.run();
            test.run();
        });

        if (!settings.token().isEmpty()) {
            test.run();
        }

        return outer;
    }
}
