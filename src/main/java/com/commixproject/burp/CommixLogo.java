/*
 * This file is part of the commix-to-burp extension (https://github.com/commixproject/commix-to-burp).
 * Copyright 2026 Anastasios Stasinopoulos (@ancst).
 *
 * Licensed under the Apache License, Version 2.0; see the LICENSE file for details.
 */

package com.commixproject.burp;

import javax.swing.*;
import java.awt.*;
import java.net.URL;

/**
 * The commix wordmark, shared by every panel so it's loaded and scaled once per size rather than
 * reimplemented per panel. The header it builds has no colors of its own - it takes whatever
 * background and text color Burp's current look and feel already gives a plain JPanel/JLabel, so
 * it sits next to Burp's own tabs without looking like a different application.
 */
final class CommixLogo {

    private static final Color SEPARATOR = new Color(0x80, 0x80, 0x80, 0x60);

    private CommixLogo() {
    }

    static ImageIcon icon(int height) {
        URL resource = CommixLogo.class.getResource("commix-logo.png");
        if (resource == null) {
            return new ImageIcon();
        }
        ImageIcon original = new ImageIcon(resource);
        int width = Math.round(height * (original.getIconWidth() / (float) original.getIconHeight()));
        Image scaled = original.getImage().getScaledInstance(width, height, Image.SCALE_SMOOTH);
        return new ImageIcon(scaled);
    }

    /** A plain header bar: the logo, and an optional one-line subtitle underneath it. */
    static JPanel header(int logoHeight, String subtitle) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, SEPARATOR),
                BorderFactory.createEmptyBorder(8, 12, 8, 12)));

        JPanel text = new JPanel();
        text.setOpaque(false);
        text.setLayout(new BoxLayout(text, BoxLayout.Y_AXIS));
        text.add(new JLabel(icon(logoHeight)));
        if (subtitle != null && !subtitle.isEmpty()) {
            JLabel subtitleLabel = new JLabel(subtitle);
            subtitleLabel.setFont(subtitleLabel.getFont().deriveFont(Font.PLAIN, 11f));
            text.add(Box.createVerticalStrut(4));
            text.add(subtitleLabel);
        }
        panel.add(text, BorderLayout.WEST);
        return panel;
    }
}
