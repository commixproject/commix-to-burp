/*
 * This file is part of the commix-to-burp extension (https://github.com/commixproject/commix-to-burp).
 * Copyright 2026 Anastasios Stasinopoulos (@ancst).
 *
 * Licensed under the Apache License, Version 2.0; see the LICENSE file for details.
 */

package com.commixproject.burp;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import java.awt.*;
import java.util.List;
import java.util.Optional;

/**
 * "Scan", wherever Burp shows a request - Proxy history, Repeater, Target. Picks the request open
 * in whatever editor was right-clicked, or the first of whatever rows are selected, then hands it
 * to MainPanel, which owns the whole options-dialog-then-scan flow (including retries).
 */
public class CommixContextMenuProvider implements ContextMenuItemsProvider {

    private final MainPanel mainPanel;

    public CommixContextMenuProvider(MainPanel mainPanel) {
        this.mainPanel = mainPanel;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        Optional<HttpRequestResponse> requestResponse = requestResponseFrom(event);
        if (requestResponse.isEmpty()) {
            return List.of();
        }

        JMenuItem item = new JMenuItem("Scan", new PlusIcon());
        item.addActionListener(e -> mainPanel.launchScan(requestResponse.get()));
        return List.of(item);
    }

    private Optional<HttpRequestResponse> requestResponseFrom(ContextMenuEvent event) {
        if (event.messageEditorRequestResponse().isPresent()) {
            return Optional.of(event.messageEditorRequestResponse().get().requestResponse());
        }
        List<HttpRequestResponse> selected = event.selectedRequestResponses();
        if (!selected.isEmpty()) {
            return Optional.of(selected.get(0));
        }
        return Optional.empty();
    }

    /** A "+" in a circle - starting a new scan is adding one, next to Burp's own built-in scan items. */
    private static final class PlusIcon implements Icon {
        @Override
        public void paintIcon(Component c, Graphics g, int x, int y) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setColor(c.getForeground());
            g2.setStroke(new BasicStroke(1.5f));

            int size = getIconWidth();
            g2.drawOval(x + 1, y + 1, size - 2, size - 2);

            int mid = y + size / 2;
            int midX = x + size / 2;
            int inset = 4;
            g2.drawLine(x + inset, mid, x + size - inset, mid);
            g2.drawLine(midX, y + inset, midX, y + size - inset);
            g2.dispose();
        }

        @Override
        public int getIconWidth() {
            return 14;
        }

        @Override
        public int getIconHeight() {
            return 14;
        }
    }
}
