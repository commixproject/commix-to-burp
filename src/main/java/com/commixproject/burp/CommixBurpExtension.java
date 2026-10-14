/*
 * This file is part of the commix-to-burp extension (https://github.com/commixproject/commix-to-burp).
 * Copyright 2026 Anastasios Stasinopoulos (@ancst).
 *
 * Licensed under the Apache License, Version 2.0; see the LICENSE file for details.
 */

package com.commixproject.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

/**
 * Entry point Burp loads. Everything here just wires the pieces together - the settings store, the
 * API client, the one suite tab, and the context menu that starts a scan from it.
 */
public class CommixBurpExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("commix");

        CommixSettings settings = new CommixSettings(api);
        CommixApiClient client = new CommixApiClient(api, settings);
        MainPanel mainPanel = new MainPanel(api, settings, client);

        api.userInterface().registerSuiteTab("commix", mainPanel);
        api.userInterface().registerContextMenuItemsProvider(new CommixContextMenuProvider(mainPanel));

        // Every open scan's polling Timer would otherwise keep firing (and keep this whole object
        // graph alive) long after Burp has moved on without it.
        api.extension().registerUnloadingHandler(mainPanel::stopAllScans);

        api.logging().logToOutput("Commix extension loaded. Configure the API server under the 'commix' tab.");
    }
}
