/*
 * This file is part of the commix-to-burp extension (https://github.com/commixproject/commix-to-burp).
 * Copyright 2026 Anastasios Stasinopoulos (@ancst).
 *
 * Licensed under the Apache License, Version 2.0; see the LICENSE file for details.
 */

package com.commixproject.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;

/**
 * Where the commixapi.py server is, and the token it wants - kept in Burp's own project
 * persistence so they survive a restart instead of being asked for every time.
 */
public class CommixSettings {

    private static final String KEY_HOST = "commix.host";
    private static final String KEY_PORT = "commix.port";
    private static final String KEY_TOKEN = "commix.token";

    private final PersistedObject store;

    public CommixSettings(MontoyaApi api) {
        this.store = api.persistence().extensionData();
    }

    public String host() {
        String value = store.getString(KEY_HOST);
        return value == null ? "127.0.0.1" : value;
    }

    public void setHost(String host) {
        store.setString(KEY_HOST, host);
    }

    public int port() {
        Integer value = store.getInteger(KEY_PORT);
        return value == null ? 8775 : value;
    }

    public void setPort(int port) {
        store.setInteger(KEY_PORT, port);
    }

    public String token() {
        String value = store.getString(KEY_TOKEN);
        return value == null ? "" : value;
    }

    public void setToken(String token) {
        store.setString(KEY_TOKEN, token);
    }

    public String baseUrl() {
        return "http://" + host() + ":" + port();
    }

    /** The raw store, for callers (ScanOptionsDialog) that keep a handful of keys of their own. */
    PersistedObject store() {
        return store;
    }
}
