/*
 * This file is part of the commix-to-burp extension (https://github.com/commixproject/commix-to-burp).
 * Copyright 2026 Anastasios Stasinopoulos (@ancst).
 *
 * Licensed under the Apache License, Version 2.0; see the LICENSE file for details.
 */

package com.commixproject.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;

import java.util.Map;

/**
 * A thin client for commixapi.py's REST contract (see the project's wiki page "API"). Every call
 * is synchronous and blocking - callers from Swing code run it off the event-dispatch thread.
 *
 * Sent through Burp's own {@code Http.sendRequest()} rather than a bare HTTP client, per BApp
 * Store acceptance criterion #7 - even though this connection is to a local control-plane service,
 * not the scan's actual target, so Burp's own upstream-proxy and session-handling rules (meant for
 * target traffic) don't really apply to it the way the criterion's own rationale assumes.
 */
public class CommixApiClient {

    private final MontoyaApi api;
    private final CommixSettings settings;

    public CommixApiClient(MontoyaApi api, CommixSettings settings) {
        this.api = api;
        this.settings = settings;
    }

    public static class ApiException extends Exception {
        public ApiException(String message) {
            super(message);
        }
    }

    private JsonObject request(String method, String path, JsonObject body) throws ApiException {
        HttpRequest request = HttpRequest.httpRequestFromUrl(settings.baseUrl() + path).withMethod(method);

        String token = settings.token();
        if (token != null && !token.isEmpty()) {
            request = request.withHeader("X-Api-Token", token);
        }

        if ("POST".equals(method)) {
            String json = body == null ? "{}" : body.toString();
            request = request.withHeader("Content-Type", "application/json").withBody(json);
        }

        HttpRequestResponse requestResponse;
        try {
            requestResponse = api.http().sendRequest(request);
        } catch (RuntimeException e) {
            throw new ApiException("Could not reach the commix API at " + settings.baseUrl() + ": " + e.getMessage());
        }
        if (!requestResponse.hasResponse()) {
            throw new ApiException("Could not reach the commix API at " + settings.baseUrl() + ".");
        }

        String responseBody = requestResponse.response().bodyToString();
        JsonObject parsed;
        try {
            parsed = JsonParser.parseString(responseBody).getAsJsonObject();
        } catch (JsonSyntaxException | IllegalStateException e) {
            throw new ApiException("The commix API answered with something that is not a JSON object "
                    + "(HTTP " + requestResponse.response().statusCode() + "): " + truncate(responseBody));
        }

        if (parsed.has("success") && !parsed.get("success").getAsBoolean()) {
            String message = parsed.has("message") ? parsed.get("message").getAsString() : "unknown error";
            throw new ApiException(message);
        }
        return parsed;
    }

    private static String truncate(String text) {
        if (text == null) {
            return "";
        }
        return text.length() > 200 ? text.substring(0, 200) + "..." : text;
    }

    private JsonObject get(String path) throws ApiException {
        return request("GET", path, null);
    }

    private JsonObject post(String path, JsonObject body) throws ApiException {
        return request("POST", path, body);
    }

    /** GET /version - the one address that asks for no token. */
    public JsonObject version() throws ApiException {
        return get("/version");
    }

    /** GET /task/new */
    public String newTask() throws ApiException {
        return get("/task/new").get("taskid").getAsString();
    }

    /** GET /task/{id}/delete */
    public void deleteTask(String taskId) throws ApiException {
        get("/task/" + taskId + "/delete");
    }

    /**
     * POST /option/{id}/set - options named the way the command line names them ('url', 'data',
     * 'agent', 'cookie', 'headers', 'tech', ...).
     */
    public void setOptions(String taskId, Map<String, Object> options) throws ApiException {
        JsonObject body = new JsonObject();
        for (Map.Entry<String, Object> entry : options.entrySet()) {
            Object value = entry.getValue();
            if (value instanceof Boolean) {
                body.addProperty(entry.getKey(), (Boolean) value);
            } else if (value instanceof Number) {
                body.addProperty(entry.getKey(), (Number) value);
            } else if (value != null) {
                body.addProperty(entry.getKey(), value.toString());
            }
        }
        post("/option/" + taskId + "/set", body);
    }

    /** POST /scan/{id}/start - options already set with setOptions(), so the body is empty here. */
    public void startScan(String taskId) throws ApiException {
        post("/scan/" + taskId + "/start", new JsonObject());
    }

    /** GET /scan/{id}/stop */
    public void stopScan(String taskId) throws ApiException {
        get("/scan/" + taskId + "/stop");
    }

    /** GET /scan/{id}/kill */
    public void killScan(String taskId) throws ApiException {
        get("/scan/" + taskId + "/kill");
    }

    /** GET /scan/{id}/status */
    public JsonObject status(String taskId) throws ApiException {
        return get("/scan/" + taskId + "/status");
    }

    /** GET /scan/{id}/data - the report, readable while the scan runs and after it ends. */
    public JsonObject data(String taskId) throws ApiException {
        return get("/scan/" + taskId + "/data");
    }

    /** GET /scan/{id}/log?start={from} - only the lines not already read. */
    public JsonObject log(String taskId, int start) throws ApiException {
        return get("/scan/" + taskId + "/log?start=" + start);
    }
}
