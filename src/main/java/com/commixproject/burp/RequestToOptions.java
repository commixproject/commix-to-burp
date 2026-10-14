/*
 * This file is part of the commix-to-burp extension (https://github.com/commixproject/commix-to-burp).
 * Copyright 2026 Anastasios Stasinopoulos (@ancst).
 *
 * Licensed under the Apache License, Version 2.0; see the LICENSE file for details.
 */

package com.commixproject.burp;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * A Burp request, read into the options commix's API takes - named the way the command line names
 * them, same as everywhere else in this extension.
 *
 * Cookie, User-Agent and Referer are pulled out into their own options rather than left in
 * 'headers': commix tests each of those as an injection point of its own from 'level' 2/3 up, which
 * it can only do where it is told which header carries which.
 *
 * A URL/body parameter wrapped in Burp's own Intruder-style '§...§' markers (meaningless to Burp
 * itself outside Intruder, so this works from any request editor, not just Intruder) is read as
 * the parameter to test. A header marked the same way - User-Agent, Referer, a custom one, same
 * idea as Burp's own convention of marking the value rather than the name - only ever has its
 * markers stripped: commix's '-p' selects among named GET/POST parameters, never a header, so
 * there is no equivalent "test this header" option to feed a header's name into.
 */
public class RequestToOptions {

    private static final char MARKER = '§';

    private RequestToOptions() {
    }

    /** The options derived from a request, and which parameters (if any) were marked. */
    public static final class Result {
        public final Map<String, Object> options;
        public final List<String> markedParameters;

        private Result(Map<String, Object> options, List<String> markedParameters) {
            this.options = options;
            this.markedParameters = markedParameters;
        }
    }

    public static Result from(HttpRequest originalRequest) {
        List<String> markedParameters = new ArrayList<>();
        List<HttpParameter> cleanedParameters = new ArrayList<>();
        for (ParsedHttpParameter parameter : originalRequest.parameters()) {
            String value = parameter.value();
            if (value == null || value.indexOf(MARKER) < 0) {
                continue;
            }
            String stripped = value.replace(String.valueOf(MARKER), "");
            cleanedParameters.add(HttpParameter.parameter(parameter.name(), stripped, parameter.type()));
            if (parameter.type() == HttpParameterType.URL || parameter.type() == HttpParameterType.BODY) {
                markedParameters.add(parameter.name());
            }
        }
        HttpRequest request = cleanedParameters.isEmpty()
                ? originalRequest
                : originalRequest.withUpdatedParameters(cleanedParameters);

        Map<String, Object> options = new LinkedHashMap<>();
        options.put("url", request.url());
        options.put("method", request.method());

        String body = request.bodyToString();
        if (body != null && !body.isEmpty()) {
            options.put("data", body);
        }

        StringBuilder extraHeaders = new StringBuilder();
        List<HttpHeader> headers = request.headers();
        for (HttpHeader header : headers) {
            String name = header.name();
            String value = header.value();
            if (name == null) {
                continue;
            }
            switch (name.toLowerCase(Locale.ROOT)) {
                case "cookie":
                    options.put("cookie", value);
                    break;
                case "user-agent":
                    // Marked or not, --level 2+ is what makes commix test this header on its own -
                    // '-p' only selects among named GET/POST parameters, never a header.
                    options.put("agent", stripMarker(value));
                    break;
                case "referer":
                    options.put("referer", stripMarker(value));
                    break;
                // 'host' and 'content-length' are worked out by commix itself from the URL and the
                // body it was just given - repeating them here would only disagree with one or the
                // other if the request being replayed is already stale.
                case "host":
                case "content-length":
                    break;
                default:
                    value = stripMarker(value);
                    if (extraHeaders.length() > 0) {
                        extraHeaders.append("\\n");
                    }
                    extraHeaders.append(name).append(": ").append(value);
            }
        }
        if (extraHeaders.length() > 0) {
            options.put("headers", extraHeaders.toString());
        }

        return new Result(options, markedParameters);
    }

    private static String stripMarker(String value) {
        return value == null ? null : value.replace(String.valueOf(MARKER), "");
    }
}
