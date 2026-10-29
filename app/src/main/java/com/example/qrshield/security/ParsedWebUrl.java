package com.example.qrshield.security;

/** Parsed pieces of a validated http/https URL. The original string is kept separately by callers. */
public final class ParsedWebUrl {
    public enum HostKind { DNS_NAME, IPV4, IPV6, NUMERIC_OBFUSCATED }

    public final String scheme;
    /** Raw text before '@' in the authority, or null. */
    public final String userInfo;
    public final HostKind hostKind;
    /** ASCII/lower-case host without brackets (punycode for IDNs). */
    public final String asciiHost;
    /** Unicode form of the host (equals asciiHost for plain ASCII names). */
    public final String unicodeHost;
    /** -1 when no explicit port. */
    public final int port;
    /** Path, query and fragment exactly as given (starts with / ? or #, or is empty). */
    public final String rest;
    public final boolean nonAsciiInput;
    public final boolean punycodeLabels;
    public final boolean mixedScript;
    public final boolean trailingDot;
    public final String normalized;

    ParsedWebUrl(String scheme, String userInfo, HostKind hostKind, String asciiHost, String unicodeHost,
                 int port, String rest, boolean nonAsciiInput, boolean punycodeLabels,
                 boolean mixedScript, boolean trailingDot, String normalized) {
        this.scheme = scheme;
        this.userInfo = userInfo;
        this.hostKind = hostKind;
        this.asciiHost = asciiHost;
        this.unicodeHost = unicodeHost;
        this.port = port;
        this.rest = rest;
        this.nonAsciiInput = nonAsciiInput;
        this.punycodeLabels = punycodeLabels;
        this.mixedScript = mixedScript;
        this.trailingDot = trailingDot;
        this.normalized = normalized;
    }

    public String path() {
        int end = rest.length();
        for (int i = 0; i < rest.length(); i++) {
            char c = rest.charAt(i);
            if (c == '?' || c == '#') { end = i; break; }
        }
        return rest.substring(0, end);
    }

    public String query() {
        int q = rest.indexOf('?');
        if (q < 0) return "";
        int h = rest.indexOf('#', q);
        return rest.substring(q + 1, h < 0 ? rest.length() : h);
    }
}
