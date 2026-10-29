package com.example.qrshield.security;

import java.net.IDN;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Validates http/https URLs structurally. Pure Java, no Android dependencies.
 * It never modifies the input; it only reports pieces and a failure reason.
 * A valid URL is NOT necessarily safe.
 */
public final class UrlValidator {

    public static final int MAX_INPUT_LENGTH = 4096;

    private static final Pattern DECIMAL_HOST = Pattern.compile("[0-9]+");
    private static final Pattern HEX_HOST = Pattern.compile("0[xX][0-9a-fA-F]+(\\.[0-9a-fA-FxX]+)*");
    private static final Pattern DOTTED_NUMERIC = Pattern.compile("[0-9.]+");

    /** Outcome: either a parsed URL or a user-readable reason (never containing the input). */
    public static final class Result {
        public final ParsedWebUrl url;
        public final String error;

        private Result(ParsedWebUrl url, String error) {
            this.url = url;
            this.error = error;
        }

        public boolean isValid() {
            return url != null;
        }

        static Result ok(ParsedWebUrl url) {
            return new Result(url, null);
        }

        static Result fail(String error) {
            return new Result(null, error);
        }
    }

    private UrlValidator() { }

    /** @param input an already-trimmed string whose scheme should be http or https */
    public static Result validateWebUrl(String input) {
        if (input == null || input.isEmpty()) {
            return Result.fail("The address is empty.");
        }
        if (input.length() > MAX_INPUT_LENGTH) {
            return Result.fail("The address is longer than QR Shield analyzes (" + MAX_INPUT_LENGTH + " characters).");
        }
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (Character.isISOControl(c) || Character.isWhitespace(c) || Character.isSpaceChar(c)) {
                return Result.fail("The address contains whitespace or control characters.");
            }
            if (Character.getType(c) == Character.FORMAT) {
                return Result.fail("The address contains invisible formatting characters.");
            }
        }

        int colon = input.indexOf(':');
        if (colon <= 0) {
            return Result.fail("The address has no scheme.");
        }
        String scheme = input.substring(0, colon).toLowerCase(Locale.ROOT);
        if (!scheme.equals("http") && !scheme.equals("https")) {
            return Result.fail("The scheme is not http or https.");
        }
        if (!input.startsWith("//", colon + 1)) {
            return Result.fail("The address is missing \"//\" after the scheme.");
        }

        int authStart = colon + 3;
        int authEnd = input.length();
        for (int i = authStart; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c == '/' || c == '?' || c == '#') { authEnd = i; break; }
        }
        String authority = input.substring(authStart, authEnd);
        String rest = input.substring(authEnd);
        if (authority.isEmpty()) {
            return Result.fail("The address has no host.");
        }

        int at = authority.lastIndexOf('@');
        String userInfo = at >= 0 ? authority.substring(0, at) : null;
        String hostPort = authority.substring(at + 1);
        if (hostPort.isEmpty()) {
            return Result.fail("The address has no host.");
        }

        String hostText;
        String portText = null;
        boolean bracketed = hostPort.startsWith("[");
        if (bracketed) {
            int close = hostPort.indexOf(']');
            if (close < 0) {
                return Result.fail("The IPv6 address is missing a closing bracket.");
            }
            hostText = hostPort.substring(1, close);
            String after = hostPort.substring(close + 1);
            if (!after.isEmpty()) {
                if (after.charAt(0) != ':') {
                    return Result.fail("Unexpected characters after the IPv6 address.");
                }
                portText = after.substring(1);
            }
            if (!isValidIpv6(hostText)) {
                return Result.fail("The IPv6 address is malformed.");
            }
        } else {
            if (hostPort.indexOf('[') >= 0 || hostPort.indexOf(']') >= 0) {
                return Result.fail("The host contains misplaced brackets.");
            }
            int lastColon = hostPort.lastIndexOf(':');
            if (lastColon >= 0) {
                hostText = hostPort.substring(0, lastColon);
                portText = hostPort.substring(lastColon + 1);
                if (hostText.indexOf(':') >= 0) {
                    return Result.fail("The host contains extra colons (an IPv6 address must be in brackets).");
                }
            } else {
                hostText = hostPort;
            }
        }

        int port = -1;
        if (portText != null) {
            if (portText.isEmpty() || portText.length() > 5 || !isAllDigits(portText)) {
                return Result.fail("The port is not a valid number.");
            }
            port = Integer.parseInt(portText);
            if (port < 1 || port > 65535) {
                return Result.fail("The port is outside the valid range 1-65535.");
            }
        }
        if (hostText.isEmpty()) {
            return Result.fail("The address has no host.");
        }

        ParsedWebUrl.HostKind kind;
        String ascii;
        String unicode;
        boolean nonAscii = false;
        boolean punycode = false;
        boolean mixed = false;
        boolean trailingDot = false;

        if (bracketed) {
            kind = ParsedWebUrl.HostKind.IPV6;
            ascii = hostText.toLowerCase(Locale.ROOT);
            unicode = ascii;
        } else if (DECIMAL_HOST.matcher(hostText).matches() || HEX_HOST.matcher(hostText).matches()) {
            kind = ParsedWebUrl.HostKind.NUMERIC_OBFUSCATED;
            ascii = hostText.toLowerCase(Locale.ROOT);
            unicode = ascii;
        } else if (DOTTED_NUMERIC.matcher(hostText).matches()) {
            if (!isValidIpv4(hostText)) {
                return Result.fail("The IPv4 address is malformed.");
            }
            kind = ParsedWebUrl.HostKind.IPV4;
            ascii = hostText;
            unicode = ascii;
        } else {
            kind = ParsedWebUrl.HostKind.DNS_NAME;
            String name = hostText;
            if (name.endsWith(".")) {
                trailingDot = true;
                name = name.substring(0, name.length() - 1);
                if (name.isEmpty() || name.endsWith(".")) {
                    return Result.fail("The hostname is malformed.");
                }
            }
            if (name.indexOf('%') >= 0) {
                return Result.fail("Percent-encoded hostnames are not accepted.");
            }
            for (int i = 0; i < name.length(); i++) {
                if (name.charAt(i) > 127) { nonAscii = true; break; }
            }
            if (nonAscii) {
                try {
                    ascii = IDN.toASCII(name, 0);
                } catch (IllegalArgumentException e) {
                    return Result.fail("The international hostname is not valid.");
                }
                ascii = ascii.toLowerCase(Locale.ROOT);
            } else {
                ascii = name.toLowerCase(Locale.ROOT);
            }
            String labelError = checkLabels(ascii);
            if (labelError != null) {
                return Result.fail(labelError);
            }
            punycode = ascii.startsWith("xn--") || ascii.contains(".xn--");
            unicode = (nonAscii || punycode) ? IDN.toUnicode(ascii) : ascii;
            mixed = hasMixedScriptLabel(unicode);
        }

        try {
            new URI(input);
        } catch (URISyntaxException e) {
            return Result.fail("The address is not well formed (for example a malformed percent escape or a character that is not allowed).");
        }

        StringBuilder norm = new StringBuilder();
        norm.append(scheme).append("://");
        if (userInfo != null) norm.append(userInfo).append('@');
        if (kind == ParsedWebUrl.HostKind.IPV6) norm.append('[').append(ascii).append(']');
        else norm.append(ascii);
        if (trailingDot) norm.append('.');
        if (port >= 0) norm.append(':').append(port);
        norm.append(rest);

        return Result.ok(new ParsedWebUrl(scheme, userInfo, kind, ascii, unicode, port, rest,
                nonAscii, punycode, mixed, trailingDot, norm.toString()));
    }

    private static String checkLabels(String ascii) {
        if (ascii.length() > 253) return "The hostname is longer than 253 characters.";
        int start = 0;
        while (start <= ascii.length()) {
            int dot = ascii.indexOf('.', start);
            int end = dot < 0 ? ascii.length() : dot;
            int len = end - start;
            if (len == 0) return "The hostname contains an empty label.";
            if (len > 63) return "A hostname label is longer than 63 characters.";
            if (ascii.charAt(start) == '-' || ascii.charAt(end - 1) == '-') {
                return "A hostname label starts or ends with a hyphen.";
            }
            for (int i = start; i < end; i++) {
                char c = ascii.charAt(i);
                boolean ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
                if (!ok) return "The hostname contains a character that is not allowed.";
            }
            if (dot < 0) break;
            start = dot + 1;
        }
        return null;
    }

    private static boolean hasMixedScriptLabel(String unicodeHost) {
        for (String label : unicodeHost.split("\\.")) {
            Set<Character.UnicodeScript> scripts = new HashSet<>();
            for (int i = 0; i < label.length(); ) {
                int cp = label.codePointAt(i);
                i += Character.charCount(cp);
                Character.UnicodeScript s = Character.UnicodeScript.of(cp);
                if (s != Character.UnicodeScript.COMMON && s != Character.UnicodeScript.INHERITED
                        && s != Character.UnicodeScript.UNKNOWN) {
                    scripts.add(s);
                }
            }
            if (scripts.size() > 1) return true;
        }
        return false;
    }

    /** Strict dotted-decimal IPv4; leading zeros are rejected as ambiguous. */
    public static boolean isValidIpv4(String s) {
        String[] parts = s.split("\\.", -1);
        if (parts.length != 4) return false;
        for (String p : parts) {
            if (p.isEmpty() || p.length() > 3 || !isAllDigits(p)) return false;
            if (p.length() > 1 && p.charAt(0) == '0') return false;
            if (Integer.parseInt(p) > 255) return false;
        }
        return true;
    }

    /** IPv6 without brackets or zone id; embedded IPv4 allowed as the last group. */
    public static boolean isValidIpv6(String s) {
        if (s.isEmpty() || s.indexOf('%') >= 0) return false;
        int dc = s.indexOf("::");
        if (dc != s.lastIndexOf("::")) return false;
        List<String> head = groups(dc >= 0 ? s.substring(0, dc) : s);
        List<String> tail = groups(dc >= 0 ? s.substring(dc + 2) : "");
        if (head == null || tail == null) return false;
        List<String> all = new ArrayList<>(head);
        all.addAll(tail);
        int count = 0;
        for (int i = 0; i < all.size(); i++) {
            String g = all.get(i);
            if (g.indexOf('.') >= 0) {
                boolean last = i == all.size() - 1;
                if (!last || !isValidIpv4(g) || (dc >= 0 && tail.isEmpty())) return false;
                count += 2;
            } else {
                if (g.length() > 4 || !isHex(g)) return false;
                count++;
            }
        }
        return dc >= 0 ? count <= 7 : count == 8;
    }

    private static List<String> groups(String s) {
        List<String> out = new ArrayList<>();
        if (s.isEmpty()) return out;
        for (String g : s.split(":", -1)) {
            if (g.isEmpty()) return null;
            out.add(g);
        }
        return out;
    }

    private static boolean isAllDigits(String s) {
        if (s.isEmpty()) return false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < '0' || c > '9') return false;
        }
        return true;
    }

    private static boolean isHex(String s) {
        if (s.isEmpty()) return false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!ok) return false;
        }
        return true;
    }
}
