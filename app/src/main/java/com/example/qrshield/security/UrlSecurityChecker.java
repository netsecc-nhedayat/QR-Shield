package com.example.qrshield.security;

import com.example.qrshield.model.AnalysisResult;
import com.example.qrshield.model.ContentType;
import com.example.qrshield.model.Finding;
import com.example.qrshield.model.RiskLevel;
import com.example.qrshield.model.SecurityIndicator;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Deterministic, local, explainable analysis of decoded content.
 *
 * <p>Scoring: every triggered indicator adds its fixed weight (see
 * {@link SecurityIndicator}); each indicator can trigger at most once.
 * Thresholds: score 0-1 = LOW, 2-4 = MEDIUM, 5+ = HIGH.
 * Invalid URLs, unsupported schemes, text and empty input are NOT scored.
 * There is no reputation lookup; the result is never a malware probability.
 */
public final class UrlSecurityChecker {

    public static final String NO_INDICATORS_MESSAGE =
            "No obvious suspicious indicators were detected by QR Shield's local checks. "
                    + "This does not guarantee that the website is safe.";

    public static final int MEDIUM_THRESHOLD = 2;
    public static final int HIGH_THRESHOLD = 5;

    /** Small example brand list. Not exhaustive; may flag unlisted official domains. */
    public static final class Brand {
        final String name;
        final List<String> officialDomains;

        public Brand(String name, String... officialDomains) {
            this.name = name.toLowerCase(Locale.ROOT);
            this.officialDomains = Collections.unmodifiableList(Arrays.asList(officialDomains));
        }
    }

    private static final List<Brand> DEFAULT_BRANDS = Collections.unmodifiableList(Arrays.asList(
            new Brand("paypal", "paypal.com", "paypal.me"),
            new Brand("google", "google.com", "google.nl", "google.de", "google.co.uk", "google.fr"),
            new Brand("microsoft", "microsoft.com", "live.com", "office.com", "microsoftonline.com"),
            new Brand("apple", "apple.com", "icloud.com"),
            new Brand("amazon", "amazon.com", "amazon.nl", "amazon.de", "amazon.co.uk", "amazon.fr",
                    "amazon.es", "amazon.it", "amazonaws.com"),
            new Brand("netflix", "netflix.com"),
            new Brand("facebook", "facebook.com", "fb.com")));

    private static final Set<String> SHORTENERS = new HashSet<>(Arrays.asList(
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly",
            "rebrand.ly", "cutt.ly", "t.ly", "shorturl.at", "tiny.cc"));

    private static final Set<String> DANGEROUS_SCHEMES = new HashSet<>(Arrays.asList(
            "javascript", "file", "intent", "content", "data", "vbscript", "blob", "android-app"));

    private static final Set<String> KNOWN_NON_WEB_SCHEMES = new HashSet<>(Arrays.asList(
            "mailto", "tel", "sms", "smsto", "mms", "geo", "wifi", "bitcoin", "market", "ftp",
            "sftp", "ws", "wss", "upi", "matmsg", "urn", "news", "nntp", "ssh", "webcal", "begin"));

    private static final Pattern SCHEME = Pattern.compile("^([A-Za-z][A-Za-z0-9+\\-]*):(?=\\S)");
    private static final Pattern PORT_LIKE_REST = Pattern.compile("^[0-9]{1,5}([/?#].*)?$");
    private static final Pattern BARE_HOST = Pattern.compile(
            "^(?:[A-Za-z0-9-]+\\.)+[A-Za-z]{2,}(?::\\d{1,5})?(?:[/?#]\\S*)?$");
    private static final Pattern OPAQUE_TOKEN = Pattern.compile("[A-Za-z0-9]{32,}");
    private static final Pattern REDIRECT_PARAM = Pattern.compile(
            "(?i)(=|%3d)(https?(://|%3a%2f%2f))");

    private final List<Brand> brands;

    public UrlSecurityChecker() {
        this(DEFAULT_BRANDS);
    }

    public UrlSecurityChecker(List<Brand> brands) {
        this.brands = brands;
    }

    public AnalysisResult analyze(String input) {
        if (input == null || input.trim().isEmpty()) {
            return simple(input, ContentType.EMPTY, RiskLevel.UNKNOWN, null,
                    "There is no content to analyze.",
                    "Scan a different code or enter some text.");
        }
        if (input.length() > UrlValidator.MAX_INPUT_LENGTH) {
            return simple(input, ContentType.TOO_LONG, RiskLevel.UNKNOWN, null,
                    "The content is longer than QR Shield analyzes ("
                            + UrlValidator.MAX_INPUT_LENGTH + " characters), so it was not assessed.",
                    "Do not open anything based on this content. Copy it only if you know where it came from.");
        }

        String trimmed = input.trim();
        Matcher m = SCHEME.matcher(trimmed);
        if (m.find()) {
            String scheme = m.group(1).toLowerCase(Locale.ROOT);
            String afterColon = trimmed.substring(m.end(1) + 1);
            boolean known = KNOWN_NON_WEB_SCHEMES.contains(scheme) || DANGEROUS_SCHEMES.contains(scheme);
            boolean portLike = !known && PORT_LIKE_REST.matcher(afterColon).matches();
            if (!portLike) {
                if (scheme.equals("http") || scheme.equals("https")) {
                    return analyzeWebUrl(input, trimmed);
                }
                return analyzeUnsupported(input, scheme);
            }
        }

        String note = BARE_HOST.matcher(trimmed).matches()
                ? " It looks like a web address without a scheme (http:// or https://). QR Shield does not add one for you."
                : "";
        return simple(input, ContentType.TEXT, RiskLevel.INFO, null,
                "No web URL was identified in this content. It is shown as plain text." + note,
                "Review the text. QR Shield offers no browser action for it.");
    }

    private AnalysisResult analyzeUnsupported(String input, String scheme) {
        boolean dangerous = DANGEROUS_SCHEMES.contains(scheme);
        List<Finding> findings = new ArrayList<>();
        findings.add(new Finding(SecurityIndicator.NON_WEB_SCHEME, "Scheme: " + safeShort(scheme, 30)));
        String why = dangerous
                ? "The \"" + safeShort(scheme, 30) + "\" scheme can run code or reach local content, so QR Shield will not open it."
                : "QR Shield only opens web links (http or https), so it will not open the \""
                + safeShort(scheme, 30) + "\" scheme through the web action.";
        return new AnalysisResult(input, ContentType.UNSUPPORTED_SCHEME,
                dangerous ? RiskLevel.HIGH : RiskLevel.UNKNOWN, false, scheme, null, null, null,
                findings, 0, why,
                "Do not act on this content unless you trust its source. You can copy the text and handle it yourself.");
    }

    private AnalysisResult analyzeWebUrl(String original, String trimmed) {
        UrlValidator.Result vr = UrlValidator.validateWebUrl(trimmed);
        String scheme = trimmed.substring(0, trimmed.indexOf(':')).toLowerCase(Locale.ROOT);
        if (!vr.isValid()) {
            return new AnalysisResult(original, ContentType.INVALID_WEB_URL, RiskLevel.UNKNOWN, false,
                    scheme, null, null, null, Collections.<Finding>emptyList(), 0,
                    "This looks like a web link but is malformed: " + vr.error
                            + " QR Shield cannot assess it and will not open it.",
                    "Do not open this content. Ask the sender for the correct link.");
        }
        ParsedWebUrl url = vr.url;
        List<Finding> findings = new ArrayList<>();
        ruleHttp(url, findings);
        ruleUserInfo(url, findings);
        ruleHostKind(url, findings);
        ruleInternational(url, findings);
        ruleStructure(url, findings);
        ruleBrand(url, findings);
        ruleShortener(url, findings);
        ruleLength(trimmed, url, findings);
        rulePathAndQuery(url, findings);
        rulePort(url, findings);

        int score = 0;
        for (Finding f : findings) score += f.indicator.weight;
        RiskLevel risk = score >= HIGH_THRESHOLD ? RiskLevel.HIGH
                : score >= MEDIUM_THRESHOLD ? RiskLevel.MEDIUM : RiskLevel.LOW;

        String explanation = findings.isEmpty()
                ? NO_INDICATORS_MESSAGE
                : "QR Shield's local checks found " + findings.size() + " indicator"
                + (findings.size() == 1 ? "" : "s") + " worth reviewing. Indicators are not proof of "
                + "malicious intent, and a link without indicators is not guaranteed safe.";
        String action;
        switch (risk) {
            case HIGH:
                action = "Treat this link with high caution. Prefer reaching the site by typing its address yourself.";
                break;
            case MEDIUM:
                action = "Review the findings before deciding. Opening requires an extra confirmation.";
                break;
            default:
                action = "Check that the destination is what you expect. Opening is always your explicit choice.";
        }
        String host = url.hostKind == ParsedWebUrl.HostKind.DNS_NAME ? url.unicodeHost : url.asciiHost;
        return new AnalysisResult(original, ContentType.VALID_WEB_URL, risk, true, scheme, trimmed,
                url.normalized, host, findings, score, explanation, action);
    }

    // ---- rules -------------------------------------------------------------------------------

    private static void ruleHttp(ParsedWebUrl u, List<Finding> out) {
        if (u.scheme.equals("http")) out.add(new Finding(SecurityIndicator.PLAIN_HTTP, null));
    }

    private static void ruleUserInfo(ParsedWebUrl u, List<Finding> out) {
        if (u.userInfo == null) return;
        out.add(new Finding(SecurityIndicator.EMBEDDED_USER_INFO, null));
        if (u.userInfo.indexOf('.') >= 0) {
            out.add(new Finding(SecurityIndicator.USERINFO_LOOKS_LIKE_HOST, "Real host: " + u.asciiHost));
        }
    }

    private static void ruleHostKind(ParsedWebUrl u, List<Finding> out) {
        switch (u.hostKind) {
            case NUMERIC_OBFUSCATED:
                out.add(new Finding(SecurityIndicator.OBFUSCATED_IP_HOST, null));
                break;
            case IPV4:
                out.add(new Finding(SecurityIndicator.IP_HOST, null));
                if (isPrivateOrLoopbackV4(u.asciiHost)) out.add(new Finding(SecurityIndicator.LOCAL_ADDRESS, null));
                break;
            case IPV6:
                out.add(new Finding(SecurityIndicator.IP_HOST, null));
                if (u.asciiHost.equals("::1")) out.add(new Finding(SecurityIndicator.LOCAL_ADDRESS, null));
                break;
            default:
                if (u.asciiHost.equals("localhost") || u.asciiHost.endsWith(".localhost")) {
                    out.add(new Finding(SecurityIndicator.LOCAL_ADDRESS, null));
                }
        }
    }

    private static void ruleInternational(ParsedWebUrl u, List<Finding> out) {
        if (u.nonAsciiInput || u.punycodeLabels) {
            out.add(new Finding(SecurityIndicator.INTERNATIONAL_HOST, "ASCII form: " + safeShort(u.asciiHost, 80)));
        }
        if (u.mixedScript) out.add(new Finding(SecurityIndicator.MIXED_SCRIPT, null));
    }

    private static void ruleStructure(ParsedWebUrl u, List<Finding> out) {
        if (u.hostKind != ParsedWebUrl.HostKind.DNS_NAME) return;
        String host = u.asciiHost;
        String[] labels = host.split("\\.");
        if (labels.length >= 6) out.add(new Finding(SecurityIndicator.EXCESS_SUBDOMAINS, labels.length + " labels"));
        if (host.length() > 60) out.add(new Finding(SecurityIndicator.LONG_HOSTNAME, host.length() + " characters"));
        boolean local = host.equals("localhost") || host.endsWith(".localhost");
        if ((labels.length == 1 && !local) || u.trailingDot) {
            out.add(new Finding(SecurityIndicator.UNUSUAL_HOST_STRUCTURE, null));
        }
        int hyphens = 0;
        String stripped = host.replace("xn--", "");
        for (int i = 0; i < stripped.length(); i++) if (stripped.charAt(i) == '-') hyphens++;
        if (hyphens >= 3) out.add(new Finding(SecurityIndicator.EXCESS_HYPHENS, hyphens + " hyphens"));
    }

    private void ruleBrand(ParsedWebUrl u, List<Finding> out) {
        if (u.hostKind != ParsedWebUrl.HostKind.DNS_NAME) return;
        String host = u.asciiHost;
        for (Brand b : brands) {
            if (isOfficial(host, b)) continue;
            for (String token : host.split("[.\\-]")) {
                if (token.isEmpty()) continue;
                if (matchesBrandToken(token, b.name)) {
                    out.add(new Finding(SecurityIndicator.BRAND_LOOKALIKE, "Resembles: " + b.name));
                    return; // one brand finding is enough; avoids inflating the score
                }
            }
        }
    }

    private static boolean isOfficial(String host, Brand b) {
        for (String d : b.officialDomains) {
            if (host.equals(d) || host.endsWith("." + d)) return true;
        }
        return false;
    }

    private static boolean matchesBrandToken(String token, String brand) {
        if (token.equals(brand)) return true;
        String norm = token.replace("rn", "m").replace("vv", "w")
                .replace('0', 'o').replace('1', 'l').replace('3', 'e').replace('4', 'a').replace('5', 's');
        if (norm.equals(brand)) return true;
        return brand.length() >= 6 && token.length() >= 5 && editDistance(token, brand) == 1;
    }

    private static void ruleShortener(ParsedWebUrl u, List<Finding> out) {
        if (u.hostKind != ParsedWebUrl.HostKind.DNS_NAME) return;
        for (String s : SHORTENERS) {
            if (u.asciiHost.equals(s) || u.asciiHost.endsWith("." + s)) {
                out.add(new Finding(SecurityIndicator.URL_SHORTENER, "Service: " + s));
                return;
            }
        }
    }

    private static void ruleLength(String trimmed, ParsedWebUrl u, List<Finding> out) {
        if (trimmed.length() > 200) {
            out.add(new Finding(SecurityIndicator.LONG_URL, trimmed.length() + " characters"));
        }
    }

    private static void rulePathAndQuery(ParsedWebUrl u, List<Finding> out) {
        if (OPAQUE_TOKEN.matcher(u.path()).find()) out.add(new Finding(SecurityIndicator.OPAQUE_PATH, null));
        if (REDIRECT_PARAM.matcher(u.query()).find()) out.add(new Finding(SecurityIndicator.REDIRECT_PARAMETER, null));
        int pct = 0;
        for (int i = 0; i < u.rest.length(); i++) if (u.rest.charAt(i) == '%') pct++;
        if (u.rest.contains("%25") || pct >= 10) out.add(new Finding(SecurityIndicator.ENCODED_CONTENT, null));
    }

    private static void rulePort(ParsedWebUrl u, List<Finding> out) {
        if (u.port < 0) return;
        int def = u.scheme.equals("https") ? 443 : 80;
        if (u.port != def) out.add(new Finding(SecurityIndicator.UNUSUAL_PORT, "Port " + u.port));
    }

    // ---- helpers -----------------------------------------------------------------------------

    private static boolean isPrivateOrLoopbackV4(String ip) {
        String[] p = ip.split("\\.");
        int a = Integer.parseInt(p[0]);
        int b = Integer.parseInt(p[1]);
        return a == 10 || a == 127 || (a == 192 && b == 168) || (a == 172 && b >= 16 && b <= 31)
                || (a == 169 && b == 254);
    }

    static int editDistance(String a, String b) {
        int[] prev = new int[b.length() + 1];
        int[] cur = new int[b.length() + 1];
        for (int j = 0; j <= b.length(); j++) prev[j] = j;
        for (int i = 1; i <= a.length(); i++) {
            cur[0] = i;
            for (int j = 1; j <= b.length(); j++) {
                int cost = a.charAt(i - 1) == b.charAt(j - 1) ? 0 : 1;
                cur[j] = Math.min(Math.min(cur[j - 1] + 1, prev[j] + 1), prev[j - 1] + cost);
            }
            int[] t = prev; prev = cur; cur = t;
        }
        return prev[b.length()];
    }

    private static String safeShort(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }

    private static AnalysisResult simple(String input, ContentType type, RiskLevel risk, String scheme,
                                         String explanation, String action) {
        return new AnalysisResult(input, type, risk, false, scheme, null, null, null,
                Collections.<Finding>emptyList(), 0, explanation, action);
    }
}
