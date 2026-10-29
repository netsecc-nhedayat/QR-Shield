package com.example.qrshield.model;

/**
 * One explainable local rule. The weight is its fixed contribution to the score.
 * No indicator proves malicious intent.
 */
public enum SecurityIndicator {
    PLAIN_HTTP(1, "Unencrypted HTTP",
            "The link uses HTTP instead of HTTPS, so traffic to the site is not encrypted. Many legitimate sites still do this."),
    EMBEDDED_USER_INFO(3, "Credentials or text before an @ sign",
            "The address contains user information before the real host. This is rarely needed and is sometimes used to disguise the true destination."),
    USERINFO_LOOKS_LIKE_HOST(2, "Text before the @ looks like a domain",
            "The part before the @ looks like a website name, which can mislead people about where the link really goes."),
    IP_HOST(2, "Host is an IP address",
            "The link points to a numeric IP address instead of a domain name. This is unusual for public sites but common for devices and test servers."),
    OBFUSCATED_IP_HOST(3, "Numeric or hexadecimal host",
            "The host is written as a single number or hexadecimal value that browsers may interpret as an IP address. This hides the real address."),
    LOCAL_ADDRESS(1, "Local or private address",
            "The link points to your own device or a private network address, not a public website."),
    INTERNATIONAL_HOST(2, "International or punycode hostname",
            "The hostname uses non-ASCII characters or punycode (xn--). This is legitimate for many languages, but look-alike characters can imitate other names."),
    MIXED_SCRIPT(3, "Mixed writing systems in one name",
            "A hostname label mixes scripts such as Latin and Cyrillic, a technique used for look-alike names."),
    EXCESS_SUBDOMAINS(1, "Many subdomain levels",
            "The hostname has an unusually deep structure, which can push the real domain out of view."),
    LONG_HOSTNAME(1, "Very long hostname",
            "The hostname is unusually long, which can hide its meaningful part on small screens."),
    UNUSUAL_HOST_STRUCTURE(1, "Unusual hostname structure",
            "The hostname has no dot-separated domain or ends with a trailing dot."),
    EXCESS_HYPHENS(1, "Many hyphens in hostname",
            "The hostname contains several hyphens. This is common in look-alike names but also in ordinary ones."),
    BRAND_LOOKALIKE(3, "Name resembles a well-known brand",
            "The hostname contains or closely resembles a brand from QR Shield's small example list, but is not one of that brand's listed domains. The list is incomplete."),
    URL_SHORTENER(2, "Link shortener",
            "Shortened links hide the final destination. QR Shield does not follow or resolve them."),
    LONG_URL(1, "Very long URL",
            "The address is unusually long. Long links are common in tracking and login flows."),
    OPAQUE_PATH(1, "Long opaque token in the path",
            "The path contains a long string of letters and digits that is not readable. This is common for legitimate IDs and session tokens."),
    UNUSUAL_PORT(1, "Non-standard port",
            "The link uses a port other than the default for its scheme."),
    REDIRECT_PARAMETER(1, "Contains another URL",
            "The query part includes another web address, which some sites use to forward visitors elsewhere."),
    ENCODED_CONTENT(1, "Heavy percent-encoding",
            "The address contains double-encoded or many percent-encoded characters, which can obscure its content."),
    NON_WEB_SCHEME(0, "Not a web link",
            "The content uses a URI scheme other than http or https.");

    public final int weight;
    public final String title;
    public final String explanation;

    SecurityIndicator(int weight, String title, String explanation) {
        this.weight = weight;
        this.title = title;
        this.explanation = explanation;
    }
}
