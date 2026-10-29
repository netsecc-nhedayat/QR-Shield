package com.example.qrshield.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import com.example.qrshield.model.AnalysisResult;
import com.example.qrshield.model.ContentType;
import com.example.qrshield.model.RiskLevel;
import com.example.qrshield.model.SecurityIndicator;

import org.junit.Test;

public class UrlSecurityCheckerTest {

    private final UrlSecurityChecker checker = new UrlSecurityChecker();

    private AnalysisResult a(String s) {
        return checker.analyze(s);
    }

    // ---- classification ----------------------------------------------------------------------

    @Test public void plainHttpsHasNoIndicatorsAndRequiredMessage() {
        AnalysisResult r = a("https://example.com");
        assertEquals(ContentType.VALID_WEB_URL, r.contentType);
        assertEquals(RiskLevel.LOW, r.riskLevel);
        assertTrue(r.urlValid);
        assertTrue(r.findings.isEmpty());
        assertEquals("example.com", r.hostname);
        assertEquals(UrlSecurityChecker.NO_INDICATORS_MESSAGE, r.explanation);
        assertTrue(r.canOpenInBrowser());
    }

    @Test public void emptyAndWhitespaceAndNull() {
        assertEquals(ContentType.EMPTY, a("").contentType);
        assertEquals(ContentType.EMPTY, a("   \n\t ").contentType);
        assertEquals(ContentType.EMPTY, a(null).contentType);
        assertEquals(RiskLevel.UNKNOWN, a("").riskLevel);
        assertFalse(a("").canOpenInBrowser());
    }

    @Test public void ordinaryTextIsNotAUrl() {
        for (String s : new String[]{"not a url", "Note: buy milk", "localhost:8080", "Hello. World"}) {
            AnalysisResult r = a(s);
            assertEquals(s, ContentType.TEXT, r.contentType);
            assertEquals(RiskLevel.INFO, r.riskLevel);
            assertNull(r.hostname);
            assertFalse(r.canOpenInBrowser());
        }
    }

    @Test public void bareDomainIsTextAndNotModified() {
        AnalysisResult r = a("example.com");
        assertEquals(ContentType.TEXT, r.contentType);
        assertTrue(r.explanation.contains("without a scheme"));
        assertNull(r.originalUrl);
        assertEquals("example.com", r.originalContent);
    }

    @Test public void unsupportedSchemesCannotOpen() {
        String[] dangerous = {"javascript:alert(1)", "file:///etc/passwd", "data:text/html,<b>x</b>",
                "intent://scan/#Intent;scheme=zxing;end", "content://media/external/1", "JAVASCRIPT:alert(1)"};
        for (String s : dangerous) {
            AnalysisResult r = a(s);
            assertEquals(s, ContentType.UNSUPPORTED_SCHEME, r.contentType);
            assertEquals(RiskLevel.HIGH, r.riskLevel);
            assertFalse(r.canOpenInBrowser());
            assertNull(r.originalUrl);
        }
        AnalysisResult tel = a("tel:+31612345678");
        assertEquals(ContentType.UNSUPPORTED_SCHEME, tel.contentType);
        assertEquals(RiskLevel.UNKNOWN, tel.riskLevel);
        assertEquals("tel", tel.scheme);
        assertFalse(tel.canOpenInBrowser());
        assertEquals(ContentType.UNSUPPORTED_SCHEME, a("mailto:a@b.example").contentType);
        assertEquals(ContentType.UNSUPPORTED_SCHEME, a("WIFI:S:net;T:WPA;P:pw;;").contentType);
    }

    @Test public void malformedWebUrlsAreInvalidNotCrashing() {
        String[] bad = {"https://example.com:99999", "https://[::1", "https://::1]", "https://example.com/%zz",
                "https://exa\u0000mple.com", "https://exa mple.com", "https://256.1.1.1", "https://1.2.3",
                "https://", "http://exa..mple.com"};
        for (String s : bad) {
            AnalysisResult r = a(s);
            assertEquals(s, ContentType.INVALID_WEB_URL, r.contentType);
            assertEquals(RiskLevel.UNKNOWN, r.riskLevel);
            assertFalse(r.urlValid);
            assertFalse(r.canOpenInBrowser());
        }
    }

    @Test public void excessivelyLongInputIsControlled() {
        StringBuilder sb = new StringBuilder("https://example.com/");
        for (int i = 0; i < 5000; i++) sb.append('a');
        AnalysisResult r = a(sb.toString());
        assertEquals(ContentType.TOO_LONG, r.contentType);
        assertEquals(RiskLevel.UNKNOWN, r.riskLevel);
        assertFalse(r.canOpenInBrowser());
    }

    @Test public void surroundingWhitespaceIsTrimmedForAnalysisOnly() {
        AnalysisResult r = a("  https://example.com\n");
        assertEquals(ContentType.VALID_WEB_URL, r.contentType);
        assertEquals("https://example.com", r.originalUrl);
        assertEquals("  https://example.com\n", r.originalContent);
    }

    // ---- individual rules --------------------------------------------------------------------

    @Test public void plainHttpIsAnIndicatorButNotHighRisk() {
        AnalysisResult r = a("http://example.com");
        assertTrue(r.hasIndicator(SecurityIndicator.PLAIN_HTTP));
        assertEquals(RiskLevel.LOW, r.riskLevel);
    }

    @Test public void httpsIsNotASafeVerdict() {
        AnalysisResult r = a("https://example.com");
        assertEquals(RiskLevel.LOW, r.riskLevel);
        assertTrue(r.explanation.contains("does not guarantee"));
    }

    @Test public void userInfo() {
        AnalysisResult plain = a("https://user:password@example.com");
        assertTrue(plain.hasIndicator(SecurityIndicator.EMBEDDED_USER_INFO));
        assertFalse(plain.hasIndicator(SecurityIndicator.USERINFO_LOOKS_LIKE_HOST));
        assertEquals(RiskLevel.MEDIUM, plain.riskLevel);

        AnalysisResult deceptive = a("https://trusted.example@evil.example");
        assertEquals("evil.example", deceptive.hostname);
        assertTrue(deceptive.hasIndicator(SecurityIndicator.USERINFO_LOOKS_LIKE_HOST));
        assertEquals(RiskLevel.HIGH, deceptive.riskLevel);
    }

    @Test public void ipAddressAloneIsCautionNotHigh() {
        AnalysisResult r = a("https://203.0.113.7");
        assertTrue(r.hasIndicator(SecurityIndicator.IP_HOST));
        assertFalse(r.hasIndicator(SecurityIndicator.LOCAL_ADDRESS));
        assertEquals(RiskLevel.MEDIUM, r.riskLevel);
        assertTrue(a("https://127.0.0.1").hasIndicator(SecurityIndicator.LOCAL_ADDRESS));
        assertTrue(a("https://192.168.1.10").hasIndicator(SecurityIndicator.LOCAL_ADDRESS));
    }

    @Test public void ipv6Literal() {
        AnalysisResult r = a("https://[::1]");
        assertEquals(ContentType.VALID_WEB_URL, r.contentType);
        assertEquals("::1", r.hostname);
        assertTrue(r.hasIndicator(SecurityIndicator.IP_HOST));
        assertTrue(r.riskLevel != RiskLevel.HIGH);
    }

    @Test public void localhostIsLowAndOnlyLocal() {
        AnalysisResult r = a("https://localhost");
        assertEquals(1, r.findings.size());
        assertTrue(r.hasIndicator(SecurityIndicator.LOCAL_ADDRESS));
        assertEquals(RiskLevel.LOW, r.riskLevel);
    }

    @Test public void obfuscatedNumericHost() {
        AnalysisResult r = a("https://2130706433/");
        assertEquals(ContentType.VALID_WEB_URL, r.contentType);
        assertTrue(r.hasIndicator(SecurityIndicator.OBFUSCATED_IP_HOST));
        assertEquals(RiskLevel.MEDIUM, r.riskLevel);
        assertTrue(a("https://0x7f.1").hasIndicator(SecurityIndicator.OBFUSCATED_IP_HOST));
    }

    @Test public void punycodeIsIndicatorNotProof() {
        AnalysisResult r = a("https://xn--example-ova.com");
        assertTrue(r.hasIndicator(SecurityIndicator.INTERNATIONAL_HOST));
        assertEquals(RiskLevel.MEDIUM, r.riskLevel);
        assertTrue(r.canOpenInBrowser());
    }

    @Test public void unicodeHostname() {
        AnalysisResult r = a("https://b\u00fccher.example");
        assertEquals(ContentType.VALID_WEB_URL, r.contentType);
        assertTrue(r.hasIndicator(SecurityIndicator.INTERNATIONAL_HOST));
        assertFalse(r.hasIndicator(SecurityIndicator.MIXED_SCRIPT));
    }

    @Test public void mixedScriptLatinAndCyrillic() {
        AnalysisResult r = a("https://p\u0430ypal.example");
        assertTrue(r.hasIndicator(SecurityIndicator.MIXED_SCRIPT));
        assertTrue(r.hasIndicator(SecurityIndicator.INTERNATIONAL_HOST));
        assertEquals(RiskLevel.HIGH, r.riskLevel);
    }

    @Test public void deepSubdomainsAndLongHostname() {
        assertTrue(a("https://a.b.c.d.e.example.com").hasIndicator(SecurityIndicator.EXCESS_SUBDOMAINS));
        assertFalse(a("https://www.example.com").hasIndicator(SecurityIndicator.EXCESS_SUBDOMAINS));
        StringBuilder sb = new StringBuilder("https://");
        for (int i = 0; i < 61; i++) sb.append('a');
        sb.append(".example");
        // single label would be > 63 only if one label; this label is 61 chars
        assertTrue(a(sb.toString()).hasIndicator(SecurityIndicator.LONG_HOSTNAME));
    }

    @Test public void singleLabelAndTrailingDotAreUnusualStructure() {
        assertTrue(a("https://intranet").hasIndicator(SecurityIndicator.UNUSUAL_HOST_STRUCTURE));
        assertTrue(a("https://example.com.").hasIndicator(SecurityIndicator.UNUSUAL_HOST_STRUCTURE));
        assertFalse(a("https://localhost").hasIndicator(SecurityIndicator.UNUSUAL_HOST_STRUCTURE));
    }

    @Test public void hyphenAloneIsNotSuspicious() {
        assertTrue(a("https://my-cool-site.example").findings.isEmpty());
        assertTrue(a("https://a-b-c-d.example").hasIndicator(SecurityIndicator.EXCESS_HYPHENS));
        assertEquals(RiskLevel.LOW, a("https://a-b-c-d.example").riskLevel);
    }

    @Test public void unknownDomainIsNotFlagged() {
        AnalysisResult r = a("https://qwertyuiop-asdf.example");
        assertTrue(r.findings.isEmpty());
        assertEquals(RiskLevel.LOW, r.riskLevel);
    }

    @Test public void brandLookalikes() {
        assertTrue(a("https://paypal-login.example").hasIndicator(SecurityIndicator.BRAND_LOOKALIKE));
        assertTrue(a("https://paypal.com.evil.example").hasIndicator(SecurityIndicator.BRAND_LOOKALIKE));
        assertTrue(a("https://paypa1.example").hasIndicator(SecurityIndicator.BRAND_LOOKALIKE));
        assertTrue(a("https://rnicrosoft.example").hasIndicator(SecurityIndicator.BRAND_LOOKALIKE));
        assertTrue(a("https://gooogle.example").hasIndicator(SecurityIndicator.BRAND_LOOKALIKE));
        assertEquals(RiskLevel.MEDIUM, a("https://paypal-login.example").riskLevel);
    }

    @Test public void brandOfficialDomainsAndUnrelatedNamesNotFlagged() {
        assertFalse(a("https://paypal.com").hasIndicator(SecurityIndicator.BRAND_LOOKALIKE));
        assertFalse(a("https://www.paypal.com/signin").hasIndicator(SecurityIndicator.BRAND_LOOKALIKE));
        assertFalse(a("https://amazon.nl").hasIndicator(SecurityIndicator.BRAND_LOOKALIKE));
        assertFalse(a("https://applepie.example").hasIndicator(SecurityIndicator.BRAND_LOOKALIKE));
        assertFalse(a("https://pineapple-farm.example").hasIndicator(SecurityIndicator.BRAND_LOOKALIKE));
    }

    @Test public void domainInPathOrQueryIsNotTheHostname() {
        AnalysisResult p = a("https://safe.example/paypal.com/login");
        assertEquals("safe.example", p.hostname);
        assertFalse(p.hasIndicator(SecurityIndicator.BRAND_LOOKALIKE));
        AnalysisResult q = a("https://safe.example/?site=paypal.com&u=google.com");
        assertFalse(q.hasIndicator(SecurityIndicator.BRAND_LOOKALIKE));
        assertEquals(RiskLevel.LOW, q.riskLevel);
    }

    @Test public void redirectParameter() {
        AnalysisResult r = a("https://example.com/path?next=https://other.example");
        assertEquals("example.com", r.hostname);
        assertTrue(r.hasIndicator(SecurityIndicator.REDIRECT_PARAMETER));
        assertEquals(RiskLevel.LOW, r.riskLevel);
        assertTrue(a("https://example.com/?u=https%3A%2F%2Fother.example").hasIndicator(SecurityIndicator.REDIRECT_PARAMETER));
    }

    @Test public void shortenerIsCautionButOpenable() {
        AnalysisResult r = a("https://bit.ly/abc123");
        assertTrue(r.hasIndicator(SecurityIndicator.URL_SHORTENER));
        assertEquals(RiskLevel.MEDIUM, r.riskLevel);
        assertTrue(r.canOpenInBrowser());
        assertFalse(a("https://notbit.ly.example/x").hasIndicator(SecurityIndicator.URL_SHORTENER));
    }

    @Test public void longUrlAndOpaquePath() {
        StringBuilder sb = new StringBuilder("https://example.com/");
        for (int i = 0; i < 250; i++) sb.append((char) ('a' + i % 26));
        AnalysisResult r = a(sb.toString());
        assertTrue(r.hasIndicator(SecurityIndicator.LONG_URL));
        assertTrue(r.hasIndicator(SecurityIndicator.OPAQUE_PATH));
        assertEquals(RiskLevel.MEDIUM, r.riskLevel);
        assertFalse(a("https://example.com/a-very-readable-article-title-with-many-words-in-it")
                .hasIndicator(SecurityIndicator.OPAQUE_PATH));
    }

    @Test public void unusualPort() {
        assertTrue(a("https://example.com:8443").hasIndicator(SecurityIndicator.UNUSUAL_PORT));
        assertFalse(a("https://example.com:443").hasIndicator(SecurityIndicator.UNUSUAL_PORT));
        assertFalse(a("http://example.com:80").hasIndicator(SecurityIndicator.UNUSUAL_PORT));
        assertTrue(a("http://example.com:443").hasIndicator(SecurityIndicator.UNUSUAL_PORT));
    }

    @Test public void heavyEncoding() {
        assertTrue(a("https://example.com/a%252Fb").hasIndicator(SecurityIndicator.ENCODED_CONTENT));
        assertFalse(a("https://example.com/a%20b").hasIndicator(SecurityIndicator.ENCODED_CONTENT));
    }

    // ---- scoring and determinism -------------------------------------------------------------

    @Test public void thresholds() {
        assertEquals(RiskLevel.LOW, a("http://example.com").riskLevel);          // 1
        assertEquals(RiskLevel.MEDIUM, a("https://bit.ly/x").riskLevel);         // 2
        assertEquals(RiskLevel.MEDIUM, a("http://paypal-login.example").riskLevel); // 4
        assertEquals(RiskLevel.HIGH, a("http://trusted.example@bit.ly").riskLevel);  // 1+3+2+2
    }

    @Test public void indicatorsTriggerOnceEach() {
        AnalysisResult r = a("https://paypal-secure.paypal-login.example");
        int brand = 0;
        for (com.example.qrshield.model.Finding f : r.findings) {
            if (f.indicator == SecurityIndicator.BRAND_LOOKALIKE) brand++;
        }
        assertEquals(1, brand);
    }

    @Test public void identicalInputGivesIdenticalResult() {
        String in = "http://user@paypa1-secure.bit.ly:8080/a?u=https://x.example";
        AnalysisResult one = a(in);
        AnalysisResult two = new UrlSecurityChecker().analyze(in);
        assertEquals(one.score, two.score);
        assertEquals(one.riskLevel, two.riskLevel);
        assertEquals(one.findings, two.findings);
        assertEquals(one.explanation, two.explanation);
    }

    @Test public void nonWebResultsNeverClaimSafety() {
        for (String s : new String[]{"hello", "tel:123456789", "https://", ""}) {
            AnalysisResult r = a(s);
            assertFalse(r.explanation.toLowerCase().contains("safe") && !r.explanation.contains("not"));
        }
    }
}
