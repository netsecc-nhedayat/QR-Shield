package com.example.qrshield.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class UrlValidatorTest {

    private static UrlValidator.Result v(String s) {
        return UrlValidator.validateWebUrl(s);
    }

    @Test public void validHttpsAndHttp() {
        assertTrue(v("https://example.com").isValid());
        assertTrue(v("http://example.com").isValid());
        assertEquals("example.com", v("https://EXAMPLE.com").url.asciiHost);
    }

    @Test public void portRange() {
        assertTrue(v("https://example.com:443").isValid());
        assertFalse(v("https://example.com:99999").isValid());
        assertFalse(v("https://example.com:0").isValid());
        assertFalse(v("https://example.com:abc").isValid());
        assertFalse(v("https://example.com:").isValid());
    }

    @Test public void missingPartsAreInvalid() {
        assertFalse(v("https://").isValid());
        assertFalse(v("https:///path").isValid());
        assertFalse(v("https:example.com").isValid());
        assertFalse(v("https://user@").isValid());
        assertFalse(v("").isValid());
    }

    @Test public void ipv4() {
        assertEquals(ParsedWebUrl.HostKind.IPV4, v("https://127.0.0.1").url.hostKind);
        assertFalse(v("https://256.1.1.1").isValid());
        assertFalse(v("https://1.2.3").isValid());
        assertFalse(v("https://01.2.3.4").isValid());
    }

    @Test public void ipv6() {
        assertEquals(ParsedWebUrl.HostKind.IPV6, v("https://[::1]").url.hostKind);
        assertTrue(v("https://[2001:db8::1]:8443/x").isValid());
        assertTrue(v("https://[::ffff:1.2.3.4]").isValid());
        assertFalse(v("https://[::1").isValid());
        assertFalse(v("https://::1]").isValid());
        assertFalse(v("https://[1:2:3]").isValid());
        assertFalse(v("https://[:::1]").isValid());
        assertFalse(v("https://[1::2::3]").isValid());
        assertFalse(v("https://[fe80::1%25eth0]").isValid());
    }

    @Test public void userInfoIsParsedNotHost() {
        UrlValidator.Result r = v("https://trusted.example@evil.example");
        assertTrue(r.isValid());
        assertEquals("evil.example", r.url.asciiHost);
        assertEquals("trusted.example", r.url.userInfo);
    }

    @Test public void internationalNames() {
        UrlValidator.Result r = v("https://b\u00fccher.example");
        assertTrue(r.isValid());
        assertEquals("xn--bcher-kva.example", r.url.asciiHost);
        assertTrue(r.url.nonAsciiInput);
        assertTrue(v("https://xn--example-ova.com").url.punycodeLabels);
    }

    @Test public void whitespaceControlAndFormatCharsRejected() {
        assertFalse(v("https://exa mple.com").isValid());
        assertFalse(v("https://exa\u0000mple.com").isValid());
        assertFalse(v("https://example.com/\u202Eabc").isValid());
        assertFalse(v("https://example.com/a\tb").isValid());
    }

    @Test public void badPercentEscapesRejected() {
        assertFalse(v("https://example.com/%zz").isValid());
        assertFalse(v("https://example.com/%").isValid());
        assertTrue(v("https://example.com/%20ok").isValid());
    }

    @Test public void backslashAndBadLabelsRejected() {
        assertFalse(v("https://example.com\\@evil.example").isValid());
        assertFalse(v("https://exa..mple.com").isValid());
        assertFalse(v("https://-example.com").isValid());
        assertFalse(v("https://exa_mple.com").isValid());
    }

    @Test public void tooLongRejectedWithoutCrash() {
        StringBuilder sb = new StringBuilder("https://example.com/");
        for (int i = 0; i < 5000; i++) sb.append('a');
        UrlValidator.Result r = v(sb.toString());
        assertFalse(r.isValid());
        assertNotNull(r.error);
    }

    @Test public void errorMessagesDoNotEchoInput() {
        UrlValidator.Result r = v("https://secret-token-12345.example:99999");
        assertFalse(r.error.contains("secret-token"));
    }

    @Test public void notAWebUrl() {
        assertFalse(v("javascript:alert(1)").isValid());
        assertFalse(v("file:///etc/passwd").isValid());
        assertFalse(v("not a url").isValid());
    }

    @Test public void normalizedFormKeepsPathAndQueryUntouched() {
        UrlValidator.Result r = v("HTTPS://Example.COM/A%2Fb?x=%41#Frag");
        assertTrue(r.isValid());
        assertEquals("https://example.com/A%2Fb?x=%41#Frag", r.url.normalized);
    }
}
