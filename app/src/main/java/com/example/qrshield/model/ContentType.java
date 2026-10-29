package com.example.qrshield.model;

/**
 * What the decoded content is. Independent of {@link RiskLevel}: a URL can be
 * syntactically valid (VALID_WEB_URL) and still carry a MEDIUM or HIGH risk level.
 */
public enum ContentType {
    EMPTY,
    TEXT,
    VALID_WEB_URL,
    INVALID_WEB_URL,
    UNSUPPORTED_SCHEME,
    TOO_LONG
}
