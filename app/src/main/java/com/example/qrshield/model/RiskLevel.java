package com.example.qrshield.model;

/**
 * Qualitative review level. It is NOT a probability that content is malicious.
 */
public enum RiskLevel {
    /** Plain information, nothing to assess (e.g. ordinary text). */
    INFO,
    /** Zero or one minor indicator found by local checks. */
    LOW,
    /** Indicators worth reviewing before opening. */
    MEDIUM,
    /** Several or strong indicators, or a scheme that can run code or reach local data. */
    HIGH,
    /** Content could not be assessed (empty, malformed, unsupported). */
    UNKNOWN;

    /** MEDIUM and HIGH require an additional warning step before opening a URL. */
    public boolean requiresExtraConfirmation() {
        return this == MEDIUM || this == HIGH;
    }
}
