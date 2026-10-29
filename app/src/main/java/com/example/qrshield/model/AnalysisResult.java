package com.example.qrshield.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Immutable outcome of analyzing decoded content. */
public final class AnalysisResult {
    public final String originalContent;
    public final ContentType contentType;
    public final RiskLevel riskLevel;
    /** True only when contentType is VALID_WEB_URL. */
    public final boolean urlValid;
    /** Lower-case scheme if one was detected, else null. */
    public final String scheme;
    /** The exact (whitespace-trimmed) URL string that would be opened; null if not a valid web URL. */
    public final String originalUrl;
    /** Display-only normalized form (lower-case scheme/host); never used for opening. */
    public final String normalizedUrl;
    public final String hostname;
    public final List<Finding> findings;
    public final int score;
    public final String explanation;
    public final String recommendedAction;

    public AnalysisResult(String originalContent, ContentType contentType, RiskLevel riskLevel,
                          boolean urlValid, String scheme, String originalUrl, String normalizedUrl,
                          String hostname, List<Finding> findings, int score,
                          String explanation, String recommendedAction) {
        this.originalContent = originalContent == null ? "" : originalContent;
        this.contentType = contentType;
        this.riskLevel = riskLevel;
        this.urlValid = urlValid;
        this.scheme = scheme;
        this.originalUrl = originalUrl;
        this.normalizedUrl = normalizedUrl;
        this.hostname = hostname;
        this.findings = Collections.unmodifiableList(new ArrayList<>(findings));
        this.score = score;
        this.explanation = explanation;
        this.recommendedAction = recommendedAction;
    }

    public boolean hasIndicator(SecurityIndicator indicator) {
        for (Finding f : findings) {
            if (f.indicator == indicator) return true;
        }
        return false;
    }

    /** Only syntactically valid http/https URLs may use the browser action. */
    public boolean canOpenInBrowser() {
        return contentType == ContentType.VALID_WEB_URL && urlValid && originalUrl != null;
    }
}
