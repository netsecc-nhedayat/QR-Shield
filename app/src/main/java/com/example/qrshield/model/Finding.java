package com.example.qrshield.model;

/** A triggered indicator with an optional detail (never the full scanned content). */
public final class Finding {
    public final SecurityIndicator indicator;
    /** May be null. */
    public final String detail;

    public Finding(SecurityIndicator indicator, String detail) {
        this.indicator = indicator;
        this.detail = detail;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof Finding)) return false;
        Finding f = (Finding) o;
        return indicator == f.indicator && (detail == null ? f.detail == null : detail.equals(f.detail));
    }

    @Override
    public int hashCode() {
        return indicator.hashCode() * 31 + (detail == null ? 0 : detail.hashCode());
    }
}
