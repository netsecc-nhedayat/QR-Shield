package com.example.qrshield.ui.result;

import android.content.ActivityNotFoundException;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import com.example.qrshield.R;
import com.example.qrshield.model.AnalysisResult;
import com.example.qrshield.model.Finding;
import com.example.qrshield.security.UrlSecurityChecker;
import com.example.qrshield.ui.home.MainActivity;

import java.util.Locale;

/**
 * Shows the analysis for decoded or typed content. Both the scanner and the manual
 * screen use this one flow, which re-runs the same {@link UrlSecurityChecker}.
 * Nothing is opened automatically; opening is a separate, confirmed action.
 */
public class ResultActivity extends AppCompatActivity {

    private static final String EXTRA_CONTENT = "com.example.qrshield.extra.CONTENT";
    private static final String EXTRA_FROM_SCANNER = "com.example.qrshield.extra.FROM_SCANNER";
    private static final int MAX_DISPLAY_CHARS = 1500;

    private final UrlSecurityChecker checker = new UrlSecurityChecker();
    private String content;
    private AnalysisResult result;

    public static Intent newIntent(Context context, String content, boolean fromScanner) {
        return new Intent(context, ResultActivity.class)
                .putExtra(EXTRA_CONTENT, content)
                .putExtra(EXTRA_FROM_SCANNER, fromScanner);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_result);
        if (getSupportActionBar() != null) getSupportActionBar().setDisplayHomeAsUpEnabled(true);

        content = getIntent().getStringExtra(EXTRA_CONTENT);
        boolean fromScanner = getIntent().getBooleanExtra(EXTRA_FROM_SCANNER, false);
        result = checker.analyze(content);

        render(result);

        Button again = findViewById(R.id.btn_scan_again);
        again.setText(fromScanner ? R.string.scan_again : R.string.analyze_another);
        again.setOnClickListener(v -> finish()); // returns to the screen that produced the content
        findViewById(R.id.btn_home).setOnClickListener(v -> {
            Intent home = new Intent(this, MainActivity.class)
                    .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP);
            startActivity(home);
            finish();
        });
        findViewById(R.id.btn_copy).setOnClickListener(v -> copyContent());
        Button open = findViewById(R.id.btn_open);
        open.setVisibility(result.canOpenInBrowser() ? View.VISIBLE : View.GONE);
        open.setOnClickListener(v -> onOpenRequested());
    }

    private void render(AnalysisResult r) {
        TextView badge = findViewById(R.id.risk_badge);
        String label = getString(riskLabelRes(r));
        badge.setText(riskGlyph(r) + "  " + label);
        badge.setContentDescription(getString(R.string.risk_badge_description, label));
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(getColor(riskColorRes(r)));
        bg.setCornerRadius(getResources().getDimension(R.dimen.corner_radius));
        badge.setBackground(bg);

        ((TextView) findViewById(R.id.explanation_text)).setText(r.explanation);
        ((TextView) findViewById(R.id.original_text)).setText(displayText(r.originalContent));
        ((TextView) findViewById(R.id.type_text)).setText(typeText(r));
        if (r.hostname != null) {
            findViewById(R.id.host_group).setVisibility(View.VISIBLE);
            ((TextView) findViewById(R.id.host_text)).setText(r.hostname);
        }
        ((TextView) findViewById(R.id.next_steps_text)).setText(r.recommendedAction);

        LinearLayout container = findViewById(R.id.findings_container);
        container.removeAllViews();
        if (r.findings.isEmpty()) {
            container.addView(textView(getString(R.string.no_findings), false));
        }
        for (Finding f : r.findings) {
            container.addView(textView("\u25B8 " + f.indicator.title, true));
            String body = f.indicator.explanation + (f.detail == null ? "" : " (" + f.detail + ")");
            container.addView(textView(body, false));
        }
    }

    private TextView textView(String text, boolean heading) {
        TextView tv = new TextView(this);
        tv.setText(text);
        tv.setTextColor(getColor(heading ? R.color.text_primary : R.color.text_secondary));
        tv.setTextSize(android.util.TypedValue.COMPLEX_UNIT_PX,
                getResources().getDimension(R.dimen.text_body));
        if (heading) tv.setTypeface(tv.getTypeface(), android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.topMargin = (int) (getResources().getDimension(R.dimen.spacing_s) / 2);
        tv.setLayoutParams(lp);
        return tv;
    }

    private String displayText(String s) {
        if (s.length() <= MAX_DISPLAY_CHARS) return s;
        return s.substring(0, MAX_DISPLAY_CHARS) + getString(R.string.content_truncated);
    }

    private String typeText(AnalysisResult r) {
        switch (r.contentType) {
            case EMPTY: return getString(R.string.type_empty);
            case TEXT: return getString(R.string.type_text);
            case VALID_WEB_URL: return getString(R.string.type_valid_web_url);
            case INVALID_WEB_URL: return getString(R.string.type_invalid_web_url);
            case UNSUPPORTED_SCHEME: return getString(R.string.type_unsupported_scheme, r.scheme);
            case TOO_LONG: return getString(R.string.type_too_long);
            default: return getString(R.string.type_text);
        }
    }

    private static int riskLabelRes(AnalysisResult r) {
        switch (r.riskLevel) {
            case INFO: return R.string.risk_info;
            case LOW: return R.string.risk_low;
            case MEDIUM: return R.string.risk_medium;
            case HIGH: return R.string.risk_high;
            default: return R.string.risk_unknown;
        }
    }

    private static int riskColorRes(AnalysisResult r) {
        switch (r.riskLevel) {
            case INFO: return R.color.risk_info;
            case LOW: return R.color.risk_low;
            case MEDIUM: return R.color.risk_medium;
            case HIGH: return R.color.risk_high;
            default: return R.color.risk_unknown;
        }
    }

    /** Text glyphs so the level never depends on color alone. */
    private static String riskGlyph(AnalysisResult r) {
        switch (r.riskLevel) {
            case INFO: return "\u24D8";   // circled i
            case LOW: return "\u25CF";    // dot
            case MEDIUM: return "\u25B2"; // triangle
            case HIGH: return "\u26A0";   // warning sign
            default: return "?";
        }
    }

    private void copyContent() {
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (cm == null) {
            Toast.makeText(this, R.string.copy_failed, Toast.LENGTH_SHORT).show();
            return;
        }
        try {
            cm.setPrimaryClip(ClipData.newPlainText("QR Shield", result.originalContent));
            Toast.makeText(this, R.string.copied, Toast.LENGTH_SHORT).show();
        } catch (SecurityException | IllegalStateException e) {
            android.util.Log.w("QRShieldResult", "Clipboard error: " + e.getClass().getSimpleName());
            Toast.makeText(this, R.string.copy_failed, Toast.LENGTH_SHORT).show();
        }
    }

    // ---- explicit, confirmed opening ---------------------------------------------------------

    private void onOpenRequested() {
        // Re-validate right before acting; never trust earlier UI state.
        AnalysisResult fresh = checker.analyze(content);
        if (!fresh.canOpenInBrowser()) {
            Toast.makeText(this, R.string.cannot_open, Toast.LENGTH_LONG).show();
            return;
        }
        if (fresh.riskLevel.requiresExtraConfirmation()) {
            showWarningDialog(fresh);
        } else {
            showDestinationDialog(fresh.originalUrl);
        }
    }

    private void showWarningDialog(@NonNull AnalysisResult r) {
        StringBuilder sb = new StringBuilder(getString(R.string.warning_intro)).append("\n");
        for (Finding f : r.findings) sb.append("\n\u2022 ").append(f.indicator.title);
        sb.append("\n\n").append(getString(R.string.warning_footer));
        new AlertDialog.Builder(this)
                .setTitle(R.string.warning_title)
                .setMessage(sb.toString())
                .setNegativeButton(R.string.cancel, null)
                .setPositiveButton(R.string.warning_continue,
                        (d, w) -> showDestinationDialog(r.originalUrl))
                .show();
    }

    private void showDestinationDialog(@NonNull String url) {
        new AlertDialog.Builder(this)
                .setTitle(R.string.destination_title)
                .setMessage(getString(R.string.destination_message, url))
                .setNegativeButton(R.string.cancel, null)
                .setPositiveButton(R.string.destination_open, (d, w) -> launchBrowser(url))
                .show();
    }

    private void launchBrowser(@NonNull String url) {
        Uri uri = Uri.parse(url);
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        if (!scheme.equals("http") && !scheme.equals("https")) {
            Toast.makeText(this, R.string.cannot_open, Toast.LENGTH_LONG).show();
            return;
        }
        Intent intent = new Intent(Intent.ACTION_VIEW, uri).addCategory(Intent.CATEGORY_BROWSABLE);
        try {
            startActivity(intent);
        } catch (ActivityNotFoundException e) {
            Toast.makeText(this, R.string.no_browser, Toast.LENGTH_LONG).show();
        }
    }

    @Override
    public boolean onSupportNavigateUp() {
        finish();
        return true;
    }
}
