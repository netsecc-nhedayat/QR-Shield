package com.example.qrshield.ui.manual;

import android.os.Bundle;
import android.widget.EditText;

import androidx.appcompat.app.AppCompatActivity;

import com.example.qrshield.R;
import com.example.qrshield.ui.result.ResultActivity;

/** Collects text and hands it, unmodified, to the shared analysis flow in ResultActivity. */
public class ManualAnalysisActivity extends AppCompatActivity {

    private EditText input;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_manual);
        if (getSupportActionBar() != null) getSupportActionBar().setDisplayHomeAsUpEnabled(true);
        input = findViewById(R.id.input_text);
        findViewById(R.id.btn_analyze).setOnClickListener(v -> analyze());
        findViewById(R.id.btn_clear).setOnClickListener(v -> {
            input.setText("");
            input.setError(null);
        });
    }

    private void analyze() {
        String text = input.getText().toString();
        if (text.trim().isEmpty()) {
            input.setError(getString(R.string.error_empty_input));
            input.requestFocus();
            return;
        }
        startActivity(ResultActivity.newIntent(this, text, false));
    }

    @Override
    public boolean onSupportNavigateUp() {
        finish();
        return true;
    }
}
