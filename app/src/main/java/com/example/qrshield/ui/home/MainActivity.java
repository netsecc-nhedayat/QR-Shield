package com.example.qrshield.ui.home;

import android.content.Intent;
import android.os.Bundle;

import androidx.appcompat.app.AppCompatActivity;

import com.example.qrshield.R;
import com.example.qrshield.ui.manual.ManualAnalysisActivity;
import com.example.qrshield.ui.privacy.PrivacyActivity;
import com.example.qrshield.ui.scanner.ScannerActivity;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        findViewById(R.id.btn_scan).setOnClickListener(v ->
                startActivity(new Intent(this, ScannerActivity.class)));
        findViewById(R.id.btn_manual).setOnClickListener(v ->
                startActivity(new Intent(this, ManualAnalysisActivity.class)));
        findViewById(R.id.btn_privacy).setOnClickListener(v ->
                startActivity(new Intent(this, PrivacyActivity.class)));
    }
}
