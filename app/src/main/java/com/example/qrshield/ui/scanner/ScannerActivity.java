package com.example.qrshield.ui.scanner;

import android.Manifest;
import android.content.Intent;
import android.content.ActivityNotFoundException;
import android.content.pm.PackageManager;
import android.media.Image;
import android.net.Uri;
import android.os.Bundle;
import android.provider.Settings;
import android.util.Log;
import android.util.Size;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.annotation.OptIn;
import androidx.appcompat.app.AppCompatActivity;
import androidx.camera.core.CameraInfoUnavailableException;
import androidx.camera.core.CameraSelector;
import androidx.camera.core.ExperimentalGetImage;
import androidx.camera.core.ImageAnalysis;
import androidx.camera.core.ImageProxy;
import androidx.camera.core.Preview;
import androidx.camera.lifecycle.ProcessCameraProvider;
import androidx.camera.view.PreviewView;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import com.example.qrshield.R;
import com.example.qrshield.ui.result.ResultActivity;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.mlkit.vision.barcode.BarcodeScanner;
import com.google.mlkit.vision.barcode.BarcodeScannerOptions;
import com.google.mlkit.vision.barcode.BarcodeScanning;
import com.google.mlkit.vision.barcode.common.Barcode;
import com.google.mlkit.vision.common.InputImage;

import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Live scanner: CameraX Preview + ImageAnalysis feeding on-device ML Kit.
 * The camera is bound only between onResume and onPause. At most one frame is
 * processed at a time, every ImageProxy is closed, and only the first detection
 * per resume starts the result screen.
 */
public class ScannerActivity extends AppCompatActivity {

    private static final String TAG = "QRShieldScanner";
    private static final int NO_DETECTION_FRAMES_BEFORE_HINT = 90;

    private PreviewView previewView;
    private TextView statusText;
    private TextView permissionTitle;
    private TextView permissionMessage;
    private Button permissionButton;
    private View permissionPanel;

    private ExecutorService analysisExecutor;
    private BarcodeScanner barcodeScanner;
    private ProcessCameraProvider cameraProvider;
    private ImageAnalysis imageAnalysis;

    private final AtomicBoolean frameInFlight = new AtomicBoolean(false);
    private final AtomicBoolean resultDispatched = new AtomicBoolean(false);
    private int framesWithoutDetection; // main thread only
    private boolean failureShown;       // main thread only
    private boolean permissionRequestedOnce;
    private boolean permissionPermanentlyDenied;
    private ActivityResultLauncher<String> permissionLauncher;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_scanner);
        if (getSupportActionBar() != null) getSupportActionBar().setDisplayHomeAsUpEnabled(true);

        previewView = findViewById(R.id.preview_view);
        statusText = findViewById(R.id.status_text);
        permissionPanel = findViewById(R.id.permission_panel);
        permissionTitle = findViewById(R.id.permission_title);
        permissionMessage = findViewById(R.id.permission_message);
        permissionButton = findViewById(R.id.permission_button);
        permissionButton.setOnClickListener(v -> onPermissionButtonClicked());

        permissionLauncher = registerForActivityResult(
                new ActivityResultContracts.RequestPermission(), granted -> {
                    if (granted) {
                        permissionPanel.setVisibility(View.GONE);
                        startCamera();
                    } else {
                        showPermissionPanel();
                    }
                });

        BarcodeScannerOptions options = new BarcodeScannerOptions.Builder()
                .setBarcodeFormats(
                        Barcode.FORMAT_QR_CODE, Barcode.FORMAT_EAN_13, Barcode.FORMAT_EAN_8,
                        Barcode.FORMAT_UPC_A, Barcode.FORMAT_UPC_E, Barcode.FORMAT_CODE_128,
                        Barcode.FORMAT_CODE_39, Barcode.FORMAT_CODE_93, Barcode.FORMAT_ITF,
                        Barcode.FORMAT_CODABAR, Barcode.FORMAT_PDF417, Barcode.FORMAT_AZTEC,
                        Barcode.FORMAT_DATA_MATRIX)
                .build();
        barcodeScanner = BarcodeScanning.getClient(options);
        analysisExecutor = Executors.newSingleThreadExecutor();
    }

    @Override
    protected void onResume() {
        super.onResume();
        resultDispatched.set(false);
        framesWithoutDetection = 0;
        failureShown = false;
        statusText.setText(R.string.scanner_hint);
        if (hasCameraPermission()) {
            permissionPanel.setVisibility(View.GONE);
            startCamera();
        } else {
            showPermissionPanel();
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (imageAnalysis != null) imageAnalysis.clearAnalyzer();
        if (cameraProvider != null) cameraProvider.unbindAll();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        analysisExecutor.shutdown();
        barcodeScanner.close();
    }

    // ---- permission --------------------------------------------------------------------------

    private boolean hasCameraPermission() {
        return ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA)
                == PackageManager.PERMISSION_GRANTED;
    }

    private void showPermissionPanel() {
        permissionPanel.setVisibility(View.VISIBLE);
        permissionPermanentlyDenied = permissionRequestedOnce
                && !ActivityCompat.shouldShowRequestPermissionRationale(this, Manifest.permission.CAMERA);
        if (permissionPermanentlyDenied) {
            permissionTitle.setText(R.string.permission_denied_title);
            permissionMessage.setText(R.string.permission_denied_message);
            permissionButton.setText(R.string.permission_button_settings);
        } else if (permissionRequestedOnce) {
            permissionTitle.setText(R.string.permission_denied_title);
            permissionMessage.setText(R.string.permission_message);
            permissionButton.setText(R.string.permission_button_allow);
        } else {
            permissionTitle.setText(R.string.permission_title);
            permissionMessage.setText(R.string.permission_message);
            permissionButton.setText(R.string.permission_button_allow);
        }
    }

    private void onPermissionButtonClicked() {
        if (permissionPermanentlyDenied) {
            Intent intent = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                    Uri.fromParts("package", getPackageName(), null));
            try {
                startActivity(intent);
            } catch (ActivityNotFoundException e) {
                Toast.makeText(this, R.string.settings_unavailable, Toast.LENGTH_LONG).show();
            }
        } else {
            permissionRequestedOnce = true;
            permissionLauncher.launch(Manifest.permission.CAMERA);
        }
    }

    // ---- camera ------------------------------------------------------------------------------

    private void startCamera() {
        ListenableFuture<ProcessCameraProvider> future = ProcessCameraProvider.getInstance(this);
        future.addListener(() -> {
            try {
                cameraProvider = future.get();
            } catch (ExecutionException e) {
                Log.e(TAG, "Camera provider failed: " + e.getCause());
                showCameraError(R.string.camera_unavailable);
                return;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
            bindUseCases();
        }, ContextCompat.getMainExecutor(this));
    }

    private void bindUseCases() {
        // The future may complete after the screen was paused or closed.
        if (isFinishing() || isDestroyed() || !hasCameraPermission()
                || !getLifecycle().getCurrentState().isAtLeast(androidx.lifecycle.Lifecycle.State.STARTED)) {
            return;
        }
        try {
            if (!cameraProvider.hasCamera(CameraSelector.DEFAULT_BACK_CAMERA)) {
                showCameraError(R.string.camera_unavailable);
                return;
            }
        } catch (CameraInfoUnavailableException e) {
            Log.e(TAG, "Camera info unavailable");
            showCameraError(R.string.camera_unavailable);
            return;
        }

        Preview preview = new Preview.Builder().build();
        preview.setSurfaceProvider(previewView.getSurfaceProvider());

        imageAnalysis = new ImageAnalysis.Builder()
                .setTargetResolution(new Size(1280, 720))
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build();
        imageAnalysis.setAnalyzer(analysisExecutor, this::analyzeFrame);

        try {
            cameraProvider.unbindAll();
            cameraProvider.bindToLifecycle(this, CameraSelector.DEFAULT_BACK_CAMERA, preview, imageAnalysis);
        } catch (IllegalArgumentException | IllegalStateException e) {
            Log.e(TAG, "Camera binding failed: " + e.getClass().getSimpleName());
            showCameraError(R.string.camera_error);
        }
    }

    private void showCameraError(int messageRes) {
        statusText.setText(messageRes);
    }

    // ---- frame analysis ----------------------------------------------------------------------

    @OptIn(markerClass = ExperimentalGetImage.class)
    private void analyzeFrame(@NonNull ImageProxy imageProxy) {
        Image mediaImage = imageProxy.getImage();
        if (mediaImage == null || resultDispatched.get() || !frameInFlight.compareAndSet(false, true)) {
            imageProxy.close();
            return;
        }
        InputImage image = InputImage.fromMediaImage(mediaImage,
                imageProxy.getImageInfo().getRotationDegrees());
        barcodeScanner.process(image)
                .addOnSuccessListener(this::onBarcodesDetected)      // main thread
                .addOnFailureListener(this::onScanFailure)           // main thread
                .addOnCompleteListener(task -> {                     // always runs: release the frame
                    frameInFlight.set(false);
                    imageProxy.close();
                });
    }

    private void onBarcodesDetected(List<Barcode> barcodes) {
        if (isFinishing() || isDestroyed() || resultDispatched.get()) return;
        if (barcodes.isEmpty()) {
            framesWithoutDetection++;
            if (framesWithoutDetection == NO_DETECTION_FRAMES_BEFORE_HINT) {
                statusText.setText(R.string.scanner_no_code);
            }
            return;
        }
        framesWithoutDetection = 0;
        for (Barcode barcode : barcodes) {
            String raw = barcode.getRawValue();
            if (raw != null && !raw.isEmpty()) {
                dispatchResult(raw);
                return;
            }
        }
        statusText.setText(R.string.scanner_unreadable);
    }

    private void onScanFailure(@NonNull Exception e) {
        // Never log decoded content; the exception class is enough for diagnostics.
        Log.w(TAG, "Barcode processing failed: " + e.getClass().getSimpleName());
        if (isFinishing() || isDestroyed() || failureShown) return;
        failureShown = true;
        statusText.setText(R.string.scanner_failure);
    }

    private void dispatchResult(String raw) {
        if (!resultDispatched.compareAndSet(false, true)) return; // ignore duplicate callbacks
        if (imageAnalysis != null) imageAnalysis.clearAnalyzer();
        startActivity(ResultActivity.newIntent(this, raw, true));
    }

    @Override
    public boolean onSupportNavigateUp() {
        finish();
        return true;
    }
}
