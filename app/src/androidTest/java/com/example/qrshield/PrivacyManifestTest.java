package com.example.qrshield;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;

import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Arrays;
import java.util.List;

/** Verifies that the installed app requests only the camera permission (no INTERNET). */
@RunWith(AndroidJUnit4.class)
public class PrivacyManifestTest {

    @Test
    public void onlyCameraPermissionIsRequested() throws Exception {
        Context context = ApplicationProvider.getApplicationContext();
        PackageInfo info = context.getPackageManager()
                .getPackageInfo(context.getPackageName(), PackageManager.GET_PERMISSIONS);
        List<String> requested = info.requestedPermissions == null
                ? java.util.Collections.<String>emptyList() : Arrays.asList(info.requestedPermissions);
        assertTrue(requested.contains(android.Manifest.permission.CAMERA));
        assertFalse(requested.contains(android.Manifest.permission.INTERNET));
        assertEquals(1, requested.size());
    }
}
