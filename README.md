# QR Shield

Android app (Java, XML Views) that scans QR codes and common barcodes, analyzes the decoded
content **locally**, explains suspicious URL traits, and lets the user decide what to do.
It never opens a link automatically.

- Application ID `com.example.qrshield`, minSdk 23, compile/target SDK 34
- Android Gradle Plugin 8.5.2, Gradle 8.7, JDK 17, CameraX 1.3.4, ML Kit `barcode-scanning:17.3.0`
- Only permission: `CAMERA`. No INTERNET permission, no analytics, no accounts.

## Build and run

1. Install Android Studio (Koala or newer) with Android SDK Platform 34 and a JDK 17 (bundled JBR is fine).
2. Open this folder in Android Studio and let Gradle sync. Android Studio creates `local.properties`.
3. Generate the wrapper jar once (it is not included in this source drop):
   `gradle wrapper --gradle-version 8.7` (or let Android Studio do it).
4. Run on a device or an emulator with a camera (emulator: *Advanced settings > Camera > Back: VirtualScene/Webcam*).

```
./gradlew assembleDebug
./gradlew testDebugUnitTest
./gradlew lintDebug
./gradlew connectedDebugAndroidTest   # needs a device/emulator
```

## Features

- Home, live scanner, result, manual analysis, privacy screens.
- Scanner: CameraX Preview + ImageAnalysis, ML Kit on-device, formats: QR, EAN-13/8, UPC-A/E,
  Code 128/39/93, ITF, Codabar, PDF417, Aztec, Data Matrix. One frame in flight, every `ImageProxy`
  closed, first detection per resume only, camera bound/unbound with the lifecycle,
  permission explained before the system prompt, denial and "open settings" handling.
- Security engine (`security/`, plain Java, no Android classes): `UrlValidator` (structure, ports,
  IPv4/IPv6, userinfo, IDN/punycode, control characters, percent escapes, length) and
  `UrlSecurityChecker` (19 explainable rules).
- Safe opening: separate button, shown only for valid http/https; re-validated at click time;
  extra warning dialog for Caution/High caution; exact destination shown; cancel anywhere;
  `ACTION_VIEW` + `CATEGORY_BROWSABLE`; `ActivityNotFoundException` handled. `javascript:`, `file:`,
  `intent:`, `content:`, `data:` and other schemes are never opened.

## Classification and scoring

`ContentType` (what it is) and `RiskLevel` (how much review it deserves) are separate. A valid URL
can be Caution. `SUSPICIOUS_WEB_URL` was deliberately not added to `ContentType` for that reason;
`TOO_LONG` was added for inputs above 4096 characters.

Each rule has a fixed weight (see `SecurityIndicator`) and triggers at most once. Score 0-1 = Low
concern, 2-4 = Caution, 5+ = High caution. Invalid URLs, unsupported schemes, text and empty input
are not scored (Unable to assess / Informational; dangerous schemes are High caution by scheme).
Scores are internal and never shown as a probability. Same input always gives the same result.
Surrounding whitespace is trimmed for analysis only; nothing else is rewritten, and no scheme is added.

## Known limitations

- No reputation, DNS, certificate or redirect checks. A clean result is not a safety guarantee.
- Brand list is a small example set (7 brands) and can flag unlisted official domains.
- No Public Suffix List, so subdomain/registrable-domain logic is approximate.
- Scan history is not implemented (documented next milestone); nothing is stored.
- Screens are single-activity-per-screen with English-only strings in the rule texts.
- The Gradle wrapper jar is not included; see step 3.

## Verification status (honest report)

See the final summary delivered with this project: the pure-Java engine was compiled and its unit
tests were run in a sandbox; the Android build, lint, instrumentation tests and camera were not run.
