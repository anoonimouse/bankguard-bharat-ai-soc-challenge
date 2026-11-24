# BankGuard

[![pub package](https://img.shields.io/pub/v/bankguard.svg)](https://pub.dev/packages/bankguard)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A comprehensive mobile banking security SDK for Flutter. Protects banking apps against device tampering, social engineering attacks, UPI fraud, phishing links, and suspicious calls - with real-time threat intelligence powered by a Fraud Risk Indicator (FRI) database.

## Features

- **Dual-Stage Offline Edge AI Architecture**:
  - **Stage 1 (Specialist Detection, <20 ms)**: Deterministic string distance (Levenshtein), homoglyph normalization, TLD scoring, and local ML classification without network access.
  - **Stage 2 (Generative Reasoning via ExecuTorch)**: In-process `Llama-3.2-1B-Instruct` (SpinQuant INT4) accelerated by `XNNPACK/Arm NEON` on Arm Cortex CPUs to synthesize plain-language, non-hallucinatory threat explanations and actionable advice.
- **Device Integrity Scanning** - Detects unknown sources, overlay abuse, accessibility exploits, and app tampering
- **APK Signature Verification** - Validates installed banking app certificates against known-good hashes
- **Social Engineering Detection** - Pattern engine covering urgency, fear, and greed tactics across 6 Indian languages
- **FRI Database Integration** - Real-time fraud lookups for UPI IDs, mobile numbers, and bank accounts
- **QR Code Analysis** - Parses UPI payment QR codes and verifies payees against FRI
- **URL Phishing Scanner** - Real-time heuristic & ML engine for detecting phishing URLs offline or via backend
- **Call Screening** - Screens incoming calls against the FRI database
- **Notification Interception** - Monitors messaging app notifications for fraud patterns
- **Event-Driven Architecture** - Typed callbacks let your app react to threats without containing security logic

## Platform Support

| Android | iOS |
|---------|-----|
| [PASS]       | [PLANNED] Planned |

## Getting Started

### 1. Add dependency

```yaml
dependencies:
  bankguard: ^1.0.0
```

### 2. Android permissions

Add to your `AndroidManifest.xml`:

```xml
<!-- Required for notification interception -->
<uses-permission android:name="android.permission.BIND_NOTIFICATION_LISTENER_SERVICE" />

<!-- Required for call screening -->
<uses-permission android:name="android.permission.BIND_SCREENING_SERVICE" />
```

### 3. Initialize

```dart
import 'package:bankguard/bankguard.dart';

await Bankguard.initialize(
  config: BankguardConfig(
    backendBaseUrl: 'https://your-backend.example.com',
    officialPackageName: 'com.yourbank.app',
    officialCertHash: 'AA:BB:CC:DD:...',
    expectedSelfPackage: 'com.yourbank.app',
  ),
  callbacks: BankguardCallbacks(
    onDeviceScanComplete: (event) => handleScan(event),
    onSuspiciousNotification: (event) => showAlert(event),
    onSuspiciousCall: (event) => showCallWarning(event),
    onFriMatch: (event) => blockTransaction(event),
    onUrlThreat: (event) => blockUrl(event),
  ),
);
```

## Usage

### Device scan

```dart
final scan = await Bankguard.instance.runDeviceScan();
if (!scan.isSecure) {
  print('Threats: ${scan.threats}');
}
```

### UPI fraud check

```dart
final result = await Bankguard.instance.checkUPIId('suspect@upi');
if (result?.found == true) {
  print('BLOCKED: ${result!.reason}');
}
```

### QR code scan

```dart
final qr = await Bankguard.instance.scanQRPayload('upi://pay?pa=merchant@upi&am=500');
if (qr.isFraud) blockPayment();
```

### Batch check (transaction history)

```dart
final results = await Bankguard.instance.checkBatch([
  FriBatchItem(identifierType: 'upi', identifierValue: 'id1@upi'),
  FriBatchItem(identifierType: 'mobile', identifierValue: '9876543210'),
]);
```

### URL scan

```dart
final url = await Bankguard.instance.scanUrl('https://sbi-update-kyc.fake.com');
if (url != null && !url.isSafe) print('Phishing: ${url.message}');
```

## Configuration Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `backendBaseUrl` | `String` | [PASS] | Backend API URL for FRI, URL scanning, and telemetry |
| `officialPackageName` | `String` | [PASS] | Official banking app package name for whitelist |
| `officialCertHash` | `String` | [PASS] | SHA-256 certificate hash of the official app |
| `expectedSelfPackage` | `String` | [PASS] | Host app's own package name |
| `expectedSelfHash` | `String?` | [FAIL] | Host app's certificate hash (anti-tamper) |
| `additionalWhitelist` | `List<String>` | [FAIL] | Extra whitelisted package names |
| `language` | `String` | [FAIL] | Preferred language code (en, hi, ta, te, bn, mr) |
| `features` | `BankguardFeatures` | [FAIL] | Feature flags for granular control |

## Callbacks Reference

| Callback | Trigger | Event Type |
|----------|---------|------------|
| `onDeviceScanComplete` | Device scan finishes | `DeviceScanEvent` |
| `onFakeAppDetected` | Suspicious app found | `FakeAppEvent` |
| `onDangerousEnvironment` | Environment flag detected | `EnvironmentEvent` |
| `onSuspiciousNotification` | Threat in notification | `NotificationThreatEvent` |
| `onSuspiciousCall` | FRI hit on incoming call | `CallThreatEvent` |
| `onFriMatch` | FRI database match | `FriMatchEvent` |
| `onUrlThreat` | Phishing URL detected | `UrlThreatEvent` |
| `onGeneralThreat` | Uncategorized threat | `GeneralThreatEvent` |

## Android Permissions

| Permission | Feature | Required By |
|------------|---------|-------------|
| `BIND_NOTIFICATION_LISTENER_SERVICE` | Notification interception | `BankguardNotificationListenerService` |
| `BIND_SCREENING_SERVICE` | Call screening | `BankguardCallScreeningService` |
| `QUERY_ALL_PACKAGES` | Package scanning | `runDeviceScan()` |
| `SYSTEM_ALERT_WINDOW` | Proactive Warnings | `openOverlaySettings()` |

## Security Paradox & Self-Exclusion

The BankGuard SDK implements a "Self-Aware" security architecture. While overlay permissions (`SYSTEM_ALERT_WINDOW`) are often used by malware for credential harvesting, BankGuard requires this permission to:
1. Show **Installer Overlays** over suspicious APK installations.
2. Display **Proactive Warnings** during social engineering attempts.

To avoid a "security paradox" where the SDK flags itself, the behavioral engine (Kotlin layer) and the Flutter bridge explicitly **exclude the host application package** from overlay and unknown-source monitoring. This ensures the app remains secure without blocking its own legitimate protection layers.

## Recommended UX: Permission Rationale

When requesting overlay permissions from the user, it is STRONGLY recommended to show a rationale dialog first. Users are often wary of "Display over other apps" requests; explaining that this is used to "Block fake app installations" significantly improves trust and conversion.

MIT - see [LICENSE](LICENSE) for details.
