/// Configuration object for Bankguard SDK initialization.
/// All deployment-specific values are injected here - no hardcoded constants in SDK.
class BankguardConfig {
  /// Base URL for the Bankguard backend (e.g. 'https://api.doy.codes').
  final String backendBaseUrl;

  /// Official banking app package name for whitelist verification.
  final String officialPackageName;

  /// SHA-256 certificate hash of the official banking app.
  final String officialCertHash;

  /// Package name of the host app itself (for self-integrity checks).
  final String expectedSelfPackage;

  /// The customer ID for verified call checks.
  final String customerId;

  /// Optional: expected SHA-256 hash of the host app's own certificate.
  /// If provided, enables anti-tamper detection.
  final String? expectedSelfHash;

  /// Additional whitelisted package names (official banking ecosystem apps).
  final List<String> additionalWhitelist;

  /// Preferred language code for threat alert strings (en, hi, ta, te, bn, mr).
  final String language;

  /// Feature flags to enable/disable individual SDK capabilities.
  final BankguardFeatures features;

  /// Configuration for the behavioral risk engine.
  final BehavioralConfig behavioralConfig;

  const BankguardConfig({
    required this.backendBaseUrl,
    required this.officialPackageName,
    required this.officialCertHash,
    required this.expectedSelfPackage,
    this.customerId = '89012345678',
    this.expectedSelfHash,
    this.additionalWhitelist = const [],
    this.language = 'en',
    this.features = const BankguardFeatures(),
    this.behavioralConfig = const BehavioralConfig(),
  });
}

/// Feature flags for granular SDK control.
class BankguardFeatures {
  /// Enable device environment scanning (unknown sources, overlay, accessibility).
  final bool deviceScan;

  /// Enable package scanning and signature verification.
  final bool packageScan;

  /// Enable notification interception and social engineering detection.
  final bool notificationInterception;

  /// Enable call screening integration.
  final bool callScreening;

  /// Enable FRI (Fraud Risk Indicator) database lookups.
  final bool friEnabled;

  /// Enable URL phishing heuristic scanning.
  final bool urlScanning;

  /// Enable telemetry reporting to backend.
  final bool telemetryEnabled;

  /// Enable behavioral risk modeling and attack chain detection.
  final bool behavioralDetection;

  /// Enable APK hash denylist checking on package install.
  final bool apkDenylist;

  /// Enable real-time Unknown Sources setting monitoring (Layer 5).
  final bool unknownSourcesMonitor;

  /// Enable DownloadManager APK download detection (Layer 2A).
  final bool downloadMonitor;

  /// Enable package installer overlay warning (Layer 3).
  final bool installerOverlay;

  /// Enable on-device URL heuristic scanning (Layer 1B).
  final bool urlHeuristicScanning;

  /// Enable MediaStore-based APK file observer (Layer 2B).
  final bool fileObserver;

  const BankguardFeatures({
    this.deviceScan = true,
    this.packageScan = true,
    this.notificationInterception = true,
    this.callScreening = true,
    this.friEnabled = true,
    this.urlScanning = true,
    this.telemetryEnabled = true,
    this.behavioralDetection = true,
    this.apkDenylist = true,
    this.unknownSourcesMonitor = true,
    this.downloadMonitor = true,
    this.installerOverlay = true,
    this.urlHeuristicScanning = true,
    this.fileObserver = true,
  });
}

/// Configuration for the behavioral risk engine.
class BehavioralConfig {
  /// Time window (in minutes) for attack chain correlation.
  /// If permission events happen within this window of installation,
  /// the risk score escalates significantly.
  final int chainWindowMinutes;

  /// Additional package name prefixes to whitelist.
  final List<String> whitelistPrefixes;

  const BehavioralConfig({
    this.chainWindowMinutes = 5,
    this.whitelistPrefixes = const [],
  });
}
