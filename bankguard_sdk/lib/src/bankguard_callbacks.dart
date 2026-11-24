import 'bankguard_events.dart';

/// Callback interface for Bankguard SDK -> host app communication.
/// Register these at SDK initialization time. The SDK fires events
/// when threats are detected - the host app decides how to present them.
class BankguardCallbacks {
  /// Fired when the initial device security scan completes.
  final void Function(DeviceScanEvent event)? onDeviceScanComplete;

  /// Fired when a fake/suspicious app is detected on the device.
  final void Function(FakeAppEvent event)? onFakeAppDetected;

  /// Fired when a dangerous device environment flag is detected.
  final void Function(EnvironmentEvent event)? onDangerousEnvironment;

  /// Fired when a suspicious notification is intercepted and analyzed.
  final void Function(NotificationThreatEvent event)? onSuspiciousNotification;

  /// Fired when a suspicious incoming call is detected.
  final void Function(CallThreatEvent event)? onSuspiciousCall;

  /// Fired when an FRI database match is found (any identifier type).
  final void Function(FriMatchEvent event)? onFriMatch;

  /// Fired when a URL is determined to be a phishing threat.
  final void Function(UrlThreatEvent event)? onUrlThreat;

  /// Fired for any general threat that doesn't fit the above categories.
  final void Function(GeneralThreatEvent event)? onGeneralThreat;

  /// Fired when the behavioral engine detects a suspicious attack chain.
  /// The event contains the full profile with timeline, score, and verdict.
  final void Function(BehavioralThreatEvent event)? onBehavioralThreatDetected;

  /// Fired when a newly installed package matches the APK hash denylist.
  final void Function(DenylistMatchEvent event)? onDenylistMatch;

  /// Fired when the "Unknown Sources" setting changes state (Layer 5).
  final void Function(UnknownSourcesEvent event)? onUnknownSourcesChanged;

  /// Fired when an APK file download is detected (Layer 2A).
  final void Function(ApkDownloadEvent event)? onApkDownloadDetected;

  /// Fired when an APK file appears in the filesystem (Layer 2B).
  final void Function(ApkFileEvent event)? onApkFileDetected;

  /// Fired when the active silent SMS challenge is invalidated due to app entering background.
  final void Function()? onSilentSmsInvalidated;

  const BankguardCallbacks({
    this.onDeviceScanComplete,
    this.onFakeAppDetected,
    this.onDangerousEnvironment,
    this.onSuspiciousNotification,
    this.onSuspiciousCall,
    this.onFriMatch,
    this.onUrlThreat,
    this.onGeneralThreat,
    this.onBehavioralThreatDetected,
    this.onDenylistMatch,
    this.onUnknownSourcesChanged,
    this.onApkDownloadDetected,
    this.onApkFileDetected,
    this.onSilentSmsInvalidated,
  });
}
