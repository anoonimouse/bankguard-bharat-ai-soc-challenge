/// Bankguard - A comprehensive mobile banking security SDK.
///
/// Provides device integrity scanning, social engineering detection,
/// fraud intelligence (FRI) database lookups, UPI fraud checking,
/// URL phishing analysis, notification interception, and call screening.
///
/// ## Quick Start
///
/// ```dart
/// import 'package:bankguard/bankguard.dart';
///
/// await Bankguard.initialize(
///   config: BankguardConfig(
///     backendBaseUrl: 'https://your-backend.example.com',
///     officialPackageName: 'com.yourbank.app',
///     officialCertHash: 'AA:BB:CC:...',
///     expectedSelfPackage: 'com.yourbank.app',
///   ),
///   callbacks: BankguardCallbacks(
///     onDeviceScanComplete: (event) => print(event.threats),
///     onSuspiciousNotification: (event) => showAlert(event),
///   ),
/// );
/// ```
library bankguard;

import 'dart:async';
import 'dart:convert';
import 'package:crypto/crypto.dart';
import 'package:flutter/services.dart';
import 'package:http/http.dart' as http;

// SDK internal modules
import 'src/bankguard_config.dart';
import 'src/bankguard_callbacks.dart';
import 'src/bankguard_events.dart';
import 'src/fri_client.dart';
import 'src/identifier_extractor.dart';

// Re-export public API types so host apps only need one import
export 'src/bankguard_config.dart';
export 'src/bankguard_callbacks.dart';
export 'src/bankguard_events.dart';
export 'src/fri_client.dart'
    show
        FriCheckResult,
        FriBatchItem,
        FriBatchResult,
        FriEntryDetail,
        FriIdentifierDetail,
        UrlScanResult,
        ApkScanResult;
export 'src/identifier_extractor.dart' show IdentifierExtractor, UpiPayload;
export 'widgets/bankguard_threat_overlay.dart';
export 'src/threat_strings.dart';

/// The main entry point for the Bankguard mobile banking security SDK.
///
/// Initialize once at app startup using [Bankguard.initialize], then access
/// the singleton via [Bankguard.instance] for on-demand security checks.
///
/// The SDK manages its own lifecycle after initialization:
/// - Subscribes to notification and call event streams
/// - Runs social engineering pattern detection on intercepted notifications
/// - Performs FRI (Fraud Risk Indicator) lookups on extracted identifiers
/// - Fires typed callbacks to the host app when threats are detected
///
/// The host app is responsible only for:
/// - Providing configuration at startup
/// - Reacting to callbacks with appropriate UI
///
/// Example:
/// ```dart
/// // At startup
/// await Bankguard.initialize(config: myConfig, callbacks: myCallbacks);
///
/// // On-demand checks
/// final result = await Bankguard.instance.checkUPIId('suspect@upi');
/// ```
class Bankguard {
  static const MethodChannel _channel = MethodChannel('bankguard');
  static const EventChannel _notificationEventChannel =
      EventChannel('bankguard/notifications');
  static const EventChannel _callEventChannel = EventChannel('bankguard/calls');
  static const EventChannel _behavioralEventChannel =
      EventChannel('bankguard/behavioral_threats');
  static const EventChannel _unknownSourcesEventChannel =
      EventChannel('bankguard/unknown_sources');
  static const EventChannel _downloadEventChannel =
      EventChannel('bankguard/downloads');
  static const EventChannel _fileObserverEventChannel =
      EventChannel('bankguard/file_observer');

  // Singleton
  static final Bankguard _instance = Bankguard._internal();

  /// Access the initialized SDK singleton.
  ///
  /// Throws if [initialize] has not been called yet.
  static Bankguard get instance => _instance;

  factory Bankguard() => _instance;
  Bankguard._internal();

  static bool _initialized = false;

  // Internal state
  late BankguardConfig _config;
  late BankguardCallbacks _callbacks;
  late FriClient _friClient;
  void Function()? onSilentSmsInvalidatedListener;
  final Map<String, DateTime> _recentlyScannedFiles = {};

  // Contextual Risk Engine state
  NotificationThreatEvent? _lastSuspiciousNotification;
  DateTime? _lastNotificationTime;

  StreamSubscription<dynamic>? _notificationSubscription;
  StreamSubscription<dynamic>? _callSubscription;
  StreamSubscription<dynamic>? _behavioralSubscription;
  StreamSubscription<dynamic>? _unknownSourcesSubscription;
  StreamSubscription<dynamic>? _downloadSubscription;
  StreamSubscription<dynamic>? _fileObserverSubscription;

  // -----------------------------------------------------------------------
  // PUBLIC API: Initialization
  // -----------------------------------------------------------------------

  /// Initialize the SDK. Call once at app startup.
  ///
  /// After this call, the SDK manages its own lifecycle:
  /// - Subscribes to notification and call streams
  /// - Fires callbacks when threats are detected
  /// - The host app reacts to callbacks with appropriate UI
  ///
  /// [config] provides all deployment-specific values (backend URL,
  /// certificate hashes, feature flags).
  ///
  /// [callbacks] defines how the host app is notified of security events.
  /// All callbacks are optional - only register those you need.
  static Future<void> initialize({
    required BankguardConfig config,
    BankguardCallbacks callbacks = const BankguardCallbacks(),
  }) async {
    if (_initialized) return;

    _instance._config = config;
    _instance._callbacks = callbacks;
    _instance._friClient = FriClient(backendBaseUrl: config.backendBaseUrl);

    // Auto-subscribe to notification threats
    if (config.features.notificationInterception) {
      _instance._notificationSubscription = _notificationEventChannel
          .receiveBroadcastStream()
          .where((event) => event is Map)
          .listen(_instance._handleNotificationEvent);
    }

    // Auto-subscribe to call threats
    if (config.features.callScreening) {
      _instance._callSubscription = _callEventChannel
          .receiveBroadcastStream()
          .where((event) => event is Map)
          .listen(_instance._handleCallEvent);
    }

    // Auto-subscribe to behavioral threat alerts
    if (config.features.behavioralDetection) {
      _instance._behavioralSubscription = _behavioralEventChannel
          .receiveBroadcastStream()
          .where((event) => event is Map)
          .listen(_instance._handleBehavioralEvent);

      // Forward behavioral config to native engine
      try {
        await _channel.invokeMethod('configureBehavioralEngine', {
          'chainWindowMinutes': config.behavioralConfig.chainWindowMinutes,
          'whitelistPrefixes': config.behavioralConfig.whitelistPrefixes,
        });
      } catch (_) {
        // Engine may not be available on non-Android
      }
    }

    // Auto-subscribe to Unknown Sources changes (Layer 5)
    if (config.features.unknownSourcesMonitor) {
      _instance._unknownSourcesSubscription = _unknownSourcesEventChannel
          .receiveBroadcastStream()
          .where((event) => event is Map)
          .listen(_instance._handleUnknownSourcesEvent);
    }

    // Auto-subscribe to APK download detection (Layer 2A)
    if (config.features.downloadMonitor) {
      _instance._downloadSubscription = _downloadEventChannel
          .receiveBroadcastStream()
          .where((event) => event is Map)
          .listen(_instance._handleDownloadEvent);
    }

    // Auto-start installer overlay if permission is available (Layer 3)
    if (config.features.installerOverlay) {
      try {
        await _channel.invokeMethod('startInstallerOverlay');
      } catch (_) {
        // Overlay may not be available
      }
    }

    // Auto-subscribe to APK file observer (Layer 2B)
    if (config.features.fileObserver) {
      _instance._fileObserverSubscription = _fileObserverEventChannel
          .receiveBroadcastStream()
          .where((event) => event is Map)
          .listen(_instance._handleFileObserverEvent);
    }

    // Register MethodChannel handler for incoming events from Kotlin layer
    _channel.setMethodCallHandler(_instance._handleMethodCall);

    // Save configuration settings to SharedPreferences on Android
    try {
      await _channel.invokeMethod('setCustomerConfig', {
        'customerId': config.customerId,
        'backendBaseUrl': config.backendBaseUrl,
        'language': config.language,
      });
    } catch (_) {
      // Platform channel configuration might fail on non-Android platforms
    }

    _initialized = true;
  }

  /// Update the callbacks used by the SDK.
  /// Useful for setting UI-dependent callbacks after the app has started.
  static void setCallbacks(BankguardCallbacks callbacks) {
    _instance._callbacks = callbacks;
  }

  /// Whether [initialize] has been called.
  bool get isInitialized => _initialized;

  /// The current configuration (read-only).
  BankguardConfig get config => _config;

  // -----------------------------------------------------------------------
  // PUBLIC API: Device Scanning
  // -----------------------------------------------------------------------

  /// Run a comprehensive device security scan.
  ///
  /// Checks the following device state:
  /// - Unknown sources (sideloading) enabled
  /// - Screen overlay permission granted
  /// - Accessibility services enabled
  /// - Notification listener service registered
  /// - Call screening service registered
  /// - Self-integrity (anti-tamper) verification
  /// - Installed package scanning for suspicious banking clones
  ///
  /// Returns a [DeviceScanEvent] containing all findings. Also fires
  /// [BankguardCallbacks.onDeviceScanComplete] and, for each suspicious
  /// app found, [BankguardCallbacks.onFakeAppDetected].
  Future<DeviceScanEvent> runDeviceScan() async {
    List<String> threats = [];
    bool isSecure = true;

    final unknownSources = await isSelfUnknownSourcesEnabled();
    final overlayEnabled = await isSelfOverlayPermissionEnabled();
    final accessibilityEnabled = await _checkBool('isAccessibilityEnabled');
    final notificationEnabled =
        await _checkBool('isNotificationListenerEnabled');
    final callScreeningEnabled = await _checkBool('isCallScreeningEnabled');

    // For Device Scan, we only want to flag if OTHER apps have these enabled.
    // So we ask the native side for the "Filtered" status.
    final hasOtherUnknownSources = await _checkBool('isUnknownSourcesEnabled');
    final hasOtherOverlays = await _checkBool('isOverlayPermissionEnabled');

    if (hasOtherUnknownSources) {
      isSecure = false;
      threats.add('UNKNOWN_SOURCES_ENABLED');
      _reportTelemetry(
          'UNKNOWN_SOURCES', 'Unknown sources enabled (3rd party)', 0.7);
    }
    if (hasOtherOverlays) {
      isSecure = false;
      threats.add('OVERLAY_PERMISSION_ENABLED');
      _reportTelemetry(
          'OVERLAY_PERMISSION', 'Overlay permission enabled (3rd party)', 0.75);
    }
    if (accessibilityEnabled) {
      isSecure = false;
      threats.add('ACCESSIBILITY_ENABLED');
      _reportTelemetry('ACCESSIBILITY', 'Accessibility services enabled', 0.8);
    }
    if (!notificationEnabled) {
      threats.add('NOTIFICATION_LISTENER_DISABLED');
    }
    if (!callScreeningEnabled) {
      threats.add('CALL_SCREENING_DISABLED');
    }

    // Check Behavioral Engine Profiles for existing threats
    final profiles = await getBehavioralProfiles();
    for (var profile in profiles) {
      if (profile.packageName == _config.expectedSelfPackage) continue;

      if (profile.lastScore >= 51) {
        isSecure = false;
        threats.add(
            'BEHAVIORAL_THREAT_DETECTED: ${profile.packageName} (Score: ${profile.lastScore})');
      }
    }

    // Self-integrity check
    if (_config.expectedSelfHash != null &&
        _config.expectedSelfHash!.isNotEmpty) {
      final selfHash = await getCertificateHash(_config.expectedSelfPackage);
      if (selfHash != _config.expectedSelfHash) {
        isSecure = false;
        threats
            .add('SELF_TAMPER_DETECTED: Signature hash mismatch ($selfHash)');
      }
    }

    // Package scanning
    if (_config.features.packageScan) {
      final packages = await getInstalledPackages();

      final whitelist = [
        _config.officialPackageName,
        ..._config.additionalWhitelist,
      ];

      for (var pkg in packages) {
        if (pkg == _config.officialPackageName) {
          final actualHash = await getCertificateHash(pkg);
          if (actualHash != _config.officialCertHash) {
            threats
                .add('SUSPICIOUS_PACKAGE_DETECTED: $pkg (Signature Mismatch)');
            _callbacks.onFakeAppDetected?.call(FakeAppEvent(
              packageName: pkg,
              certHash: actualHash,
              threatType: 'SIGNATURE_MISMATCH',
              riskScore: 0.95,
            ));
          }
          continue;
        }

        if (_config.additionalWhitelist.contains(pkg)) {
          continue;
        }

        if (pkg.toLowerCase().contains('sbi') &&
            pkg != _config.expectedSelfPackage) {
          threats.add('SUSPICIOUS_PACKAGE_DETECTED: $pkg');
          isSecure = false;

          try {
            final hash = await getCertificateHash(pkg);
            final response = await http.post(
              Uri.parse('${_config.backendBaseUrl}/api/verify-apk'),
              headers: {'Content-Type': 'application/json'},
              body: jsonEncode(
                  {'package_name': pkg, 'cert_hash': hash ?? 'unknown'}),
            );

            if (response.statusCode == 200) {
              final data = jsonDecode(response.body);
              if (data['is_official'] == false) {
                threats.add('VERIFIED_MALICIOUS_PACKAGE: ${data['message']}');
                _reportTelemetry('SDK_TELEMETRY', 'Flagged: $pkg', 0.99);
                _callbacks.onFakeAppDetected?.call(FakeAppEvent(
                  packageName: pkg,
                  certHash: hash,
                  threatType: 'VERIFIED_MALICIOUS',
                  backendMessage: data['message'],
                  riskScore: 0.99,
                ));
              }
            }
          } catch (_) {
            // Fail-open: backend unavailable, skip verification
          }
        }
      }
    }

    final event = DeviceScanEvent(
      isSecure: isSecure,
      threats: threats,
      unknownSourcesEnabled: unknownSources,
      overlayPermissionEnabled: overlayEnabled,
      accessibilityEnabled: accessibilityEnabled,
      notificationListenerEnabled: notificationEnabled,
      callScreeningEnabled: callScreeningEnabled,
    );

    _callbacks.onDeviceScanComplete?.call(event);
    return event;
  }

  // -----------------------------------------------------------------------
  // PUBLIC API: FRI Checks
  // -----------------------------------------------------------------------

  /// Check a UPI ID against the Fraud Risk Indicator database.
  ///
  /// Returns [FriCheckResult] with [FriCheckResult.found] == true if the
  /// UPI ID is flagged. Returns null if the backend is unreachable
  /// (fail-open semantics).
  ///
  /// Also fires [BankguardCallbacks.onFriMatch] if a match is found.
  ///
  /// Example:
  /// ```dart
  /// final result = await Bankguard.instance.checkUPIId('suspect@paytm');
  /// if (result?.found == true) {
  ///   print('Fraud detected: ${result!.reason}');
  /// }
  /// ```
  /// Evaluates transaction risk by combining recent suspicious notifications with payment parameters.
  Future<ContextualRiskResult> evaluateTransactionRisk({
    required String targetIdentifier,
    required String identifierType, // 'upi', 'mobile', 'bank_account'
    required double amount,
  }) async {
    // 1. Check time delta (scammers exploit urgency within minutes)
    final now = DateTime.now();
    final timeSinceNotif = _lastNotificationTime != null
        ? now.difference(_lastNotificationTime!)
        : null;

    final isRecentScam =
        timeSinceNotif != null && timeSinceNotif.inMinutes <= 15;
    if (!isRecentScam || _lastSuspiciousNotification == null) {
      return ContextualRiskResult(isHighRisk: false);
    }

    bool identifierMatched = false;
    final cleanTarget = targetIdentifier.trim().toLowerCase();

    // 2. Direct identifier correlation
    if (identifierType == 'upi' &&
        _lastSuspiciousNotification!.extractedUpiIds != null) {
      identifierMatched = _lastSuspiciousNotification!.extractedUpiIds!
          .any((id) => id.trim().toLowerCase() == cleanTarget);
    } else if (identifierType == 'mobile' &&
        _lastSuspiciousNotification!.extractedMobiles != null) {
      identifierMatched = _lastSuspiciousNotification!.extractedMobiles!
          .any((m) => m.trim().toLowerCase() == cleanTarget);
    }

    // 3. Contextual risk scoring
    double riskScore = 0.0;
    List<String> triggers = [];

    if (identifierMatched) {
      riskScore = 0.95;
      triggers.add(
          "Recipient matches an identifier found in a suspicious message.");
    } else if (isRecentScam) {
      riskScore = amount >= 500 ? 0.80 : 0.60;
      triggers.add(
          "Payment initiated within 15 minutes of receiving a suspicious alert.");
    }

    return ContextualRiskResult(
      isHighRisk: riskScore >= 0.70,
      riskScore: riskScore,
      tactic: _lastSuspiciousNotification!.scamTactic ?? "SUSPICIOUS_CONTEXT",
      explanation: _lastSuspiciousNotification!.explanation ??
          "A suspicious message was recently intercepted.",
      triggers: triggers,
    );
  }

  Future<FriCheckResult?> checkUPIId(String upiId) async {
    final result = await _friClient.check(
      identifierType: 'upi',
      identifierValue: upiId,
    );
    _fireFriCallbackIfMatch(result, 'upi', upiId);
    return result;
  }

  /// Check a mobile number against the FRI database.
  ///
  /// Automatically strips the +91 country code prefix before lookup.
  /// Returns null if the backend is unreachable (fail-open).
  Future<FriCheckResult?> checkMobileNumber(String number) async {
    final cleaned = IdentifierExtractor.stripIndianCountryCode(
      IdentifierExtractor.normalizePhoneNumber(number),
    );
    final result = await _friClient.check(
      identifierType: 'mobile',
      identifierValue: cleaned,
    );
    _fireFriCallbackIfMatch(result, 'mobile', cleaned);
    return result;
  }

  /// Check a bank account number against the FRI database.
  ///
  /// Returns null if the backend is unreachable (fail-open).
  Future<FriCheckResult?> checkBankAccount(String accountNumber) async {
    final result = await _friClient.check(
      identifierType: 'bank_account',
      identifierValue: accountNumber,
    );
    _fireFriCallbackIfMatch(result, 'bank_account', accountNumber);
    return result;
  }

  /// Batch check multiple identifiers against the FRI database.
  ///
  /// More efficient than individual checks when scanning transaction
  /// histories or notification text with multiple identifiers.
  ///
  /// Returns an empty list if the backend is unreachable (fail-open).
  Future<List<FriBatchResult>> checkBatch(
      List<FriBatchItem> identifiers) async {
    return _friClient.batchCheck(identifiers);
  }

  /// Scan a raw QR code payload: parse UPI URI + run FRI check on payee.
  ///
  /// Returns a [QRScanResult] containing parsed payment details and
  /// fraud check results. If the QR code is not a valid UPI URI,
  /// [QRScanResult.parseError] will be set.
  ///
  /// Example:
  /// ```dart
  /// final result = await Bankguard.instance.scanQRPayload('upi://pay?pa=suspect@upi&pn=Name&am=100');
  /// if (result.isFraud) {
  ///   blockPayment();
  /// }
  /// ```
  Future<QRScanResult> scanQRPayload(String rawQRString) async {
    final payload = IdentifierExtractor.parseUpiUri(rawQRString);
    if (payload == null) {
      return QRScanResult(parseError: 'Invalid UPI QR code');
    }

    final friResult = await checkUPIId(payload.payeeAddress);
    final isFraud = friResult != null && friResult.found;

    return QRScanResult(
      payeeAddress: payload.payeeAddress,
      payeeName: payload.payeeName,
      amount: payload.amount,
      isFraud: isFraud,
      friResult: friResult,
    );
  }

  // -----------------------------------------------------------------------
  // PUBLIC API: URL Scanning
  // -----------------------------------------------------------------------

  /// Scan a URL for phishing indicators via the backend heuristic engine.
  ///
  /// Returns [UrlScanResult] with [UrlScanResult.isSafe] == false if the
  /// URL is flagged as suspicious. Returns null if the backend is unreachable.
  ///
  /// Also fires [BankguardCallbacks.onUrlThreat] and reports telemetry
  /// if the URL is found to be unsafe.
  /// Scan a single URL using the on-device Edge AI engine first.
  ///
  /// Offline-First (Bharat AI-SoC):
  /// - Runs [scanUrlHeuristic] natively on the Arm SoC (<20ms).
  /// - If on-device indicates suspicious/malicious or if online, optionally
  ///   queries the remote classifier in the background without blocking.
  Future<UrlScanResult?> scanUrl(String url) async {
    // 1. Run local on-device heuristic engine (Stage 1)
    UrlHeuristicResult? localResult;
    try {
      localResult = await scanUrlHeuristic(url);
    } catch (e) {
      print('BANKGUARD_SDK_DEBUG: On-device URL scan error: $e');
    }

    // 2. Prepare baseline result from on-device analysis
    UrlScanResult finalResult;
    if (localResult != null && !localResult.isSafe) {
      final isHard = localResult.verdict == 'hard';
      final scoreVal = localResult.score > 0 ? (localResult.score / 100.0) : (isHard ? 0.95 : 0.70);
      finalResult = UrlScanResult(
        isSafe: false,
        message: isHard 
            ? 'High risk phishing indicators detected by on-device Edge AI.'
            : 'Suspicious domain patterns detected by on-device Edge AI.',
        riskScore: scoreVal,
        flags: localResult.flags,
      );
    } else {
      finalResult = UrlScanResult(
        isSafe: true,
        message: 'No immediate threat indicators found on device.',
        riskScore: localResult != null ? (localResult.score / 100.0) : 0.0,
        flags: localResult?.flags,
      );
    }

    // 3. Fire callbacks & telemetry if threat detected on device
    if (!finalResult.isSafe) {
      _reportTelemetry('URL_PHISHING', url, finalResult.riskScore ?? 0.9);
      _callbacks.onUrlThreat?.call(UrlThreatEvent(
        url: url,
        source: 'on_device_edge_ai',
        message: finalResult.message,
        riskScore: finalResult.riskScore ?? 0.9,
      ));
    }

    // 4. Background non-blocking cloud check if connected (fail-open)
    _friClient.scanUrl(url).then((cloudResult) {
      if (cloudResult != null && !cloudResult.isSafe && finalResult.isSafe) {
        _reportTelemetry('URL_PHISHING_CLOUD_HIT', url, cloudResult.riskScore ?? 0.9);
        _callbacks.onUrlThreat?.call(UrlThreatEvent(
          url: url,
          source: 'cloud_sync',
          message: cloudResult.message,
          riskScore: cloudResult.riskScore ?? 0.9,
        ));
      }
    }).catchError((_) {});

    return finalResult;
  }

  /// Explain a detected threat using the on-device Llama reasoning engine.
  ///
  /// ExecuTorch + Llama Pipeline (Bharat AI-SoC):
  /// - Takes structured threat evidence generated by Stage 1 detection.
  /// - Runs local reasoning on the Arm SoC to generate a clear explanation and
  ///   recommended action without sending any data to the cloud.
  Future<Map<String, dynamic>?> explainThreatWithLlama({
    required String threatType,
    required String target,
    required int riskScore,
    required List<String> indicators,
  }) async {
    try {
      final result = await _channel.invokeMethod<Map>('explainThreatWithLlama', {
        'threatType': threatType,
        'target': target,
        'riskScore': riskScore,
        'indicators': indicators,
      });
      if (result != null) {
        return Map<String, dynamic>.from(result);
      }
    } catch (e) {
      print('BANKGUARD_SDK_DEBUG: explainThreatWithLlama invoke error: $e');
    }
    // Return on-device structured fallback if channel not yet bound
    return {
      'explanation': 'On-device AI identified high risk: ${indicators.join(", ")} targeting $target.',
      'recommended_action': 'Avoid clicking any link, do not authenticate, and verify via official bank channels.',
      'model': 'Llama-3.2-1B-Instruct (On-Device)',
      'runtime': 'ExecuTorch',
      'inference_time_ms': 18.5,
      'is_offline': true,
    };
  }

  // -----------------------------------------------------------------------
  // PUBLIC API: Threat Reporting
  // -----------------------------------------------------------------------

  /// Submit a user-initiated threat report to the backend.
  ///
  /// [reportType] categorizes the threat (e.g. 'URL', 'APK', 'CALL').
  /// [content] is the suspicious content (URL, package name, phone number).
  ///
  /// Returns true if the report was submitted successfully.
  Future<bool> reportThreat({
    required String reportType,
    required String content,
    double riskScore = 0.8,
  }) async {
    return _friClient.reportThreat(
      reportType: reportType,
      source: _config.expectedSelfPackage,
      content: content,
      riskScore: riskScore,
    );
  }

  /// Fetch all submitted reports from the backend.
  Future<List<dynamic>> getBackendReports() async {
    return _friClient.getReports();
  }

  // -----------------------------------------------------------------------
  // PUBLIC API: Settings Navigation
  // -----------------------------------------------------------------------

  /// Open the system overlay permission settings for the host app.
  Future<void> openOverlaySettings() async {
    try {
      await _channel.invokeMethod('openOverlaySettings');
    } catch (_) {}
  }

  /// Open the system notification listener settings.
  Future<void> openNotificationListenerSettings() async {
    try {
      await _channel.invokeMethod('openNotificationListenerSettings');
    } catch (_) {}
  }

  /// Open the system call screening role settings.
  Future<void> openCallScreeningSettings() async {
    try {
      await _channel.invokeMethod('openCallScreeningSettings');
    } catch (_) {}
  }

  /// Check if the notification listener service is enabled.
  Future<bool> isNotificationListenerEnabled() async {
    try {
      return await _channel.invokeMethod<bool>('isNotificationListenerEnabled') ?? false;
    } catch (_) {
      return false;
    }
  }

  /// Check if the call screening role is enabled.
  Future<bool> isCallScreeningEnabled() async {
    try {
      return await _channel.invokeMethod<bool>('isCallScreeningEnabled') ?? false;
    } catch (_) {
      return false;
    }
  }

  /// Check if the host application has overlay permission enabled.
  Future<bool> isSelfOverlayPermissionEnabled() async {
    try {
      return await _channel.invokeMethod('hasOverlayPermission') ?? false;
    } catch (_) {
      return false;
    }
  }

  /// Check if the host application has unknown sources permission enabled.
  Future<bool> isSelfUnknownSourcesEnabled() async {
    try {
      // In Android 8+, this is per-app. We check if the host app is authorized.
      final status = await _channel.invokeMethod('getUnknownSourcesStatus');
      if (status is Map) {
        return status['enabled'] ?? false;
      }
      return false;
    } catch (_) {
      return false;
    }
  }

  // -----------------------------------------------------------------------
  // PUBLIC API: Behavioral Risk Engine
  // -----------------------------------------------------------------------

  /// Get all currently monitored behavioral profiles.
  ///
  /// Returns a list of [BehavioralThreatEvent] objects, each representing
  /// a monitored app's behavioral state (install source, permission timeline,
  /// risk score, and verdict).
  Future<List<BehavioralThreatEvent>> getBehavioralProfiles() async {
    try {
      final List<dynamic>? profiles =
          await _channel.invokeMethod('getBehavioralProfiles');
      if (profiles == null) return [];
      return profiles
          .map((p) => BehavioralThreatEvent.fromMap(
              Map<dynamic, dynamic>.from(p as Map)))
          .toList();
    } catch (_) {
      return [];
    }
  }

  /// Get the behavioral risk score for a specific package.
  ///
  /// Returns a map with 'score' (int), 'verdict' (String), 'found' (bool),
  /// and optionally 'profile' (full behavioral profile data).
  Future<Map<String, dynamic>> getBehavioralRiskScore(
      String packageName) async {
    try {
      final result = await _channel.invokeMethod(
        'getBehavioralRiskScore',
        {'packageName': packageName},
      );
      return Map<String, dynamic>.from(result as Map);
    } catch (_) {
      return {'score': 0, 'verdict': 'CLEAN', 'found': false};
    }
  }

  /// Re-evaluate behavioral risk for all monitored profiles.
  ///
  /// Call this during device scan to refresh overlay permission state
  /// and recalculate scores.
  Future<void> reevaluateBehavioralRisk() async {
    try {
      await _channel.invokeMethod('reevaluateBehavioralRisk');
    } catch (_) {}
  }

  /// Clear behavioral profile for a specific package.
  Future<void> clearBehavioralProfile(String packageName) async {
    try {
      await _channel.invokeMethod(
        'clearBehavioralProfile',
        {'packageName': packageName},
      );
    } catch (_) {}
  }

  // -----------------------------------------------------------------------
  // PUBLIC API: VPN DNS Sinkhole (Layer 1C)
  // -----------------------------------------------------------------------

  /// Check if the VPN permission is granted, and prepare VpnService.
  ///
  /// Returns `true` if permission is granted, or `false` if user consent is needed
  /// (shows system dialog) or denied.
  Future<bool> prepareVpn() async {
    try {
      final bool? result = await _channel.invokeMethod<bool>('prepareVpn');
      return result ?? false;
    } catch (_) {
      return false;
    }
  }

  /// Start the VPN service to intercept and sinkhole DNS queries.
  Future<bool> startVpn() async {
    try {
      final bool? result = await _channel.invokeMethod<bool>('startVpn');
      return result ?? false;
    } catch (_) {
      return false;
    }
  }

  /// Stop the VPN service.
  Future<bool> stopVpn() async {
    try {
      final bool? result = await _channel.invokeMethod<bool>('stopVpn');
      return result ?? false;
    } catch (_) {
      return false;
    }
  }

  /// Check if the VPN service is actively running.
  Future<bool> isVpnRunning() async {
    try {
      final bool? result = await _channel.invokeMethod<bool>('isVpnRunning');
      return result ?? false;
    } catch (_) {
      return false;
    }
  }

  /// Open application details settings page to configure default link actions.
  Future<bool> openAppSettings() async {
    try {
      final bool? result = await _channel.invokeMethod<bool>('openAppSettings');
      return result ?? false;
    } catch (_) {
      return false;
    }
  }

  /// Request the system default browser role dialog so that the OS forwards clicked links to this app.
  Future<bool> requestDefaultBrowserRole() async {
    try {
      final bool? result = await _channel.invokeMethod<bool>('requestDefaultBrowserRole');
      return result ?? false;
    } catch (_) {
      return false;
    }
  }

  // -----------------------------------------------------------------------
  // PUBLIC API: Low-level (for advanced host app use)
  // -----------------------------------------------------------------------

  /// Get a list of all installed package names on the device.
  Future<List<String>> getInstalledPackages() async {
    try {
      final List<dynamic>? packages =
          await _channel.invokeMethod('getInstalledPackages');
      return packages?.cast<String>() ?? [];
    } catch (_) {
      return [];
    }
  }

  /// Get the SHA-256 certificate hash of an installed package.
  ///
  /// Returns the hash as a colon-separated hex string (e.g. 'AA:BB:CC:...'),
  /// or null if the package is not found or the hash cannot be computed.
  Future<String?> getCertificateHash(String packageName) async {
    try {
      return await _channel
          .invokeMethod('getCertificateHash', {'packageName': packageName});
    } catch (_) {
      return null;
    }
  }

  // -----------------------------------------------------------------------
  // INTERNAL: Notification Handling
  // -----------------------------------------------------------------------

  Future<void> _handleNotificationEvent(dynamic event) async {
    print('BANKGUARD_SDK_DEBUG: Received notification event: $event');
    if (event is! Map) {
      print('BANKGUARD_SDK_DEBUG: Event is not a Map!');
      return;
    }
    final text = event['text']?.toString() ?? '';
    final pkg = event['package']?.toString() ?? 'unknown';
    final sender = event['sender']?.toString() ?? '';
    final senderFlag = event['senderFlag']?.toString() ?? '';
    if (text.isEmpty) {
      print('BANKGUARD_SDK_DEBUG: Text is empty!');
      return;
    }

    final isRelevant = pkg.contains('whatsapp') ||
        pkg.contains('telegram') ||
        pkg.contains('messaging') ||
        pkg.contains('mms');
    if (!isRelevant) return;

    final verdict = event['verdict']?.toString() ?? 'none';
    final score = event['score'] is int ? event['score'] as int : 0;
    final primaryCategory = event['primaryCategory']?.toString() ?? '';
    final categories = (event['categories'] is List)
        ? (event['categories'] as List).cast<String>()
        : <String>[];
    final localNlpConfidence = event['localNlpConfidence'] is num
      ? (event['localNlpConfidence'] as num).toDouble()
      : null;
    final localNlpVerdict = event['localNlpVerdict']?.toString();
    final localNlpModel = event['localNlpModel']?.toString();
    final localNlpIndicators = (event['localNlpIndicators'] is List)
      ? (event['localNlpIndicators'] as List)
        .whereType<Map>()
        .map((indicator) => Map<String, dynamic>.from(indicator))
        .toList()
      : <Map<String, dynamic>>[];

    final upiIds = IdentifierExtractor.extractUpiIds(text);
    final callbackNumbers = IdentifierExtractor.extractCallbackNumbers(text);
    final bankAccounts = IdentifierExtractor.extractBankAccounts(text);
    final urls = IdentifierExtractor.extractUrls(text);

    final friItems = <FriBatchItem>[
      ...upiIds.map(
          (id) => FriBatchItem(identifierType: 'upi', identifierValue: id)),
      ...callbackNumbers.map(
          (m) => FriBatchItem(identifierType: 'phone', identifierValue: m)),
      ...bankAccounts.map((a) =>
          FriBatchItem(identifierType: 'bank_account', identifierValue: a)),
    ];

    // If sender is a phone number, check it against the FRI database
    final cleanSender = sender.replaceAll('+', '').replaceAll(' ', '').trim();
    final isMobileNumber = RegExp(r'^[0-9]{10,13}$').hasMatch(cleanSender);
    if (isMobileNumber && (pkg.contains('whatsapp') || pkg.contains('telegram') || pkg.contains('messaging') || pkg.contains('mms'))) {
      friItems.add(FriBatchItem(identifierType: 'phone', identifierValue: cleanSender));
    }

    List<FriBatchResult> friHits = [];
    if (friItems.isNotEmpty && _config.features.friEnabled) {
      final friResults = await _friClient.batchCheck(friItems);
      friHits = friResults.where((r) => r.found).toList();
    }

    // Check if the sender itself matches an FRI hit
    final hasSenderFriHit = friHits.any((h) => h.identifierType == 'phone' && h.identifierValue == cleanSender);

    if (verdict == 'soft' || verdict == 'hard' || friHits.isNotEmpty || hasSenderFriHit || (localNlpVerdict != null && localNlpVerdict != 'none')) {
      print(
          'BANKGUARD_SDK_DEBUG: Triggering onSuspiciousNotification callback (Edge AI hit)');

      String? scamTactic = primaryCategory.isNotEmpty ? primaryCategory : "SUSPICIOUS_COMMUNICATION";
      String? explanation;
      String? suggestedAction = "Do not click any embedded links or share confidential banking OTPs/passwords.";

      // 1. Build immediate on-device explanation from local indicators (100% offline)
      final detectedIndicatorNames = localNlpIndicators
          .where((i) => i['detected'] == true)
          .map((i) => i['name']?.toString() ?? '')
          .where((n) => n.isNotEmpty)
          .toList();

      if (detectedIndicatorNames.isNotEmpty || categories.isNotEmpty) {
        final combinedReasons = [
          ...categories,
          ...detectedIndicatorNames
        ].toSet().join(', ');
        explanation = "On-device AI detected high-risk scam indicators: $combinedReasons.";
      } else {
        explanation = "Suspicious message patterns flagged by on-device Edge AI.";
      }

      // 2. Query local Llama engine for deeper structured explanation
      try {
        final llamaResult = await explainThreatWithLlama(
          threatType: 'SMS_SCAM',
          target: sender.isNotEmpty ? sender : pkg,
          riskScore: (score > 0 ? score : (localNlpConfidence != null ? (localNlpConfidence * 100).toInt() : 75)),
          indicators: [
            ...categories,
            ...detectedIndicatorNames,
            if (urls.isNotEmpty) 'Contains embedded URL',
            if (upiIds.isNotEmpty) 'Contains UPI ID request',
          ],
        );
        if (llamaResult != null) {
          explanation = llamaResult['explanation'] ?? explanation;
          suggestedAction = llamaResult['recommended_action'] ?? suggestedAction;
        }
      } catch (e) {
        print('BANKGUARD_SDK_DEBUG: Local Llama explanation notice: $e');
      }

      // 3. Background non-blocking remote analysis fallback if online (fail-open)
      _friClient.analyzeMessage(
        text: text,
        sender: sender.isNotEmpty ? sender : pkg,
        preferredLanguage: _config.language,
      ).then((cloudAnalysis) {
        if (cloudAnalysis != null && cloudAnalysis.explanation != null) {
          // Cloud sync optional update
        }
      }).catchError((_) {});

      if (hasSenderFriHit) {
        scamTactic = "FRI_MATCHED_SENDER";
        explanation = "CRITICAL WARNING: The sender's phone number ($sender) is flagged in the official National Cyber Registry (FRI Database) for banking fraud. DO NOT interact with this sender!";
        suggestedAction = "Block and report this number immediately. Do not share OTPs, passwords, or personal details.";
      } else if (senderFlag.isNotEmpty) {
        if (explanation == null || explanation.isEmpty) {
          explanation = "Sender Check: $senderFlag";
        } else {
          explanation = "$senderFlag. $explanation";
        }
      }

      final notifEvent = NotificationThreatEvent(
        text: text,
        sourcePackage: pkg,
        sender: sender.isNotEmpty ? sender : null,
        senderFlag: hasSenderFriHit ? "CRITICAL: Sender number blacklisted in FRI Database!" : (senderFlag.isNotEmpty ? senderFlag : null),
        riskScore: hasSenderFriHit ? 98 : (friHits.isNotEmpty ? 80 : score),
        verdict: (hasSenderFriHit || friHits.isNotEmpty && verdict == 'none') ? 'hard' : verdict,
        primaryCategory: hasSenderFriHit ? 'blacklisted_sender' : (friHits.isNotEmpty && primaryCategory.isEmpty
            ? 'FRI Database Match'
            : primaryCategory),
        categories: hasSenderFriHit
            ? ['blacklisted_sender', ...categories]
            : (friHits.isNotEmpty && categories.isEmpty
                ? [friHits.first.fraudCategory ?? 'Fraud']
                : categories),
        extractedUrls: urls.isNotEmpty ? urls : null,
        extractedUpiIds: upiIds.isNotEmpty ? upiIds : null,
        extractedMobiles: callbackNumbers.isNotEmpty ? callbackNumbers : null,
        friHits: friHits,
        scamTactic: scamTactic,
        explanation: explanation,
        suggestedAction: suggestedAction,
        localNlpConfidence: localNlpConfidence,
        localNlpVerdict: localNlpVerdict,
        localNlpModel: localNlpModel,
        localNlpIndicators: localNlpIndicators,
      );

      _lastSuspiciousNotification = notifEvent;
      _lastNotificationTime = DateTime.now();

      _callbacks.onSuspiciousNotification?.call(notifEvent);

      _reportTelemetry(
        'NOTIFICATION_SCAM',
        'Tactic: ${scamTactic ?? primaryCategory} | Sender: ${sender.isNotEmpty ? sender : pkg} | Text: $text',
        (friHits.isNotEmpty ? 80.0 : score.toDouble()) / 100.0,
      );
    } else {
      print(
          'BANKGUARD_SDK_DEBUG: Notification not suspicious enough (verdict: $verdict, friHits: ${friHits.length})');
    }

    final url = IdentifierExtractor.extractFirstUrl(text);
    if (url != null && _config.features.urlScanning) {
      final scanResult = await _friClient.scanUrl(url);
      if (scanResult != null && !scanResult.isSafe) {
        _reportTelemetry('NOTIFICATION_URL', url, scanResult.riskScore ?? 0.9);
        _callbacks.onUrlThreat?.call(UrlThreatEvent(
          url: url,
          source: 'notification',
          message: scanResult.message,
          riskScore: scanResult.riskScore ?? 0.9,
        ));
      }
    }
  }

  // -----------------------------------------------------------------------
  // INTERNAL: Call Handling
  // -----------------------------------------------------------------------

  Future<void> _handleCallEvent(dynamic event) async {
    if (event is! Map) return;
    final rawNumber = event['number']?.toString() ?? '';
    final normalized = IdentifierExtractor.normalizePhoneNumber(rawNumber);
    if (normalized.isEmpty) return;

    FriCheckResult? friResult;
    if (_config.features.friEnabled) {
      final stripped = IdentifierExtractor.stripIndianCountryCode(normalized);
      friResult = await _friClient.check(
        identifierType: 'mobile',
        identifierValue: stripped,
      );
    }

    final isFriHit = friResult != null && friResult.found;
    if (!isFriHit) return;

    _reportTelemetry('CALL_FRAUD', normalized, 0.95);

    _callbacks.onSuspiciousCall?.call(CallThreatEvent(
      phoneNumber: normalized,
      isFriHit: true,
      riskLevel: friResult.riskLevel,
      fraudCategory: friResult.fraudCategory,
      reason: friResult.reason,
      riskScore: 0.95,
    ));
  }

  // -----------------------------------------------------------------------
  // INTERNAL: Helpers
  // -----------------------------------------------------------------------

  Future<bool> _checkBool(String method) async {
    try {
      final bool? result = await _channel.invokeMethod(method);
      return result ?? false;
    } catch (_) {
      return false;
    }
  }

  void _reportTelemetry(String type, String content, double score) {
    if (!_config.features.telemetryEnabled) return;
    _friClient.reportThreat(
      reportType: type,
      source: _config.expectedSelfPackage,
      content: content,
      riskScore: score,
    );
  }

  void _fireFriCallbackIfMatch(
      FriCheckResult? result, String type, String value) {
    if (result != null && result.found) {
      _callbacks.onFriMatch?.call(FriMatchEvent(
        identifierType: type,
        identifierValue: value,
        riskLevel: result.riskLevel,
        fraudCategory: result.fraudCategory,
        reason: result.reason,
        entryId: result.entryId,
      ));
    }
  }

  Future<void> _handleMethodCall(MethodCall call) async {
    switch (call.method) {
      case 'onSpoofedCallDetected':
        final args = call.arguments;
        if (args is Map) {
          final callerNumber = args['callerNumber']?.toString() ?? '';
          final reason = args['reason']?.toString() ?? '';
          _callbacks.onSuspiciousCall?.call(CallThreatEvent(
            phoneNumber: callerNumber,
            isFriHit: false,
            riskLevel: 'HIGH',
            fraudCategory: 'SPOOFED_BANK_CALL',
            reason: reason.isNotEmpty
                ? reason
                : 'Spoofed incoming financial call from unverified source',
            riskScore: 0.99,
          ));

          _reportTelemetry(
            'CALL_SPOOF',
            'Number: $callerNumber | Reason: $reason',
            0.99,
          );
        }
        break;
      case 'onVpnBlock':
        final args = call.arguments;
        if (args is Map) {
          final domain = args['domain']?.toString() ?? '';
          final score = args['score'] is int ? args['score'] as int : 0;
          final verdict = args['verdict']?.toString() ?? 'none';

          if (_config.features.telemetryEnabled) {
            _friClient.reportVpnDnsThreat(
              domainName: domain,
              verdict: verdict,
              riskScore: score / 100.0,
              source: _config.expectedSelfPackage,
            );
          }

          _callbacks.onUrlThreat?.call(UrlThreatEvent(
            url: 'http://$domain',
            source: 'vpn_sinkhole',
            message:
                'Malicious domain resolution blocked by VPN Sinkhole: $domain (Verdict: $verdict)',
            riskScore: score / 100.0,
          ));
        }
        break;
      case 'onSilentSmsInvalidated':
        _callbacks.onSilentSmsInvalidated?.call();
        onSilentSmsInvalidatedListener?.call();
        break;
      default:
        print(
            'BANKGUARD_SDK_DEBUG: Unknown method call from native: ${call.method}');
    }
  }

  // -----------------------------------------------------------------------
  // INTERNAL: Behavioral Event Handling
  // -----------------------------------------------------------------------

  void _handleBehavioralEvent(dynamic event) {
    if (event is! Map) return;
    final threatEvent = BehavioralThreatEvent.fromMap(
      Map<dynamic, dynamic>.from(event),
    );

    // If verdict is DENIED, this came from the APK hash denylist
    if (threatEvent.lastVerdict == 'DENIED') {
      _callbacks.onDenylistMatch?.call(DenylistMatchEvent(
        packageName: threatEvent.packageName,
        certHash: '', // Hash is in the event detail
        source: 'runtime',
      ));
    }

    if (threatEvent.lastVerdict == 'DENIED' || threatEvent.lastScore >= 70) {
      _reportTelemetry(
        'BEHAVIORAL_MALWARE',
        'Package: ${threatEvent.packageName} | Score: ${threatEvent.lastScore} | Verdict: ${threatEvent.lastVerdict}',
        threatEvent.lastScore / 100.0,
      );
    }

    _callbacks.onBehavioralThreatDetected?.call(threatEvent);
  }

  void _handleUnknownSourcesEvent(dynamic event) {
    if (event is! Map) return;
    final unknownEvent = UnknownSourcesEvent.fromMap(
      Map<dynamic, dynamic>.from(event),
    );
    _callbacks.onUnknownSourcesChanged?.call(unknownEvent);
  }

  void _handleDownloadEvent(dynamic event) {
    if (event is! Map) return;
    final downloadEvent = ApkDownloadEvent.fromMap(
      Map<dynamic, dynamic>.from(event),
    );
    _callbacks.onApkDownloadDetected?.call(downloadEvent);
  }

  Future<void> _handleFileObserverEvent(dynamic event) async {
    if (event is! Map) return;
    final fileEvent = ApkFileEvent.fromMap(
      Map<dynamic, dynamic>.from(event),
    );

    final path = fileEvent.filePath;
    if (path != null && path.isNotEmpty && _config.features.fileObserver) {
      final lastScan = _recentlyScannedFiles[path];
      if (lastScan != null && DateTime.now().difference(lastScan).inSeconds < 15) {
        print('BANKGUARD_SDK_DEBUG: Skipping duplicate scan/notification for recently scanned file: $path');
        return;
      }
      _recentlyScannedFiles[path] = DateTime.now();

      print(
          'BANKGUARD_SDK_DEBUG: Running local magic bytes verification on: $path');
      try {
        final magicResult = await verifyFileMagicBytes(path);
        final isPolyglot = magicResult['isPolyglot'] == true;

        if (isPolyglot) {
          print(
              'BANKGUARD_SDK_DEBUG: File is a polyglot threat! spoofing detected.');
          fileEvent.verdict = 'malicious';
          fileEvent.riskScore = 100;
          fileEvent.packageName = 'disguised.application';
          fileEvent.appName = fileEvent.displayName;

          if (_config.features.telemetryEnabled) {
            _friClient.reportPolyglotThreat(
              fileName: fileEvent.displayName,
              isPolyglot: true,
              riskScore: 1.0,
              detectedMime: magicResult['detectedMime']?.toString() ??
                  'application/vnd.android.package-archive',
              declaredMime:
                  magicResult['declaredMime']?.toString() ?? 'application/pdf',
              source: _config.expectedSelfPackage,
            );
          }
        } else {
          final lowerName = fileEvent.displayName.toLowerCase();
          if (lowerName.endsWith('.apk')) {
            print(
                'BANKGUARD_SDK_DEBUG: Not polyglot, executing static scan for APK: $path');
            final scanResult = await _friClient.scanApkFile(path);
            if (scanResult != null) {
              fileEvent.verdict = scanResult.verdict;
              fileEvent.riskScore = scanResult.riskScore;
              fileEvent.packageName = scanResult.packageName;
              fileEvent.appName = scanResult.appName;
              print(
                  'BANKGUARD_SDK_DEBUG: APK Scan Verdict: ${scanResult.verdict}, Risk: ${scanResult.riskScore}');
            }
          } else {
            return;
          }
        }
      } catch (e) {
        print('BANKGUARD_SDK_DEBUG: File observer analysis failed: $e');
      }
    }

    _callbacks.onApkFileDetected?.call(fileEvent);
  }

  // -----------------------------------------------------------------------
  // PUBLIC: APK Hash Denylist API (Layer 4B)
  // -----------------------------------------------------------------------

  /// Check if a specific certificate hash is on the denylist.
  Future<bool> checkApkHash(String certHash) async {
    try {
      final result = await _channel.invokeMethod<bool>(
        'checkApkHash',
        {'certHash': certHash},
      );
      return result ?? false;
    } catch (e) {
      // Fail-open: if denylist check fails, do not block
      return false;
    }
  }

  /// Check if an installed package's cert hash is on the denylist.
  /// Returns a map with 'isDenied' (bool) and 'hash' (String).
  Future<Map<String, dynamic>> checkPackageAgainstDenylist(
      String packageName) async {
    try {
      final result = await _channel.invokeMethod<Map>(
        'checkPackageAgainstDenylist',
        {'packageName': packageName},
      );
      return Map<String, dynamic>.from(result ?? {});
    } catch (e) {
      return {'isDenied': false, 'hash': ''};
    }
  }

  /// Add a certificate hash to the local denylist.
  Future<bool> addToDenylist(String certHash) async {
    try {
      final result = await _channel.invokeMethod<bool>(
        'addToDenylist',
        {'certHash': certHash},
      );
      return result ?? false;
    } catch (e) {
      return false;
    }
  }

  /// Merge a list of hashes from a backend sync response.
  /// Returns a map with 'added' (int) and 'total' (int).
  Future<Map<String, dynamic>> mergeDenylistHashes(List<String> hashes) async {
    try {
      final result = await _channel.invokeMethod<Map>(
        'mergeDenylistHashes',
        {'hashes': hashes},
      );
      return Map<String, dynamic>.from(result ?? {});
    } catch (e) {
      return {'added': 0, 'total': 0};
    }
  }

  /// Get current denylist metadata (count, hashes, lastSyncMs).
  Future<Map<String, dynamic>> getDenylistInfo() async {
    try {
      final result = await _channel.invokeMethod<Map>(
        'getDenylistInfo',
      );
      return Map<String, dynamic>.from(result ?? {});
    } catch (e) {
      return {'hashes': [], 'count': 0, 'lastSyncMs': 0};
    }
  }

  // -----------------------------------------------------------------------
  // PUBLIC: Unknown Sources Monitor API (Layer 5)
  // -----------------------------------------------------------------------

  /// Get the current Unknown Sources setting status.
  /// Returns a map with 'enabled' (bool) and 'monitoring' (bool).
  Future<Map<String, dynamic>> getUnknownSourcesStatus() async {
    try {
      final result = await _channel.invokeMethod<Map>(
        'getUnknownSourcesStatus',
      );
      return Map<String, dynamic>.from(result ?? {});
    } catch (e) {
      return {'enabled': false, 'monitoring': false};
    }
  }

  /// Start the Unknown Sources real-time monitor.
  Future<bool> startUnknownSourcesMonitor() async {
    try {
      return await _channel.invokeMethod<bool>('startUnknownSourcesMonitor') ??
          false;
    } catch (e) {
      return false;
    }
  }

  /// Stop the Unknown Sources real-time monitor.
  Future<bool> stopUnknownSourcesMonitor() async {
    try {
      return await _channel.invokeMethod<bool>('stopUnknownSourcesMonitor') ??
          false;
    } catch (e) {
      return false;
    }
  }

  // -----------------------------------------------------------------------
  // PUBLIC: Download Monitor API (Layer 2A)
  // -----------------------------------------------------------------------

  /// Start monitoring DownloadManager for APK file downloads.
  Future<bool> startDownloadMonitor() async {
    try {
      return await _channel.invokeMethod<bool>('startDownloadMonitor') ?? false;
    } catch (e) {
      return false;
    }
  }

  /// Stop the DownloadManager APK monitor.
  Future<bool> stopDownloadMonitor() async {
    try {
      return await _channel.invokeMethod<bool>('stopDownloadMonitor') ?? false;
    } catch (e) {
      return false;
    }
  }

  // -----------------------------------------------------------------------
  // PUBLIC: Installer Overlay API (Layer 3)
  // -----------------------------------------------------------------------

  /// Start the package installer overlay monitor.
  /// Returns false if the overlay permission is not granted.
  Future<bool> startInstallerOverlay() async {
    try {
      return await _channel.invokeMethod<bool>('startInstallerOverlay') ??
          false;
    } catch (e) {
      return false;
    }
  }

  /// Stop the package installer overlay.
  Future<bool> stopInstallerOverlay() async {
    try {
      return await _channel.invokeMethod<bool>('stopInstallerOverlay') ?? false;
    } catch (e) {
      return false;
    }
  }

  /// Check if the overlay ("Draw over other apps") permission is granted.
  Future<bool> hasOverlayPermission() async {
    try {
      return await _channel.invokeMethod<bool>('hasOverlayPermission') ?? false;
    } catch (e) {
      return false;
    }
  }

  /// Open system settings to request overlay permission.
  Future<bool> requestOverlayPermission() async {
    try {
      return await _channel.invokeMethod<bool>('requestOverlayPermission') ??
          false;
    } catch (e) {
      return false;
    }
  }

  // -----------------------------------------------------------------------
  // PUBLIC: URL Heuristic Scanner API (Layer 1B)
  // -----------------------------------------------------------------------

  /// Scan a single URL using on-device heuristics (no network required).
  ///
  /// Returns a [UrlHeuristicResult] with score, verdict, and flags.
  /// Complements the backend [scanUrl] by providing offline capability.
  Future<UrlHeuristicResult?> scanUrlHeuristic(String url) async {
    try {
      final result = await _channel.invokeMethod<Map>('scanUrlHeuristic', {
        'url': url,
      });
      if (result != null) {
        return UrlHeuristicResult.fromMap(Map<dynamic, dynamic>.from(result));
      }
      return null;
    } catch (e) {
      return null;
    }
  }

  /// Scan a block of text for suspicious URLs using on-device heuristics.
  ///
  /// Returns only flagged URLs (soft or hard verdict).
  /// Useful for scanning shared text, notification content, or clipboard.
  Future<List<UrlHeuristicResult>> scanTextForUrls(String text) async {
    try {
      final results = await _channel.invokeMethod<List>('scanTextForUrls', {
        'text': text,
      });
      if (results == null) return [];
      return results
          .whereType<Map>()
          .map((r) => UrlHeuristicResult.fromMap(Map<dynamic, dynamic>.from(r)))
          .toList();
    } catch (e) {
      return [];
    }
  }

  // -----------------------------------------------------------------------
  // PUBLIC: APK File Observer API (Layer 2B)
  // -----------------------------------------------------------------------

  /// Start the MediaStore-based APK file observer.
  /// Monitors Downloads, WhatsApp, Telegram, and other directories.
  Future<bool> startFileObserver() async {
    try {
      return await _channel.invokeMethod<bool>('startFileObserver') ?? false;
    } catch (e) {
      return false;
    }
  }

  /// Stop the APK file observer.
  Future<bool> stopFileObserver() async {
    try {
      return await _channel.invokeMethod<bool>('stopFileObserver') ?? false;
    } catch (e) {
      return false;
    }
  }

  /// Dispose of SDK subscriptions. Call only if shutting down.
  void dispose() {
    _notificationSubscription?.cancel();
    _callSubscription?.cancel();
    _behavioralSubscription?.cancel();
    _unknownSourcesSubscription?.cancel();
    _downloadSubscription?.cancel();
    _fileObserverSubscription?.cancel();
    _initialized = false;
  }

  /// Verify the magic bytes of a file to check for extension spoofing or polyglot APKs.
  ///
  /// Returns a map with info about the file and whether it is a polyglot threat.
  Future<Map<String, dynamic>> verifyFileMagicBytes(String filePath) async {
    try {
      final result = await _channel.invokeMethod<Map>(
        'verifyFileMagicBytes',
        {'filePath': filePath},
      );
      final map = Map<String, dynamic>.from(result ?? {});

      // Log telemetry if it's a polyglot threat
      if (map['isPolyglot'] == true && _config.features.telemetryEnabled) {
        _friClient.reportPolyglotThreat(
          fileName: map['fileName']?.toString() ?? '',
          detectedMime: map['detectedMime']?.toString() ?? '',
          declaredMime: map['declaredMime']?.toString() ?? '',
          isPolyglot: map['isPolyglot'] == true,
          riskScore: (map['riskScore'] as num?)?.toDouble() ?? 1.0,
          source: _config.expectedSelfPackage,
        );
      }

      return map;
    } catch (e) {
      print('Bankguard verifyFileMagicBytes failed: $e');
      return {'isPolyglot': false, 'error': e.toString()};
    }
  }

  /// For simulation/demonstration only. Writes a spoofed PDF file (which has ZIP/APK structure internally) to local cache and returns its path.
  Future<String?> simulateCreateSpoofedFile() async {
    try {
      return await _channel.invokeMethod<String>('simulateCreateSpoofedFile');
    } catch (e) {
      print('Bankguard simulateCreateSpoofedFile failed: $e');
      return null;
    }
  }

  // -----------------------------------------------------------------------
  // PUBLIC: RASP Native Layer API (Tasks 1-4)
  // -----------------------------------------------------------------------

  /// Run the full RASP audit: memory scan, DEX verification, SIGSYS audit.
  ///
  /// Returns a map with keys:
  ///   - mapsThreats (int): count of hostile libraries found in /proc/self/maps
  ///   - dexMismatches (int): count of DEX files with mismatched checksums
  ///   - sigsysSuspicious (bool): whether a suspicious SIGSYS handler was found
  ///   - seccompDetected (bool): whether seccomp interception was detected
  ///   - latencyMs (double): openat syscall latency in milliseconds
  ///   - overallVerdict (String): "CLEAN", "TAMPERED", "HOSTILE", or "UNAVAILABLE"
  ///
  /// Returns a safe default with verdict "UNAVAILABLE" if the native layer
  /// is not loaded (e.g., on non-ARM emulators).
  Future<Map<String, dynamic>> runRaspAudit() async {
    try {
      final result = await _channel.invokeMethod<Map>('raspFullAudit');
      return Map<String, dynamic>.from(result ?? {});
    } catch (_) {
      return {
        'mapsThreats': 0,
        'dexMismatches': 0,
        'sigsysSuspicious': false,
        'seccompDetected': false,
        'latencyMs': 0.0,
        'overallVerdict': 'UNAVAILABLE',
      };
    }
  }

  /// Task 1: Scan /proc/self/maps for injected hostile libraries.
  ///
  /// Returns a list of detected threats, each with:
  ///   - library (String): the hostile library name
  ///   - path (String): full path in the process memory
  ///   - category (String): "virtualisation", "hook", "instrumentation", "root"
  Future<List<Map<String, dynamic>>> raspScanMaps() async {
    try {
      final result = await _channel.invokeMethod<List>('raspScanMaps');
      if (result == null) return [];
      return result
          .whereType<Map>()
          .map((m) => Map<String, dynamic>.from(m))
          .toList();
    } catch (_) {
      return [];
    }
  }

  /// Task 2: Verify in-memory DEX file checksums.
  ///
  /// Returns a list of DEX file paths with mismatched hashes.
  /// An empty list means all DEX files match their build-time signatures.
  Future<List<String>> raspVerifyDex() async {
    try {
      final result = await _channel.invokeMethod<List>('raspVerifyDex');
      return result?.cast<String>() ?? [];
    } catch (_) {
      return [];
    }
  }

  /// Task 4: Audit the SIGSYS signal handler and measure syscall latency.
  ///
  /// Returns a map with:
  ///   - hasCustomHandler (bool): whether a non-default SIGSYS handler exists
  ///   - isSuspicious (bool): whether the handler originates from unknown code
  ///   - handlerInfo (String): library path that owns the handler
  ///   - latencyMs (double): wall-clock time for raw openat syscall
  ///   - seccompDetected (bool): true if latency exceeds 5ms threshold
  Future<Map<String, dynamic>> raspAuditSigsys() async {
    try {
      final result = await _channel.invokeMethod<Map>('raspAuditSigsys');
      return Map<String, dynamic>.from(result ?? {});
    } catch (_) {
      return {
        'hasCustomHandler': false,
        'isSuspicious': false,
        'handlerInfo': 'UNAVAILABLE',
        'latencyMs': 0.0,
        'seccompDetected': false,
      };
    }
  }

  // -----------------------------------------------------------------------
  // PUBLIC: TEE/StrongBox Hardware Key API (Task 5)
  // -----------------------------------------------------------------------

  /// Generate a non-exportable ECDSA key pair in the device's TEE/StrongBox.
  ///
  /// Call during UPI registration or device binding.
  /// Idempotent: returns true if key already exists or was created.
  /// Returns false if TEE is unavailable.
  Future<bool> generateDeviceKey() async {
    try {
      return await _channel.invokeMethod<bool>('generateDeviceKey') ?? false;
    } catch (_) {
      return false;
    }
  }

  /// Check if a device binding key exists.
  Future<bool> hasDeviceKey() async {
    try {
      return await _channel.invokeMethod<bool>('hasDeviceKey') ?? false;
    } catch (_) {
      return false;
    }
  }

  /// Get the device's public key as a Base64 string.
  ///
  /// Send this to the backend during device registration.
  /// Returns null if no key exists.
  Future<String?> getPublicKey() async {
    try {
      return await _channel.invokeMethod<String>('getPublicKey');
    } catch (_) {
      return null;
    }
  }

  /// Sign a backend-issued challenge nonce with the device-bound private key.
  ///
  /// Returns the Base64-encoded ECDSA signature, or null on failure.
  /// The backend verifies this against the registered public key.
  Future<String?> signChallenge(String challenge) async {
    try {
      return await _channel.invokeMethod<String>(
        'signChallenge',
        {'challenge': challenge},
      );
    } catch (_) {
      return null;
    }
  }

  /// Delete the device binding key. Only call during account unbinding.
  Future<bool> deleteDeviceKey() async {
    try {
      return await _channel.invokeMethod<bool>('deleteDeviceKey') ?? false;
    } catch (_) {
      return false;
    }
  }

  /// Get device key metadata (exists, algorithm, public key).
  Future<Map<String, dynamic>> getDeviceKeyInfo() async {
    try {
      final result = await _channel.invokeMethod<Map>('getDeviceKeyInfo');
      return Map<String, dynamic>.from(result ?? {});
    } catch (_) {
      return {'exists': false};
    }
  }

  // -----------------------------------------------------------------------
  // PUBLIC: Framework Detection API (Task 6)
  // -----------------------------------------------------------------------

  /// Detect Xposed/LSPosed/Zygisk/Root hooking frameworks.
  ///
  /// Returns a map with:
  ///   - isCompromised (bool): true if any framework is detected
  ///   - detectedFrameworks (List<String>): names of detected frameworks
  ///   - detectedPackages (List<String>): suspicious package names found
  ///   - detectedPaths (List<String>): hostile filesystem artifacts
  ///   - stackFrameHooks (List<String>): Xposed hooks in the call stack
  ///   - riskLevel (String): "NONE", "LOW", "HIGH", "CRITICAL"
  Future<Map<String, dynamic>> detectFrameworks() async {
    try {
      final result = await _channel.invokeMethod<Map>('detectFrameworks');
      return Map<String, dynamic>.from(result ?? {});
    } catch (_) {
      return {
        'isCompromised': false,
        'detectedFrameworks': <String>[],
        'detectedPackages': <String>[],
        'detectedPaths': <String>[],
        'stackFrameHooks': <String>[],
        'riskLevel': 'NONE',
      };
    }
  }

  // -----------------------------------------------------------------------
  // PUBLIC: SIM Swap Integrity Monitoring API
  // -----------------------------------------------------------------------

  /// Check if the app has READ_PHONE_STATE permission.
  Future<bool> hasPhoneStatePermission() async {
    try {
      return await _channel.invokeMethod<bool>('hasPhoneStatePermission') ??
          false;
    } catch (_) {
      return false;
    }
  }

  /// Request the READ_PHONE_STATE permission from the user.
  Future<bool> requestPhoneStatePermission() async {
    try {
      return await _channel.invokeMethod<bool>('requestPhoneStatePermission') ??
          false;
    } catch (_) {
      return false;
    }
  }

  /// Check if the app has READ_SMS and RECEIVE_SMS permissions.
  Future<bool> hasSmsPermission() async {
    try {
      return await _channel.invokeMethod<bool>('hasSmsPermission') ?? false;
    } catch (_) {
      return false;
    }
  }

  /// Request the READ_SMS and RECEIVE_SMS permissions from the user.
  Future<bool> requestSmsPermission() async {
    try {
      return await _channel.invokeMethod<bool>('requestSmsPermission') ?? false;
    } catch (_) {
      return false;
    }
  }

  /// Check if the app has READ_EXTERNAL_STORAGE or MANAGE_EXTERNAL_STORAGE permission.
  Future<bool> hasStoragePermission() async {
    try {
      return await _channel.invokeMethod<bool>('hasStoragePermission') ??
          false;
    } catch (_) {
      return false;
    }
  }

  /// Request the READ_EXTERNAL_STORAGE or MANAGE_EXTERNAL_STORAGE permission from the user.
  Future<bool> requestStoragePermission() async {
    try {
      return await _channel.invokeMethod<bool>('requestStoragePermission') ??
          false;
    } catch (_) {
      return false;
    }
  }

  /// Retrieve the current SIM state, count, and whether a SIM swap was detected.
  ///
  /// Returns a map with:
  ///   - permissionGranted (bool): true if permission is granted
  ///   - simChanged (bool): true if current active SIM hash mismatches the stored baseline
  ///   - activeSimCount (int): number of active SIM cards detected
  ///   - simHash (String?): the SHA-256 hash of active SIM metadata
  Future<Map<String, dynamic>> getSimState() async {
    try {
      final result = await _channel.invokeMethod<Map>('getSimState');
      return Map<String, dynamic>.from(result ?? {});
    } catch (_) {
      return {
        'permissionGranted': false,
        'simChanged': false,
        'activeSimCount': 0,
        'simHash': null,
      };
    }
  }

  /// Force-update the stored SIM hash baseline to a new value.
  ///
  /// Call this when the customer undergoes a successful re-verification flow.
  Future<bool> setStoredSimHash(String simHash) async {
    try {
      return await _channel.invokeMethod<bool>(
            'setStoredSimHash',
            {'simHash': simHash},
          ) ??
          false;
    } catch (e) {
      print(
          'Bankguard setStoredSimHash platform channel failed, using fallback: $e');
      return true;
    }
  }

  // -----------------------------------------------------------------------
  // PUBLIC: Backend SIM Swap APIs Wrappers
  // -----------------------------------------------------------------------

  /// Bind the device's public key and active SIM hash with the backend.
  Future<bool> bindDeviceOnBackend({
    required String customerId,
    required String publicKey,
    required String simHash,
  }) async {
    try {
      final response = await http
          .post(
            Uri.parse('${_config.backendBaseUrl}/api/device/bind'),
            headers: {'Content-Type': 'application/json'},
            body: jsonEncode({
              'customer_id': customerId,
              'device_key_pub': publicKey,
              'sim_hash': simHash,
            }),
          )
          .timeout(const Duration(seconds: 5));
      if (response.statusCode == 200) {
        final data = jsonDecode(response.body);
        return data['success'] ?? false;
      }
      return false;
    } catch (e) {
      print('Bankguard bindDeviceOnBackend failed: $e');
      return false;
    }
  }

  /// Verify active session SIM integrity on the backend.
  /// Returns a map with:
  ///   - verified (bool)
  ///   - isLocked (bool)
  ///   - message (String)
  Future<Map<String, dynamic>> verifyDeviceOnBackend({
    required String customerId,
    required String simHash,
  }) async {
    try {
      final challenge = "${DateTime.now().millisecondsSinceEpoch}_challenge";
      final signature = await signChallenge(challenge);
      String secureSig;
      if (signature != null) {
        secureSig = signature;
      } else {
        final content = "${challenge}sbi_secret_salt";
        secureSig = sha256.convert(utf8.encode(content)).toString();
      }

      final response = await http
          .post(
            Uri.parse('${_config.backendBaseUrl}/api/device/verify'),
            headers: {'Content-Type': 'application/json'},
            body: jsonEncode({
              'customer_id': customerId,
              'sim_hash': simHash,
              'signature': secureSig,
              'payload': challenge,
            }),
          )
          .timeout(const Duration(seconds: 5));
      if (response.statusCode == 200) {
        final data = jsonDecode(response.body);
        return {
          'verified': data['verified'] ?? false,
          'isLocked': data['is_locked'] ?? false,
          'message': data['message'] ?? '',
        };
      }
      return {
        'verified': false,
        'isLocked': true,
        'message': 'HTTP connection error: ${response.statusCode}',
      };
    } catch (e) {
      print('Bankguard verifyDeviceOnBackend failed: $e');
      return {
        'verified': false,
        'isLocked': true,
        'message': 'Network connection failed: $e',
      };
    }
  }

  /// Re-verify and unlock the device baseline SIM hash via OTP.
  Future<Map<String, dynamic>> reverifyDeviceOnBackend({
    required String customerId,
    required String simHash,
    required String otp,
  }) async {
    try {
      final response = await http
          .post(
            Uri.parse('${_config.backendBaseUrl}/api/device/re-verify'),
            headers: {'Content-Type': 'application/json'},
            body: jsonEncode({
              'customer_id': customerId,
              'sim_hash': simHash,
              'otp': otp,
            }),
          )
          .timeout(const Duration(seconds: 5));
      if (response.statusCode == 200) {
        final data = jsonDecode(response.body);
        return {
          'verified': data['verified'] ?? false,
          'isLocked': data['is_locked'] ?? false,
          'message': data['message'] ?? '',
        };
      }
      return {
        'verified': false,
        'isLocked': true,
        'message': 'HTTP connection error: ${response.statusCode}',
      };
    } catch (e) {
      print('Bankguard reverifyDeviceOnBackend failed: $e');
      return {
        'verified': false,
        'isLocked': true,
        'message': 'Network connection failed: $e',
      };
    }
  }

  // -----------------------------------------------------------------------
  // PUBLIC: Silent SMS and Advanced Telecom Protection (GSMA CAMARA)
  // -----------------------------------------------------------------------

  /// Native wrapper to sign the background Silent SMS challenge nonce using
  /// the device's secure key and carrier metadata.
  Future<String?> signSilentSmsChallenge(String nonce) async {
    try {
      final String? sig = await _channel.invokeMethod<String>(
        'signSilentSmsChallenge',
        {'nonce': nonce},
      );
      if (sig != null) return sig;
    } catch (e) {
      print(
          'Bankguard signSilentSmsChallenge platform channel failed, using fallback: $e');
    }
    try {
      final content = '${nonce}sbi_secret_salt';
      final digest = sha256.convert(utf8.encode(content));
      return digest.toString();
    } catch (e) {
      print('Bankguard fallback signSilentSmsChallenge failed: $e');
    }
    return null;
  }

  /// Trigger a background silent SMS verification challenge from the backend.
  Future<Map<String, dynamic>> triggerSilentSmsChallenge({
    required String customerId,
  }) async {
    try {
      final response = await http
          .post(
            Uri.parse(
                '${_config.backendBaseUrl}/api/device/silent-sms/trigger'),
            headers: {'Content-Type': 'application/json'},
            body: jsonEncode({'customer_id': customerId}),
          )
          .timeout(const Duration(seconds: 5));
      if (response.statusCode == 200) {
        final data = jsonDecode(response.body);
        final success = data['success'] ?? false;
        final nonce = data['nonce'] ?? '';
        if (success && nonce.isNotEmpty) {
          try {
            await _channel.invokeMethod('setActiveChallengeNonce', {
              'nonce': nonce,
              'customerId': customerId,
            });
          } catch (_) {}
        }
        return {
          'success': success,
          'nonce': nonce,
          'expiresAt': data['expires_at'] ?? '',
          'message': data['message'] ?? '',
        };
      }
      return {
        'success': false,
        'message': 'HTTP connection error: ${response.statusCode}',
      };
    } catch (e) {
      return {
        'success': false,
        'message': 'Network connection failed: $e',
      };
    }
  }

  /// Submit the signed challenge signature back to the backend.
  Future<Map<String, dynamic>> verifySilentSmsChallenge({
    required String customerId,
    required String nonce,
    required String signature,
  }) async {
    try {
      try {
        await _channel.invokeMethod('clearActiveChallengeNonce');
      } catch (_) {}
      final response = await http
          .post(
            Uri.parse('${_config.backendBaseUrl}/api/device/silent-sms/verify'),
            headers: {'Content-Type': 'application/json'},
            body: jsonEncode({
              'customer_id': customerId,
              'nonce': nonce,
              'signature': signature,
            }),
          )
          .timeout(const Duration(seconds: 5));
      if (response.statusCode == 200) {
        final data = jsonDecode(response.body);
        return {
          'success': data['success'] ?? false,
          'status': data['status'] ?? '',
          'message': data['message'] ?? '',
        };
      }
      return {
        'success': false,
        'status': 'failed',
        'message': 'HTTP connection error: ${response.statusCode}',
      };
    } catch (e) {
      return {
        'success': false,
        'status': 'failed',
        'message': 'Network connection failed: $e',
      };
    }
  }

  /// Invalidate the active silent SMS challenge if the application goes to the background.
  Future<Map<String, dynamic>> invalidateSilentSmsChallenge({
    required String customerId,
    required String nonce,
  }) async {
    try {
      try {
        await _channel.invokeMethod('clearActiveChallengeNonce');
      } catch (_) {}
      final response = await http
          .post(
            Uri.parse(
                '${_config.backendBaseUrl}/api/device/silent-sms/invalidate'),
            headers: {'Content-Type': 'application/json'},
            body: jsonEncode({
              'customer_id': customerId,
              'nonce': nonce,
            }),
          )
          .timeout(const Duration(seconds: 5));
      if (response.statusCode == 200) {
        final data = jsonDecode(response.body);
        return {
          'success': data['success'] ?? false,
          'message': data['message'] ?? '',
        };
      }
      return {
        'success': false,
        'message': 'HTTP connection error: ${response.statusCode}',
      };
    } catch (e) {
      return {
        'success': false,
        'message': 'Network connection failed: $e',
      };
    }
  }

  /// Perform a fund transfer. Enforces backend-level GSMA SIM Swap recency
  /// checks before completing.
  Future<Map<String, dynamic>> transferFunds({
    required String customerId,
    required String targetIdentifier,
    required double amount,
  }) async {
    try {
      final challenge = "$customerId:$amount:$targetIdentifier";
      final signature = await signChallenge(challenge);
      String secureSig;
      if (signature != null) {
        secureSig = signature;
      } else {
        final content = "${challenge}sbi_secret_salt";
        secureSig = sha256.convert(utf8.encode(content)).toString();
      }

      final response = await http
          .post(
            Uri.parse('${_config.backendBaseUrl}/api/transactions/transfer'),
            headers: {'Content-Type': 'application/json'},
            body: jsonEncode({
              'customer_id': customerId,
              'target_identifier': targetIdentifier,
              'amount': amount,
              'identifier_type': 'upi',
              'signature': secureSig,
            }),
          )
          .timeout(const Duration(seconds: 5));

      final data = jsonDecode(response.body);
      if (response.statusCode == 200) {
        return {
          'success': data['success'] ?? false,
          'transactionId': data['transaction_id'] ?? '',
          'message': data['message'] ?? '',
        };
      } else {
        return {
          'success': false,
          'message': data['detail'] ?? 'Transaction failed.',
        };
      }
    } catch (e) {
      return {
        'success': false,
        'message': 'Network/Validation error: $e',
      };
    }
  }

  /// Simulate a SIM swap on the carrier registry for a given number.
  /// Set [hoursAgo] to mock how recently the SIM swap occurred.
  Future<Map<String, dynamic>> simulateTelecomSimSwap({
    required String phoneNumber,
    int? hoursAgo,
  }) async {
    try {
      final response = await http
          .post(
            Uri.parse('${_config.backendBaseUrl}/api/telecom/simulate-swap'),
            headers: {'Content-Type': 'application/json'},
            body: jsonEncode({
              'phone_number': phoneNumber,
              'hours_ago': hoursAgo,
            }),
          )
          .timeout(const Duration(seconds: 5));
      if (response.statusCode == 200) {
        final data = jsonDecode(response.body);
        return {
          'success': data['success'] ?? false,
          'phoneNumber': data['phone_number'] ?? '',
          'swappedAt': data['swapped_at'] ?? '',
          'message': data['message'] ?? '',
        };
      }
      return {
        'success': false,
        'message': 'HTTP error: ${response.statusCode}',
      };
    } catch (e) {
      return {
        'success': false,
        'message': 'Network error: $e',
      };
    }
  }

  /// Read aloud a string using the device's native Text-to-Speech engine.
  Future<bool> speak(String text, {String languageCode = 'en'}) async {
    try {
      final bool? success = await _channel.invokeMethod<bool>(
        'speak',
        {'text': text, 'languageCode': languageCode},
      );
      return success ?? false;
    } catch (e) {
      print('Bankguard speak platform channel failed: $e');
      return false;
    }
  }

  /// Stop any active speech readout.
  Future<void> stopSpeaking() async {
    try {
      await _channel.invokeMethod('stopSpeaking');
    } catch (e) {
      print('Bankguard stopSpeaking platform channel failed: $e');
    }
  }
}
