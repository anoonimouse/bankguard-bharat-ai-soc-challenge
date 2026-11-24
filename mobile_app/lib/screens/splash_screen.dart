import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'dart:async';
import 'dart:io' show Platform;
import 'dart:ui' show PlatformDispatcher;
import 'package:bankguard/bankguard.dart';
import '../notifications.dart';
import '../data/dummy_data.dart';
import '../main.dart';

/// Splash Screen — a thin UI shell.
/// All security logic is delegated to the BankGuard SDK.
/// This screen only:
///   1. Tells the SDK to scan
///   2. Reacts to SDK callbacks
///   3. Displays UI based on events
class SplashScreen extends StatefulWidget {
  const SplashScreen({super.key});

  @override
  State<SplashScreen> createState() => _SplashScreenState();
}

class _SplashScreenState extends State<SplashScreen> {
  static const MethodChannel _shareChannel = MethodChannel('bankguard_share');
  static const MethodChannel _smsChannel = MethodChannel('bankguard_sms');
  static const EventChannel _smsEventChannel =
      EventChannel('bankguard_sms_stream');

  final _sdk = Bankguard();
  final List<String> _logs = [];
  bool _threatDetected = false;
  StreamSubscription<dynamic>? _smsSubscription;

  @override
  void initState() {
    super.initState();
    _registerSDKCallbacks();
    _smsSubscription = _smsEventChannel
        .receiveBroadcastStream()
        .listen(_handleSmsEvent);
    _startBankguardScan();
  }

  @override
  void dispose() {
    _smsSubscription?.cancel();
    super.dispose();
  }

  /// Register SDK callbacks — the SDK fires events, we react with UI.
  void _registerSDKCallbacks() {
    // Re-initialize with callbacks for this screen's lifecycle.
    // Since SDK is already initialized, we update callbacks via a fresh init
    // that preserves config but adds our UI callbacks.
    // Note: In a production SDK you'd have a separate setCallbacks() method.
    // For now, the SDK handles notification/call events internally
    // and fires callbacks registered at init time.
  }

  void _addLog(String log) {
    if (!mounted) return;
    setState(() {
      _logs.add(log);
    });
  }

  Future<void> _startBankguardScan() async {
    try {
      _addLog("Initializing BankGuard SDK...");
      await Future.delayed(const Duration(milliseconds: 500));

      await _startSmsUserConsent();

      final shareThreat = await _checkSharedIntent();
      if (shareThreat) return;

      _addLog("Scanning installed packages & verifying signatures...");

      if (!Platform.isAndroid) {
        _addLog("SDK scan skipped: non-Android device.");
        await Future.delayed(const Duration(milliseconds: 600));
        _navigateToNextScreen();
        return;
      }

      // 1. Device Registration Flow (One-Time)
      final hasKey = await _sdk.hasDeviceKey();
      if (!hasKey) {
        _addLog("First launch detected. Registering device identity...");
        
        final hasPhonePermission = await _sdk.hasPhoneStatePermission();
        if (!hasPhonePermission) {
          _addLog("Requesting Phone State permission...");
          final granted = await _sdk.requestPhoneStatePermission();
          if (!granted) {
            _addLog("[!] Phone State permission denied. Binding with fallback hash.");
          }
        }
        
        final simState = await _sdk.getSimState();
        final simHash = simState['simHash'] ?? 'fallback_sim_hash_123456';
        
        _addLog("Generating hardware-backed cryptographic key...");
        final keyGenerated = await _sdk.generateDeviceKey();
        if (!keyGenerated) {
          _addLog("[!] Failed to generate hardware-backed key.");
        }
        
        final pubKey = await _sdk.getPublicKey() ?? 'fallback_public_key_abc';
        
        _addLog("Enrolling device and SIM baseline on backend...");
        final bound = await _sdk.bindDeviceOnBackend(
          customerId: CustomerData.customerId,
          publicKey: pubKey,
          simHash: simHash,
        );
        if (bound) {
          _addLog("[PASS] Device successfully registered on backend.");
        } else {
          _addLog("[!] Device registration failed on backend.");
        }
      } else {
        _addLog("Device identity already registered. Verifying SIM status...");
        final simState = await _sdk.getSimState();
        if (simState['simChanged'] == true) {
          _addLog("[!] CRITICAL: SIM SWAP DETECTED!");
          await Future.delayed(const Duration(milliseconds: 1000));
          if (mounted) {
            Navigator.pushReplacementNamed(
              context,
              '/sim-verification',
              arguments: {
                'customerId': CustomerData.customerId,
                'newSimHash': simState['simHash'] ?? '',
              },
            );
          }
          return;
        }
        _addLog("SIM card integrity verified.");
      }

      // 2. Storage Permission Flow (for APK/File Scanner)
      var hasStorage = await _sdk.hasStoragePermission();
      while (!hasStorage) {
        _addLog("[!] Storage permission is required. Please allow All Files Access.");
        _addLog("Launching Settings screen...");
        await _sdk.requestStoragePermission();
        
        // Wait for the user to return to the app and grant permission
        bool granted = false;
        for (int i = 0; i < 15; i++) {
          await Future.delayed(const Duration(milliseconds: 1500));
          hasStorage = await _sdk.hasStoragePermission();
          if (hasStorage) {
            granted = true;
            break;
          }
        }
        if (granted) {
          break;
        }
        _addLog("[!] Permission not detected yet. Retrying...");
        await Future.delayed(const Duration(seconds: 3));
        hasStorage = await _sdk.hasStoragePermission();
      }
      _addLog("[PASS] Storage permission verified.");

      // 2B. SMS Permission Flow (for fallback SMS Scanner)
      var hasSms = await _sdk.hasSmsPermission();
      if (!hasSms) {
        _addLog("[!] SMS reading permissions are required. Requesting SMS access...");
        await _sdk.requestSmsPermission();
        await Future.delayed(const Duration(seconds: 2));
        hasSms = await _sdk.hasSmsPermission();
        if (hasSms) {
          _addLog("[PASS] SMS permissions granted.");
        } else {
          _addLog("[!] SMS permissions not granted. Falling back to notifications.");
        }
      } else {
        _addLog("[PASS] SMS permissions verified.");
      }

      // 2C. Overlay Permission Flow (for vishing/phishing warning badges)
      var hasOverlay = await _sdk.isSelfOverlayPermissionEnabled();
      if (!hasOverlay) {
        _addLog("[!] Overlay permission is required to display security badges over WhatsApp.");
        _addLog("Launching Overlay Settings...");
        await _sdk.requestOverlayPermission();
        for (int i = 0; i < 8; i++) {
          await Future.delayed(const Duration(milliseconds: 1500));
          hasOverlay = await _sdk.isSelfOverlayPermissionEnabled();
          if (hasOverlay) break;
        }
        if (hasOverlay) {
          _addLog("[PASS] Overlay permission verified.");
        } else {
          _addLog("[WARN] Overlay permission not granted. Warning badge alerts will not overlay.");
        }
      } else {
        _addLog("[PASS] Overlay permission verified.");
      }

      // 2D. Notification Access (Optional - Zero-Friction Onboarding for Adoption Reality)
      var hasNotificationAccess = await _sdk.isNotificationListenerEnabled();
      if (!hasNotificationAccess) {
        _addLog("Notification Access: Optional (Bypassed for Zero-Friction Onboarding).");
        _addLog("Ensuring seamless adoption for rural and semi-urban users.");
        _addLog("Active Defense uses background SMS BroadcastReceivers (No settings redirect).");
        await Future.delayed(const Duration(milliseconds: 800));
      } else {
        _addLog("[PASS] Notification Access verified.");
      }

      // 2E. Call Screening Permission Flow
      var hasCallScreening = await _sdk.isCallScreeningEnabled();
      if (!hasCallScreening) {
        _addLog("[!] Call Screening is required to block fraud callers.");
        _addLog("Launching Call Screening Settings...");
        await _sdk.openCallScreeningSettings();
        for (int i = 0; i < 8; i++) {
          await Future.delayed(const Duration(milliseconds: 1500));
          hasCallScreening = await _sdk.isCallScreeningEnabled();
          if (hasCallScreening) break;
        }
        if (hasCallScreening) {
          _addLog("[PASS] Call Screening verified.");
        } else {
          _addLog("[WARN] Call Screening role not granted. Real-time call screening disabled.");
        }
      } else {
        _addLog("[PASS] Call Screening verified.");
      }

      // 3. Request Default Browser Role (one-time, non-blocking)
      _addLog("Requesting Link Interception Gate activation...");
      try {
        final gateActivated = await _sdk.requestDefaultBrowserRole();
        if (gateActivated) {
          _addLog("[PASS] Link Interception Gate activated. All HTTP/HTTPS links are protected.");
        } else {
          _addLog("[!] Link Interception Gate: user declined or prompt unavailable.");
        }
      } catch (_) {
        _addLog("Link Interception Gate: prompt not available on this device.");
      }

      // Delegate entire device scan to SDK
      final scanEvent = await _sdk.runDeviceScan();

      if (scanEvent.threats.isNotEmpty || _threatDetected) {
        for (var threat in scanEvent.threats) {
          _addLog("[!] $threat");
          await Future.delayed(const Duration(milliseconds: 300));
        }

        // SDK handles settings navigation
        if (scanEvent.threats.contains("NOTIFICATION_LISTENER_DISABLED")) {
          await _sdk.openNotificationListenerSettings();
        }
        if (scanEvent.threats.contains("CALL_SCREENING_DISABLED")) {
          await _sdk.openCallScreeningSettings();
        }
        if (scanEvent.threats.contains("OVERLAY_PERMISSION_ENABLED")) {
          await _sdk.openOverlaySettings();
        }

        if (_threatDetected && scanEvent.threats.isEmpty) {
          _addLog("[!] THREAT DETECTED: Side-loaded fake app package name mismatch!");
        }

        await Future.delayed(const Duration(milliseconds: 1000));
        final detail = _buildThreatDetail(
          threats: scanEvent.threats,
          forcedThreat: _threatDetected,
        );
        await AppNotifications.show(
          title: "BankGuard Security Alert",
          body: detail,
        );
        _showThreatAlert(
          sourceType: 'scan',
          threats: scanEvent.threats,
          forcedThreat: _threatDetected,
        );
      } else {
        _addLog("Environment Secure. Launching BankGuard...");
        await Future.delayed(const Duration(milliseconds: 1000));
        _navigateToNextScreen();
      }
    } catch (e, stacktrace) {
      _addLog("[!] CRITICAL SDK CRASH: $e");
      print(stacktrace);
    }
  }

  void _navigateToNextScreen() {
    if (!mounted) return;
    BankGuardApp.isSplashActive = false;
    if (BankGuardApp.pendingDeepLinkRoute != null) {
      Navigator.pushReplacementNamed(context, '/login');
      BankGuardApp.navigatorKey.currentState?.pushNamed(
        BankGuardApp.pendingDeepLinkRoute!,
        arguments: BankGuardApp.pendingDeepLinkArgs,
      );
      BankGuardApp.pendingDeepLinkRoute = null;
      BankGuardApp.pendingDeepLinkArgs = null;
    } else {
      Navigator.pushReplacementNamed(context, '/login');
    }
  }

  String _buildThreatDetail({
    required List<String> threats,
    required bool forcedThreat,
  }) {
    final strings = ThreatStrings.forLocale('en');
    final messages = <String>[];

    if (forcedThreat && threats.isEmpty) {
      messages.add(strings.simulatedThreat);
    }

    for (final threat in threats) {
      if (threat.startsWith("SUSPICIOUS_PACKAGE_DETECTED")) {
        messages.add(strings.suspiciousPackage);
      } else if (threat.startsWith("VERIFIED_MALICIOUS_PACKAGE")) {
        messages.add(strings.verifiedMalicious);
      } else if (threat == "UNKNOWN_SOURCES_ENABLED") {
        messages.add(strings.unknownSources);
      } else if (threat == "OVERLAY_PERMISSION_ENABLED") {
        messages.add(strings.overlayPermission);
      } else if (threat == "ACCESSIBILITY_ENABLED") {
        messages.add(strings.accessibility);
      } else if (threat == "NOTIFICATION_LISTENER_DISABLED") {
        messages.add(strings.notificationListener);
      } else if (threat == "CALL_SCREENING_DISABLED") {
        messages.add(strings.callScreening);
      } else if (threat.startsWith("SELF_TAMPER_DETECTED")) {
        messages.add(strings.selfTamper);
      }
    }

    if (messages.isEmpty) return strings.genericRisk;
    return messages.join("\n\n");
  }

  Future<void> _startSmsUserConsent() async {
    try {
      await _smsChannel.invokeMethod('startSmsUserConsent');
      _addLog("SMS consent listener active.");
    } catch (e) {
      _addLog("SMS consent unavailable.");
    }
  }

  Future<void> _handleSmsEvent(dynamic event) async {
    final message = event?.toString() ?? '';
    if (message.isEmpty) return;
    _addLog("SMS received for consent scan.");

    // Delegate URL scanning to SDK
    final url = IdentifierExtractor.extractFirstUrl(message);
    if (url == null) return;

    final result = await _sdk.scanUrl(url);
    if (result != null && !result.isSafe) {
      _addLog("[!] LINK THREAT: ${result.message}");
      await AppNotifications.show(
        title: "BankGuard Link Alert",
        body: "A suspicious link was detected in an SMS. Avoid opening it.",
      );
      _showThreatAlert(sourceType: 'sms');
    }
  }

  Future<bool> _checkSharedIntent() async {
    String? sharedText;
    try {
      sharedText = await _shareChannel.invokeMethod<String>('getSharedText');
    } catch (e) {
      return false;
    }

    if (sharedText == null || sharedText.trim().isEmpty) return false;

    _addLog("Shared content detected. Scanning link...");
    final url = IdentifierExtractor.extractFirstUrl(sharedText);
    if (url == null) {
      _addLog("No URL found in shared content.");
      return false;
    }

    final result = await _sdk.scanUrl(url);
    if (result != null && !result.isSafe) {
      _addLog("[!] LINK THREAT: ${result.message}");
      await AppNotifications.show(
        title: "BankGuard Link Alert",
        body: "This shared link appears malicious. Avoid opening it.",
      );
      _showThreatAlert(sourceType: 'shared');
      return true;
    }

    _addLog("Shared link appears safe.");
    return false;
  }

  String _getHeadlineForSource(String sourceType, ThreatStringSet strings) {
    if (sourceType == 'sms') return strings.phishingSmsHeadline;
    if (sourceType == 'call') return strings.suspiciousCallHeadline;
    if (sourceType == 'notification' || sourceType == 'shared') return strings.phishingLinkHeadline;
    return strings.securityAlertHeadline;
  }

  String _getDetailForSource(String sourceType, ThreatStringSet strings, List<String> threats, bool forcedThreat) {
    if (sourceType == 'sms') return strings.phishingSmsDetail;
    if (sourceType == 'call') return strings.suspiciousCallDetail;
    if (sourceType == 'notification') return strings.phishingLinkNotificationDetail;
    if (sourceType == 'shared') return strings.phishingLinkSharedDetail;

    final messages = <String>[];
    if (forcedThreat && threats.isEmpty) messages.add(strings.simulatedThreat);

    for (final threat in threats) {
      if (threat.startsWith("SUSPICIOUS_PACKAGE_DETECTED")) messages.add(strings.suspiciousPackage);
      else if (threat.startsWith("VERIFIED_MALICIOUS_PACKAGE")) messages.add(strings.verifiedMalicious);
      else if (threat == "UNKNOWN_SOURCES_ENABLED") messages.add(strings.unknownSources);
      else if (threat == "OVERLAY_PERMISSION_ENABLED") messages.add(strings.overlayPermission);
      else if (threat == "ACCESSIBILITY_ENABLED") messages.add(strings.accessibility);
      else if (threat == "NOTIFICATION_LISTENER_DISABLED") messages.add(strings.notificationListener);
      else if (threat == "CALL_SCREENING_DISABLED") messages.add(strings.callScreening);
      else if (threat.startsWith("SELF_TAMPER_DETECTED")) messages.add(strings.selfTamper);
    }

    if (messages.isEmpty) return strings.genericRisk;
    return messages.join("\n\n");
  }

  void _showThreatAlert({required String sourceType, List<String> threats = const [], bool forcedThreat = false}) {
    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (context) {
        String? demoLanguageOverride;
        bool isFirstLoad = true;

        return StatefulBuilder(
          builder: (context, setStateBuilder) {
            final activeLang = demoLanguageOverride ?? PlatformDispatcher.instance.locale.languageCode;
            final topStrings = ThreatStrings.forLocale(activeLang);
            final topHeadline = _getHeadlineForSource(sourceType, topStrings);
            final topDetail = _getDetailForSource(sourceType, topStrings, threats, forcedThreat);
            final textToSpeak = "$topHeadline. $topDetail";

            if (isFirstLoad) {
              isFirstLoad = false;
              WidgetsBinding.instance.addPostFrameCallback((_) {
                _sdk.speak(textToSpeak, languageCode: activeLang);
              });
            }

            final allLangs = ['hi', 'ta', 'te', 'bn', 'mr'];
            allLangs.remove(activeLang);
            if (allLangs.contains('hi')) {
              allLangs.remove('hi');
              allLangs.insert(0, 'hi');
            }

            return PopScope(
              onPopInvoked: (didPop) {
                if (didPop) {
                  _sdk.stopSpeaking();
                }
              },
              child: AlertDialog(
                backgroundColor: Colors.red.shade50,
                contentPadding: EdgeInsets.zero,
                content: SingleChildScrollView(
                  child: Padding(
                    padding: const EdgeInsets.all(24.0),
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        SingleChildScrollView(
                          scrollDirection: Axis.horizontal,
                          child: Row(
                            children: [
                              _buildLangChip('en', 'English', demoLanguageOverride, (code) {
                                setStateBuilder(() {
                                  demoLanguageOverride = code;
                                });
                                _sdk.stopSpeaking();
                                final updatedStrings = ThreatStrings.forLocale(code);
                                final updatedHeadline = _getHeadlineForSource(sourceType, updatedStrings);
                                final updatedDetail = _getDetailForSource(sourceType, updatedStrings, threats, forcedThreat);
                                _sdk.speak("$updatedHeadline. $updatedDetail", languageCode: code);
                              }),
                              _buildLangChip('hi', 'हिन्दी', demoLanguageOverride, (code) {
                                setStateBuilder(() {
                                  demoLanguageOverride = code;
                                });
                                _sdk.stopSpeaking();
                                final updatedStrings = ThreatStrings.forLocale(code);
                                final updatedHeadline = _getHeadlineForSource(sourceType, updatedStrings);
                                final updatedDetail = _getDetailForSource(sourceType, updatedStrings, threats, forcedThreat);
                                _sdk.speak("$updatedHeadline. $updatedDetail", languageCode: code);
                              }),
                              _buildLangChip('ta', 'தமிழ்', demoLanguageOverride, (code) {
                                setStateBuilder(() {
                                  demoLanguageOverride = code;
                                });
                                _sdk.stopSpeaking();
                                final updatedStrings = ThreatStrings.forLocale(code);
                                final updatedHeadline = _getHeadlineForSource(sourceType, updatedStrings);
                                final updatedDetail = _getDetailForSource(sourceType, updatedStrings, threats, forcedThreat);
                                _sdk.speak("$updatedHeadline. $updatedDetail", languageCode: code);
                              }),
                              _buildLangChip('te', 'తెలుగు', demoLanguageOverride, (code) {
                                setStateBuilder(() {
                                  demoLanguageOverride = code;
                                });
                                _sdk.stopSpeaking();
                                final updatedStrings = ThreatStrings.forLocale(code);
                                final updatedHeadline = _getHeadlineForSource(sourceType, updatedStrings);
                                final updatedDetail = _getDetailForSource(sourceType, updatedStrings, threats, forcedThreat);
                                _sdk.speak("$updatedHeadline. $updatedDetail", languageCode: code);
                              }),
                              _buildLangChip('bn', 'বাংলা', demoLanguageOverride, (code) {
                                setStateBuilder(() {
                                  demoLanguageOverride = code;
                                });
                                _sdk.stopSpeaking();
                                final updatedStrings = ThreatStrings.forLocale(code);
                                final updatedHeadline = _getHeadlineForSource(sourceType, updatedStrings);
                                final updatedDetail = _getDetailForSource(sourceType, updatedStrings, threats, forcedThreat);
                                _sdk.speak("$updatedHeadline. $updatedDetail", languageCode: code);
                              }),
                              _buildLangChip('mr', 'मराठी', demoLanguageOverride, (code) {
                                setStateBuilder(() {
                                  demoLanguageOverride = code;
                                });
                                _sdk.stopSpeaking();
                                final updatedStrings = ThreatStrings.forLocale(code);
                                final updatedHeadline = _getHeadlineForSource(sourceType, updatedStrings);
                                final updatedDetail = _getDetailForSource(sourceType, updatedStrings, threats, forcedThreat);
                                _sdk.speak("$updatedHeadline. $updatedDetail", languageCode: code);
                              }),
                            ],
                          ),
                        ),
                        const SizedBox(height: 16),

                        Row(
                          children: [
                            const Icon(Icons.warning_amber_rounded, color: Colors.red, size: 32),
                            const SizedBox(width: 8),
                            Expanded(
                              child: Text(topHeadline, style: const TextStyle(color: Colors.red, fontSize: 18, fontWeight: FontWeight.bold)),
                            ),
                            IconButton(
                              icon: const Icon(Icons.volume_up, color: Colors.red, size: 28),
                              onPressed: () {
                                _sdk.stopSpeaking();
                                _sdk.speak(textToSpeak, languageCode: activeLang);
                              },
                            ),
                          ],
                        ),
                        const SizedBox(height: 16),
                        Text(topDetail, style: const TextStyle(fontSize: 16)),
                        const SizedBox(height: 24),
                        const Divider(color: Colors.redAccent),
                        const SizedBox(height: 16),

                        ...allLangs.map((lang) {
                          final strings = ThreatStrings.forLocale(lang);
                          final headline = _getHeadlineForSource(sourceType, strings);
                          final detail = _getDetailForSource(sourceType, strings, threats, forcedThreat);
                          return Padding(
                            padding: const EdgeInsets.only(bottom: 16.0),
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text(headline, style: const TextStyle(color: Colors.red, fontWeight: FontWeight.bold)),
                                const SizedBox(height: 4),
                                Text(detail.split('\n').first, style: const TextStyle(fontSize: 14)),
                              ],
                            ),
                          );
                        }),

                        const SizedBox(height: 24),
                        ElevatedButton(
                          style: ElevatedButton.styleFrom(
                            backgroundColor: Colors.red,
                            padding: const EdgeInsets.symmetric(vertical: 16),
                          ),
                          onPressed: () {
                            _sdk.stopSpeaking();
                            Navigator.pop(context);
                            setState(() {
                              _threatDetected = false;
                              _logs.clear();
                            });
                            _startBankguardScan();
                          },
                          child: Text(
                            topStrings.exitApp,
                            style: const TextStyle(color: Colors.white, fontSize: 16, fontWeight: FontWeight.bold),
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
              ),
            );
          },
        );
      },
    );
  }

  Widget _buildLangChip(String code, String label, String? currentOverride, Function(String) onSelect) {
    final isSelected = (currentOverride ?? 'en') == code;
    return Padding(
      padding: const EdgeInsets.only(right: 6.0),
      child: ChoiceChip(
        label: Text(label),
        labelStyle: TextStyle(
          color: isSelected ? Colors.white : Colors.black87,
          fontWeight: isSelected ? FontWeight.bold : FontWeight.normal,
          fontSize: 12,
        ),
        selected: isSelected,
        selectedColor: Colors.red.shade700,
        backgroundColor: Colors.white,
        side: BorderSide(
          color: isSelected ? Colors.red.shade700 : Colors.black26,
          width: isSelected ? 1.5 : 1.0,
        ),
        showCheckmark: false,
        onSelected: (selected) {
          if (selected) onSelect(code);
        },
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0F172A),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24.0),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              const Spacer(),
              const Icon(Icons.shield, size: 80, color: Colors.blueAccent),
              const SizedBox(height: 24),
              const Text(
                "BankGuard",
                textAlign: TextAlign.center,
                style: TextStyle(
                  color: Colors.white,
                  fontSize: 32,
                  fontWeight: FontWeight.bold,
                  letterSpacing: 1.5,
                ),
              ),
              const SizedBox(height: 8),
              const Text(
                "Secure Digital Banking",
                textAlign: TextAlign.center,
                style: TextStyle(color: Colors.white70, fontSize: 16),
              ),
              const SizedBox(height: 48),
              Container(
                height: 150,
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: Colors.black54,
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: Colors.white24),
                ),
                child: ListView.builder(
                  itemCount: _logs.length,
                  itemBuilder: (context, index) {
                    final isError = _logs[index].contains("[!]");
                    return Padding(
                      padding: const EdgeInsets.symmetric(vertical: 2.0),
                      child: Text(
                        "> ${_logs[index]}",
                        style: TextStyle(
                          color: isError ? Colors.redAccent : Colors.greenAccent,
                          fontFamily: 'monospace',
                          fontSize: 12,
                        ),
                      ),
                    );
                  },
                ),
              ),
              const Spacer(),
              GestureDetector(
                onLongPress: () {
                  setState(() => _threatDetected = true);
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text("Simulated Threat Enabled for Demo")),
                  );
                },
                child: const Text(
                  "v1.0.0 (Hold me for Demo 2)",
                  textAlign: TextAlign.center,
                  style: TextStyle(color: Colors.white24, fontSize: 12),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
