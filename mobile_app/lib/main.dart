import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:bankguard/bankguard.dart';
import 'notifications.dart';
import 'screens/splash_screen.dart';
import 'screens/login_screen.dart';
import 'screens/report_screen.dart';
import 'screens/home_screen.dart';
import 'screens/upi_payment_screen.dart';
import 'screens/fund_transfer_screen.dart';
import 'screens/transaction_history_screen.dart';
import 'screens/verify_link_screen.dart';
import 'screens/soc_diagnostics_screen.dart';
import 'screens/safety_academy_screen.dart';
import 'screens/sim_verification_screen.dart';
import 'screens/telco_lab_screen.dart';
import 'data/security_alerts_storage.dart';
import 'screens/security_alerts_screen.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  AppNotifications.init();

  // Initialize SDK with config — the app is now a thin shell.
  // All security logic, FRI checks, notification/call handling
  // is managed internally by the SDK.
  await Bankguard.initialize(
    config: const BankguardConfig(
      backendBaseUrl: 'https://api.doy.codes',
      officialPackageName: 'com.sbi.lotusintouch',
      officialCertHash:
          '25:11:66:DD:48:0A:AC:3C:90:0C:8E:80:95:98:0E:27:9C:BD:10:1E:B5:07:D8:61:80:99:A3:38:FD:CA:EE:F7',
      expectedSelfPackage: 'com.example.mobile_app',
      additionalWhitelist: [
        'com.sbi.SBIFreedomPlus',
        'com.sbi.bankguard',
        'com.sbi.YonoLite',
        'com.sbi.yonobusiness',
        'com.sbi.upi',
        'com.enstage.wibmo.hdfc',
        'com.hdfcbank.payzapp',
        'com.icicibank.pockets',
        'com.icicibank.bizibiz',
        'org.npci.upi.boscl'
      ],
      language: 'en',
    ),
    callbacks: BankguardCallbacks(
      onSuspiciousNotification: (event) {
        SecurityAlertsStorage.addLocalAlert(SecurityAlert(
          id: DateTime.now().millisecondsSinceEpoch.toString(),
          type: 'SMS/WhatsApp',
          title: event.senderFlag != null && event.senderFlag!.contains('CRITICAL')
              ? 'Blacklisted Sender Alert'
              : (event.senderFlag != null && event.senderFlag!.contains('Suspicious')
                  ? 'Suspicious Sender Blocked'
                  : 'Suspicious Message Blocked'),
          message: event.text,
          riskScore: event.riskScore,
          explanation: event.explanation ?? 'Message intercepted by local heuristics or TinyBERT NLP engine.',
          suggestedAction: event.suggestedAction ?? 'Do not click links or share details.',
          timestamp: DateTime.now(),
          sourceApp: event.sourcePackage ?? 'SMS Messaging',
          isLocalOnly: true,
          sender: event.sender,
          senderFlag: event.senderFlag,
        ));
        _showGlobalThreatDialog(event);
      },
      onApkFileDetected: (event) async {
        if (event.verdict == 'malicious' || event.verdict == 'suspicious') {
          SecurityAlertsStorage.addLocalAlert(SecurityAlert(
            id: DateTime.now().millisecondsSinceEpoch.toString(),
            type: 'APK Threat',
            title: event.verdict == 'malicious' ? 'Malicious App Detected' : 'Suspicious App Detected',
            message: event.displayName ?? event.packageName ?? 'unknown.apk',
            riskScore: event.verdict == 'malicious' ? 95 : 70,
            explanation: 'Side-loaded Android package "${event.displayName ?? event.packageName ?? 'unknown.apk'}" lacks a valid certificate signature or is registered on blacklist registries.',
            suggestedAction: 'Uninstall the application immediately to secure your device.',
            timestamp: DateTime.now(),
            sourceApp: 'File Scanner',
            isLocalOnly: true,
          ));
          await AppNotifications.show(
            title: "BankGuard Threat Alert",
            body: "Dangerous file detected in storage: ${event.displayName ?? 'unknown.apk'}. Tap to secure device.",
          );
          _showGlobalApkThreatDialog(event);
        }
      },
      onUrlThreat: (event) async {
        // If the URL block is triggered from a notification intercept,
        // we suppress the duplicate alert and notification, because the notification listener
        // and onSuspiciousNotification dialog have already comprehensively alerted the user.
        if (event.source == 'notification') {
          print('BANKGUARD_APP: Suppressing duplicate URL alert for notification source');
          return;
        }

        SecurityAlertsStorage.addLocalAlert(SecurityAlert(
          id: DateTime.now().millisecondsSinceEpoch.toString(),
          type: 'URL Block',
          title: 'Phishing Connection Blocked',
          message: event.url,
          riskScore: (event.riskScore * 100).toInt(),
          explanation: event.message ?? 'Malicious URL intercepted and terminated by Link Interception Gate.',
          suggestedAction: 'The connection was blocked. Avoid visiting this URL.',
          timestamp: DateTime.now(),
          sourceApp: 'Link Gate Intercept',
          isLocalOnly: true,
        ));

        await AppNotifications.show(
          title: "BankGuard Block Alert",
          body: "Suspicious link blocked: ${event.url}. Tap for details.",
        );
        _showVpnThreatAlert(event);
      },
    ),

  );

  runApp(const BankGuardApp());
}

void _showGlobalThreatDialog(NotificationThreatEvent event) {
  final context = BankGuardApp.navigatorKey.currentState?.overlay?.context;
  if (context == null) {
    print('BANKGUARD_APP: Navigator context not available to show dialog');
    return;
  }

  final dialogTranslations = {
    'en': {
      'title': 'BankGuard Threat Alert',
      'score': 'Threat Score:',
      'msg': 'Intercepted Message:',
      'ai': 'AI Threat Analysis:',
      'rec': 'Recommended Action:',
      'understand': 'I Understand',
      'dontOpen': "DON'T OPEN",
    },
    'hi': {
      'title': 'बैंकगार्ड खतरा चेतावनी',
      'score': 'खतरे का स्कोर:',
      'msg': 'पकड़ा गया संदेश:',
      'ai': 'एआई खतरा विश्लेषण:',
      'rec': 'अनुशंसित कार्रवाई:',
      'understand': 'मैं समझता हूँ',
      'dontOpen': 'न खोलें',
    },
    'mr': {
      'title': 'बँकगार्ड सुरक्षा इशारा',
      'score': 'धोका पातळी स्कोर:',
      'msg': 'पकडलेला संदेश:',
      'ai': 'एआय धोका विश्लेषण:',
      'rec': 'शिफारस केलेली कृती:',
      'understand': 'मला समजले',
      'dontOpen': 'उघडू नका',
    },
    'ta': {
      'title': 'வங்கிபாதுகாப்பு அச்சுறுத்தல் எச்சரிக்கை',
      'score': 'அச்சுறுத்தல் மதிப்பெண்:',
      'msg': 'கைப்பற்றப்பட்ட செய்தி:',
      'ai': 'செயற்கை நுண்ணறிவு அச்சுறுத்தல் பகுப்பாய்வு:',
      'rec': 'பரிந்துரைக்கப்பட்ட நடவடிக்கை:',
      'understand': 'எனக்கு புரிகிறது',
      'dontOpen': 'திறக்க வேண்டாம்',
    },
    'te': {
      'title': 'బ్యాంక్‌గార్డ్ ముప్పు హెచ్చరిక',
      'score': 'ముప్పు స్కోర్:',
      'msg': 'అంతరాయం కలిగించిన సందేశం:',
      'ai': 'AI ముప్పు విశ్లేషణ:',
      'rec': 'సిఫార్సు చేయబడిన చర్య:',
      'understand': 'నాకు అర్థమైంది',
      'dontOpen': 'తెరవవద్దు',
    },
    'bn': {
      'title': 'ব্যাংকগার্ড হুমকি সতর্কতা',
      'score': 'হুমকির স্কোর:',
      'msg': 'বাধা দেওয়া বার্তা:',
      'ai': 'এআই হুমকি বিশ্লেষণ:',
      'rec': 'প্রস্তাবিত পদক্ষেপ:',
      'understand': 'আমি বুঝতে পেরেছি',
      'dontOpen': 'খুলবেন না',
    },
  };

  showDialog(
    context: context,
    barrierDismissible: true,
    builder: (BuildContext context) {
      String? demoLanguageOverride;
      bool isFirstLoad = true;
      final _sdk = Bankguard();

      return StatefulBuilder(
        builder: (context, setStateBuilder) {
          String systemLang = 'en';
          try {
            systemLang = Localizations.localeOf(context).languageCode;
          } catch (_) {}

          final activeLang = demoLanguageOverride ?? systemLang;
          final currentTranslations = dialogTranslations[activeLang] ?? dialogTranslations['en']!;
          final textToSpeak = "${currentTranslations['title']}. ${currentTranslations['score']} ${event.riskScore}%. ${event.explanation ?? ''}. ${event.suggestedAction ?? ''}";

          if (isFirstLoad) {
            isFirstLoad = false;
            WidgetsBinding.instance.addPostFrameCallback((_) {
              _sdk.speak(textToSpeak, languageCode: activeLang);
            });
          }

          final scorePercent = event.riskScore / 100.0;
          final severityText = event.riskScore >= 90
              ? "CRITICAL RISK"
              : event.riskScore >= 70
              ? "HIGH RISK"
              : "SUSPICIOUS";

          final themeColor = event.riskScore >= 70
              ? const Color(0xFFDC2626) // Red
              : const Color(0xFFD97706); // Amber

          Widget buildLangChip(String code, String label) {
            final isSelected = activeLang == code;
            return Padding(
              padding: const EdgeInsets.only(right: 6.0),
              child: ChoiceChip(
                label: Text(label),
                labelStyle: TextStyle(
                  color: isSelected ? Colors.white : Colors.white70,
                  fontWeight: isSelected ? FontWeight.bold : FontWeight.normal,
                  fontSize: 11,
                ),
                selected: isSelected,
                selectedColor: themeColor,
                backgroundColor: const Color(0xFF0F172A),
                side: BorderSide(
                  color: isSelected ? themeColor : Colors.white24,
                  width: isSelected ? 1.5 : 1.0,
                ),
                showCheckmark: false,
                onSelected: (selected) {
                  if (selected) {
                    setStateBuilder(() {
                      demoLanguageOverride = code;
                    });
                    _sdk.stopSpeaking();
                    final newTranslations = dialogTranslations[code] ?? dialogTranslations['en']!;
                    final newTextToSpeak = "${newTranslations['title']}. ${newTranslations['score']} ${event.riskScore}%. ${event.explanation ?? ''}. ${event.suggestedAction ?? ''}";
                    _sdk.speak(newTextToSpeak, languageCode: code);
                  }
                },
              ),
            );
          }

          return PopScope(
            onPopInvoked: (didPop) {
              if (didPop) {
                _sdk.stopSpeaking();
              }
            },
            child: Dialog(
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
              backgroundColor: Colors.transparent,
              elevation: 0,
              child: Container(
                decoration: BoxDecoration(
                  color: const Color(0xFF1E293B), // Dark slate
                  borderRadius: BorderRadius.circular(16),
                  border: Border.all(color: themeColor.withOpacity(0.5), width: 1.5),
                  boxShadow: [
                    BoxShadow(
                      color: themeColor.withOpacity(0.2),
                      blurRadius: 16,
                      spreadRadius: 4,
                    ),
                  ],
                ),
                padding: const EdgeInsets.all(20),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    // Language selector chips
                    SingleChildScrollView(
                      scrollDirection: Axis.horizontal,
                      child: Row(
                        children: [
                          buildLangChip('en', 'English'),
                          buildLangChip('hi', 'हिन्दी'),
                          buildLangChip('mr', 'मराठी'),
                          buildLangChip('ta', 'தமிழ்'),
                          buildLangChip('te', 'తెలుగు'),
                          buildLangChip('bn', 'বাংলা'),
                        ],
                      ),
                    ),
                    const SizedBox(height: 12),

                    Row(
                      children: [
                        Icon(Icons.gpp_bad, color: themeColor, size: 28),
                        const SizedBox(width: 10),
                        Expanded(
                          child: Text(
                            currentTranslations['title']!,
                            style: const TextStyle(
                              color: Colors.white,
                              fontSize: 16,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                        ),
                        IconButton(
                          icon: const Icon(Icons.volume_up, color: Colors.white, size: 24),
                          onPressed: () {
                            _sdk.stopSpeaking();
                            _sdk.speak(textToSpeak, languageCode: activeLang);
                          },
                        ),
                      ],
                    ),
                    const Divider(color: Colors.white24, height: 20),

                  Flexible(
                    child: SingleChildScrollView(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.stretch,
                        children: [
                          // Universal Visual Warning Graphic
                          Center(
                            child: ClipRRect(
                              borderRadius: BorderRadius.circular(12),
                              child: Image.asset(
                                'assets/images/hacker_link_warning.png',
                                height: 110,
                                fit: BoxFit.contain,
                                errorBuilder: (context, error, stackTrace) =>
                                    const Icon(Icons.security, size: 70, color: Colors.red),
                              ),
                            ),
                          ),
                          const SizedBox(height: 12),

                          // Scam Category / Tactic Badge
                          Container(
                            padding: const EdgeInsets.symmetric(
                              horizontal: 10,
                              vertical: 6,
                            ),
                            decoration: BoxDecoration(
                              color: themeColor.withOpacity(0.2),
                              borderRadius: BorderRadius.circular(8),
                            ),
                            child: Text(
                              "${event.scamTactic ?? 'SUSPICIOUS_MESSAGE'} - $severityText",
                              style: TextStyle(
                                color: themeColor,
                                fontSize: 12,
                                fontWeight: FontWeight.bold,
                                letterSpacing: 1.1,
                              ),
                              textAlign: TextAlign.center,
                            ),
                          ),
                          const SizedBox(height: 12),

                          // Threat Risk Meter
                          Row(
                            children: [
                              Text(
                                currentTranslations['score']!,
                                style: const TextStyle(color: Colors.white70, fontSize: 12),
                              ),
                              const SizedBox(width: 8),
                              Expanded(
                                child: LinearProgressIndicator(
                                  value: scorePercent,
                                  backgroundColor: Colors.white10,
                                  valueColor: AlwaysStoppedAnimation<Color>(themeColor),
                                  minHeight: 6,
                                ),
                              ),
                              const SizedBox(width: 8),
                              Text(
                                "${event.riskScore}%",
                                style: TextStyle(
                                  color: themeColor,
                                  fontSize: 12,
                                  fontWeight: FontWeight.bold,
                                ),
                              ),
                            ],
                          ),
                          const SizedBox(height: 12),

                          // Raw Intercepted Content
                          Text(
                            currentTranslations['msg']!,
                            style: const TextStyle(
                              color: Colors.white70,
                              fontSize: 12,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                          const SizedBox(height: 6),
                          Container(
                            constraints: const BoxConstraints(maxHeight: 80),
                            decoration: BoxDecoration(
                              color: Colors.black26,
                              borderRadius: BorderRadius.circular(8),
                              border: Border.all(color: Colors.white12),
                            ),
                            child: SingleChildScrollView(
                              padding: const EdgeInsets.all(10),
                              child: Text(
                                event.text,
                                style: const TextStyle(
                                  color: Colors.white,
                                  fontSize: 12,
                                  fontStyle: FontStyle.italic,
                                ),
                              ),
                            ),
                          ),
                          const SizedBox(height: 12),

                          // LLM Explanation
                          if (event.explanation != null &&
                              event.explanation!.isNotEmpty) ...[
                            Text(
                              currentTranslations['ai']!,
                              style: const TextStyle(
                                color: Colors.white70,
                                fontSize: 12,
                                fontWeight: FontWeight.bold,
                              ),
                            ),
                            const SizedBox(height: 6),
                            Container(
                              constraints: const BoxConstraints(maxHeight: 80),
                              child: SingleChildScrollView(
                                child: Text(
                                  event.explanation!,
                                  style: const TextStyle(color: Colors.white, fontSize: 12),
                                ),
                              ),
                            ),
                            const SizedBox(height: 12),
                          ],

                          // LLM Recommended Action
                          if (event.suggestedAction != null &&
                              event.suggestedAction!.isNotEmpty) ...[
                            Text(
                              currentTranslations['rec']!,
                              style: const TextStyle(
                                color: Colors.white70,
                                fontSize: 12,
                                fontWeight: FontWeight.bold,
                              ),
                            ),
                            const SizedBox(height: 6),
                            Container(
                              padding: const EdgeInsets.all(10),
                              decoration: BoxDecoration(
                                color: const Color(0xFF0F172A),
                                borderRadius: BorderRadius.circular(8),
                                border: Border.all(color: const Color(0xFF1E293B)),
                              ),
                              child: Text(
                                event.suggestedAction!,
                                style: const TextStyle(
                                  color: Color(0xFF38BDF8),
                                  fontSize: 12,
                                  fontWeight: FontWeight.w500,
                                ),
                              ),
                            ),
                          ],
                        ],
                      ),
                    ),
                  ),
                  const SizedBox(height: 16),

                  // Action Buttons
                  Row(
                    children: [
                      Expanded(
                        child: OutlinedButton(
                          style: OutlinedButton.styleFrom(
                            side: const BorderSide(color: Colors.white30),
                            shape: RoundedRectangleBorder(
                              borderRadius: BorderRadius.circular(8),
                            ),
                          ),
                          onPressed: () => Navigator.pop(context),
                          child: Row(
                            mainAxisAlignment: MainAxisAlignment.center,
                            children: [
                              const Icon(Icons.shield, color: Colors.green, size: 14),
                              const SizedBox(width: 4),
                              Text(
                                currentTranslations['understand']!,
                                style: const TextStyle(color: Colors.white, fontSize: 11),
                              ),
                            ],
                          ),
                        ),
                      ),
                      const SizedBox(width: 8),
                      Expanded(
                        child: ElevatedButton(
                          style: ElevatedButton.styleFrom(
                            backgroundColor: themeColor,
                            shape: RoundedRectangleBorder(
                              borderRadius: BorderRadius.circular(8),
                            ),
                          ),
                          onPressed: () {
                            Navigator.pop(context);
                            BankGuardApp.navigatorKey.currentState?.pushNamed(
                              '/report',
                              arguments: {
                                'url': event.extractedUrls?.first ?? '',
                                'source': event.sourcePackage,
                                'category':
                                    event.scamTactic ?? 'SUSPICIOUS_MESSAGE',
                                'reportType': 'SMS/WhatsApp',
                              },
                            );
                          },
                          child: Row(
                            mainAxisAlignment: MainAxisAlignment.center,
                            children: [
                              const Icon(Icons.front_hand, color: Colors.white, size: 14),
                              const SizedBox(width: 4),
                              Text(
                                currentTranslations['dontOpen']!,
                                style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 11),
                              ),
                            ],
                          ),
                        ),
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ),
        );
        },
      );
    },
  );
}

void _showVpnThreatAlert(UrlThreatEvent event) {
  final context = BankGuardApp.navigatorKey.currentState?.overlay?.context;
  if (context == null) {
    print('BANKGUARD_APP: Navigator context not available to show VPN threat dialog');
    return;
  }

  showDialog(
    context: context,
    barrierDismissible: true,
    builder: (BuildContext context) {
      bool isFirstLoad = true;
      final _sdk = Bankguard();

      return StatefulBuilder(
        builder: (context, setStateBuilder) {
          final scorePercent = event.riskScore;
          final scoreInt = (scorePercent * 100).toInt();
          final severityText = scoreInt >= 90
              ? "CRITICAL RISK"
              : scoreInt >= 70
              ? "HIGH RISK"
              : "SUSPICIOUS";

          final themeColor = scoreInt >= 70
              ? const Color(0xFFDC2626) // Red
              : const Color(0xFFD97706); // Amber

          final textToSpeak = "BankGuard Link Blocked. Threat Score: $scoreInt percent. Blocked URL: ${event.url}. Block Explanation: ${event.message ?? ''}. Recommended Action: The connection was terminated locally. Do not attempt to bypass this block.";

          if (isFirstLoad) {
            isFirstLoad = false;
            WidgetsBinding.instance.addPostFrameCallback((_) {
              _sdk.speak(textToSpeak, languageCode: 'en');
            });
          }

          return PopScope(
            onPopInvoked: (didPop) {
              if (didPop) {
                _sdk.stopSpeaking();
              }
            },
            child: Dialog(
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
              backgroundColor: Colors.transparent,
              elevation: 0,
              child: Container(
                decoration: BoxDecoration(
                  color: const Color(0xFF1E293B), // Dark slate
                  borderRadius: BorderRadius.circular(16),
                  border: Border.all(color: themeColor.withOpacity(0.5), width: 1.5),
                  boxShadow: [
                    BoxShadow(
                      color: themeColor.withOpacity(0.2),
                      blurRadius: 16,
                      spreadRadius: 4,
                    ),
                  ],
                ),
                padding: const EdgeInsets.all(20),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    Row(
                      children: [
                        Icon(Icons.gpp_bad, color: themeColor, size: 28),
                        const SizedBox(width: 10),
                        const Expanded(
                          child: Text(
                            "BankGuard Link Blocked",
                            style: TextStyle(
                              color: Colors.white,
                              fontSize: 18,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                        ),
                        IconButton(
                          icon: const Icon(Icons.volume_up, color: Colors.white, size: 24),
                          onPressed: () {
                            _sdk.stopSpeaking();
                            _sdk.speak(textToSpeak, languageCode: 'en');
                          },
                        ),
                      ],
                    ),
                    const Divider(color: Colors.white24, height: 20),
                    Flexible(
                      child: SingleChildScrollView(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.stretch,
                          children: [
                            // Universal Visual Warning Graphic
                            Center(
                              child: ClipRRect(
                                borderRadius: BorderRadius.circular(12),
                                child: Image.asset(
                                  'assets/images/site_blocked_warning.png',
                                  height: 120,
                                  fit: BoxFit.contain,
                                  errorBuilder: (context, error, stackTrace) =>
                                      const Icon(Icons.language, size: 80, color: Colors.red),
                                ),
                              ),
                            ),
                            const SizedBox(height: 16),

                            // Scam Category / Tactic Badge
                            Container(
                              padding: const EdgeInsets.symmetric(
                                horizontal: 10,
                                vertical: 6,
                              ),
                              decoration: BoxDecoration(
                                color: themeColor.withOpacity(0.2),
                                borderRadius: BorderRadius.circular(8),
                              ),
                              child: Text(
                                "DNS SINKHOLE BLOCK - $severityText",
                                style: TextStyle(
                                  color: themeColor,
                                  fontSize: 12,
                                  fontWeight: FontWeight.bold,
                                  letterSpacing: 1.1,
                                ),
                                textAlign: TextAlign.center,
                              ),
                            ),
                            const SizedBox(height: 16),

                            // Threat Risk Meter
                            Row(
                              children: [
                                const Text(
                                  "Threat Score:",
                                  style: TextStyle(color: Colors.white70, fontSize: 13),
                                ),
                                const SizedBox(width: 8),
                                Expanded(
                                  child: LinearProgressIndicator(
                                    value: scorePercent,
                                    backgroundColor: Colors.white10,
                                    valueColor: AlwaysStoppedAnimation<Color>(themeColor),
                                    minHeight: 8,
                                  ),
                                ),
                                const SizedBox(width: 8),
                                Text(
                                  "$scoreInt%",
                                  style: TextStyle(
                                    color: themeColor,
                                    fontSize: 13,
                                    fontWeight: FontWeight.bold,
                                  ),
                                ),
                              ],
                            ),
                            const SizedBox(height: 16),

                            // Intercepted Content
                            const Text(
                              "Blocked URL:",
                              style: TextStyle(
                                color: Colors.white70,
                                fontSize: 13,
                                fontWeight: FontWeight.bold,
                              ),
                            ),
                            const SizedBox(height: 6),
                            Container(
                              constraints: const BoxConstraints(maxHeight: 100),
                              decoration: BoxDecoration(
                                color: Colors.black26,
                                borderRadius: BorderRadius.circular(8),
                                border: Border.all(color: Colors.white12),
                              ),
                              child: SingleChildScrollView(
                                padding: const EdgeInsets.all(12),
                                child: Text(
                                  event.url,
                                  style: const TextStyle(
                                    color: Colors.white,
                                    fontSize: 13,
                                    fontStyle: FontStyle.italic,
                                  ),
                                ),
                              ),
                            ),
                            const SizedBox(height: 16),

                            // Explanation
                            if (event.message != null && event.message!.isNotEmpty) ...[
                              const Text(
                                "Block Explanation:",
                                style: TextStyle(
                                  color: Colors.white70,
                                  fontSize: 13,
                                  fontWeight: FontWeight.bold,
                                ),
                              ),
                              const SizedBox(height: 6),
                              Container(
                                constraints: const BoxConstraints(maxHeight: 100),
                                child: SingleChildScrollView(
                                  child: Text(
                                    event.message!,
                                    style: const TextStyle(color: Colors.white, fontSize: 13),
                                  ),
                                ),
                              ),
                              const SizedBox(height: 16),
                            ],

                            const Text(
                              "Security Recommendation:",
                              style: TextStyle(
                                color: Colors.white70,
                                fontSize: 13,
                                fontWeight: FontWeight.bold,
                              ),
                            ),
                            const SizedBox(height: 6),
                            Container(
                              padding: const EdgeInsets.all(10),
                              decoration: BoxDecoration(
                                color: const Color(0xFF0F172A),
                                borderRadius: BorderRadius.circular(8),
                                border: Border.all(color: const Color(0xFF1E293B)),
                              ),
                              child: const Text(
                                "The connection was terminated locally. Do not attempt to bypass this block or use an alternative network connection. Verify any messages requesting payments or KYC updates.",
                                style: TextStyle(
                                  color: Color(0xFF38BDF8),
                                  fontSize: 13,
                                  fontWeight: FontWeight.w500,
                                ),
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                    const SizedBox(height: 20),
                    Row(
                      children: [
                        Expanded(
                          child: OutlinedButton(
                            style: OutlinedButton.styleFrom(
                              side: const BorderSide(color: Colors.white30),
                              shape: RoundedRectangleBorder(
                                borderRadius: BorderRadius.circular(8),
                              ),
                            ),
                            onPressed: () => Navigator.pop(context),
                            child: const Row(
                              mainAxisAlignment: MainAxisAlignment.center,
                              children: [
                                Icon(Icons.shield, color: Colors.green, size: 14),
                                SizedBox(width: 4),
                                Text(
                                  "I Understand",
                                  style: TextStyle(color: Colors.white, fontSize: 12),
                                ),
                              ],
                            ),
                          ),
                        ),
                        const SizedBox(width: 10),
                        Expanded(
                          child: ElevatedButton(
                            style: ElevatedButton.styleFrom(
                              backgroundColor: themeColor,
                              foregroundColor: Colors.white,
                              shape: RoundedRectangleBorder(
                                borderRadius: BorderRadius.circular(8),
                              ),
                            ),
                            onPressed: () => Navigator.pop(context),
                            child: const Row(
                              mainAxisAlignment: MainAxisAlignment.center,
                              children: [
                                Icon(Icons.front_hand, color: Colors.white, size: 14),
                                SizedBox(width: 4),
                                Text(
                                  "SITE BLOCKED",
                                  style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 12),
                                ),
                              ],
                            ),
                          ),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
            ),
          );
        },
      );
    },
  );
}


void _showGlobalApkThreatDialog(ApkFileEvent event) {
  final context = BankGuardApp.navigatorKey.currentState?.overlay?.context;
  if (context == null) {
    print('BANKGUARD_APP: Navigator context not available to show APK dialog');
    return;
  }

  showDialog(
    context: context,
    barrierDismissible: true,
    builder: (BuildContext context) {
      bool isFirstLoad = true;
      final _sdk = Bankguard();

      return StatefulBuilder(
        builder: (context, setStateBuilder) {
          final themeColor = const Color(0xFFD97706); // Amber for warning/don't install
          final textToSpeak = "Malicious APK Downloaded. File Name: ${event.displayName}. Risk Score: ${event.riskScore ?? 0} out of 100. Warning: This package appears to impersonate BankGuard or requests dangerous system permissions. We strongly recommend that you DO NOT install this application.";

          if (isFirstLoad) {
            isFirstLoad = false;
            WidgetsBinding.instance.addPostFrameCallback((_) {
              _sdk.speak(textToSpeak, languageCode: 'en');
            });
          }

          return PopScope(
            onPopInvoked: (didPop) {
              if (didPop) {
                _sdk.stopSpeaking();
              }
            },
            child: Dialog(
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
              backgroundColor: Colors.transparent,
              elevation: 0,
              child: Container(
                decoration: BoxDecoration(
                  color: const Color(0xFF1E293B),
                  borderRadius: BorderRadius.circular(16),
                  border: Border.all(color: themeColor.withOpacity(0.5), width: 1.5),
                  boxShadow: [
                    BoxShadow(
                      color: themeColor.withOpacity(0.2),
                      blurRadius: 16,
                      spreadRadius: 4,
                    ),
                  ],
                ),
                padding: const EdgeInsets.all(20),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    Row(
                      children: [
                        Icon(Icons.gpp_maybe, color: themeColor, size: 28),
                        const SizedBox(width: 10),
                        const Expanded(
                          child: Text(
                            "Malicious APK Downloaded",
                            style: TextStyle(
                              color: Colors.white,
                              fontSize: 18,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                        ),
                        IconButton(
                          icon: const Icon(Icons.volume_up, color: Colors.white, size: 24),
                          onPressed: () {
                            _sdk.stopSpeaking();
                            _sdk.speak(textToSpeak, languageCode: 'en');
                          },
                        ),
                      ],
                    ),
                    const Divider(color: Colors.white24, height: 20),
                    Flexible(
                      child: SingleChildScrollView(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.stretch,
                          children: [
                            // Universal Visual Warning Graphic
                            Center(
                              child: ClipRRect(
                                borderRadius: BorderRadius.circular(12),
                                child: Image.asset(
                                  'assets/images/apk_box_warning.png',
                                  height: 120,
                                  fit: BoxFit.contain,
                                  errorBuilder: (context, error, stackTrace) =>
                                      const Icon(Icons.install_mobile, size: 80, color: Colors.orange),
                                ),
                              ),
                            ),
                            const SizedBox(height: 16),

                            Text(
                              'BankGuard has detected a dangerous app installation package in your storage:',
                              style: TextStyle(
                                color: Colors.white.withOpacity(0.8),
                                fontSize: 13,
                              ),
                            ),
                            const SizedBox(height: 12),

                            _buildInfoRow('File Name', event.displayName),
                            _buildInfoRow('Package', event.packageName ?? 'Unknown'),
                            _buildInfoRow('Risk Score', '${event.riskScore ?? 0} / 100'),
                            const SizedBox(height: 16),

                            Container(
                              padding: const EdgeInsets.all(12),
                              decoration: BoxDecoration(
                                color: Colors.black26,
                                borderRadius: BorderRadius.circular(8),
                                border: Border.all(color: Colors.white12),
                              ),
                              child: const Text(
                                'Warning: This package appears to impersonate BankGuard or requests dangerous system permissions. We strongly recommend that you DO NOT install this application.',
                                style: TextStyle(
                                  color: Colors.orangeAccent,
                                  fontSize: 12,
                                  height: 1.4,
                                ),
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                    const SizedBox(height: 20),
                    Row(
                      children: [
                        Expanded(
                          child: OutlinedButton(
                            style: OutlinedButton.styleFrom(
                              side: const BorderSide(color: Colors.white30),
                              shape: RoundedRectangleBorder(
                                borderRadius: BorderRadius.circular(8),
                              ),
                            ),
                            onPressed: () => Navigator.pop(context),
                            child: const FittedBox(
                              fit: BoxFit.scaleDown,
                              child: Row(
                                mainAxisAlignment: MainAxisAlignment.center,
                                children: [
                                  Icon(Icons.shield, color: Colors.green, size: 14),
                                  SizedBox(width: 4),
                                  Text(
                                    "I Understand",
                                    style: TextStyle(color: Colors.white, fontSize: 12),
                                  ),
                                ],
                              ),
                            ),
                          ),
                        ),
                        const SizedBox(width: 10),
                        Expanded(
                          child: ElevatedButton(
                            style: ElevatedButton.styleFrom(
                              backgroundColor: themeColor,
                              foregroundColor: Colors.white,
                              shape: RoundedRectangleBorder(
                                borderRadius: BorderRadius.circular(8),
                              ),
                            ),
                            onPressed: () {
                              Navigator.pop(context);
                              BankGuardApp.navigatorKey.currentState?.pushNamed(
                                '/report',
                                arguments: {
                                  'url': event.displayName,
                                  'source': event.packageName ?? 'download',
                                  'category': 'MALICIOUS_APK',
                                  'reportType': 'APK',
                                },
                              );
                            },
                            child: const FittedBox(
                              fit: BoxFit.scaleDown,
                              child: Row(
                                mainAxisAlignment: MainAxisAlignment.center,
                                children: [
                                  Icon(Icons.front_hand, color: Colors.white, size: 14),
                                  SizedBox(width: 4),
                                  Text(
                                    "DON'T INSTALL",
                                    style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 11),
                                  ),
                                ],
                              ),
                            ),
                          ),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
            ),
          );
        },
      );
    },
  );
}

Widget _buildInfoRow(String label, String value) {
  return Padding(
    padding: const EdgeInsets.symmetric(vertical: 4),
    child: Row(
      mainAxisAlignment: MainAxisAlignment.spaceBetween,
      children: [
        Text(
          label,
          style: const TextStyle(color: Colors.white60, fontSize: 12),
        ),
        Text(
          value,
          style: const TextStyle(
            color: Colors.white,
            fontSize: 12,
            fontWeight: FontWeight.bold,
          ),
        ),
      ],
    ),
  );
}

class BankGuardApp extends StatefulWidget {
  const BankGuardApp({super.key});

  static final GlobalKey<NavigatorState> navigatorKey =
      GlobalKey<NavigatorState>();
  static bool isSplashActive = true;
  static String? pendingDeepLinkRoute;
  static Map<String, dynamic>? pendingDeepLinkArgs;

  @override
  State<BankGuardApp> createState() => _BankGuardAppState();
}

class _BankGuardAppState extends State<BankGuardApp>
    with WidgetsBindingObserver {
  static const _channel = MethodChannel('bankguard_deeplink');

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    // Check for initial deep link (cold start from notification action)
    _handleInitialDeepLink();
    // Listen for deep links while app is running
    _channel.setMethodCallHandler(_handleDeepLinkMethodCall);
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  Future<void> _handleInitialDeepLink() async {
    // Give the app time to build the widget tree
    await Future.delayed(const Duration(milliseconds: 500));
    try {
      final String? initialUri = await _channel.invokeMethod('getInitialUri');
      if (initialUri != null && initialUri.isNotEmpty) {
        _routeDeepLink(Uri.parse(initialUri));
      }
    } catch (_) {
      // MethodChannel not available (non-Android or channel not registered)
    }
  }

  Future<dynamic> _handleDeepLinkMethodCall(MethodCall call) async {
    if (call.method == 'onDeepLink') {
      final uri = Uri.parse(call.arguments as String);
      _routeDeepLink(uri);
    }
    return null;
  }

  void _routeDeepLink(Uri uri) {
    if (uri.scheme != 'bankguard') return;

    String? route;
    Map<String, dynamic>? args;

    switch (uri.host) {
      case 'verify':
        route = '/verify-link';
        args = {'url': uri.queryParameters['url'] ?? ''};
        break;
      case 'report':
        route = '/report';
        args = {
          'url': uri.queryParameters['url'] ?? '',
          'source': uri.queryParameters['source'] ?? '',
          'category': uri.queryParameters['category'] ?? '',
          'reportType': 'URL',
        };
        break;
    }

    if (route != null) {
      if (BankGuardApp.isSplashActive) {
        BankGuardApp.pendingDeepLinkRoute = route;
        BankGuardApp.pendingDeepLinkArgs = args;
        print(
          "BANKGUARD_APP: Deferring deep link route $route to post-splash phase",
        );
      } else {
        BankGuardApp.navigatorKey.currentState?.pushNamed(
          route,
          arguments: args,
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'BankGuard',
      debugShowCheckedModeBanner: false,
      navigatorKey: BankGuardApp.navigatorKey,
      theme: ThemeData(
        primaryColor: const Color(0xFF1E3A8A),
        scaffoldBackgroundColor: Colors.white,
        appBarTheme: const AppBarTheme(
          backgroundColor: Color(0xFF1E3A8A),
          foregroundColor: Colors.white,
        ),
        elevatedButtonTheme: ElevatedButtonThemeData(
          style: ElevatedButton.styleFrom(
            backgroundColor: const Color(0xFF1E3A8A),
            foregroundColor: Colors.white,
          ),
        ),
        colorScheme: ColorScheme.fromSeed(seedColor: const Color(0xFF1E3A8A)),
      ),
      initialRoute: '/',
      onGenerateRoute: (settings) {
        final args = settings.arguments as Map<String, dynamic>?;

        switch (settings.name) {
          case '/':
            return MaterialPageRoute(builder: (_) => const SplashScreen());
          case '/login':
            return MaterialPageRoute(builder: (_) => const LoginScreen());
          case '/report':
            return MaterialPageRoute(
              builder: (_) => ReportFraudScreen(initialArgs: args),
            );
          case '/home':
            return MaterialPageRoute(builder: (_) => const HomeScreen());
          case '/upi-payment':
            return MaterialPageRoute(builder: (_) => const UpiPaymentScreen());
          case '/fund-transfer':
            return MaterialPageRoute(
              builder: (_) => const FundTransferScreen(),
            );
          case '/transactions':
            return MaterialPageRoute(
              builder: (_) => const TransactionHistoryScreen(),
            );
          case '/verify-link':
            return MaterialPageRoute(
              builder: (_) =>
                  VerifyLinkScreen(initialUrl: args?['url'] as String?),
            );
          case '/soc-diagnostics':
            return MaterialPageRoute(
              builder: (_) => const SocDiagnosticsScreen(),
            );
          case '/safety-academy':
            return MaterialPageRoute(
              builder: (_) => const SafetyAcademyScreen(),
            );
          case '/sim-verification':
            return MaterialPageRoute(
              builder: (_) => SimVerificationScreen(
                customerId: args?['customerId'] as String? ?? '',
                newSimHash: args?['newSimHash'] as String? ?? '',
              ),
            );
          case '/telco-lab':
            return MaterialPageRoute(builder: (_) => const TelcoLabScreen());
          case '/security-alerts':
            return MaterialPageRoute(builder: (_) => const SecurityAlertsScreen());
          default:
            return MaterialPageRoute(builder: (_) => const SplashScreen());
        }
      },
    );
  }
}
