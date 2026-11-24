import 'dart:async';
import 'package:bankguard/bankguard.dart';

class SecurityAlert {
  final String id;
  final String type; // 'SMS/WhatsApp', 'URL Block', 'APK Threat'
  final String title;
  final String message;
  final int riskScore;
  final String explanation;
  final String suggestedAction;
  final DateTime timestamp;
  final String sourceApp;
  final bool isLocalOnly;
  final String? sender;
  final String? senderFlag;

  SecurityAlert({
    required this.id,
    required this.type,
    required this.title,
    required this.message,
    required this.riskScore,
    required this.explanation,
    required this.suggestedAction,
    required this.timestamp,
    required this.sourceApp,
    this.isLocalOnly = true,
    this.sender,
    this.senderFlag,
  });

  factory SecurityAlert.fromJson(Map<String, dynamic> json) {
    // Map backend response models to SecurityAlert
    final type = json['report_type'] ?? 'URL';
    final content = json['content'] ?? '';
    final riskScoreFloat = json['risk_score'] ?? 0.8;
    final riskScore = (riskScoreFloat * 100).toInt();
    final reportedAt = json['reported_at'] != null 
        ? DateTime.parse(json['reported_at']) 
        : DateTime.now();

    String title = 'Threat Logged';
    String explanation = 'Report submitted and logged to BankGuard Cyber Intelligence dashboard.';
    String suggestedAction = 'The bank security team is taking down this domain/app. No user action required.';

    if (type == 'URL') {
      title = 'Phishing URL Reported';
      explanation = 'Phishing link was logged to central security registry: $content';
    } else if (type == 'APK') {
      title = 'Malicious APK Reported';
      explanation = 'Suspicious package or installer name logged: $content';
    } else if (type == 'SMS' || type == 'SMS/WhatsApp') {
      title = 'Smishing Attempt Reported';
      explanation = 'Smishing SMS text logged for analysis: $content';
    }

    return SecurityAlert(
      id: 'backend_${json['id']}',
      type: type == 'URL' ? 'URL Block' : (type == 'APK' ? 'APK Threat' : 'SMS/WhatsApp'),
      title: title,
      message: content,
      riskScore: riskScore,
      explanation: explanation,
      suggestedAction: suggestedAction,
      timestamp: reportedAt.toLocal(),
      sourceApp: json['source'] ?? 'System',
      isLocalOnly: false,
      sender: json['sender'],
      senderFlag: json['sender_flag'],
    );
  }
}

class SecurityAlertsStorage {
  // Local list to keep track of real-time intercepted events
  static final List<SecurityAlert> _localAlerts = [
    SecurityAlert(
      id: 'local_1',
      type: 'SMS/WhatsApp',
      title: 'KYC Phishing SMS Blocked',
      message: 'Dear Customer, your bank account will be blocked today. Please update your KYC immediately at: http://bank-kyc-verify.com',
      riskScore: 94,
      explanation: 'Message contains a high-urgency account blocking threat with a lookalike domain impersonating the bank.',
      suggestedAction: 'Do not open the link or share OTPs. The domain has been blacklisted.',
      timestamp: DateTime.now().subtract(const Duration(hours: 2)),
      sourceApp: 'SMS Messaging',
      isLocalOnly: true,
    ),
    SecurityAlert(
      id: 'local_2',
      type: 'URL Block',
      title: 'Phishing Connection Intercepted',
      message: 'http://bankguard-login-portal.net/login.php',
      riskScore: 98,
      explanation: 'VPN Sinkhole intercepted a connection request to an unregistered lookalike banking portal.',
      suggestedAction: 'Connection terminated. Verify official URLs inside BankGuard Trust Intelligence.',
      timestamp: DateTime.now().subtract(const Duration(hours: 4)),
      sourceApp: 'VPN Intercept',
      isLocalOnly: true,
    ),
    SecurityAlert(
      id: 'local_3',
      type: 'APK Threat',
      title: 'Unofficial APK Detected',
      message: 'bankguard_helper.apk',
      riskScore: 88,
      explanation: 'Detected side-loaded Android package mimicking banking branding with an invalid signature.',
      suggestedAction: 'Uninstall the application immediately. Download banking apps only from the official Play Store.',
      timestamp: DateTime.now().subtract(const Duration(days: 1)),
      sourceApp: 'File Scanner',
      isLocalOnly: true,
    ),
  ];

  static final _streamController = StreamController<List<SecurityAlert>>.broadcast();

  static Stream<List<SecurityAlert>> get alertsStream => _streamController.stream;

  static void addLocalAlert(SecurityAlert alert) {
    _localAlerts.insert(0, alert);
    _streamController.add(getLocalAlerts());
  }

  static List<SecurityAlert> getLocalAlerts() {
    return List.unmodifiable(_localAlerts);
  }

  static void clearLocalAlerts() {
    _localAlerts.clear();
    _streamController.add(getLocalAlerts());
  }

  /// Fetches both remote threat reports and local intercepts, then merges them sorted by timestamp.
  static Future<List<SecurityAlert>> fetchCombinedAlerts() async {
    final sdk = Bankguard();
    List<SecurityAlert> combined = [];

    // 1. Fetch remote reports
    try {
      final backendData = await sdk.getBackendReports();
      final remoteAlerts = backendData.map((json) => SecurityAlert.fromJson(json)).toList();
      combined.addAll(remoteAlerts);
    } catch (e) {
      print('Failed to fetch backend reports: $e');
    }

    // 2. Add local intercepts
    combined.addAll(_localAlerts);

    // 3. Sort by timestamp descending
    combined.sort((a, b) => b.timestamp.compareTo(a.timestamp));

    return combined;
  }
}
