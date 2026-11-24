/// # Bankguard SDK - Example Integration
///
/// This example demonstrates how to integrate the Bankguard mobile banking
/// security SDK into a Flutter app. It shows initialization, device scanning,
/// UPI fraud checking, batch FRI lookups, and URL scanning.
///
/// In production, you would wire the callbacks to your app's alert system,
/// transaction blocking logic, and user notification framework.
library;

import 'package:flutter/material.dart';
import 'package:bankguard/bankguard.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // --- Step 1: Initialize the SDK ---------------------------------------
  // Call once at app startup. The SDK manages its own lifecycle after this.
  // All security configuration is injected via BankguardConfig.
  await Bankguard.initialize(
    config: const BankguardConfig(
      // Your backend URL for FRI lookups, URL scanning, and telemetry
      backendBaseUrl: 'https://your-backend.example.com',
      // The official banking app package name for whitelist verification
      officialPackageName: 'com.yourbank.app',
      // SHA-256 certificate hash of the official banking app
      officialCertHash: 'AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99',
      // Your own app's package name (for self-integrity checks)
      expectedSelfPackage: 'com.yourbank.app',
      // Optional: disable specific features
      features: BankguardFeatures(
        deviceScan: true,
        packageScan: true,
        notificationInterception: true,
        callScreening: true,
        friEnabled: true,
        urlScanning: true,
        telemetryEnabled: true,
      ),
    ),
    callbacks: BankguardCallbacks(
      // --- Step 2: React to security events ---------------------------
      onDeviceScanComplete: (event) {
        debugPrint('Device secure: ${event.isSecure}');
        debugPrint('Threats found: ${event.threats}');
      },
      onFakeAppDetected: (event) {
        debugPrint('FAKE APP: ${event.packageName} (${event.threatType})');
      },
      onSuspiciousNotification: (event) {
        debugPrint('THREAT NOTIFICATION: ${event.verdict} '
            '(score: ${event.riskScore}, category: ${event.primaryCategory})');
      },
      onSuspiciousCall: (event) {
        debugPrint('SUSPICIOUS CALL: ${event.phoneNumber} '
            '(FRI: ${event.fraudCategory})');
      },
      onFriMatch: (event) {
        debugPrint(
            'FRI MATCH: ${event.identifierType} = ${event.identifierValue} '
            '(${event.riskLevel})');
      },
      onUrlThreat: (event) {
        debugPrint('URL THREAT: ${event.url} (score: ${event.riskScore})');
      },
    ),
  );

  runApp(const BankguardExampleApp());
}

class BankguardExampleApp extends StatelessWidget {
  const BankguardExampleApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Bankguard Example',
      theme: ThemeData(
        colorSchemeSeed: const Color(0xFF1E3A8A),
        useMaterial3: true,
      ),
      home: const SecurityDashboard(),
    );
  }
}

class SecurityDashboard extends StatefulWidget {
  const SecurityDashboard({super.key});

  @override
  State<SecurityDashboard> createState() => _SecurityDashboardState();
}

class _SecurityDashboardState extends State<SecurityDashboard> {
  final _sdk = Bankguard.instance;
  final List<String> _log = [];

  void _addLog(String msg) => setState(() => _log.insert(0, msg));

  // --- Step 3: On-demand security checks ------------------------------

  Future<void> _runDeviceScan() async {
    _addLog('Running device scan...');
    final result = await _sdk.runDeviceScan();
    _addLog(result.isSecure
        ? '[OK] Device is secure'
        : '[WARN] ${result.threats.length} threats found');
  }

  Future<void> _checkUpi() async {
    _addLog('Checking UPI ID: test@upi...');
    final result = await _sdk.checkUPIId('test@upi');
    _addLog(result?.found == true
        ? '[ALERT] UPI flagged: ${result!.reason}'
        : '[OK] UPI ID is clean');
  }

  Future<void> _batchCheck() async {
    _addLog('Running batch FRI check...');
    final results = await _sdk.checkBatch([
      FriBatchItem(identifierType: 'upi', identifierValue: 'test@upi'),
      FriBatchItem(identifierType: 'mobile', identifierValue: '9876543210'),
    ]);
    final hits = results.where((r) => r.found).length;
    _addLog('Batch: $hits/${results.length} identifiers flagged');
  }

  Future<void> _scanUrl() async {
    _addLog('Scanning URL...');
    final result = await _sdk.scanUrl('https://sbi-kyc-update.fake.com');
    _addLog(result != null && !result.isSafe
        ? '[ALERT] Phishing: ${result.message}'
        : '[OK] URL appears safe');
  }

  Future<void> _scanQR() async {
    _addLog('Scanning QR payload...');
    final result = await _sdk
        .scanQRPayload('upi://pay?pa=merchant@upi&pn=Merchant&am=500');
    _addLog(result.isFraud
        ? '[ALERT] QR payee is fraudulent!'
        : '[OK] QR payee verified: ${result.payeeAddress}');
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Bankguard Demo')),
      body: Column(
        children: [
          Padding(
            padding: const EdgeInsets.all(16),
            child: Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                ElevatedButton(
                    onPressed: _runDeviceScan,
                    child: const Text('Device Scan')),
                ElevatedButton(
                    onPressed: _checkUpi, child: const Text('Check UPI')),
                ElevatedButton(
                    onPressed: _batchCheck, child: const Text('Batch Check')),
                ElevatedButton(
                    onPressed: _scanUrl, child: const Text('Scan URL')),
                ElevatedButton(
                    onPressed: _scanQR, child: const Text('Scan QR')),
              ],
            ),
          ),
          const Divider(),
          Expanded(
            child: ListView.builder(
              padding: const EdgeInsets.all(16),
              itemCount: _log.length,
              itemBuilder: (_, i) => Text(_log[i],
                  style: TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 13,
                    color: _log[i].contains('[ALERT]')
                        ? Colors.red
                        : _log[i].contains('[WARN]')
                            ? Colors.orange
                            : null,
                  )),
            ),
          ),
        ],
      ),
    );
  }
}
