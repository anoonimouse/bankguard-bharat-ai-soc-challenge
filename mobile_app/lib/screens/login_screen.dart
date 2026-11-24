import 'package:flutter/material.dart';
import 'package:bankguard/bankguard.dart';

class LoginScreen extends StatefulWidget {
  const LoginScreen({super.key});

  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen> {
  final _mpinController = TextEditingController();
  final _sdk = Bankguard();

  @override
  void dispose() {
    _mpinController.dispose();
    super.dispose();
  }

  Future<void> _handleLogin() async {
    // Run device scan to check for active threats before login
    final scanEvent = await _sdk.runDeviceScan();
    
    final criticalThreats = scanEvent.threats.where((t) {
      return t.startsWith("SUSPICIOUS_PACKAGE_DETECTED") ||
             t.startsWith("VERIFIED_MALICIOUS_PACKAGE") ||
             t.startsWith("SELF_TAMPER_DETECTED") ||
             t == "UNKNOWN_SOURCES_ENABLED";
    }).toList();

    if (criticalThreats.isNotEmpty) {
      if (mounted) {
        showDialog(
          context: context,
          barrierDismissible: false,
          builder: (context) => AlertDialog(
            title: const Row(
              children: [
                Icon(Icons.gpp_bad, color: Colors.red, size: 28),
                SizedBox(width: 8),
                Text("Login Blocked", style: TextStyle(color: Colors.red, fontWeight: FontWeight.bold)),
              ],
            ),
            content: Text(
              "Access is blocked because active threats were detected on your device:\n\n"
              "${criticalThreats.map((t) => '• $t').join('\n')}\n\n"
              "Please uninstall the threat apps or disable unknown sources before logging in.",
            ),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(context),
                child: const Text("OK"),
              ),
              ElevatedButton(
                style: ElevatedButton.styleFrom(backgroundColor: Colors.red),
                onPressed: () {
                  Navigator.pop(context);
                  Navigator.pushNamed(context, '/security-alerts');
                },
                child: const Text("View in Security Center"),
              ),
            ],
          ),
        );
      }
      return;
    }

    // MPIN is hardcoded as 1234 for the mock banking app
    if (_mpinController.text == '1234') {
      Navigator.pushReplacementNamed(context, '/home');
    } else {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Incorrect MPIN. Try 1234.')),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('BankGuard'),
        centerTitle: true,
        actions: [
          IconButton(
            icon: const Icon(Icons.security),
            tooltip: 'Report Fraud',
            onPressed: () {
              Navigator.pushNamed(context, '/report');
            },
          ),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(24.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const SizedBox(height: 40),
            GestureDetector(
              onLongPress: () {
                Navigator.pushNamed(context, '/telco-lab');
              },
              child: const Icon(
                Icons.shield,
                size: 80,
                color: Color(0xFF1E3A8A),
              ),
            ),
            const SizedBox(height: 24),
            const Text(
              "Welcome to BankGuard",
              textAlign: TextAlign.center,
              style: TextStyle(
                fontSize: 28,
                fontWeight: FontWeight.bold,
                color: Color(0xFF1E3A8A),
              ),
            ),
            const SizedBox(height: 8),
            const Text(
              "Your Secure Digital Guardian.",
              textAlign: TextAlign.center,
              style: TextStyle(fontSize: 16, color: Colors.grey),
            ),
            const SizedBox(height: 48),

            TextFormField(
              controller: _mpinController,
              decoration: const InputDecoration(
                labelText: 'MPIN',
                border: OutlineInputBorder(),
                prefixIcon: Icon(Icons.lock_outline),
              ),
              keyboardType: TextInputType.number,
              obscureText: true,
              maxLength: 4,
              onFieldSubmitted: (_) => _handleLogin(),
            ),
            const SizedBox(height: 24),
            ElevatedButton(
              onPressed: _handleLogin,
              style: ElevatedButton.styleFrom(
                padding: const EdgeInsets.symmetric(vertical: 16),
                textStyle: const TextStyle(
                  fontSize: 18,
                  fontWeight: FontWeight.bold,
                ),
              ),
              child: const Text("Login"),
            ),
            const SizedBox(height: 16),
            TextButton(onPressed: () {}, child: const Text("Forgot MPIN?")),

            const SizedBox(height: 48),
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: Colors.green.shade50,
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: Colors.green.shade200),
              ),
              child: const Row(
                children: [
                  Icon(Icons.verified_user, color: Colors.green),
                  SizedBox(width: 12),
                  Expanded(
                    child: Text(
                      "BankGuard Security is Active.\nYour device is protected against overlay and phishing attacks.",
                      style: TextStyle(color: Colors.green, fontSize: 13),
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}
