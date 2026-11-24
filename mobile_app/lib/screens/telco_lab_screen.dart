import 'package:flutter/material.dart';
import 'package:bankguard/bankguard.dart';
import '../data/dummy_data.dart';

class TelcoLabScreen extends StatefulWidget {
  const TelcoLabScreen({super.key});

  @override
  State<TelcoLabScreen> createState() => _TelcoLabScreenState();
}

class _TelcoLabScreenState extends State<TelcoLabScreen> {
  final _sdk = Bankguard();
  bool _isLoading = false;

  // Telco state
  bool _simSwapActive = false;
  String _telcoStatusMessage = "No active SIM swap simulated.";

  // Silent SMS states
  String _handshakeStep =
      "Idle"; // Idle -> NonceFetched -> Signed -> Verifying -> Success / Failed
  String? _nonce;
  String? _signature;
  String _handshakeLog = "";

  // VPN states
  bool _vpnRunning = false;
  String _vpnStatusMessage = "DNS Shield is inactive.";

  // File Interceptor states
  Map<String, dynamic>? _fileScanResult;
  String _fileScanMessage = "No simulated file scans run yet.";

  @override
  void initState() {
    super.initState();
    _checkInitialStatus();
    _sdk.onSilentSmsInvalidatedListener = () {
      _log(
        "[!] Security Alert: Application entered background during registration. Nonce invalidated.",
      );
      setState(() {
        _handshakeStep = "Invalidated (Background)";
      });
    };
  }

  @override
  void dispose() {
    _sdk.onSilentSmsInvalidatedListener = null;
    super.dispose();
  }

  Future<void> _checkInitialStatus() async {
    setState(() {
      _simSwapActive = false;
      _vpnRunning = true;
      _vpnStatusMessage = "Priority 999 Intent Handler Registered.";
    });
  }

  Future<void> _requestDefaultBrowser() async {
    setState(() {
      _isLoading = true;
    });
    try {
      final success = await _sdk.requestDefaultBrowserRole();
      if (success) {
        _log("Settings: Successfully requested Default Browser role.");
      } else {
        _log("Settings: Default Browser role request returned false.");
      }
    } catch (e) {
      _log("Error requesting default browser: $e");
    } finally {
      setState(() {
        _isLoading = false;
      });
    }
  }

  Future<void> _simulateFileScan() async {
    setState(() {
      _isLoading = true;
      _fileScanMessage = "Generating spoofed file...";
      _fileScanResult = null;
    });
    try {
      final filePath = await _sdk.simulateCreateSpoofedFile();
      if (filePath == null) {
        setState(() {
          _fileScanMessage = "Error: Failed to write spoofed file to cache.";
        });
        return;
      }

      _log("File Interceptor: Spoofed file written to $filePath");
      setState(() {
        _fileScanMessage = "Scanning file header and ZIP records...";
      });

      final result = await _sdk.verifyFileMagicBytes(filePath);
      setState(() {
        _fileScanResult = result;
        if (result['isPolyglot'] == true) {
          _fileScanMessage =
              "ALERT! extension spoofing detected!\n"
              "File declared as: ${result['fileName']} (MIME: ${result['declaredMime']})\n"
              "Internal structure detected as: Android APK (MIME: ${result['detectedMime']})\n"
              "This polyglot file was flagged and reported to the backend.";
        } else {
          _fileScanMessage = "Scan complete. File appears normal.";
        }
      });
      _log(
        result['isPolyglot'] == true
            ? "File Interceptor ALERT: Polyglot APK detected (${result['fileName']})!"
            : "File Interceptor: File scan completed successfully.",
      );
    } catch (e) {
      setState(() {
        _fileScanMessage = "Scan failed: $e";
      });
    } finally {
      setState(() {
        _isLoading = false;
      });
    }
  }

  void _log(String message) {
    setState(() {
      _handshakeLog +=
          "[${DateTime.now().toLocal().toString().substring(11, 19)}] $message\n";
    });
  }

  Future<void> _simulateSwap(bool active) async {
    setState(() {
      _isLoading = true;
    });
    try {
      final res = await _sdk.simulateTelecomSimSwap(
        phoneNumber: CustomerData.customerId,
        hoursAgo: active ? 2 : null,
      );

      setState(() {
        _simSwapActive = active;
        _telcoStatusMessage =
            res['message'] ??
            (active ? "SIM swap set to 2 hours ago." : "SIM swap cleared.");
      });
      _log(
        active
            ? "Carrier Alert: SIM Swap registry updated (Active)."
            : "Carrier Registry cleared.",
      );
    } catch (e) {
      setState(() {
        _telcoStatusMessage = "Failed to update telecom registry: $e";
      });
    } finally {
      setState(() {
        _isLoading = false;
      });
    }
  }

  Future<void> _runSilentSmsLoop() async {
    setState(() {
      _handshakeStep = "Initiating";
      _handshakeLog = "";
      _nonce = null;
      _signature = null;
    });

    _log("1. Requesting challenge nonce from backend...");
    try {
      // Step 1: Trigger Silent SMS
      final triggerRes = await _sdk.triggerSilentSmsChallenge(
        customerId: CustomerData.customerId,
      );
      if (triggerRes['success'] != true) {
        _log("Error: Failed to generate challenge nonce.");
        setState(() => _handshakeStep = "Failed");
        return;
      }

      final nonce = triggerRes['nonce'];
      setState(() {
        _nonce = nonce;
        _handshakeStep = "NonceFetched";
      });
      _log("Nonce received: $nonce");
      _log("2. Invoking native MethodChannel to sign challenge...");

      // Step 2: Sign Challenge on-device natively
      final signature = await _sdk.signSilentSmsChallenge(nonce);
      if (signature == null) {
        _log("Error: On-device signature creation failed.");
        setState(() => _handshakeStep = "Failed");
        return;
      }

      setState(() {
        _signature = signature;
        _handshakeStep = "Signed";
      });
      _log("Signature created on device (HMAC-SHA256): $signature");
      _log("3. Sending signature back to backend for verification...");

      // Step 3: Verify on Backend
      final verifyRes = await _sdk.verifySilentSmsChallenge(
        customerId: CustomerData.customerId,
        nonce: nonce,
        signature: signature,
      );

      if (verifyRes['success'] == true) {
        _log("Verification SUCCESS: binding confirmed.");
        setState(() => _handshakeStep = "Success");
      } else {
        _log("Verification FAILED: profile locked on backend.");
        setState(() => _handshakeStep = "Failed");
      }
    } catch (e) {
      _log("Error: Network or SDK error occurred: $e");
      setState(() => _handshakeStep = "Failed");
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0F172A), // Premium Dark Slate
      appBar: AppBar(
        title: const Text('Telco Security Lab'),
        backgroundColor: const Color(0xFF1E293B),
        elevation: 0,
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(20.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            _buildInfoCard(),
            const SizedBox(height: 20),
            _buildCarrierSimulatorCard(),
            const SizedBox(height: 20),
            _buildSilentSmsCard(),
            const SizedBox(height: 20),
            _buildVpnCard(),
            const SizedBox(height: 20),
            _buildFileInterceptorCard(),
            const SizedBox(height: 24),
          ],
        ),
      ),
    );
  }

  Widget _buildInfoCard() {
    return Card(
      color: const Color(0xFF1E293B),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
      child: Padding(
        padding: const EdgeInsets.all(18.0),
        child: Row(
          children: [
            Icon(
              Icons.terminal_outlined,
              color: Colors.blueAccent.shade200,
              size: 36,
            ),
            const SizedBox(width: 16),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text(
                    "Simulation & Diagnostics Console",
                    style: TextStyle(
                      color: Colors.white,
                      fontSize: 16,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    "Target Customer ID: ${CustomerData.customerId}",
                    style: TextStyle(
                      color: Colors.grey.shade400,
                      fontSize: 13,
                      fontFamily: 'monospace',
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

  Widget _buildCarrierSimulatorCard() {
    return Card(
      color: const Color(0xFF1E293B),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
      child: Padding(
        padding: const EdgeInsets.all(20.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Row(
              children: [
                Icon(
                  Icons.cell_tower_rounded,
                  color: _simSwapActive ? Colors.redAccent : Colors.greenAccent,
                ),
                const SizedBox(width: 12),
                const Text(
                  "GSMA Carrier Registry Mock",
                  style: TextStyle(
                    color: Colors.white,
                    fontSize: 16,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 12),
            const Text(
              "Allows setting a carrier-level SIM swap timestamp to simulate an off-device hijack.",
              style: TextStyle(
                color: Colors.white70,
                fontSize: 13,
                height: 1.4,
              ),
            ),
            const SizedBox(height: 16),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Colors.black26,
                borderRadius: BorderRadius.circular(10),
                border: Border.all(
                  color: _simSwapActive
                      ? Colors.redAccent.withOpacity(0.3)
                      : Colors.greenAccent.withOpacity(0.3),
                ),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Container(
                        width: 8,
                        height: 8,
                        decoration: BoxDecoration(
                          shape: BoxShape.circle,
                          color: _simSwapActive
                              ? Colors.redAccent
                              : Colors.greenAccent,
                        ),
                      ),
                      const SizedBox(width: 8),
                      Text(
                        _simSwapActive
                            ? "ACTIVE SIM SWAP (Fraud State)"
                            : "SECURE (Normal State)",
                        style: TextStyle(
                          color: _simSwapActive
                              ? Colors.redAccent
                              : Colors.greenAccent,
                          fontWeight: FontWeight.bold,
                          fontSize: 12,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 6),
                  Text(
                    _telcoStatusMessage,
                    style: const TextStyle(color: Colors.white54, fontSize: 12),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 16),
            Row(
              children: [
                Expanded(
                  child: ElevatedButton(
                    onPressed: _isLoading ? null : () => _simulateSwap(true),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: Colors.redAccent.shade700,
                      foregroundColor: Colors.white,
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(10),
                      ),
                    ),
                    child: const Text("Simulate Swap"),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: OutlinedButton(
                    onPressed: _isLoading ? null : () => _simulateSwap(false),
                    style: OutlinedButton.styleFrom(
                      side: const BorderSide(color: Colors.grey),
                      foregroundColor: Colors.white,
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(10),
                      ),
                    ),
                    child: const Text("Clear Registry"),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildSilentSmsCard() {
    Color stepColor = Colors.grey;
    if (_handshakeStep == "Success") {
      stepColor = Colors.greenAccent;
    } else if (_handshakeStep == "Failed") {
      stepColor = Colors.redAccent;
    } else if (_handshakeStep != "Idle") {
      stepColor = Colors.amberAccent;
    }

    return Card(
      color: const Color(0xFF1E293B),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
      child: Padding(
        padding: const EdgeInsets.all(20.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Row(
              children: [
                Icon(Icons.sms_failed_outlined, color: stepColor),
                const SizedBox(width: 12),
                const Text(
                  "Silent SMS Binding Check",
                  style: TextStyle(
                    color: Colors.white,
                    fontSize: 16,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 12),
            const Text(
              "Initiate an on-demand cryptographic challenge to ensure this physical device matches the registered SIM number.",
              style: TextStyle(
                color: Colors.white70,
                fontSize: 13,
                height: 1.4,
              ),
            ),
            const SizedBox(height: 16),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Colors.black26,
                borderRadius: BorderRadius.circular(10),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    "Handshake Status: $_handshakeStep",
                    style: TextStyle(
                      color: stepColor,
                      fontWeight: FontWeight.bold,
                      fontSize: 13,
                    ),
                  ),
                  if (_handshakeLog.isNotEmpty) ...[
                    const Divider(color: Colors.white24, height: 16),
                    Text(
                      _handshakeLog,
                      style: const TextStyle(
                        fontFamily: 'monospace',
                        color: Colors.white70,
                        fontSize: 11,
                        height: 1.3,
                      ),
                    ),
                  ],
                ],
              ),
            ),
            const SizedBox(height: 16),
            ElevatedButton(
              onPressed: _isLoading ? null : _runSilentSmsLoop,
              style: ElevatedButton.styleFrom(
                backgroundColor: Colors.blueAccent.shade700,
                foregroundColor: Colors.white,
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(10),
                ),
              ),
              child: const Text("Perform Cryptographic Binding Check"),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildVpnCard() {
    return Card(
      color: const Color(0xFF1E293B),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
      child: Padding(
        padding: const EdgeInsets.all(20.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Row(
              children: [
                Icon(
                  Icons.link_outlined,
                  color: Colors.greenAccent,
                ),
                const SizedBox(width: 12),
                const Text(
                  "Link Interception Gate",
                  style: TextStyle(
                    color: Colors.white,
                    fontSize: 16,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 12),
            const Text(
              "Standard HTTP/HTTPS Intent Interception catches unverified redirects system-wide before any browser loads them, protecting credentials from lookalike phishing templates.",
              style: TextStyle(
                color: Colors.white70,
                fontSize: 13,
                height: 1.4,
              ),
            ),
            const SizedBox(height: 16),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Colors.black26,
                borderRadius: BorderRadius.circular(10),
                border: Border.all(
                  color: Colors.greenAccent.withOpacity(0.3),
                ),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Container(
                        width: 8,
                        height: 8,
                        decoration: const BoxDecoration(
                          shape: BoxShape.circle,
                          color: Colors.greenAccent,
                        ),
                      ),
                      const SizedBox(width: 8),
                      const Text(
                        "GATE ACTIVE",
                        style: TextStyle(
                          color: Colors.greenAccent,
                          fontWeight: FontWeight.bold,
                          fontSize: 12,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 6),
                  Text(
                    _vpnStatusMessage,
                    style: const TextStyle(color: Colors.white54, fontSize: 12),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 16),
            ElevatedButton(
              onPressed: _isLoading ? null : _requestDefaultBrowser,
              style: ElevatedButton.styleFrom(
                backgroundColor: Colors.blueAccent.shade700,
                foregroundColor: Colors.white,
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(10),
                ),
              ),
              child: const Text("Enable System Link Interceptor (Default Browser)"),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildFileInterceptorCard() {
    final hasThreat =
        _fileScanResult != null && _fileScanResult!['isPolyglot'] == true;
    return Card(
      color: const Color(0xFF1E293B),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
      child: Padding(
        padding: const EdgeInsets.all(20.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Row(
              children: [
                Icon(
                  Icons.file_present_outlined,
                  color: hasThreat ? Colors.redAccent : Colors.blueAccent,
                ),
                const SizedBox(width: 12),
                const Text(
                  "File Type Magic Check (Polyglot Detector)",
                  style: TextStyle(
                    color: Colors.white,
                    fontSize: 16,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 12),
            const Text(
              "Inspects file magic bytes and central ZIP records to stop fraudsters from bypassing sideload scanners by naming malicious files as .pdf or .jpg (WhatsApp/Telegram attachments).",
              style: TextStyle(
                color: Colors.white70,
                fontSize: 13,
                height: 1.4,
              ),
            ),
            const SizedBox(height: 16),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Colors.black26,
                borderRadius: BorderRadius.circular(10),
                border: Border.all(
                  color: hasThreat
                      ? Colors.redAccent.withOpacity(0.3)
                      : Colors.blueAccent.withOpacity(0.3),
                ),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    hasThreat
                        ? "ALERT: DISGUISED MALICIOUS FILE DETECTED"
                        : "STATUS",
                    style: TextStyle(
                      color: hasThreat ? Colors.redAccent : Colors.blueAccent,
                      fontWeight: FontWeight.bold,
                      fontSize: 12,
                    ),
                  ),
                  const SizedBox(height: 6),
                  Text(
                    _fileScanMessage,
                    style: const TextStyle(
                      color: Colors.white70,
                      fontSize: 12,
                      height: 1.4,
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 16),
            ElevatedButton(
              onPressed: _isLoading ? null : _simulateFileScan,
              style: ElevatedButton.styleFrom(
                backgroundColor: Colors.blueAccent.shade700,
                foregroundColor: Colors.white,
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(10),
                ),
              ),
              child: const Text("Simulate & Scan Spoofed PDF File"),
            ),
          ],
        ),
      ),
    );
  }
}
