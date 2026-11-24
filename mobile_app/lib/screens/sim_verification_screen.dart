import 'package:flutter/material.dart';
import 'package:bankguard/bankguard.dart';

class SimVerificationScreen extends StatefulWidget {
  final String customerId;
  final String newSimHash;

  const SimVerificationScreen({
    super.key,
    required this.customerId,
    required this.newSimHash,
  });

  @override
  State<SimVerificationScreen> createState() => _SimVerificationScreenState();
}

class _SimVerificationScreenState extends State<SimVerificationScreen> {
  final _otpController = TextEditingController();
  final _sdk = Bankguard();
  bool _isLoading = false;
  String? _errorMessage;
  bool _isSuccess = false;

  @override
  void dispose() {
    _otpController.dispose();
    super.dispose();
  }

  Future<void> _handleReverification() async {
    final otp = _otpController.text.trim();
    if (otp.length != 6 || !RegExp(r'^\d+$').hasMatch(otp)) {
      setState(() {
        _errorMessage = 'Please enter a valid 6-digit OTP.';
      });
      return;
    }

    setState(() {
      _isLoading = true;
      _errorMessage = null;
    });

    try {
      // 1. Call backend API re-verify endpoint
      final result = await _sdk.reverifyDeviceOnBackend(
        customerId: widget.customerId,
        simHash: widget.newSimHash,
        otp: otp,
      );

      if (result['verified'] == true) {
        // 2. Commit the new SIM hash baseline to SharedPreferences natively
        final localUpdated = await _sdk.setStoredSimHash(widget.newSimHash);

        if (localUpdated) {
          setState(() {
            _isSuccess = true;
            _isLoading = false;
          });

          await Future.delayed(const Duration(milliseconds: 1500));
          if (mounted) {
            // Unlocked successfully, route to login
            Navigator.pushReplacementNamed(context, '/login');
          }
        } else {
          setState(() {
            _isLoading = false;
            _errorMessage =
                'Failed to update local SIM baseline. Please contact support.';
          });
        }
      } else {
        setState(() {
          _isLoading = false;
          _errorMessage = result['message'] ?? 'OTP verification failed.';
        });
      }
    } catch (e) {
      setState(() {
        _isLoading = false;
        _errorMessage =
            'An error occurred during verification. Please try again.';
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Container(
        decoration: const BoxDecoration(
          gradient: LinearGradient(
            begin: Alignment.topCenter,
            end: Alignment.bottomCenter,
            colors: [
              Color(0xFF0F172A), // Slate 900
              Color(0xFF1E293B), // Slate 800
            ],
          ),
        ),
        child: SafeArea(
          child: Center(
            child: SingleChildScrollView(
              padding: const EdgeInsets.symmetric(
                horizontal: 24.0,
                vertical: 16.0,
              ),
              child: Card(
                elevation: 12,
                color: const Color(
                  0xFF1E293B,
                ).withOpacity(0.9), // Glassmorphism-like
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(20),
                  side: BorderSide(
                    color: Colors.red.shade400.withOpacity(0.3),
                    width: 1.5,
                  ),
                ),
                child: Padding(
                  padding: const EdgeInsets.all(28.0),
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      // Icon with subtle glow / red warning
                      Container(
                        padding: const EdgeInsets.all(16),
                        decoration: BoxDecoration(
                          color: Colors.red.shade900.withOpacity(0.3),
                          shape: BoxShape.circle,
                          border: Border.all(
                            color: Colors.red.shade400,
                            width: 2,
                          ),
                        ),
                        child: Icon(
                          Icons.sim_card_alert_rounded,
                          size: 48,
                          color: Colors.red.shade400,
                        ),
                      ),
                      const SizedBox(height: 24),
                      Text(
                        'SIM SWAP DETECTED',
                        style: TextStyle(
                          fontSize: 22,
                          fontWeight: FontWeight.bold,
                          letterSpacing: 1.5,
                          color: Colors.red.shade300,
                        ),
                      ),
                      const SizedBox(height: 16),
                      const Text(
                        'A change in your device SIM card configuration has been detected. As a fail-closed security measure, BankGuard has locked banking access.',
                        textAlign: TextAlign.center,
                        style: TextStyle(
                          fontSize: 14,
                          color: Colors.white70,
                          height: 1.5,
                        ),
                      ),
                      const SizedBox(height: 12),
                      Container(
                        padding: const EdgeInsets.all(12),
                        decoration: BoxDecoration(
                          color: Colors.black26,
                          borderRadius: BorderRadius.circular(10),
                        ),
                        child: Text(
                          'New Hash: ${widget.newSimHash.length > 20 ? "${widget.newSimHash.substring(0, 16)}..." : widget.newSimHash}',
                          style: const TextStyle(
                            fontFamily: 'monospace',
                            fontSize: 12,
                            color: Colors.amberAccent,
                          ),
                        ),
                      ),
                      const SizedBox(height: 24),
                      if (_isSuccess) ...[
                        const Icon(
                          Icons.check_circle_outline_rounded,
                          size: 64,
                          color: Colors.green,
                        ),
                        const SizedBox(height: 12),
                        const Text(
                          'Verification Successful!',
                          style: TextStyle(
                            fontSize: 16,
                            fontWeight: FontWeight.bold,
                            color: Colors.green,
                          ),
                        ),
                        const Text(
                          'Updating baseline and unlocking access...',
                          style: TextStyle(fontSize: 13, color: Colors.white54),
                        ),
                      ] else ...[
                        const Text(
                          'Enter the 6-digit OTP sent to your registered number to re-bind this SIM:',
                          textAlign: TextAlign.center,
                          style: TextStyle(fontSize: 13, color: Colors.white54),
                        ),
                        const SizedBox(height: 16),
                        TextField(
                          controller: _otpController,
                          keyboardType: TextInputType.number,
                          maxLength: 6,
                          textAlign: TextAlign.center,
                          obscureText: true,
                          style: const TextStyle(
                            fontSize: 24,
                            fontWeight: FontWeight.bold,
                            letterSpacing: 8,
                            color: Colors.white,
                          ),
                          decoration: InputDecoration(
                            counterText: '',
                            filled: true,
                            fillColor: const Color(0xFF0F172A),
                            hintText: '000000',
                            hintStyle: TextStyle(
                              color: Colors.white.withOpacity(0.2),
                              letterSpacing: 8,
                            ),
                            border: OutlineInputBorder(
                              borderRadius: BorderRadius.circular(12),
                              borderSide: BorderSide.none,
                            ),
                            focusedBorder: OutlineInputBorder(
                              borderRadius: BorderRadius.circular(12),
                              borderSide: const BorderSide(
                                color: Colors.blueAccent,
                                width: 2,
                              ),
                            ),
                          ),
                          onSubmitted: (_) => _handleReverification(),
                        ),
                        const SizedBox(height: 8),
                        if (_errorMessage != null)
                          Padding(
                            padding: const EdgeInsets.only(top: 8.0),
                            child: Text(
                              _errorMessage!,
                              textAlign: TextAlign.center,
                              style: TextStyle(
                                color: Colors.red.shade400,
                                fontSize: 13,
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                          ),
                        const SizedBox(height: 24),
                        SizedBox(
                          width: double.infinity,
                          child: ElevatedButton(
                            onPressed: _isLoading
                                ? null
                                : _handleReverification,
                            style: ElevatedButton.styleFrom(
                              backgroundColor: Colors.blueAccent.shade700,
                              foregroundColor: Colors.white,
                              padding: const EdgeInsets.symmetric(vertical: 14),
                              shape: RoundedRectangleBorder(
                                borderRadius: BorderRadius.circular(12),
                              ),
                              elevation: 4,
                            ),
                            child: _isLoading
                                ? const SizedBox(
                                    height: 20,
                                    width: 20,
                                    child: CircularProgressIndicator(
                                      strokeWidth: 2.5,
                                      valueColor: AlwaysStoppedAnimation<Color>(
                                        Colors.white,
                                      ),
                                    ),
                                  )
                                : const Text(
                                    'Verify & Re-bind SIM',
                                    style: TextStyle(
                                      fontSize: 16,
                                      fontWeight: FontWeight.bold,
                                    ),
                                  ),
                          ),
                        ),
                      ],
                    ],
                  ),
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}
