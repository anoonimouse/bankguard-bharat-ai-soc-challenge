import 'package:flutter/material.dart';
import 'package:bankguard/bankguard.dart';

class ReportFraudScreen extends StatefulWidget {
  final Map<String, dynamic>? initialArgs;
  const ReportFraudScreen({super.key, this.initialArgs});

  @override
  State<ReportFraudScreen> createState() => _ReportFraudScreenState();
}

class _ReportFraudScreenState extends State<ReportFraudScreen> {
  String _reportType = 'URL';
  final _contentController = TextEditingController();
  bool _isSubmitting = false;
  final _sdk = Bankguard();

  @override
  void initState() {
    super.initState();
    // Pre-populate from deep link arguments if provided
    final args = widget.initialArgs;
    if (args != null) {
      if (args['reportType'] != null) {
        _reportType = args['reportType'] as String;
      }
      if (args['url'] != null && (args['url'] as String).isNotEmpty) {
        _contentController.text = args['url'] as String;
      }
    }
  }

  /// Delegate report submission to SDK
  Future<void> _submitReport() async {
    if (_contentController.text.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Please enter the suspicious link or app name.'),
        ),
      );
      return;
    }

    setState(() => _isSubmitting = true);

    try {
      final success = await _sdk.reportThreat(
        reportType: _reportType,
        content: _contentController.text.trim(),
        riskScore: 0.8,
      );

      if (!mounted) return;

      if (success) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Threat report submitted securely.')),
        );
        Navigator.pop(context);
      } else {
        throw Exception('Failed to submit report');
      }
    } catch (error) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Network error. Please try again.')),
      );
    } finally {
      if (mounted) setState(() => _isSubmitting = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text("Report Suspicious Activity"),
        backgroundColor: Colors.red.shade800,
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(24.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const Icon(
              Icons.warning_amber_rounded,
              size: 64,
              color: Colors.orange,
            ),
            const SizedBox(height: 16),
            const Text(
              "Help us protect the ecosystem",
              textAlign: TextAlign.center,
              style: TextStyle(fontSize: 22, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 8),
            const Text(
              "If you received a fake SMS asking for KYC or found a fake banking app, report it here. Our security team will review it and take it down.",
              textAlign: TextAlign.center,
              style: TextStyle(color: Colors.black54),
            ),
            const SizedBox(height: 32),
            const Text(
              "What are you reporting?",
              style: TextStyle(fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 8),
            SegmentedButton<String>(
              segments: const [
                ButtonSegment(value: 'URL', label: Text('Phishing Link / SMS')),
                ButtonSegment(value: 'APK', label: Text('Fake App / APK')),
              ],
              selected: {_reportType},
              onSelectionChanged: (Set<String> newSelection) {
                setState(() => _reportType = newSelection.first);
              },
            ),
            const SizedBox(height: 24),
            Text(
              _reportType == 'URL'
                  ? "Suspicious Link (URL)"
                  : "Fake App Package / Name",
              style: const TextStyle(fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 8),
            TextField(
              controller: _contentController,
              decoration: InputDecoration(
                hintText: _reportType == 'URL'
                    ? 'e.g. http://sbikyc-update.in'
                    : 'e.g. Fake Security Update App',
                border: const OutlineInputBorder(),
              ),
              maxLines: 2,
            ),
            const SizedBox(height: 32),
            ElevatedButton(
              onPressed: _isSubmitting ? null : _submitReport,
              style: ElevatedButton.styleFrom(
                backgroundColor: Colors.red.shade800,
                padding: const EdgeInsets.symmetric(vertical: 16),
              ),
              child: _isSubmitting
                  ? const SizedBox(
                      height: 20,
                      width: 20,
                      child: CircularProgressIndicator(
                        color: Colors.white,
                        strokeWidth: 2,
                      ),
                    )
                  : const Text("Submit Report Securely"),
            ),
          ],
        ),
      ),
    );
  }
}
