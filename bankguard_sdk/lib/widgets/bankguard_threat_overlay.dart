import 'package:flutter/material.dart';

/// Bankguard SDK Threat Overlay - reusable overlay that can be dropped
/// into any host banking app to display contextual threat alerts.
class BankguardThreatOverlay {
  static OverlayEntry? _currentOverlay;

  /// Show a threat overlay with enriched notification data.
  /// [onVerifyLink] is called when user taps 'Verify This Link' with the URL.
  /// [onReportScam] is called when user taps 'Report Scam' with the URL.
  static void show(
    BuildContext context,
    Map<String, dynamic> data, {
    void Function(String url)? onVerifyLink,
    void Function(String url)? onReportScam,
  }) {
    dismiss();
    _currentOverlay = OverlayEntry(
      builder: (ctx) => _ThreatOverlayWidget(
        data: data,
        onDismiss: dismiss,
        onVerifyLink: onVerifyLink,
        onReportScam: onReportScam,
      ),
    );
    Overlay.of(context).insert(_currentOverlay!);
  }

  /// Dismiss the current overlay.
  static void dismiss() {
    _currentOverlay?.remove();
    _currentOverlay = null;
  }
}

class _ThreatOverlayWidget extends StatelessWidget {
  final Map<String, dynamic> data;
  final VoidCallback onDismiss;
  final void Function(String url)? onVerifyLink;
  final void Function(String url)? onReportScam;

  const _ThreatOverlayWidget({
    required this.data,
    required this.onDismiss,
    this.onVerifyLink,
    this.onReportScam,
  });

  @override
  Widget build(BuildContext context) {
    final verdict = data['verdict'] as String? ?? 'soft';
    final score = data['score'] as int? ?? 0;
    final primaryCategory = data['primaryCategory'] as String? ?? '';
    final categories = (data['categories'] as List?)?.cast<String>() ?? [];
    final text = data['text'] as String? ?? '';

    final urlMatch =
        RegExp(r'https?://[^\s]+', caseSensitive: false).firstMatch(text);
    final detectedUrl = urlMatch?.group(0);

    final isHard = verdict == 'hard';
    final bgColor = isHard ? const Color(0xCC000000) : const Color(0xAA000000);
    final accentColor =
        isHard ? const Color(0xFFEF4444) : const Color(0xFFF59E0B);

    final title = _getTitle(primaryCategory);
    final body = _getBody(primaryCategory);

    return Material(
      color: Colors.transparent,
      child: Stack(
        children: [
          GestureDetector(
            onTap: () {},
            child: Container(color: bgColor),
          ),
          Center(
            child: Container(
              margin: const EdgeInsets.symmetric(horizontal: 24),
              padding: const EdgeInsets.all(24),
              decoration: BoxDecoration(
                color: Colors.white,
                borderRadius: BorderRadius.circular(20),
                border: Border.all(color: accentColor, width: 2),
                boxShadow: [
                  BoxShadow(
                    color: accentColor.withOpacity(0.3),
                    blurRadius: 30,
                    spreadRadius: 5,
                  ),
                ],
              ),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Container(
                    padding: const EdgeInsets.all(16),
                    decoration: BoxDecoration(
                      color: accentColor.withOpacity(0.1),
                      shape: BoxShape.circle,
                    ),
                    child: Icon(
                      isHard ? Icons.gpp_bad : Icons.warning_amber_rounded,
                      size: 48,
                      color: accentColor,
                    ),
                  ),
                  const SizedBox(height: 16),
                  Text(
                    title,
                    style: TextStyle(
                      fontSize: 18,
                      fontWeight: FontWeight.w800,
                      color: accentColor,
                    ),
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(height: 12),
                  Text(
                    body,
                    style: const TextStyle(
                      fontSize: 14,
                      color: Color(0xFF374151),
                      height: 1.5,
                    ),
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(height: 16),
                  Container(
                    padding:
                        const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                    decoration: BoxDecoration(
                      color: accentColor.withOpacity(0.1),
                      borderRadius: BorderRadius.circular(12),
                    ),
                    child: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Icon(Icons.speed, size: 18, color: accentColor),
                        const SizedBox(width: 8),
                        Text(
                          'Risk Score: $score / 100',
                          style: TextStyle(
                            fontWeight: FontWeight.bold,
                            color: accentColor,
                          ),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(height: 12),
                  if (categories.isNotEmpty)
                    Wrap(
                      spacing: 8,
                      runSpacing: 8,
                      alignment: WrapAlignment.center,
                      children: categories.map((c) {
                        return Container(
                          padding: const EdgeInsets.symmetric(
                            horizontal: 12,
                            vertical: 6,
                          ),
                          decoration: BoxDecoration(
                            color: _chipColor(c).withOpacity(0.15),
                            borderRadius: BorderRadius.circular(20),
                            border: Border.all(
                              color: _chipColor(c).withOpacity(0.5),
                            ),
                          ),
                          child: Text(
                            _chipLabel(c),
                            style: TextStyle(
                              fontSize: 12,
                              fontWeight: FontWeight.w700,
                              color: _chipColor(c),
                            ),
                          ),
                        );
                      }).toList(),
                    ),
                  const SizedBox(height: 20),
                  if (detectedUrl != null) ...[
                    SizedBox(
                      width: double.infinity,
                      child: ElevatedButton.icon(
                        icon: const Icon(Icons.verified_user, size: 18),
                        label: const Text('Verify This Link'),
                        style: ElevatedButton.styleFrom(
                          backgroundColor: const Color(0xFF1E3A8A),
                          foregroundColor: Colors.white,
                          padding: const EdgeInsets.symmetric(vertical: 14),
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(12),
                          ),
                        ),
                        onPressed: () {
                          onDismiss();
                          onVerifyLink?.call(detectedUrl);
                        },
                      ),
                    ),
                    const SizedBox(height: 10),
                    SizedBox(
                      width: double.infinity,
                      child: ElevatedButton.icon(
                        icon: const Icon(Icons.flag, size: 18),
                        label: const Text('Report Scam'),
                        style: ElevatedButton.styleFrom(
                          backgroundColor: const Color(0xFFDC2626),
                          foregroundColor: Colors.white,
                          padding: const EdgeInsets.symmetric(vertical: 14),
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(12),
                          ),
                        ),
                        onPressed: () {
                          onDismiss();
                          onReportScam?.call(detectedUrl);
                        },
                      ),
                    ),
                    const SizedBox(height: 10),
                  ],
                  SizedBox(
                    width: double.infinity,
                    child: OutlinedButton(
                      style: OutlinedButton.styleFrom(
                        foregroundColor: const Color(0xFF6B7280),
                        side: const BorderSide(color: Color(0xFFD1D5DB)),
                        padding: const EdgeInsets.symmetric(vertical: 14),
                        shape: RoundedRectangleBorder(
                          borderRadius: BorderRadius.circular(12),
                        ),
                      ),
                      onPressed: onDismiss,
                      child: const Text('Dismiss'),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  String _getTitle(String category) {
    switch (category) {
      case 'urgency':
        return '[ALERT] Fraud Urgency Tactic Detected';
      case 'fear':
        return '[ALERT] Known Fraud Script Detected';
      case 'greed':
        return '[ALERT] Fake Reward Scam Detected';
      case 'url_only':
        return '[ALERT] Suspicious Banking Link Detected';
      default:
        return '[ALERT] Suspicious Message Detected';
    }
  }

  String _getBody(String category) {
    switch (category) {
      case 'urgency':
        return 'This message is creating false urgency. SBI never threatens to block accounts or expire KYC via SMS or WhatsApp.';
      case 'fear':
        return 'This message is using a known banking fraud pattern. Your account is not compromised. Do not click any links.';
      case 'greed':
        return 'This message is offering fake rewards to steal your credentials. SBI does not send prize notifications via WhatsApp or SMS.';
      case 'url_only':
        return 'A link related to SBI was found in a message. Verify it before clicking.';
      default:
        return 'A potentially malicious link was found in a message notification.';
    }
  }

  Color _chipColor(String category) {
    switch (category) {
      case 'urgency':
        return const Color(0xFFEF4444);
      case 'fear':
        return const Color(0xFFDC2626);
      case 'greed':
        return const Color(0xFFF59E0B);
      default:
        return const Color(0xFF6B7280);
    }
  }

  String _chipLabel(String category) {
    switch (category) {
      case 'urgency':
        return 'URGENCY TACTIC';
      case 'fear':
        return 'FEAR TACTIC';
      case 'greed':
        return 'GREED TACTIC';
      default:
        return category.toUpperCase();
    }
  }
}
