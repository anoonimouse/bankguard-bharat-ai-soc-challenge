import 'package:flutter/material.dart';
import '../data/security_alerts_storage.dart';

class SecurityAlertsScreen extends StatefulWidget {
  const SecurityAlertsScreen({super.key});

  @override
  State<SecurityAlertsScreen> createState() => _SecurityAlertsScreenState();
}

class _SecurityAlertsScreenState extends State<SecurityAlertsScreen> {
  String _selectedFilter = 'All';
  List<SecurityAlert> _alerts = [];
  bool _isLoading = true;
  String? _error;

  final Set<String> _expandedAlertIds = {};

  @override
  void initState() {
    super.initState();
    _loadAlerts();
  }

  Future<void> _loadAlerts() async {
    setState(() {
      _isLoading = true;
      _error = null;
    });

    try {
      final combined = await SecurityAlertsStorage.fetchCombinedAlerts();
      if (mounted) {
        setState(() {
          _alerts = combined;
          _isLoading = false;
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _error = 'Failed to load alerts history: $e';
          _isLoading = false;
        });
      }
    }
  }

  List<SecurityAlert> get _filteredAlerts {
    if (_selectedFilter == 'All') return _alerts;
    return _alerts.where((alert) {
      if (_selectedFilter == 'Messages') return alert.type == 'SMS/WhatsApp';
      if (_selectedFilter == 'Web Blocks') return alert.type == 'URL Block';
      if (_selectedFilter == 'App Threats') return alert.type == 'APK Threat';
      return true;
    }).toList();
  }

  void _toggleExpand(String id) {
    setState(() {
      if (_expandedAlertIds.contains(id)) {
        _expandedAlertIds.remove(id);
      } else {
        _expandedAlertIds.add(id);
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    final themeColor = const Color(0xFF1E3A8A); // Flagship Blue

    return Scaffold(
      backgroundColor: const Color(0xFFF8FAFC), // Premium light background
      appBar: AppBar(
        title: const Text(
          "Security Center",
          style: TextStyle(fontWeight: FontWeight.bold, fontSize: 20),
        ),
        backgroundColor: themeColor,
        elevation: 0,
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            tooltip: 'Sync Logs',
            onPressed: _loadAlerts,
          ),
          IconButton(
            icon: const Icon(Icons.delete_sweep_outlined),
            tooltip: 'Clear Local Logs',
            onPressed: () {
              showDialog(
                context: context,
                builder: (context) => AlertDialog(
                  backgroundColor: const Color(0xFF1E293B),
                  title: const Text(
                    "Clear Alerts History?",
                    style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold),
                  ),
                  content: const Text(
                    "This will wipe all locally intercepted logs from this device. Remote backend database logs will not be affected.",
                    style: TextStyle(color: Colors.white70),
                  ),
                  actions: [
                    TextButton(
                      child: const Text("Cancel", style: TextStyle(color: Colors.white60)),
                      onPressed: () => Navigator.pop(context),
                    ),
                    ElevatedButton(
                      style: ElevatedButton.styleFrom(backgroundColor: Colors.red),
                      child: const Text("Clear Logs"),
                      onPressed: () {
                        SecurityAlertsStorage.clearLocalAlerts();
                        Navigator.pop(context);
                        _loadAlerts();
                      },
                    ),
                  ],
                ),
              );
            },
          ),
        ],
      ),
      body: Column(
        children: [
          // Header Status Area
          _buildStatusSummaryPanel(themeColor),

          // Filter Chips
          _buildFilterBar(themeColor),

          // Log List
          Expanded(
            child: RefreshIndicator(
              onRefresh: _loadAlerts,
              color: themeColor,
              child: _isLoading
                  ? const Center(child: CircularProgressIndicator())
                  : _error != null
                      ? _buildErrorView()
                      : _filteredAlerts.isEmpty
                          ? _buildEmptyState()
                          : _buildAlertList(),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildStatusSummaryPanel(Color primary) {
    final localCount = _alerts.where((a) => a.isLocalOnly).length;
    final remoteCount = _alerts.where((a) => !a.isLocalOnly).length;
    final criticalCount = _alerts.where((a) => a.riskScore >= 75).length;

    return Container(
      width: double.infinity,
      decoration: BoxDecoration(
        color: primary,
        borderRadius: const BorderRadius.only(
          bottomLeft: Radius.circular(24),
          bottomRight: Radius.circular(24),
        ),
      ),
      padding: const EdgeInsets.fromLTRB(20, 0, 20, 24),
      child: Column(
        children: [
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
            decoration: BoxDecoration(
              color: Colors.white.withOpacity(0.15),
              borderRadius: BorderRadius.circular(16),
              border: Border.all(color: Colors.white24),
            ),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(
                  criticalCount > 0 ? Icons.gpp_maybe : Icons.verified_user,
                  color: criticalCount > 0 ? Colors.orangeAccent : Colors.greenAccent,
                  size: 18,
                ),
                const SizedBox(width: 8),
                Text(
                  criticalCount > 0 ? "$criticalCount High Threats Blocked" : "Device Fully Secured",
                  style: const TextStyle(
                    color: Colors.white,
                    fontWeight: FontWeight.bold,
                    fontSize: 13,
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 18),
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceAround,
            children: [
              _buildSummaryStat(
                localCount.toString(),
                "Local Blocks",
                Icons.phonelink_setup,
              ),
              Container(width: 1, height: 32, color: Colors.white24),
              _buildSummaryStat(
                remoteCount.toString(),
                "API Submissions",
                Icons.cloud_done_outlined,
              ),
              Container(width: 1, height: 32, color: Colors.white24),
              _buildSummaryStat(
                _alerts.length.toString(),
                "Total Events",
                Icons.analytics_outlined,
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildSummaryStat(String value, String label, IconData icon) {
    return Column(
      children: [
        Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, color: Colors.white70, size: 14),
            const SizedBox(width: 4),
            Text(
              value,
              style: const TextStyle(
                color: Colors.white,
                fontSize: 18,
                fontWeight: FontWeight.bold,
              ),
            ),
          ],
        ),
        const SizedBox(height: 2),
        Text(
          label,
          style: const TextStyle(color: Colors.white60, fontSize: 11),
        ),
      ],
    );
  }

  Widget _buildFilterBar(Color primary) {
    final filters = ['All', 'Messages', 'Web Blocks', 'App Threats'];

    return Container(
      height: 48,
      margin: const EdgeInsets.symmetric(vertical: 12),
      child: ListView.builder(
        scrollDirection: Axis.horizontal,
        padding: const EdgeInsets.symmetric(horizontal: 16),
        itemCount: filters.length,
        itemBuilder: (context, index) {
          final filter = filters[index];
          final isSelected = _selectedFilter == filter;

          return Padding(
            padding: const EdgeInsets.only(right: 8.0),
            child: ChoiceChip(
              label: Text(filter),
              labelStyle: TextStyle(
                color: isSelected ? Colors.white : Colors.black87,
                fontWeight: isSelected ? FontWeight.bold : FontWeight.normal,
                fontSize: 12,
              ),
              selected: isSelected,
              selectedColor: primary,
              backgroundColor: Colors.white,
              elevation: isSelected ? 2 : 0,
              side: BorderSide(
                color: isSelected ? primary : Colors.grey.shade300,
              ),
              onSelected: (selected) {
                if (selected) {
                  setState(() => _selectedFilter = filter);
                }
              },
            ),
          );
        },
      ),
    );
  }

  Widget _buildErrorView() {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24.0),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.error_outline, size: 48, color: Colors.red),
            const SizedBox(height: 16),
            Text(
              _error ?? 'An unexpected error occurred.',
              textAlign: TextAlign.center,
              style: const TextStyle(color: Colors.black54),
            ),
            const SizedBox(height: 16),
            ElevatedButton(
              onPressed: _loadAlerts,
              child: const Text("Retry"),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildEmptyState() {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32.0),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Container(
              padding: const EdgeInsets.all(20),
              decoration: BoxDecoration(
                color: Colors.green.shade50,
                shape: BoxShape.circle,
              ),
              child: Icon(Icons.shield_outlined, size: 64, color: Colors.green.shade600),
            ),
            const SizedBox(height: 20),
            const Text(
              "All Systems Clear",
              style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold, color: Color(0xFF1E293B)),
            ),
            const SizedBox(height: 8),
            const Text(
              "No threats detected or intercepted. Your device is running under active BankGuard protection.",
              textAlign: TextAlign.center,
              style: TextStyle(color: Colors.black54, height: 1.4),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildAlertList() {
    final list = _filteredAlerts;
    return ListView.builder(
      padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
      itemCount: list.length,
      itemBuilder: (context, index) {
        final alert = list[index];
        final isExpanded = _expandedAlertIds.contains(alert.id);

        return Card(
          margin: const EdgeInsets.only(bottom: 12),
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
          elevation: 2,
          shadowColor: Colors.black.withOpacity(0.06),
          color: Colors.white,
          child: InkWell(
            borderRadius: BorderRadius.circular(14),
            onTap: () => _toggleExpand(alert.id),
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // Header Row
                  Row(
                    children: [
                      _buildTypeIcon(alert.type),
                      const SizedBox(width: 12),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              alert.title,
                              style: const TextStyle(
                                fontSize: 14,
                                fontWeight: FontWeight.bold,
                                color: Color(0xFF1E293B),
                              ),
                            ),
                            const SizedBox(height: 3),
                            Text(
                              "${_formatTime(alert.timestamp)}${alert.sender != null ? '  •  From: ${alert.sender}' : ''}",
                              style: const TextStyle(
                                fontSize: 11,
                                color: Colors.black45,
                              ),
                            ),
                          ],
                        ),
                      ),
                      const SizedBox(width: 8),
                      _buildRiskBadge(alert.riskScore),
                    ],
                  ),

                  // Always visible message excerpt
                  const SizedBox(height: 12),
                  Container(
                    width: double.infinity,
                    padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
                    decoration: BoxDecoration(
                      color: const Color(0xFFF8FAFC),
                      borderRadius: BorderRadius.circular(8),
                      border: Border.all(color: const Color(0xFFE2E8F0)),
                    ),
                    child: Text(
                      alert.message,
                      style: const TextStyle(
                        fontSize: 12,
                        color: Color(0xFF475569),
                        fontStyle: FontStyle.italic,
                      ),
                      maxLines: isExpanded ? 5 : 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),

                  // Expanded area
                  if (isExpanded) ...[
                    const SizedBox(height: 16),
                    const Divider(height: 1, color: Colors.black12),
                    const SizedBox(height: 12),

                    // Risk progress bar
                    Row(
                      children: [
                        const Text(
                          "Calculated Threat Level:",
                          style: TextStyle(
                            fontSize: 11,
                            fontWeight: FontWeight.bold,
                            color: Colors.black54,
                          ),
                        ),
                        const Spacer(),
                        Text(
                          "${alert.riskScore}%",
                          style: TextStyle(
                            fontSize: 11,
                            fontWeight: FontWeight.bold,
                            color: _getSeverityColor(alert.riskScore),
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 6),
                    ClipRRect(
                      borderRadius: BorderRadius.circular(4),
                      child: LinearProgressIndicator(
                        value: alert.riskScore / 100.0,
                        backgroundColor: Colors.grey.shade200,
                        valueColor: AlwaysStoppedAnimation<Color>(
                          _getSeverityColor(alert.riskScore),
                        ),
                        minHeight: 5,
                      ),
                    ),
                    if (alert.sender != null && alert.sender!.isNotEmpty) ...[
                      const SizedBox(height: 16),
                      const Text(
                        "Sender Information",
                        style: TextStyle(
                          fontSize: 11,
                          fontWeight: FontWeight.bold,
                          color: Colors.black54,
                        ),
                      ),
                      const SizedBox(height: 4),
                      Row(
                        children: [
                          Icon(
                            alert.type.contains('WhatsApp') ? Icons.phone_android : Icons.sms,
                            size: 14,
                            color: Colors.black54,
                          ),
                          const SizedBox(width: 6),
                          Text(
                            alert.sender!,
                            style: const TextStyle(
                              fontSize: 12,
                              fontWeight: FontWeight.w600,
                              color: Color(0xFF1E293B),
                            ),
                          ),
                          if (alert.senderFlag != null && alert.senderFlag!.isNotEmpty) ...[
                            const SizedBox(width: 8),
                            Container(
                              padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                              decoration: BoxDecoration(
                                color: alert.senderFlag!.contains('CRITICAL') || alert.senderFlag!.contains('Suspicious')
                                    ? Colors.red.shade50
                                    : Colors.green.shade50,
                                borderRadius: BorderRadius.circular(4),
                                border: Border.all(
                                  color: alert.senderFlag!.contains('CRITICAL') || alert.senderFlag!.contains('Suspicious')
                                      ? Colors.red.shade100
                                      : Colors.green.shade100,
                                ),
                              ),
                              child: Text(
                                alert.senderFlag!.contains('CRITICAL')
                                    ? 'BLACKLISTED'
                                    : (alert.senderFlag!.contains('Verified') ? 'VERIFIED' : 'UNVERIFIED'),
                                style: TextStyle(
                                  fontSize: 9,
                                  fontWeight: FontWeight.bold,
                                  color: alert.senderFlag!.contains('CRITICAL') || alert.senderFlag!.contains('Suspicious')
                                      ? Colors.red.shade700
                                      : Colors.green.shade700,
                                ),
                              ),
                            ),
                          ],
                        ],
                      ),
                      if (alert.senderFlag != null && alert.senderFlag!.isNotEmpty) ...[
                        const SizedBox(height: 4),
                        Text(
                          alert.senderFlag!,
                          style: TextStyle(
                            fontSize: 11,
                            color: alert.senderFlag!.contains('CRITICAL') || alert.senderFlag!.contains('Suspicious')
                                ? Colors.red.shade700
                                : Colors.green.shade700,
                            fontWeight: FontWeight.w500,
                          ),
                        ),
                      ],
                    ],
                    const SizedBox(height: 16),

                    // Technical Explanation
                    const Text(
                      "Detection Explanation",
                      style: TextStyle(
                        fontSize: 11,
                        fontWeight: FontWeight.bold,
                        color: Colors.black54,
                      ),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      alert.explanation,
                      style: const TextStyle(
                        fontSize: 12,
                        color: Color(0xFF334155),
                        height: 1.4,
                      ),
                    ),
                    const SizedBox(height: 16),

                    // Remediation suggested action
                    const Text(
                      "Remediation Action Required",
                      style: TextStyle(
                        fontSize: 11,
                        fontWeight: FontWeight.bold,
                        color: Colors.black54,
                      ),
                    ),
                    const SizedBox(height: 4),
                    Container(
                      width: double.infinity,
                      padding: const EdgeInsets.all(10),
                      decoration: BoxDecoration(
                        color: const Color(0xFFF0F9FF), // Sky blue tint
                        borderRadius: BorderRadius.circular(8),
                        border: Border.all(color: const Color(0xFFE0F2FE)),
                      ),
                      child: Text(
                        alert.suggestedAction,
                        style: const TextStyle(
                          fontSize: 12,
                          color: Color(0xFF0369A1),
                          fontWeight: FontWeight.w500,
                          height: 1.4,
                        ),
                      ),
                    ),
                    const SizedBox(height: 16),

                    // Stat Footer
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        Text(
                          "Source: ${alert.sourceApp}",
                          style: TextStyle(
                            fontSize: 10,
                            color: Colors.grey.shade500,
                            fontWeight: FontWeight.w500,
                          ),
                        ),
                        Text(
                          alert.isLocalOnly ? "On-Device Sandbox Check" : "Sync Server Logged",
                          style: TextStyle(
                            fontSize: 10,
                            color: alert.isLocalOnly ? Colors.indigo : Colors.teal,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      ],
                    ),

                    // Proactive submit/report action for locally caught alerts
                    if (alert.isLocalOnly) ...[
                      const SizedBox(height: 16),
                      SizedBox(
                        width: double.infinity,
                        child: OutlinedButton.icon(
                          icon: const Icon(Icons.share, size: 14),
                          label: const Text(
                            "Submit to Cyber Security Registry",
                            style: TextStyle(fontSize: 12),
                          ),
                          style: OutlinedButton.styleFrom(
                            foregroundColor: Colors.red.shade800,
                            side: BorderSide(color: Colors.red.shade800),
                            padding: const EdgeInsets.symmetric(vertical: 10),
                            shape: RoundedRectangleBorder(
                              borderRadius: BorderRadius.circular(8),
                            ),
                          ),
                          onPressed: () {
                            Navigator.pushNamed(
                              context,
                              '/report',
                              arguments: {
                                'url': alert.message,
                                'source': alert.sourceApp,
                                'category': alert.type == 'URL Block'
                                    ? 'PHISHING_URL'
                                    : (alert.type == 'APK' ? 'MALICIOUS_APK' : 'SMISHING_SMS'),
                                'reportType': alert.type == 'APK Threat' ? 'APK' : 'URL',
                              },
                            ).then((_) => _loadAlerts());
                          },
                        ),
                      ),
                    ],
                  ],
                ],
              ),
            ),
          ),
        );
      },
    );
  }

  Widget _buildTypeIcon(String type) {
    IconData icon;
    Color color;

    if (type == 'SMS/WhatsApp') {
      icon = Icons.chat_bubble_outline_rounded;
      color = Colors.indigo.shade600;
    } else if (type == 'URL Block') {
      icon = Icons.language_outlined;
      color = Colors.blue.shade600;
    } else {
      icon = Icons.install_mobile_rounded;
      color = Colors.amber.shade700;
    }

    return Container(
      padding: const EdgeInsets.all(8),
      decoration: BoxDecoration(
        color: color.withOpacity(0.1),
        shape: BoxShape.circle,
      ),
      child: Icon(icon, color: color, size: 18),
    );
  }

  Widget _buildRiskBadge(int score) {
    final color = _getSeverityColor(score);
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: color.withOpacity(0.15),
        borderRadius: BorderRadius.circular(12),
      ),
      child: Text(
        "Risk $score%",
        style: TextStyle(
          color: color,
          fontSize: 10,
          fontWeight: FontWeight.bold,
        ),
      ),
    );
  }

  Color _getSeverityColor(int score) {
    if (score >= 90) return const Color(0xFFDC2626); // Critical Red
    if (score >= 70) return const Color(0xFFEA580C); // High Orange
    return const Color(0xFFD97706); // Medium Amber
  }

  String _formatTime(DateTime time) {
    final now = DateTime.now();
    final difference = now.difference(time);

    if (difference.inMinutes < 1) {
      return "Just now";
    } else if (difference.inMinutes < 60) {
      return "${difference.inMinutes}m ago";
    } else if (difference.inHours < 24) {
      return "${difference.inHours}h ago";
    } else if (difference.inDays == 1) {
      return "Yesterday";
    } else {
      return "${time.day}/${time.month}/${time.year}";
    }
  }
}
