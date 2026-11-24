import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:bankguard/bankguard.dart';
import '../data/dummy_data.dart';

class SafetyAcademyScreen extends StatefulWidget {
  const SafetyAcademyScreen({super.key});

  @override
  State<SafetyAcademyScreen> createState() => _SafetyAcademyScreenState();
}

class _SafetyAcademyScreenState extends State<SafetyAcademyScreen> with SingleTickerProviderStateMixin {
  late TabController _tabController;
  final _sdk = Bankguard.instance;

  List<dynamic> _scenarios = [];
  bool _loadingScenarios = true;
  int _currentScenarioIndex = 0;
  int _userPoints = 0;
  List<dynamic> _myVouchers = [];

  // Quiz state
  bool _quizSubmitting = false;
  Map<String, dynamic>? _lastResult;

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 2, vsync: this);
    _fetchScenarios();
    _fetchUserProfile();
  }

  @override
  void dispose() {
    _tabController.dispose();
    super.dispose();
  }

  String get _baseUrl => _sdk.config.backendBaseUrl.replaceAll(RegExp(r'/$'), '');
  String get _customerId => _sdk.config.customerId.isNotEmpty ? _sdk.config.customerId : CustomerData.customerId;

  Future<void> _fetchUserProfile() async {
    try {
      final res = await http.get(Uri.parse('$_baseUrl/api/admin/devices'));
      if (res.statusCode == 200) {
        final List<dynamic> devices = json.decode(res.body);
        final myProfile = devices.firstWhere(
          (d) => d['customer_id'] == _customerId,
          orElse: () => null,
        );
        if (myProfile != null && mounted) {
          setState(() {
            _userPoints = myProfile['shield_points'] ?? 0;
            try {
              _myVouchers = json.decode(myProfile['redeemed_vouchers'] ?? '[]');
            } catch (_) {
              _myVouchers = [];
            }
          });
        }
      }
    } catch (e) {
      print("Error fetching user profile for rewards: $e");
    }
  }

  Future<void> _fetchScenarios() async {
    setState(() => _loadingScenarios = true);
    try {
      final res = await http.get(Uri.parse('$_baseUrl/api/rewards/scenarios'));
      if (res.statusCode == 200 && mounted) {
        setState(() {
          _scenarios = json.decode(res.body);
          _loadingScenarios = false;
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() => _loadingScenarios = false);
      }
    }
  }

  Future<void> _submitAnswer(bool isMaliciousGuess) async {
    if (_quizSubmitting || _currentScenarioIndex >= _scenarios.length) return;
    setState(() {
      _quizSubmitting = true;
      _lastResult = null;
    });

    final scenarioId = _scenarios[_currentScenarioIndex]['id'];

    try {
      final res = await http.post(
        Uri.parse('$_baseUrl/api/rewards/submit'),
        headers: {'Content-Type': 'application/json'},
        body: json.encode({
          'scenario_id': scenarioId,
          'is_malicious_guess': isMaliciousGuess,
          'customer_id': _customerId,
        }),
      );

      if (res.statusCode == 200 && mounted) {
        final data = json.decode(res.body);
        setState(() {
          _lastResult = data;
          _userPoints = data['current_points'] ?? _userPoints;
          _quizSubmitting = false;
        });
        _showResultDialog(data);
      }
    } catch (e) {
      if (mounted) {
        setState(() => _quizSubmitting = false);
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Submission failed. Check network.')),
        );
      }
    }
  }

  Future<void> _redeemReward(String rewardId, int cost) async {
    if (_userPoints < cost) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('You need $cost SP to redeem this reward.')),
      );
      return;
    }

    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (context) => const Center(
        child: CircularProgressIndicator(color: Color(0xFF1E3A8A)),
      ),
    );

    try {
      final res = await http.post(
        Uri.parse('$_baseUrl/api/rewards/redeem'),
        headers: {'Content-Type': 'application/json'},
        body: json.encode({
          'reward_id': rewardId,
          'customer_id': _customerId,
        }),
      );

      Navigator.pop(context); // Close loading spinner

      if (res.statusCode == 200) {
        final data = json.decode(res.body);
        if (data['success'] == true) {
          setState(() {
            _userPoints = data['current_points'] ?? _userPoints;
            _myVouchers.add(data['voucher']);
          });
          _showVoucherDialog(data['voucher']);
        } else {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text(data['message'] ?? 'Failed to redeem reward')),
          );
        }
      }
    } catch (e) {
      Navigator.pop(context);
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Redemption request failed. Check network.')),
      );
    }
  }

  void _showResultDialog(Map<String, dynamic> result) {
    final correct = result['correct'] == true;
    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (context) => AlertDialog(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        title: Row(
          children: [
            Icon(
              correct ? Icons.check_circle : Icons.cancel,
              color: correct ? Colors.green : Colors.red,
            ),
            const SizedBox(width: 8),
            Text(
              correct ? "Correct! +50 SP" : "Incorrect",
              style: TextStyle(
                color: correct ? Colors.green : Colors.red,
                fontWeight: FontWeight.bold,
              ),
            ),
          ],
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              result['explanation'] ?? '',
              style: const TextStyle(fontSize: 14, color: Colors.black87),
            ),
            const SizedBox(height: 16),
            Text(
              "Current Shield Balance: $_userPoints SP",
              style: const TextStyle(fontWeight: FontWeight.bold, color: Color(0xFF1E3A8A)),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () {
              Navigator.pop(context);
              setState(() {
                _currentScenarioIndex++;
              });
            },
            child: const Text(
              "Next Challenge",
              style: TextStyle(fontWeight: FontWeight.bold, color: Color(0xFF1E3A8A)),
            ),
          )
        ],
      ),
    );
  }

  void _showVoucherDialog(Map<String, dynamic> voucher) {
    showDialog(
      context: context,
      builder: (context) => Dialog(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        child: Padding(
          padding: const EdgeInsets.all(20),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Icon(Icons.stars, color: Colors.amber, size: 64),
              const SizedBox(height: 16),
              const Text(
                "Voucher Claimed!",
                style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
              ),
              const SizedBox(height: 8),
              Text(
                voucher['title'] ?? '',
                textAlign: TextAlign.center,
                style: const TextStyle(color: Colors.black54),
              ),
              const SizedBox(height: 16),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
                decoration: BoxDecoration(
                  color: const Color(0xFFF1F5F9),
                  border: Border.all(color: const Color(0xFFCBD5E1)),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Text(
                  voucher['code'] ?? '',
                  style: const TextStyle(
                    fontSize: 20,
                    fontWeight: FontWeight.bold,
                    fontFamily: 'monospace',
                    letterSpacing: 1.5,
                    color: Color(0xFF1E3A8A),
                  ),
                ),
              ),
              const SizedBox(height: 24),
              ElevatedButton(
                style: ElevatedButton.styleFrom(
                  backgroundColor: const Color(0xFF1E3A8A),
                  padding: const EdgeInsets.symmetric(horizontal: 32, vertical: 12),
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                ),
                onPressed: () => Navigator.pop(context),
                child: const Text("Awesome"),
              ),
            ],
          ),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFFF8FAFC),
      appBar: AppBar(
        title: const Text("Cyber Shield Academy"),
        backgroundColor: const Color(0xFF1E3A8A),
        bottom: TabBar(
          controller: _tabController,
          labelColor: Colors.white,
          unselectedLabelColor: Colors.white70,
          indicatorColor: Colors.white,
          tabs: const [
            Tab(icon: Icon(Icons.psychology), text: "Academy Quiz"),
            Tab(icon: Icon(Icons.card_giftcard), text: "Rewards Store"),
          ],
        ),
      ),
      body: TabBarView(
        controller: _tabController,
        children: [
          _buildQuizTab(),
          _buildRewardsTab(),
        ],
      ),
    );
  }

  Widget _buildQuizTab() {
    if (_loadingScenarios) {
      return const Center(child: CircularProgressIndicator(color: Color(0xFF1E3A8A)));
    }

    if (_scenarios.isEmpty) {
      return const Center(child: Text("Failed to load security scenarios. Check API connection."));
    }

    if (_currentScenarioIndex >= _scenarios.length) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const Icon(Icons.military_tech, size: 80, color: Colors.amber),
              const SizedBox(height: 16),
              const Text(
                "Academy Completed!",
                style: TextStyle(fontSize: 22, fontWeight: FontWeight.bold),
              ),
              const SizedBox(height: 8),
              const Text(
                "You have solved all of today's cybersecurity scenarios. Head over to the Rewards Store to redeem your Shield Points!",
                textAlign: TextAlign.center,
                style: TextStyle(color: Colors.black54),
              ),
              const SizedBox(height: 24),
              ElevatedButton.icon(
                style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF1E3A8A)),
                onPressed: () => _tabController.animateTo(1),
                icon: const Icon(Icons.shopping_bag),
                label: const Text("Go to Rewards Store"),
              )
            ],
          ),
        ),
      );
    }

    final scenario = _scenarios[_currentScenarioIndex];

    return Padding(
      padding: const EdgeInsets.all(20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          // Academy Stats bar
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Text(
                "Challenge ${_currentScenarioIndex + 1} of ${_scenarios.length}",
                style: const TextStyle(fontWeight: FontWeight.bold, color: Colors.black54),
              ),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                decoration: BoxDecoration(
                  color: const Color(0xFFEFF6FF),
                  borderRadius: BorderRadius.circular(16),
                ),
                child: Row(
                  children: [
                    const Icon(Icons.shield, color: Color(0xFF3B82F6), size: 16),
                    const SizedBox(width: 4),
                    Text(
                      "$_userPoints SP",
                      style: const TextStyle(
                        fontWeight: FontWeight.bold,
                        color: Color(0xFF1E3A8A),
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: 20),

          // Scenario swiping / rendering Card
          Expanded(
            child: Card(
              elevation: 4,
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
              child: Padding(
                padding: const EdgeInsets.all(24),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    Row(
                      children: [
                        const Icon(Icons.help_outline, color: Color(0xFF1E3A8A)),
                        const SizedBox(width: 8),
                        Expanded(
                          child: Text(
                            scenario['title'] ?? '',
                            style: const TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                          ),
                        ),
                      ],
                    ),
                    const Divider(height: 24),
                    Expanded(
                      child: Center(
                        child: SingleChildScrollView(
                          child: Container(
                            width: double.infinity,
                            padding: const EdgeInsets.all(16),
                            decoration: BoxDecoration(
                              color: const Color(0xFFF8FAFC),
                              border: Border.all(color: const Color(0xFFE2E8F0)),
                              borderRadius: BorderRadius.circular(12),
                            ),
                            child: Text(
                              scenario['message'] ?? '',
                              style: const TextStyle(
                                fontSize: 15,
                                fontStyle: FontStyle.italic,
                                color: Color(0xFF334155),
                                height: 1.5,
                              ),
                            ),
                          ),
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ),
          const SizedBox(height: 24),

          // Bottom Swiper Selection Buttons
          Row(
            children: [
              Expanded(
                child: ElevatedButton.icon(
                  style: ElevatedButton.styleFrom(
                    backgroundColor: const Color(0xFFDC2626), // Red
                    padding: const EdgeInsets.symmetric(vertical: 16),
                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                  ),
                  onPressed: _quizSubmitting ? null : () => _submitAnswer(true),
                  icon: const Icon(Icons.gpp_bad),
                  label: const Text(
                    "Report Phishing",
                    style: TextStyle(fontWeight: FontWeight.bold, fontSize: 15),
                  ),
                ),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: ElevatedButton.icon(
                  style: ElevatedButton.styleFrom(
                    backgroundColor: const Color(0xFF16A34A), // Green
                    padding: const EdgeInsets.symmetric(vertical: 16),
                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                  ),
                  onPressed: _quizSubmitting ? null : () => _submitAnswer(false),
                  icon: const Icon(Icons.verified),
                  label: const Text(
                    "Safe / Genuine",
                    style: TextStyle(fontWeight: FontWeight.bold, fontSize: 15),
                  ),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildRewardsTab() {
    final catalog = [
      {
        'id': 'yono_discount',
        'title': 'Yono Shopping Voucher',
        'desc': 'Get ₹250 instant discount on YONO shopping catalog.',
        'cost': 500,
        'icon': Icons.shopping_cart
      },
      {
        'id': 'card_waiver',
        'title': 'SBI Card Fee Waiver',
        'desc': 'Waive credit card annual fee for one billing cycle.',
        'cost': 1000,
        'icon': Icons.credit_card
      },
      {
        'id': 'antivirus_sub',
        'title': 'Premium Mobile Antivirus',
        'desc': '6-month free subscription to mobile security suite.',
        'cost': 1500,
        'icon': Icons.security_update_good
      },
    ];

    return ListView(
      padding: const EdgeInsets.all(20),
      children: [
        // Balance Display
        Container(
          padding: const EdgeInsets.all(20),
          decoration: BoxDecoration(
            gradient: const LinearGradient(
              colors: [Color(0xFF1E3A8A), Color(0xFF3B82F6)],
              begin: Alignment.topLeft,
              end: Alignment.bottomRight,
            ),
            borderRadius: BorderRadius.circular(16),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text(
                "My Shield Points Balance",
                style: TextStyle(color: Colors.white70, fontSize: 14),
              ),
              const SizedBox(height: 4),
              Text(
                "$_userPoints SP",
                style: const TextStyle(
                  color: Colors.white,
                  fontSize: 32,
                  fontWeight: FontWeight.w800,
                ),
              ),
              const SizedBox(height: 8),
              const Text(
                "Learn about security, protect your money, and unlock premium banking benefits.",
                style: TextStyle(color: Colors.white60, fontSize: 11),
              ),
            ],
          ),
        ),
        const SizedBox(height: 24),

        const Text(
          "Available Rewards",
          style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold, color: Color(0xFF1E293B)),
        ),
        const SizedBox(height: 12),

        // Reward cards
        ...catalog.map((item) {
          final cost = item['cost'] as int;
          final isAffordable = _userPoints >= cost;

          return Card(
            margin: const EdgeInsets.only(bottom: 12),
            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Row(
                children: [
                  Container(
                    padding: const EdgeInsets.all(12),
                    decoration: BoxDecoration(
                      color: const Color(0xFFEFF6FF),
                      borderRadius: BorderRadius.circular(10),
                    ),
                    child: Icon(item['icon'] as IconData, color: const Color(0xFF1E3A8A)),
                  ),
                  const SizedBox(width: 16),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          item['title'] as String,
                          style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 14),
                        ),
                        const SizedBox(height: 4),
                        Text(
                          item['desc'] as String,
                          style: const TextStyle(fontSize: 12, color: Colors.black54),
                        ),
                        const SizedBox(height: 8),
                        Text(
                          "Cost: $cost SP",
                          style: const TextStyle(
                            fontWeight: FontWeight.bold,
                            color: Color(0xFF1E3A8A),
                            fontSize: 13,
                          ),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(width: 8),
                  ElevatedButton(
                    style: ElevatedButton.styleFrom(
                      backgroundColor: isAffordable ? const Color(0xFF1E3A8A) : Colors.grey,
                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
                    ),
                    onPressed: isAffordable ? () => _redeemReward(item['id'] as String, cost) : null,
                    child: const Text(
                      "Claim",
                      style: TextStyle(fontWeight: FontWeight.bold, fontSize: 12),
                    ),
                  ),
                ],
              ),
            ),
          );
        }),

        if (_myVouchers.isNotEmpty) ...[
          const SizedBox(height: 24),
          const Text(
            "My Claimed Vouchers",
            style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold, color: Color(0xFF1E293B)),
          ),
          const SizedBox(height: 12),
          ..._myVouchers.map((v) {
            return Card(
              margin: const EdgeInsets.only(bottom: 8),
              color: const Color(0xFFF1F5F9),
              child: ListTile(
                title: Text(v['title'] ?? '', style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 13)),
                subtitle: Text("Redeemed at: ${v['redeemed_at'].split('T')[0]}", style: const TextStyle(fontSize: 11)),
                trailing: Text(
                  v['code'] ?? '',
                  style: const TextStyle(
                    fontWeight: FontWeight.bold,
                    fontFamily: 'monospace',
                    color: Color(0xFF1E3A8A),
                  ),
                ),
              ),
            );
          }),
        ]
      ],
    );
  }
}
