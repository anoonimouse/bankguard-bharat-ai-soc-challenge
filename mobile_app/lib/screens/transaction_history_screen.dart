import 'package:flutter/material.dart';
import '../data/dummy_data.dart';
import 'package:bankguard/bankguard.dart';

class TransactionHistoryScreen extends StatefulWidget {
  const TransactionHistoryScreen({super.key});

  @override
  State<TransactionHistoryScreen> createState() =>
      _TransactionHistoryScreenState();
}

class _TransactionHistoryScreenState extends State<TransactionHistoryScreen> {
  static const _sbiBlue = Color(0xFF1E3A8A);
  final _sdk = Bankguard();

  bool _friScanning = true;
  final Map<String, FriBatchResult> _friFlags = {};

  @override
  void initState() {
    super.initState();
    _runBatchFriCheck();
  }

  /// Delegate batch FRI check to SDK
  Future<void> _runBatchFriCheck() async {
    final items = <FriBatchItem>[];
    final txList = dummyTransactions.take(20).toList();

    for (final tx in txList) {
      if (tx.counterpartyUpi != null && tx.counterpartyUpi!.isNotEmpty) {
        items.add(
          FriBatchItem(
            identifierType: 'upi',
            identifierValue: tx.counterpartyUpi!,
          ),
        );
      }
      if (tx.counterpartyMobile != null && tx.counterpartyMobile!.isNotEmpty) {
        items.add(
          FriBatchItem(
            identifierType: 'mobile',
            identifierValue: tx.counterpartyMobile!,
          ),
        );
      }
    }

    final results = await _sdk.checkBatch(items);

    if (!mounted) return;
    setState(() {
      _friScanning = false;
      for (final r in results) {
        if (r.found) {
          for (final tx in txList) {
            if ((tx.counterpartyUpi != null &&
                    r.identifierType == 'upi' &&
                    r.identifierValue == tx.counterpartyUpi) ||
                (tx.counterpartyMobile != null &&
                    r.identifierType == 'mobile' &&
                    r.identifierValue == tx.counterpartyMobile)) {
              _friFlags[tx.id] = r;
            }
          }
        }
      }
    });
  }

  void _showFriDetail(FriBatchResult flag) {
    showModalBottomSheet(
      context: context,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (ctx) {
        final isVeryHigh = flag.riskLevel == 'Very High';
        final accent = isVeryHigh
            ? Colors.red.shade700
            : Colors.orange.shade700;
        return Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Icon(Icons.gpp_bad, color: accent, size: 28),
                  const SizedBox(width: 12),
                  Text(
                    'FRI Alert',
                    style: TextStyle(
                      fontSize: 20,
                      fontWeight: FontWeight.bold,
                      color: accent,
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 16),
              _detailRow('Identifier', flag.identifierValue),
              _detailRow('Type', flag.identifierType.toUpperCase()),
              _detailRow('Risk Level', flag.riskLevel ?? 'Unknown'),
              _detailRow('Fraud Category', flag.fraudCategory ?? 'Unknown'),
              const SizedBox(height: 12),
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: accent.withOpacity(0.06),
                  borderRadius: BorderRadius.circular(10),
                ),
                child: Text(
                  flag.reason ?? 'Flagged for suspected fraudulent activity.',
                  style: const TextStyle(fontSize: 14, height: 1.5),
                ),
              ),
              const SizedBox(height: 16),
              SizedBox(
                width: double.infinity,
                child: ElevatedButton(
                  onPressed: () => Navigator.pop(ctx),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: accent,
                    foregroundColor: Colors.white,
                    padding: const EdgeInsets.symmetric(vertical: 14),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(12),
                    ),
                  ),
                  child: const Text('Close'),
                ),
              ),
            ],
          ),
        );
      },
    );
  }

  Widget _detailRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 120,
            child: Text(
              label,
              style: const TextStyle(
                color: Colors.black54,
                fontWeight: FontWeight.w500,
              ),
            ),
          ),
          Expanded(
            child: Text(
              value,
              style: const TextStyle(fontWeight: FontWeight.w600),
            ),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Transaction History'),
        backgroundColor: _sbiBlue,
        foregroundColor: Colors.white,
      ),
      backgroundColor: const Color(0xFFF0F4F8),
      body: Column(
        children: [
          if (_friScanning)
            Container(
              width: double.infinity,
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
              color: _sbiBlue.withOpacity(0.08),
              child: const Row(
                children: [
                  SizedBox(
                    width: 16,
                    height: 16,
                    child: CircularProgressIndicator(
                      strokeWidth: 2,
                      color: _sbiBlue,
                    ),
                  ),
                  SizedBox(width: 12),
                  Text(
                    'Scanning transactions against FRI database...',
                    style: TextStyle(fontSize: 13, color: _sbiBlue),
                  ),
                ],
              ),
            ),
          if (!_friScanning && _friFlags.isNotEmpty)
            Container(
              width: double.infinity,
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
              color: Colors.red.shade50,
              child: Row(
                children: [
                  Icon(
                    Icons.warning_amber,
                    color: Colors.red.shade700,
                    size: 18,
                  ),
                  const SizedBox(width: 8),
                  Text(
                    '${_friFlags.length} transaction(s) flagged by FRI',
                    style: TextStyle(
                      fontSize: 13,
                      color: Colors.red.shade700,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ],
              ),
            ),
          Expanded(
            child: ListView.builder(
              padding: const EdgeInsets.all(16),
              itemCount: dummyTransactions.length,
              itemBuilder: (context, index) {
                final tx = dummyTransactions[index];
                final flag = _friFlags[tx.id];
                return _buildTransactionCard(tx, flag);
              },
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildTransactionCard(Transaction tx, FriBatchResult? flag) {
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(12),
        border: flag != null
            ? Border.all(color: Colors.red.shade300, width: 1.5)
            : null,
        boxShadow: [
          BoxShadow(
            color: Colors.black.withOpacity(0.03),
            blurRadius: 6,
            offset: const Offset(0, 2),
          ),
        ],
      ),
      child: ListTile(
        contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 6),
        leading: Container(
          width: 42,
          height: 42,
          decoration: BoxDecoration(
            color: tx.isCredit
                ? const Color(0xFFECFDF5)
                : const Color(0xFFFEF2F2),
            borderRadius: BorderRadius.circular(10),
          ),
          child: Icon(
            tx.isCredit ? Icons.arrow_downward : Icons.arrow_upward,
            color: tx.isCredit
                ? const Color(0xFF059669)
                : const Color(0xFFDC2626),
            size: 20,
          ),
        ),
        title: Row(
          children: [
            Expanded(
              child: Text(
                tx.description,
                style: const TextStyle(
                  fontSize: 14,
                  fontWeight: FontWeight.w600,
                ),
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
              ),
            ),
            if (flag != null)
              GestureDetector(
                onTap: () => _showFriDetail(flag),
                child: Container(
                  padding: const EdgeInsets.symmetric(
                    horizontal: 6,
                    vertical: 2,
                  ),
                  decoration: BoxDecoration(
                    color: Colors.red.shade50,
                    borderRadius: BorderRadius.circular(6),
                    border: Border.all(color: Colors.red.shade200),
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Icon(Icons.flag, size: 12, color: Colors.red.shade700),
                      const SizedBox(width: 3),
                      Text(
                        flag.riskLevel ?? 'Risk',
                        style: TextStyle(
                          fontSize: 10,
                          fontWeight: FontWeight.w700,
                          color: Colors.red.shade700,
                        ),
                      ),
                    ],
                  ),
                ),
              ),
          ],
        ),
        subtitle: Text(
          '${tx.type} • ${tx.date} ${tx.time}',
          style: const TextStyle(fontSize: 12, color: Colors.black45),
        ),
        trailing: Text(
          '${tx.isCredit ? '+' : '-'} ₹${_formatAmount(tx.amount)}',
          style: TextStyle(
            fontSize: 14,
            fontWeight: FontWeight.w700,
            color: tx.isCredit
                ? const Color(0xFF059669)
                : const Color(0xFFDC2626),
          ),
        ),
      ),
    );
  }

  String _formatAmount(double amount) {
    final parts = amount.toStringAsFixed(2).split('.');
    final intPart = parts[0];
    final decPart = parts[1];
    if (intPart.length <= 3) return '$intPart.$decPart';
    final last3 = intPart.substring(intPart.length - 3);
    var remaining = intPart.substring(0, intPart.length - 3);
    final groups = <String>[];
    while (remaining.length > 2) {
      groups.insert(0, remaining.substring(remaining.length - 2));
      remaining = remaining.substring(0, remaining.length - 2);
    }
    if (remaining.isNotEmpty) groups.insert(0, remaining);
    return '${groups.join(',')},${last3}.$decPart';
  }
}
