import 'package:flutter/material.dart';
import 'package:bankguard/bankguard.dart';

class FundTransferScreen extends StatefulWidget {
  const FundTransferScreen({super.key});

  @override
  State<FundTransferScreen> createState() => _FundTransferScreenState();
}

class _FundTransferScreenState extends State<FundTransferScreen>
    with SingleTickerProviderStateMixin {
  static const _sbiBlue = Color(0xFF1E3A8A);

  late TabController _tabController;
  final _identifierController = TextEditingController();
  final _ifscController = TextEditingController();
  final _amountController = TextEditingController();
  final _sdk = Bankguard();

  bool _friChecking = false;
  bool _friUnavailable = false;
  FriCheckResult? _friResult;
  bool _showReview = false;
  bool _paymentDone = false;
  bool _hasSpokenBlocked = false;

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 3, vsync: this);
    _tabController.addListener(() {
      if (_tabController.indexIsChanging) _resetForm();
    });
  }

  @override
  void dispose() {
    _sdk.stopSpeaking();
    _tabController.dispose();
    _identifierController.dispose();
    _ifscController.dispose();
    _amountController.dispose();
    super.dispose();
  }

  static const _scamWarningTranslations = {
    'en': {
      'title': 'Potential Scam Warning',
      'body': 'A suspicious notification was recently detected matching this payment context:',
      'reason_prefix': 'Reason: ',
      'explanation_header': 'Scam Explanation:',
      'checkbox': 'I confirm I have verified the identity of this payee via voice call.',
      'cancel': 'Cancel Transfer',
      'confirm': 'CHECK BEFORE PAYING',
      'tts': 'Potential Scam Warning. A suspicious notification was recently detected matching this payment context. Recipient matches an identifier found in a suspicious message or payment initiated within 15 minutes of receiving a suspicious alert. Please verify before paying.',
    },
    'hi': {
      'title': 'संभावित घोटाले की चेतावनी',
      'body': 'हाल ही में इस भुगतान संदर्भ से मेल खाता एक संदिग्ध नोटिफिकेशन पाया गया है:',
      'reason_prefix': 'कारण: ',
      'explanation_header': 'घोटाले का स्पष्टीकरण:',
      'checkbox': 'मैं पुष्टि करता हूं कि मैंने वॉयस कॉल के माध्यम से इस प्राप्तकर्ता की पहचान सत्यापित कर ली है.',
      'cancel': 'रद्द करें',
      'confirm': 'भुगतान से पहले जांचें',
      'tts': 'संभावित घोटाले की चेतावनी। हाल ही में इस भुगतान संदर्भ से मेल खाता एक संदिग्ध नोटिफिकेशन पाया गया है। कृपया आगे बढ़ने से पहले वॉयस कॉल के माध्यम से प्राप्तकर्ता की पहचान सत्यापित करें।',
    },
    'ta': {
      'title': 'சாத்தியமான மோசடி எச்சரிக்கை',
      'body': 'சமீபத்தில் இந்த கட்டண சூழலுடன் பொருந்தக்கூடிய சந்தேகத்திற்கிடமான அறிவிப்பு கண்டறியப்பட்டது:',
      'reason_prefix': 'காரணம்: ',
      'explanation_header': 'மோசடி விளக்கம்:',
      'checkbox': 'குரல் அழைப்பு மூலம் இந்த பெறுநரின் அடையாளத்தை நான் சரிபார்த்தேன் என்பதை உறுதிப்படுத்துகிறேன்.',
      'cancel': 'ரத்துசெய்',
      'confirm': 'செலுத்துவதற்கு முன் சரிபார்க்கவும்',
      'tts': 'சாத்தியமான மோசடி எச்சரிக்கை. சமீபத்தில் இந்த கட்டண சூழலுடன் பொருந்தக்கூடிய சந்தேகத்திற்கிடமான அறிவிப்பு கண்டறியப்பட்டது. தொடர்வதற்கு முன் குரல் அழைப்பு மூலம் பணம் பெறுபவரின் அடையாளத்தை சரிபார்க்கவும்.',
    },
    'te': {
      'title': 'సంభావ్య మోసం హెచ్చరిక',
      'body': 'ఇటీవలే ఈ చెల్లింపు సందర్భానికి సరిపోయే అనుమానాస్పద నోటిఫికేషన్ కనుగొనబడింది:',
      'reason_prefix': 'కారణం: ',
      'explanation_header': 'మోసం వివరణ:',
      'checkbox': 'నేను వాయిస్ కాల్ ద్వారా ఈ గ్రహీత గుర్తింపును ధృవీకరించినట్లు ధృవీకరిస్తున్నాను.',
      'cancel': 'రద్దు చేయి',
      'confirm': 'చెల్లించే ముందు తనిఖీ చేయండి',
      'tts': 'సంభావ్య మోసం హెచ్చరిక. ఇటీవలే ఈ చెల్లింపు సందర్భానికి సరిపోయే అనుమానాస్పద నోటిఫికేషన్ కనుగొనబడింది. కొనసాగడానికి ముందు వాయిస్ కాల్ ద్వారా గ్రహీత గుర్తింపును ధృవీకరించండి.',
    },
    'bn': {
      'title': 'সম্ভাব্য প্রতারণার সতর্কতা',
      'body': 'সম্প্রতি এই অর্থপ্রদানের প্রসঙ্গের সাথে মিলে যাওয়া একটি সন্দেহজনক বিজ্ঞপ্তি সনাক্ত করা হয়েছে:',
      'reason_prefix': 'কারণ: ',
      'explanation_header': 'প্রতারণার ব্যাখ্যা:',
      'checkbox': 'আমি নিশ্চিত করছি যে আমি ভয়েস কলের মাধ্যমে এই প্রাপকের পরিচয় যাচাই করেছি।',
      'cancel': 'বাতিল করুন',
      'confirm': 'দেওয়ার আগে যাচাই করুন',
      'tts': 'সম্ভাব্য প্রতারণার সতর্কতা। সম্প্রতি এই অর্থপ্রদানের প্রসঙ্গের সাথে মিলে যাওয়া একটি সন্দেহজনক বিজ্ঞপ্তি সনাক্ত করা হয়েছে। অনুগ্রহ করে এগিয়ে যাওয়ার আগে ভয়েস কলের মাধ্যমে প্রাপকের পরিচয় যাচাই করুন।',
    },
    'mr': {
      'title': 'संभाव्य फसवणुकीचा इशारा',
      'body': 'नुकतीच या पेमेंट संदर्भाशी जुळणारी संशयास्पद सूचना आढळली आहे:',
      'reason_prefix': 'कारण: ',
      'explanation_header': 'फसवणुकीचे स्पष्टीकरण:',
      'checkbox': 'मी पुष्टी करतो की मी व्हॉइस कॉलद्वारे या प्राप्तकर्त्याची ओळख सत्यापित केली आहे.',
      'cancel': 'रद्द करा',
      'confirm': 'भरण्यापूर्वी तपासा',
      'tts': 'संभाव्य फसवणुकीचा इशारा. नुकतीच या पेमेंट संदर्भाशी जुळणारी संशयास्पद सूचना आढळली आहे. कृपया पुढे जाण्यापूर्वी व्हॉइस कॉलद्वारे प्राप्तकर्त्याची ओळख सत्यापित करा.',
    }
  };

  Widget _buildLangChip(String code, String label, String currentOverride, Function(String) onSelect) {
    final isSelected = currentOverride == code;
    return Padding(
      padding: const EdgeInsets.only(right: 6.0),
      child: ChoiceChip(
        label: Text(label),
        labelStyle: TextStyle(
          color: isSelected ? Colors.white : Colors.black87,
          fontWeight: isSelected ? FontWeight.bold : FontWeight.normal,
          fontSize: 12,
        ),
        selected: isSelected,
        selectedColor: Colors.amber.shade700,
        backgroundColor: Colors.white,
        side: BorderSide(
          color: isSelected ? Colors.amber.shade700 : Colors.black26,
          width: isSelected ? 1.5 : 1.0,
        ),
        showCheckmark: false,
        onSelected: (selected) {
          if (selected) onSelect(code);
        },
      ),
    );
  }

  Future<void> _verifyContextAndConfirm() async {
    final amt = double.tryParse(_amountController.text) ?? 0.0;
    final id = _identifierController.text.trim();
    final type = _currentIdType;

    final riskResult = await _sdk.evaluateTransactionRisk(
      targetIdentifier: id,
      identifierType: type,
      amount: amt,
    );

    if (!mounted) return;

    if (riskResult.isHighRisk) {
      showDialog(
        context: context,
        barrierDismissible: false,
        builder: (BuildContext context) {
          bool confirmed = false;
          String? dialogLangOverride;
          bool isFirstLoad = true;

          return StatefulBuilder(
            builder: (context, setDialogState) {
              final activeLang = dialogLangOverride ?? 'en';
              final translations = _scamWarningTranslations[activeLang] ?? _scamWarningTranslations['en']!;
              final textToSpeak = translations['tts']!;

              if (isFirstLoad) {
                isFirstLoad = false;
                WidgetsBinding.instance.addPostFrameCallback((_) {
                  _sdk.speak(textToSpeak, languageCode: activeLang);
                });
              }

              return PopScope(
                onPopInvoked: (didPop) {
                  if (didPop) {
                    _sdk.stopSpeaking();
                  }
                },
                child: AlertDialog(
                  backgroundColor: const Color(0xFF1E293B),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(16),
                  ),
                  title: Row(
                    children: [
                      const Icon(Icons.warning, color: Colors.amber, size: 24),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          translations['title']!,
                          style: const TextStyle(
                            color: Colors.white,
                            fontSize: 18,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      ),
                      IconButton(
                        icon: const Icon(Icons.volume_up, color: Colors.amber, size: 24),
                        onPressed: () {
                          _sdk.stopSpeaking();
                          _sdk.speak(textToSpeak, languageCode: activeLang);
                        },
                      ),
                    ],
                  ),
                  content: SingleChildScrollView(
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        // Language Selector Chips
                        SingleChildScrollView(
                          scrollDirection: Axis.horizontal,
                          child: Row(
                            children: [
                              _buildLangChip('en', 'English', activeLang, (code) {
                                setDialogState(() {
                                  dialogLangOverride = code;
                                });
                                _sdk.stopSpeaking();
                                _sdk.speak(_scamWarningTranslations[code]!['tts']!, languageCode: code);
                              }),
                              _buildLangChip('hi', 'हिन्दी', activeLang, (code) {
                                setDialogState(() {
                                  dialogLangOverride = code;
                                });
                                _sdk.stopSpeaking();
                                _sdk.speak(_scamWarningTranslations[code]!['tts']!, languageCode: code);
                              }),
                              _buildLangChip('ta', 'தமிழ்', activeLang, (code) {
                                setDialogState(() {
                                  dialogLangOverride = code;
                                });
                                _sdk.stopSpeaking();
                                _sdk.speak(_scamWarningTranslations[code]!['tts']!, languageCode: code);
                              }),
                              _buildLangChip('te', 'తెలుగు', activeLang, (code) {
                                setDialogState(() {
                                  dialogLangOverride = code;
                                });
                                _sdk.stopSpeaking();
                                _sdk.speak(_scamWarningTranslations[code]!['tts']!, languageCode: code);
                              }),
                              _buildLangChip('bn', 'বাংলা', activeLang, (code) {
                                setDialogState(() {
                                  dialogLangOverride = code;
                                });
                                _sdk.stopSpeaking();
                                _sdk.speak(_scamWarningTranslations[code]!['tts']!, languageCode: code);
                              }),
                              _buildLangChip('mr', 'मराठी', activeLang, (code) {
                                setDialogState(() {
                                  dialogLangOverride = code;
                                });
                                _sdk.stopSpeaking();
                                _sdk.speak(_scamWarningTranslations[code]!['tts']!, languageCode: code);
                              }),
                            ],
                          ),
                        ),
                        const SizedBox(height: 16),
                        // Universal Warning Graphic
                        Center(
                          child: ClipRRect(
                            borderRadius: BorderRadius.circular(12),
                            child: Image.asset(
                              'assets/images/rupee_transfer_warning.png',
                              height: 100,
                              fit: BoxFit.contain,
                            ),
                          ),
                        ),
                        const SizedBox(height: 16),

                        Text(
                          translations['body']!,
                          style: TextStyle(
                            color: Colors.white.withOpacity(0.8),
                            fontSize: 13,
                          ),
                        ),
                        const SizedBox(height: 12),
                        Container(
                          width: double.infinity,
                          padding: const EdgeInsets.all(10),
                          decoration: BoxDecoration(
                            color: Colors.black26,
                            borderRadius: BorderRadius.circular(8),
                            border: Border.all(color: Colors.white12),
                          ),
                          child: Text(
                            '${translations['reason_prefix']!}${riskResult.triggers.join("\n")}',
                            style: const TextStyle(
                              color: Colors.orangeAccent,
                              fontSize: 12,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                        ),
                        const SizedBox(height: 12),
                        Text(
                          translations['explanation_header']!,
                          style: TextStyle(
                            color: Colors.white.withOpacity(0.9),
                            fontSize: 13,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                        Text(
                          riskResult.explanation ?? '',
                          style: TextStyle(
                            color: Colors.white.withOpacity(0.7),
                            fontSize: 12,
                          ),
                        ),
                        const SizedBox(height: 16),
                        Row(
                          children: [
                            Checkbox(
                              value: confirmed,
                              onChanged: (val) {
                                setDialogState(() {
                                  confirmed = val ?? false;
                                });
                              },
                              checkColor: Colors.black,
                              activeColor: Colors.amber,
                              side: const BorderSide(color: Colors.white60),
                            ),
                            Expanded(
                              child: Text(
                                translations['checkbox']!,
                                style: const TextStyle(
                                  color: Colors.white70,
                                  fontSize: 11,
                                ),
                              ),
                            ),
                          ],
                        ),
                      ],
                    ),
                  ),
                  actions: [
                    TextButton(
                      onPressed: () {
                        _sdk.stopSpeaking();
                        Navigator.pop(context);
                      },
                      child: Text(
                        translations['cancel']!,
                        style: const TextStyle(color: Colors.white60),
                      ),
                    ),
                    ElevatedButton(
                      onPressed: confirmed
                          ? () {
                              _sdk.stopSpeaking();
                              Navigator.pop(context);
                              setState(() => _paymentDone = true);
                            }
                          : null,
                      style: ElevatedButton.styleFrom(
                        backgroundColor: Colors.amber.shade700,
                        disabledBackgroundColor: Colors.grey.shade800,
                        disabledForegroundColor: Colors.white30,
                      ),
                      child: Text(
                        translations['confirm']!,
                        style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 11),
                      ),
                    ),
                  ],
                ),
              );
            },
          );
        },
      );
    } else {
      setState(() => _paymentDone = true);
    }
  }

  void _resetForm() {
    _sdk.stopSpeaking();
    setState(() {
      _identifierController.clear();
      _ifscController.clear();
      _amountController.clear();
      _friChecking = false;
      _friUnavailable = false;
      _friResult = null;
      _showReview = false;
      _paymentDone = false;
      _hasSpokenBlocked = false;
    });
  }

  String get _currentIdType {
    switch (_tabController.index) {
      case 0:
        return 'upi';
      case 1:
        return 'mobile';
      case 2:
        return 'bank_account';
      default:
        return 'upi';
    }
  }

  String get _currentLabel {
    switch (_tabController.index) {
      case 0:
        return 'UPI ID';
      case 1:
        return 'Mobile Number';
      case 2:
        return 'Account Number';
      default:
        return 'Identifier';
    }
  }

  /// Delegate FRI check to SDK
  Future<void> _proceed() async {
    final identifier = _identifierController.text.trim();
    final amount = _amountController.text.trim();
    if (identifier.isEmpty || amount.isEmpty) {
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('Please fill all fields')));
      return;
    }

    setState(() {
      _friChecking = true;
      _friResult = null;
      _friUnavailable = false;
    });

    // Use the correct SDK method based on identifier type
    FriCheckResult? result;
    switch (_currentIdType) {
      case 'upi':
        result = await _sdk.checkUPIId(identifier);
        break;
      case 'mobile':
        result = await _sdk.checkMobileNumber(identifier);
        break;
      case 'bank_account':
        result = await _sdk.checkBankAccount(identifier);
        break;
    }

    if (!mounted) return;
    setState(() {
      _friChecking = false;
      if (result == null) {
        _friUnavailable = true;
        _showReview = true;
      } else if (result.found) {
        _friResult = result;
      } else {
        _showReview = true;
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Fund Transfer'),
        backgroundColor: _sbiBlue,
        foregroundColor: Colors.white,
        bottom: _paymentDone || (_friResult != null && _friResult!.found)
            ? null
            : TabBar(
                controller: _tabController,
                indicatorColor: Colors.white,
                labelColor: Colors.white,
                unselectedLabelColor: Colors.white60,
                tabs: const [
                  Tab(text: 'UPI ID'),
                  Tab(text: 'Mobile'),
                  Tab(text: 'Account'),
                ],
              ),
      ),
      body: _paymentDone
          ? _buildSuccess()
          : _friChecking
          ? _buildChecking()
          : (_friResult != null && _friResult!.found)
          ? _buildBlocked()
          : _showReview
          ? _buildReview()
          : _buildForm(),
    );
  }

  Widget _buildForm() {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          const SizedBox(height: 16),
          TextField(
            controller: _identifierController,
            decoration: InputDecoration(
              labelText: _currentLabel,
              border: const OutlineInputBorder(),
              prefixIcon: Icon(
                _tabController.index == 0
                    ? Icons.alternate_email
                    : _tabController.index == 1
                    ? Icons.phone
                    : Icons.account_balance,
              ),
              hintText: _tabController.index == 0
                  ? 'e.g. name@upi'
                  : _tabController.index == 1
                  ? 'e.g. 9876543210'
                  : 'e.g. 20410100045231',
            ),
            keyboardType: _tabController.index == 0
                ? TextInputType.emailAddress
                : TextInputType.number,
          ),
          if (_tabController.index == 2) ...[
            const SizedBox(height: 16),
            TextField(
              controller: _ifscController,
              decoration: const InputDecoration(
                labelText: 'IFSC Code',
                border: OutlineInputBorder(),
                prefixIcon: Icon(Icons.business),
                hintText: 'e.g. SBIN0001234',
              ),
              textCapitalization: TextCapitalization.characters,
            ),
          ],
          const SizedBox(height: 16),
          TextField(
            controller: _amountController,
            decoration: const InputDecoration(
              labelText: 'Amount (₹)',
              border: OutlineInputBorder(),
              prefixText: '₹ ',
              prefixIcon: Icon(Icons.currency_rupee),
            ),
            keyboardType: TextInputType.number,
          ),
          const SizedBox(height: 32),
          ElevatedButton(
            onPressed: _proceed,
            style: ElevatedButton.styleFrom(
              backgroundColor: _sbiBlue,
              foregroundColor: Colors.white,
              padding: const EdgeInsets.symmetric(vertical: 16),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12),
              ),
            ),
            child: const Text(
              'Proceed',
              style: TextStyle(fontSize: 16, fontWeight: FontWeight.w600),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildChecking() {
    return const Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          CircularProgressIndicator(color: _sbiBlue),
          SizedBox(height: 24),
          Text(
            'Verifying against FRI database...',
            style: TextStyle(fontSize: 16, color: Colors.black54),
          ),
        ],
      ),
    );
  }

  Widget _buildBlocked() {
    final result = _friResult!;
    final isVeryHigh = result.riskLevel == 'Very High';
    final accent = isVeryHigh ? Colors.red.shade700 : Colors.orange.shade700;

    final textToSpeak = "Transfer Blocked. This identifier is flagged in the Fraud Risk Indicator database. Risk Level: ${result.riskLevel ?? 'Unknown'}. Fraud Category: ${result.fraudCategory ?? 'Unknown'}. Reason: ${result.reason ?? 'This identifier has been reported for fraudulent activity.'}";

    if (!_hasSpokenBlocked) {
      _hasSpokenBlocked = true;
      WidgetsBinding.instance.addPostFrameCallback((_) {
        _sdk.speak(textToSpeak, languageCode: 'en');
      });
    }

    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        children: [
          const SizedBox(height: 24),
          // Universal Warning Graphic
          Center(
            child: ClipRRect(
              borderRadius: BorderRadius.circular(12),
              child: Image.asset(
                'assets/images/qr_skull_warning.png',
                height: 120,
                fit: BoxFit.contain,
              ),
            ),
          ),
          const SizedBox(height: 24),

          Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Text(
                'TRANSFER BLOCKED',
                style: TextStyle(
                  fontSize: 24,
                  fontWeight: FontWeight.w900,
                  color: accent,
                ),
              ),
              const SizedBox(width: 8),
              IconButton(
                icon: Icon(Icons.volume_up, color: accent, size: 24),
                onPressed: () {
                  _sdk.stopSpeaking();
                  _sdk.speak(textToSpeak, languageCode: 'en');
                },
              ),
            ],
          ),
          const SizedBox(height: 8),
          const Text(
            'This identifier is flagged in the Fraud Risk Indicator database',
            style: TextStyle(fontSize: 15, color: Colors.black54),
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: 24),
          _infoCard(_currentLabel, _identifierController.text, accent),
          const SizedBox(height: 12),
          _infoCard('Risk Level', result.riskLevel ?? 'Unknown', accent),
          const SizedBox(height: 12),
          _infoCard(
            'Fraud Category',
            result.fraudCategory ?? 'Unknown',
            accent,
          ),
          const SizedBox(height: 12),
          Container(
            width: double.infinity,
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: accent.withOpacity(0.06),
              borderRadius: BorderRadius.circular(12),
              border: Border.all(color: accent.withOpacity(0.2)),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Why is this dangerous?',
                  style: TextStyle(
                    fontWeight: FontWeight.w700,
                    color: accent,
                    fontSize: 13,
                  ),
                ),
                const SizedBox(height: 8),
                Text(
                  result.reason ??
                      'This identifier has been reported for fraudulent activity.',
                  style: const TextStyle(fontSize: 14, height: 1.5),
                ),
              ],
            ),
          ),
          const SizedBox(height: 32),
          SizedBox(
            width: double.infinity,
            child: ElevatedButton.icon(
              onPressed: () {
                _sdk.stopSpeaking();
                Navigator.pushNamed(context, '/report');
              },
              icon: const Icon(Icons.front_hand),
              label: const Text(
                "DON'T PAY",
                style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold),
              ),
              style: ElevatedButton.styleFrom(
                backgroundColor: const Color(0xFFDC2626), // Solid Red
                foregroundColor: Colors.white,
                padding: const EdgeInsets.symmetric(vertical: 16),
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(12),
                ),
              ),
            ),
          ),
          const SizedBox(height: 12),
          TextButton(onPressed: _resetForm, child: const Text('Start Over')),
        ],
      ),
    );
  }

  Widget _buildReview() {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          if (_friUnavailable)
            Container(
              padding: const EdgeInsets.all(12),
              margin: const EdgeInsets.only(bottom: 16),
              decoration: BoxDecoration(
                color: Colors.amber.shade50,
                borderRadius: BorderRadius.circular(10),
                border: Border.all(color: Colors.amber.shade200),
              ),
              child: const Row(
                children: [
                  Icon(Icons.info_outline, color: Colors.amber, size: 20),
                  SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      'Fraud verification unavailable. Proceed with caution.',
                      style: TextStyle(fontSize: 13, color: Colors.black54),
                    ),
                  ),
                ],
              ),
            ),
          const SizedBox(height: 16),
          const Icon(Icons.check_circle, size: 48, color: Color(0xFF059669)),
          const SizedBox(height: 12),
          const Text(
            'Review Transfer',
            style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: 24),
          Container(
            padding: const EdgeInsets.all(20),
            decoration: BoxDecoration(
              color: Colors.white,
              borderRadius: BorderRadius.circular(14),
              boxShadow: [
                BoxShadow(
                  color: Colors.black.withOpacity(0.05),
                  blurRadius: 10,
                ),
              ],
            ),
            child: Column(
              children: [
                _detailRow(_currentLabel, _identifierController.text),
                if (_tabController.index == 2 &&
                    _ifscController.text.isNotEmpty) ...[
                  const Divider(height: 24),
                  _detailRow('IFSC', _ifscController.text),
                ],
                const Divider(height: 24),
                _detailRow('Amount', '₹ ${_amountController.text}'),
              ],
            ),
          ),
          const SizedBox(height: 32),
          ElevatedButton(
            onPressed: _verifyContextAndConfirm,
            style: ElevatedButton.styleFrom(
              backgroundColor: _sbiBlue,
              foregroundColor: Colors.white,
              padding: const EdgeInsets.symmetric(vertical: 16),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12),
              ),
            ),
            child: const Text(
              'Confirm Transfer',
              style: TextStyle(fontSize: 16, fontWeight: FontWeight.w600),
            ),
          ),
          const SizedBox(height: 12),
          TextButton(onPressed: _resetForm, child: const Text('Cancel')),
        ],
      ),
    );
  }

  Widget _buildSuccess() {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Container(
              padding: const EdgeInsets.all(24),
              decoration: const BoxDecoration(
                color: Color(0xFFECFDF5),
                shape: BoxShape.circle,
              ),
              child: const Icon(
                Icons.check,
                size: 56,
                color: Color(0xFF059669),
              ),
            ),
            const SizedBox(height: 24),
            const Text(
              'Transfer Successful!',
              style: TextStyle(
                fontSize: 24,
                fontWeight: FontWeight.bold,
                color: Color(0xFF059669),
              ),
            ),
            const SizedBox(height: 8),
            Text(
              '₹ ${_amountController.text} transferred',
              style: const TextStyle(fontSize: 16, color: Colors.black54),
            ),
            const SizedBox(height: 4),
            const Text(
              '(Simulated — no real transaction)',
              style: TextStyle(fontSize: 12, color: Colors.black38),
            ),
            const SizedBox(height: 32),
            ElevatedButton(
              onPressed: () => Navigator.pop(context),
              style: ElevatedButton.styleFrom(
                backgroundColor: _sbiBlue,
                foregroundColor: Colors.white,
              ),
              child: const Text('Back to Home'),
            ),
          ],
        ),
      ),
    );
  }

  Widget _infoCard(String label, String value, Color accent) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: accent.withOpacity(0.2)),
      ),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(
            label,
            style: const TextStyle(
              fontSize: 13,
              color: Colors.black54,
              fontWeight: FontWeight.w500,
            ),
          ),
          Text(
            value,
            style: TextStyle(
              fontSize: 14,
              fontWeight: FontWeight.w700,
              color: accent,
            ),
          ),
        ],
      ),
    );
  }

  Widget _detailRow(String label, String value) {
    return Row(
      mainAxisAlignment: MainAxisAlignment.spaceBetween,
      children: [
        Text(label, style: const TextStyle(color: Colors.black54)),
        Flexible(
          child: Text(
            value,
            style: const TextStyle(fontWeight: FontWeight.w600),
            textAlign: TextAlign.end,
          ),
        ),
      ],
    );
  }
}
