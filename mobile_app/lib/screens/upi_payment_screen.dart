import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:image_picker/image_picker.dart';
import 'package:bankguard/bankguard.dart';

class UpiPaymentScreen extends StatefulWidget {
  const UpiPaymentScreen({super.key});

  @override
  State<UpiPaymentScreen> createState() => _UpiPaymentScreenState();
}

class _UpiPaymentScreenState extends State<UpiPaymentScreen> {
  static const _sbiBlue = Color(0xFF1E3A8A);

  bool _scanning = true;
  bool _friChecking = false;
  String? _extractedUpi;
  String? _payeeName;
  String? _amount;
  FriCheckResult? _friResult;
  bool _friUnavailable = false;
  bool _paymentDone = false;
  bool _hasSpokenBlocked = false;
  final _amountController = TextEditingController();
  final MobileScannerController _scannerController = MobileScannerController();
  final _sdk = Bankguard();

  @override
  void dispose() {
    _sdk.stopSpeaking();
    _scannerController.dispose();
    _amountController.dispose();
    super.dispose();
  }

  void _onBarcodeDetected(BarcodeCapture capture) {
    if (!_scanning) return;
    for (final barcode in capture.barcodes) {
      final raw = barcode.rawValue;
      if (raw != null) {
        if (raw.contains('upi://pay')) {
          setState(() => _scanning = false);
          _scannerController.stop();
          _handleQRPayload(raw);
          return;
        } else if (raw.startsWith('http://') || raw.startsWith('https://')) {
          setState(() => _scanning = false);
          _scannerController.stop();
          _redirectToVerifyLink(raw);
          return;
        }
      }
    }
  }

  void _redirectToVerifyLink(String url) {
    if (mounted) {
      Navigator.pushReplacementNamed(
        context,
        '/verify-link',
        arguments: {'url': url},
      );
    }
  }

  Future<void> _pickFromGallery() async {
    final picker = ImagePicker();
    final picked = await picker.pickImage(source: ImageSource.gallery);
    if (picked == null) return;

    final result = await _scannerController.analyzeImage(picked.path);
    if (result != null && result.barcodes.isNotEmpty) {
      for (final barcode in result.barcodes) {
        final raw = barcode.rawValue;
        if (raw != null) {
          if (raw.contains('upi://pay')) {
            setState(() => _scanning = false);
            _scannerController.stop();
            _handleQRPayload(raw);
            return;
          } else if (raw.startsWith('http://') || raw.startsWith('https://')) {
            setState(() => _scanning = false);
            _scannerController.stop();
            _redirectToVerifyLink(raw);
            return;
          }
        }
      }
    }

    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('No valid UPI QR or web link found in image')),
      );
    }
  }

  /// Delegate QR parsing + FRI check to SDK
  Future<void> _handleQRPayload(String rawUri) async {
    setState(() {
      _friChecking = true;
      _friResult = null;
      _friUnavailable = false;
    });

    final qrResult = await _sdk.scanQRPayload(rawUri);

    if (!mounted) return;

    if (qrResult.parseError != null) {
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text(qrResult.parseError!)));
      setState(() {
        _friChecking = false;
        _scanning = true;
      });
      _scannerController.start();
      return;
    }

    setState(() {
      _extractedUpi = qrResult.payeeAddress;
      _payeeName = qrResult.payeeName ?? 'Unknown';
      _amount = qrResult.amount;
      if (qrResult.amount != null && qrResult.amount!.isNotEmpty) {
        _amountController.text = qrResult.amount!;
      }
      _friChecking = false;
      if (qrResult.friResult == null) {
        _friUnavailable = true;
      } else {
        _friResult = qrResult.friResult;
      }
    });
  }

  static const _scamWarningTranslations = {
    'en': {
      'title': 'Potential Scam Warning',
      'body': 'A suspicious notification was recently detected matching this payment context:',
      'reason_prefix': 'Reason: ',
      'explanation_header': 'Scam Explanation:',
      'checkbox': 'I confirm I have verified the identity of this payee via voice call.',
      'cancel': 'Cancel Payment',
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
    final upi = _extractedUpi ?? '';

    // Evaluate risk
    final riskResult = await _sdk.evaluateTransactionRisk(
      targetIdentifier: upi,
      identifierType: 'upi',
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
                              _confirmPayment();
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
      _confirmPayment();
    }
  }

  void _confirmPayment() {
    setState(() => _paymentDone = true);
  }

  void _resetScanner() {
    _sdk.stopSpeaking();
    setState(() {
      _scanning = true;
      _extractedUpi = null;
      _payeeName = null;
      _amount = null;
      _friResult = null;
      _friUnavailable = false;
      _paymentDone = false;
      _hasSpokenBlocked = false;
      _amountController.clear();
    });
    _scannerController.start();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('UPI Payment'),
        backgroundColor: _sbiBlue,
        foregroundColor: Colors.white,
      ),
      body: _paymentDone
          ? _buildSuccessView()
          : _scanning
          ? _buildScannerView()
          : _friChecking
          ? _buildCheckingView()
          : (_friResult != null && _friResult!.found)
          ? _buildBlockedView()
          : _buildConfirmationView(),
    );
  }

  Widget _buildScannerView() {
    return Column(
      children: [
        Expanded(
          flex: 3,
          child: Stack(
            children: [
              MobileScanner(
                controller: _scannerController,
                onDetect: _onBarcodeDetected,
              ),
              Center(
                child: Container(
                  width: 250,
                  height: 250,
                  decoration: BoxDecoration(
                    border: Border.all(color: Colors.white70, width: 2),
                    borderRadius: BorderRadius.circular(16),
                  ),
                ),
              ),
            ],
          ),
        ),
        Expanded(
          flex: 1,
          child: Container(
            padding: const EdgeInsets.all(24),
            color: Colors.white,
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                const Text(
                  'Scan any UPI QR code to pay',
                  style: TextStyle(fontSize: 16, fontWeight: FontWeight.w600),
                ),
                const SizedBox(height: 16),
                OutlinedButton.icon(
                  onPressed: _pickFromGallery,
                  icon: const Icon(Icons.image),
                  label: const Text('Upload from Gallery'),
                  style: OutlinedButton.styleFrom(
                    foregroundColor: _sbiBlue,
                    side: const BorderSide(color: _sbiBlue),
                    padding: const EdgeInsets.symmetric(
                      horizontal: 24,
                      vertical: 12,
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildCheckingView() {
    return const Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          CircularProgressIndicator(color: _sbiBlue),
          SizedBox(height: 24),
          Text(
            'Verifying payee against FRI database...',
            style: TextStyle(fontSize: 16, color: Colors.black54),
          ),
          SizedBox(height: 8),
          Text(
            'Checking for fraud indicators',
            style: TextStyle(fontSize: 14, color: Colors.black38),
          ),
        ],
      ),
    );
  }

  Widget _buildBlockedView() {
    final result = _friResult!;
    final isVeryHigh = result.riskLevel == 'Very High';
    final accentColor = isVeryHigh
        ? Colors.red.shade700
        : Colors.orange.shade700;

    final textToSpeak = "Payment Blocked. This UPI ID is flagged in the Fraud Risk Indicator database. Risk Level: ${result.riskLevel ?? 'Unknown'}. Fraud Category: ${result.fraudCategory ?? 'Unknown'}. Reason: ${result.reason ?? 'This identifier has been reported for fraudulent activity.'}";

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
                'PAYMENT BLOCKED',
                style: TextStyle(
                  fontSize: 24,
                  fontWeight: FontWeight.w900,
                  color: accentColor,
                ),
              ),
              const SizedBox(width: 8),
              IconButton(
                icon: Icon(Icons.volume_up, color: accentColor, size: 24),
                onPressed: () {
                  _sdk.stopSpeaking();
                  _sdk.speak(textToSpeak, languageCode: 'en');
                },
              ),
            ],
          ),
          const SizedBox(height: 8),
          const Text(
            'This UPI ID is flagged in the Fraud Risk Indicator database',
            style: TextStyle(fontSize: 15, color: Colors.black54),
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: 24),
          _buildInfoCard('UPI ID', _extractedUpi ?? '', accentColor),
          const SizedBox(height: 12),
          _buildInfoCard(
            'Risk Level',
            result.riskLevel ?? 'Unknown',
            accentColor,
          ),
          const SizedBox(height: 12),
          _buildInfoCard(
            'Fraud Category',
            result.fraudCategory ?? 'Unknown',
            accentColor,
          ),
          const SizedBox(height: 12),
          Container(
            width: double.infinity,
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: accentColor.withOpacity(0.06),
              borderRadius: BorderRadius.circular(12),
              border: Border.all(color: accentColor.withOpacity(0.2)),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Why is this dangerous?',
                  style: TextStyle(
                    fontWeight: FontWeight.w700,
                    color: accentColor,
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
          TextButton(
            onPressed: _resetScanner,
            child: const Text('Scan Another QR'),
          ),
        ],
      ),
    );
  }

  Widget _buildConfirmationView() {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        children: [
          if (_friUnavailable)
            Container(
              width: double.infinity,
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
          const Icon(Icons.check_circle, size: 64, color: Color(0xFF059669)),
          const SizedBox(height: 16),
          const Text(
            'Payee Verified',
            style: TextStyle(
              fontSize: 20,
              fontWeight: FontWeight.bold,
              color: Color(0xFF059669),
            ),
          ),
          const SizedBox(height: 24),
          Container(
            width: double.infinity,
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
                _detailRow('Payee Name', _payeeName ?? 'Unknown'),
                const Divider(height: 24),
                _detailRow('UPI ID', _extractedUpi ?? ''),
                const Divider(height: 24),
                TextField(
                  controller: _amountController,
                  keyboardType: TextInputType.number,
                  decoration: const InputDecoration(
                    labelText: 'Amount (₹)',
                    border: OutlineInputBorder(),
                    prefixText: '₹ ',
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 32),
          SizedBox(
            width: double.infinity,
            child: ElevatedButton(
              onPressed: () {
                if (_amountController.text.isEmpty) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('Please enter an amount')),
                  );
                  return;
                }
                _verifyContextAndConfirm();
              },
              style: ElevatedButton.styleFrom(
                backgroundColor: _sbiBlue,
                foregroundColor: Colors.white,
                padding: const EdgeInsets.symmetric(vertical: 16),
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(12),
                ),
              ),
              child: const Text(
                'Confirm Payment',
                style: TextStyle(fontSize: 16, fontWeight: FontWeight.w600),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildSuccessView() {
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
              'Payment Successful!',
              style: TextStyle(
                fontSize: 24,
                fontWeight: FontWeight.bold,
                color: Color(0xFF059669),
              ),
            ),
            const SizedBox(height: 8),
            Text(
              '₹ ${_amountController.text} sent to ${_payeeName ?? _extractedUpi}',
              style: const TextStyle(fontSize: 16, color: Colors.black54),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 8),
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

  Widget _buildInfoCard(String label, String value, Color accent) {
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
