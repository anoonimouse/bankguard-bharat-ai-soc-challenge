class ThreatStringSet {
  final String exitApp;
  final String securityAlertHeadline;
  final String phishingSmsHeadline;
  final String suspiciousCallHeadline;
  final String phishingLinkHeadline;

  final String simulatedThreat;
  final String suspiciousPackage;
  final String verifiedMalicious;
  final String unknownSources;
  final String overlayPermission;
  final String accessibility;
  final String notificationListener;
  final String callScreening;
  final String selfTamper;
  final String genericRisk;

  final String phishingSmsDetail;
  final String suspiciousCallDetail;
  final String phishingLinkNotificationDetail;
  final String phishingLinkSharedDetail;

  const ThreatStringSet({
    required this.exitApp,
    required this.securityAlertHeadline,
    required this.phishingSmsHeadline,
    required this.suspiciousCallHeadline,
    required this.phishingLinkHeadline,
    required this.simulatedThreat,
    required this.suspiciousPackage,
    required this.verifiedMalicious,
    required this.unknownSources,
    required this.overlayPermission,
    required this.accessibility,
    required this.notificationListener,
    required this.callScreening,
    required this.selfTamper,
    required this.genericRisk,
    required this.phishingSmsDetail,
    required this.suspiciousCallDetail,
    required this.phishingLinkNotificationDetail,
    required this.phishingLinkSharedDetail,
  });
}

class ThreatStrings {
  static ThreatStringSet forLocale(String languageCode) {
    switch (languageCode) {
      case 'hi': // Hindi (हिन्दी)
        return hindi;
      case 'ta': // Tamil (தமிழ்)
        return tamil;
      case 'te': // Telugu (తెలుగు)
        return telugu;
      case 'bn': // Bengali (বাংলা)
        return bengali;
      case 'mr': // Marathi (मराठी)
        return marathi;
      case 'en': // English
      default:
        return english;
    }
  }

  static const english = ThreatStringSet(
    exitApp: "Exit App",
    securityAlertHeadline: "Security Alert",
    phishingSmsHeadline: "Phishing SMS Detected",
    suspiciousCallHeadline: "Suspicious Call Detected",
    phishingLinkHeadline: "Phishing Link Detected",
    simulatedThreat: "A simulated threat was triggered for demo purposes.",
    suspiciousPackage:
        "Suspicious SBI-branded app detected. Uninstall the app shown in logs.",
    verifiedMalicious:
        "Malicious app verified by SBI backend. Uninstall immediately.",
    unknownSources:
        "Unknown sources are enabled. Disable it in Settings > Security.",
    overlayPermission:
        "Overlay permission is enabled. Disable Draw over other apps.",
    accessibility:
        "Accessibility services are enabled. Disable any untrusted service.",
    notificationListener:
        "Notification listener is disabled. Enable it for WhatsApp/SMS scans.",
    callScreening:
        "Call screening is disabled. Set the app as Caller ID & spam app.",
    selfTamper: "App integrity check failed. Reinstall from official source.",
    genericRisk:
        "A security risk was detected. Please review your device settings.",
    phishingSmsDetail:
        "A suspicious link was detected in an SMS message. Avoid opening it and report it to security.",
    suspiciousCallDetail:
        "A call from a known scam number was detected. Do not share OTPs or personal details.",
    phishingLinkNotificationDetail:
        "A suspicious link was detected in a notification. Avoid opening it and report it to security.",
    phishingLinkSharedDetail:
        "This shared link appears malicious and may distribute fake SBI apps.\n\nAvoid opening it and report it to security.",
  );

  static const hindi = ThreatStringSet(
    exitApp: "ऐप से बाहर निकलें",
    securityAlertHeadline: "सुरक्षा चेतावनी",
    phishingSmsHeadline: "फिशिंग SMS की पहचान की गई",
    suspiciousCallHeadline: "संदिग्ध कॉल की पहचान की गई",
    phishingLinkHeadline: "फिशिंग लिंक की पहचान की गई",
    simulatedThreat: "डेमो के लिए एक नकली खतरा ट्रिगर किया गया है।",
    suspiciousPackage:
        "फ़र्ज़ी SBI ऐप पाया गया। लॉग में दिखाए गए ऐप को अनइंस्टॉल करें।",
    verifiedMalicious:
        "SBI के सिस्टम ने इसे खतरनाक ऐप माना है। तुरंत अनइंस्टॉल करें।",
    unknownSources:
        "अनजान स्रोत (Unknown sources) चालू हैं। इन्हें सेटिंग्स > सुरक्षा में बंद करें।",
    overlayPermission:
        "ओवरले अनुमति चालू है। 'अन्य ऐप पर ड्रा करें' को बंद करें।",
    accessibility:
        "एक्सेसिबिलिटी सेवाएं चालू हैं। किसी भी अवांछित सेवा को बंद करें।",
    notificationListener:
        "नोटिफिकेशन लिसनर बंद है। इसे WhatsApp/SMS स्कैन के लिए चालू करें।",
    callScreening:
        "कॉल स्क्रीनिंग बंद है। ऐप को कॉलर ID और स्पैम ऐप के रूप में सेट करें।",
    selfTamper:
        "ऐप की सुरक्षा जांच विफल। आधिकारिक स्रोत से फिर से इंस्टॉल करें।",
    genericRisk:
        "एक सुरक्षा जोखिम का पता चला है। कृपया अपने डिवाइस की सेटिंग्स जांचें।",
    phishingSmsDetail:
        "SMS में एक संदिग्ध लिंक का पता चला है। इसे खोलने से बचें और रिपोर्ट करें।",
    suspiciousCallDetail:
        "ज्ञात घोटालेबाज नंबर से कॉल का पता चला है। OTP या व्यक्तिगत जानकारी साझा न करें।",
    phishingLinkNotificationDetail:
        "एक नोटिफिकेशन में संदिग्ध लिंक पाया गया है। इसे खोलने से बचें।",
    phishingLinkSharedDetail:
        "यह साझा किया गया लिंक खतरनाक लग रहा है और फ़र्ज़ी SBI ऐप फैला सकता है।\n\nइसे न खोलें।",
  );

  static const tamil = ThreatStringSet(
    exitApp: "செயலியை மூடு",
    securityAlertHeadline: "எச்சரிக்கை: பாதுகாப்பு அச்சுறுத்தல்",
    phishingSmsHeadline: "மோசடி SMS கண்டறியப்பட்டது",
    suspiciousCallHeadline: "மோசடி அழைப்பு கண்டறியப்பட்டது",
    phishingLinkHeadline: "மோசடி இணைப்பு கண்டறியப்பட்டது",
    simulatedThreat: "மாதிரி பாதுகாப்பு அச்சுறுத்தல் கண்டறியப்பட்டது (Demo).",
    suspiciousPackage:
        "சந்தேகத்திற்கிடமான போலி SBI செயலி கண்டறியப்பட்டது. உடனே நீக்கவும்.",
    verifiedMalicious:
        "இது ஒரு ஆபத்தான செயலி என உறுதி செய்யப்பட்டுள்ளது. உடனே நீக்கவும்.",
    unknownSources:
        "தெரியாத மூலங்கள் (Unknown sources) அனுமதிக்கப்பட்டுள்ளன. பாதுகாப்பிற்காக அதை முடக்கவும்.",
    overlayPermission:
        "ஸ்கிரீன் ஓவர்லே (Overlay) அனுமதிக்கப்பட்டுள்ளது. அதை உடனே முடக்கவும்.",
    accessibility:
        "அணுகல்தன்மை சேவை (Accessibility) அனுமதிக்கப்பட்டுள்ளது. அதை முடக்கவும்.",
    notificationListener:
        "அறிவிப்பு கேட்பான் (Notification listener) முடக்கப்பட்டுள்ளது. அதை இயக்கவும்.",
    callScreening:
        "அழைப்புத் திரையிடல் (Call screening) முடக்கப்பட்டுள்ளது. இதை இயக்கவும்.",
    selfTamper:
        "செயலி பாதுகாப்பு சோதனை தோல்வியடைந்தது. மீண்டும் பதிவிறக்கவும்.",
    genericRisk:
        "உங்கள் போனில் ஒரு பாதுகாப்பு குறைபாடு உள்ளது. தயவுசெய்து உங்கள் செட்டிங்ஸை சரிபார்க்கவும்.",
    phishingSmsDetail:
        "SMS-இல் ஒரு மோசடி இணைப்பு கண்டறியப்பட்டது. அதைத் திறக்க வேண்டாம்.",
    suspiciousCallDetail:
        "மோசடி எண்ணிலிருந்து அழைப்பு வந்துள்ளது. OTP அல்லது தனிப்பட்ட தகவலைப் பகிர வேண்டாம்.",
    phishingLinkNotificationDetail:
        "அறிவிப்பில் ஒரு மோசடி இணைப்பு கண்டறியப்பட்டது. அதைத் திறக்க வேண்டாம்.",
    phishingLinkSharedDetail:
        "இந்த இணைப்பு ஆபத்தானது. இது போலி SBI செயலியைப் பரப்பக்கூடும். இதைத் திறக்க வேண்டாம்.",
  );

  static const telugu = ThreatStringSet(
    exitApp: "యాప్ నుండి నిష్క్రమించండి",
    securityAlertHeadline: "భద్రతా హెచ్చరిక",
    phishingSmsHeadline: "మోసపూరిత SMS కనుగొనబడింది",
    suspiciousCallHeadline: "అనుమానాస్పద కాల్ కనుగొనబడింది",
    phishingLinkHeadline: "మోసపూరిత లింక్ కనుగొనబడింది",
    simulatedThreat: "డెమో కోసం నకిలీ ముప్పు సృష్టించబడింది.",
    suspiciousPackage:
        "నకిలీ SBI యాప్ కనుగొనబడింది. వెంటనే అన్‌ఇన్‌స్టాల్ చేయండి.",
    verifiedMalicious:
        "ఇది ప్రమాదకరమైన యాప్ అని నిర్ధారించబడింది. వెంటనే అన్‌ఇన్‌స్టాల్ చేయండి.",
    unknownSources:
        "తెలియని మూలాలు (Unknown sources) ఆన్‌లో ఉన్నాయి. సెట్టింగ్‌లలో దాన్ని ఆఫ్ చేయండి.",
    overlayPermission: "ఓవర్‌లే ఆన్‌లో ఉంది. దాన్ని ఆఫ్ చేయండి.",
    accessibility:
        "యాక్సెసిబిలిటీ సేవలు ఆన్‌లో ఉన్నాయి. నమ్మని సేవలను ఆఫ్ చేయండి.",
    notificationListener:
        "నోటిఫికేషన్ లిజనర్ ఆఫ్ చేయబడింది. దాన్ని ఆన్ చేయండి.",
    callScreening: "కాల్ స్క్రీనింగ్ ఆఫ్ చేయబడింది. మాని యాప్‌ను సెట్ చేయండి.",
    selfTamper: "యాప్ భద్రతా తనిఖీ విఫలమైంది. దయచేసి మళ్లీ ఇన్‌స్టాల్ చేయండి.",
    genericRisk:
        "భద్రతా ప్రమాదం కనుగొనబడింది. దయచేసి మీ పరికర సెట్టింగ్‌లను తనిఖీ చేయండి.",
    phishingSmsDetail:
        "SMS లో అనుమానాస్పద లింక్ కనుగొనబడింది. దాన్ని తెరవకండి.",
    suspiciousCallDetail:
        "నకిలీ నంబర్ నుండి కాల్ కనుగొనబడింది. OTP ని భాగస్వామ్యం చేయవద్దు.",
    phishingLinkNotificationDetail:
        "నోటిఫికేషన్‌లో మోసపూరిత లింక్ కనుగొనబడింది. దాన్ని తెరవకండి.",
    phishingLinkSharedDetail:
        "ఈ షేర్ చేయబడిన లింక్ ప్రమాదకరంగా ఉంది. దాన్ని తెరవకండి.",
  );

  static const bengali = ThreatStringSet(
    exitApp: "অ্যাপ থেকে প্রস্থান করুন",
    securityAlertHeadline: "নিরাপত্তা সতর্কতা",
    phishingSmsHeadline: "ফিশিং SMS শনাক্ত হয়েছে",
    suspiciousCallHeadline: "সন্দেহজনক কল শনাক্ত হয়েছে",
    phishingLinkHeadline: "ফিশিং লিঙ্ক শনাক্ত হয়েছে",
    simulatedThreat: "ডেমোর জন্য একটি জাল হুমকি তৈরি করা হয়েছে।",
    suspiciousPackage:
        "সন্দেহজনক SBI অ্যাপ পাওয়া গেছে। অ্যাপটি আনইনস্টল করুন।",
    verifiedMalicious:
        "এটি ক্ষতিকারক অ্যাপ হিসেবে যাচাই করা হয়েছে। অবিলম্বে আনইনস্টল করুন।",
    unknownSources:
        "অজানা উৎস (Unknown sources) সচল আছে। সেটিংসে এটি বন্ধ করুন।",
    overlayPermission: "ওভারলে অনুমতি চালু আছে। এটি বন্ধ করুন।",
    accessibility: "অ্যাক্সেসিবিলিটি পরিষেবা সচল আছে। এটি বন্ধ করুন।",
    notificationListener: "নোটিফিকেশন লিসেনার বন্ধ আছে। এটি চালু করুন।",
    callScreening: "কল স্ক্রিনিং বন্ধ আছে। মক অ্যাপ সেট করুন।",
    selfTamper: "অ্যাপটির নিরাপত্তা যাচাই ব্যর্থ হয়েছে। আবার ইনস্টল করুন।",
    genericRisk:
        "একটি নিরাপত্তা ঝুঁকি পাওয়া গেছে। অনুগ্রহ করে সেটিংস চেক করুন।",
    phishingSmsDetail: "SMS-এ একটি সন্দেহজনক লিঙ্ক পাওয়া গেছে। এটি খুলবেন না।",
    suspiciousCallDetail:
        "প্রতারণামূলক নম্বর থেকে কল পাওয়া গেছে। OTP শেয়ার করবেন না।",
    phishingLinkNotificationDetail:
        "নোটিফিকেশনে একটি সন্দেহজনক লিঙ্ক পাওয়া গেছে। এটি খুলবেন না।",
    phishingLinkSharedDetail: "এই লিঙ্কটি ক্ষতিকারক হতে পারে। এটি খুলবেন না।",
  );

  static const marathi = ThreatStringSet(
    exitApp: "अॅपमधून बाहेर पडा",
    securityAlertHeadline: "सुरक्षा इशारा",
    phishingSmsHeadline: "फिशिंग SMS आढळला",
    suspiciousCallHeadline: "संशयास्पद कॉल आढळला",
    phishingLinkHeadline: "फिशिंग लिंक आढळली",
    simulatedThreat: "डेमोसाठी एक बनावट धोका ट्रिगर केला आहे.",
    suspiciousPackage: "बनावट SBI अॅप आढळले. अॅप अनइंस्टॉल करा.",
    verifiedMalicious:
        "हे धोकादायक अॅप असल्याचे सत्यापित केले आहे. त्वरित अनइंस्टॉल करा.",
    unknownSources:
        "अज्ञात स्रोत (Unknown sources) सुरू आहेत. सेटिंग्जमध्ये ते बंद करा.",
    overlayPermission: "ओव्हरले परवानगी सुरू आहे. ती बंद करा.",
    accessibility: "अॅक्सेसिबिलिटी सेवा सुरू आहेत. त्या बंद करा.",
    notificationListener: "नोटिफिकेशन लिसनर बंद आहे. ते सुरू करा.",
    callScreening: "कॉल स्क्रीनिंग बंद आहे. ती सुरू करा.",
    selfTamper: "अॅप सुरक्षितता तपासणी अयशस्वी. पुन्हा इंस्टॉल करा.",
    genericRisk: "सुरक्षा धोका आढळला आहे. कृपया सेटिंग्ज तपासा.",
    phishingSmsDetail: "SMS मध्ये एक संशयास्पद लिंक आढळली आहे. ती उघडू नका.",
    suspiciousCallDetail: "फसव्या नंबरवरून कॉल आला आहे. OTP शेअर करू नका.",
    phishingLinkNotificationDetail:
        "नोटिफिकेशनमध्ये संशयास्पद लिंक आढळली आहे. ती उघडू नका.",
    phishingLinkSharedDetail: "ही लिंक धोकादायक आहे. ती उघडू नका.",
  );
}
