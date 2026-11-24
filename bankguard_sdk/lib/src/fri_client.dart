import 'dart:convert';
import 'package:http/http.dart' as http;

/// SDK-internal FRI (Fraud Risk Indicator) client.
/// Owns all HTTP communication with the Bankguard backend FRI endpoints.
/// Host apps never call these endpoints directly - they use SDK public methods.
class FriClient {
  final String _backendBaseUrl;

  FriClient({required String backendBaseUrl})
      : _backendBaseUrl = backendBaseUrl;

  /// Check a single identifier against the FRI database.
  /// Returns null on network failure (fail-open semantics).
  Future<FriCheckResult?> check({
    required String identifierType,
    required String identifierValue,
  }) async {
    try {
      final response = await http
          .post(
            Uri.parse('$_backendBaseUrl/api/fri/check'),
            headers: {'Content-Type': 'application/json'},
            body: jsonEncode({
              'identifier_type': identifierType,
              'identifier_value': identifierValue,
            }),
          )
          .timeout(const Duration(seconds: 5));

      if (response.statusCode == 200) {
        return FriCheckResult.fromJson(jsonDecode(response.body));
      }
      return null;
    } catch (e) {
      print('Bankguard FRI check failed: $e');
      return null;
    }
  }

  /// Batch check multiple identifiers against FRI.
  /// Returns empty list on network failure (fail-open).
  Future<List<FriBatchResult>> batchCheck(
      List<FriBatchItem> identifiers) async {
    if (identifiers.isEmpty) return [];
    try {
      final response = await http
          .post(
            Uri.parse('$_backendBaseUrl/api/fri/batch-check'),
            headers: {'Content-Type': 'application/json'},
            body: jsonEncode({
              'identifiers': identifiers.map((i) => i.toJson()).toList(),
            }),
          )
          .timeout(const Duration(seconds: 10));

      if (response.statusCode == 200) {
        final data = jsonDecode(response.body);
        return (data['results'] as List)
            .map((r) => FriBatchResult.fromJson(r))
            .toList();
      }
      return [];
    } catch (e) {
      print('Bankguard FRI batch check failed: $e');
      return [];
    }
  }

  /// Get full FRI entry details by ID.
  Future<FriEntryDetail?> getEntry(int entryId) async {
    try {
      final response = await http
          .get(Uri.parse('$_backendBaseUrl/api/fri/entry/$entryId'))
          .timeout(const Duration(seconds: 5));

      if (response.statusCode == 200) {
        return FriEntryDetail.fromJson(jsonDecode(response.body));
      }
      return null;
    } catch (e) {
      print('Bankguard FRI entry lookup failed: $e');
      return null;
    }
  }

  /// Submit a threat report to the backend.
  Future<bool> reportThreat({
    required String reportType,
    required String source,
    required String content,
    double riskScore = 0.8,
  }) async {
    try {
      final response = await http
          .post(
            Uri.parse('$_backendBaseUrl/api/reports'),
            headers: {'Content-Type': 'application/json'},
            body: jsonEncode({
              'report_type': reportType,
              'source': source,
              'content': content,
              'risk_score': riskScore,
            }),
          )
          .timeout(const Duration(seconds: 5));
      return response.statusCode == 200;
    } catch (e) {
      print('Bankguard report submission failed: $e');
      return false;
    }
  }

  /// Get all reports from the backend.
  Future<List<dynamic>> getReports() async {
    try {
      final response = await http
          .get(Uri.parse('$_backendBaseUrl/api/reports'))
          .timeout(const Duration(seconds: 5));

      if (response.statusCode == 200) {
        return jsonDecode(response.body) as List<dynamic>;
      }
      return [];
    } catch (e) {
      print('Bankguard getReports failed: $e');
      return [];
    }
  }

  /// Scan a URL for phishing indicators via the backend heuristic engine.
  Future<UrlScanResult?> scanUrl(String url) async {
    try {
      final response = await http
          .post(
            Uri.parse('$_backendBaseUrl/api/check-url'),
            headers: {'Content-Type': 'application/json'},
            body: jsonEncode({'url': url}),
          )
          .timeout(const Duration(seconds: 5));

      if (response.statusCode == 200) {
        return UrlScanResult.fromJson(jsonDecode(response.body));
      }
      return null;
    } catch (e) {
      print('Bankguard URL scan failed: $e');
      return null;
    }
  }

  /// Log a VPN DNS block event to the backend.
  Future<bool> reportVpnDnsThreat({
    required String domainName,
    required String verdict,
    required double riskScore,
    String? source,
  }) async {
    try {
      final response = await http
          .post(
            Uri.parse('$_backendBaseUrl/api/vpn/dns-threat'),
            headers: {'Content-Type': 'application/json'},
            body: jsonEncode({
              'domain_name': domainName,
              'verdict': verdict,
              'risk_score': riskScore,
              'source': source ?? 'com.bankguard.app',
            }),
          )
          .timeout(const Duration(seconds: 5));
      return response.statusCode == 200;
    } catch (e) {
      print('Bankguard VPN threat log failed: $e');
      return false;
    }
  }

  /// Log a Polyglot scan threat event to the backend.
  Future<bool> reportPolyglotThreat({
    required String fileName,
    required String detectedMime,
    required String declaredMime,
    required bool isPolyglot,
    required double riskScore,
    String? source,
  }) async {
    try {
      final response = await http
          .post(
            Uri.parse('$_backendBaseUrl/api/scan-file/magic-bytes'),
            headers: {'Content-Type': 'application/json'},
            body: jsonEncode({
              'file_name': fileName,
              'detected_mime': detectedMime,
              'declared_mime': declaredMime,
              'is_polyglot': isPolyglot,
              'risk_score': riskScore,
              'source': source ?? 'com.bankguard.app',
            }),
          )
          .timeout(const Duration(seconds: 5));
      return response.statusCode == 200;
    } catch (e) {
      print('Bankguard Polyglot threat log failed: $e');
      return false;
    }
  }

  /// Analyze a raw message text via the backend LLM analysis endpoint.
  Future<MessageAnalysisResult?> analyzeMessage({
    required String text,
    required String sender,
    String? preferredLanguage,
  }) async {
    try {
      final response = await http
          .post(
            Uri.parse('$_backendBaseUrl/api/analyze-message'),
            headers: {'Content-Type': 'application/json'},
            body: jsonEncode({
              'text': text,
              'sender': sender,
              'preferred_language': preferredLanguage ?? 'en',
            }),
          )

          .timeout(const Duration(seconds: 5));

      if (response.statusCode == 200) {
        return MessageAnalysisResult.fromJson(jsonDecode(response.body));
      }
      return null;
    } catch (e) {
      print('Bankguard analyzeMessage failed: $e');
      return null;
    }
  }

  /// Scan an APK file for dangerous permissions and lookalike package signatures.
  Future<ApkScanResult?> scanApkFile(String filePath) async {
    try {
      final request = http.MultipartRequest(
        'POST',
        Uri.parse('$_backendBaseUrl/api/scan-apk'),
      );
      request.files.add(await http.MultipartFile.fromPath('file', filePath));

      final streamedResponse =
          await request.send().timeout(const Duration(seconds: 15));
      final response = await http.Response.fromStream(streamedResponse);

      if (response.statusCode == 200) {
        return ApkScanResult.fromJson(jsonDecode(response.body));
      }
      return null;
    } catch (e) {
      print('Bankguard scanApkFile failed: $e');
      return null;
    }
  }
}

class MessageAnalysisResult {
  final String tactic;
  final double severityScore;
  final String explanation;
  final String suggestedAction;
  final double? phishingConfidence;
  final double? fusedConfidence;
  final List<Map<String, dynamic>> detectorScores;
  final List<Map<String, dynamic>> indicators;
  final String? modelVersion;

  MessageAnalysisResult({
    required this.tactic,
    required this.severityScore,
    required this.explanation,
    required this.suggestedAction,
    this.phishingConfidence,
    this.fusedConfidence,
    this.detectorScores = const [],
    this.indicators = const [],
    this.modelVersion,
  });

  factory MessageAnalysisResult.fromJson(Map<String, dynamic> json) {
    return MessageAnalysisResult(
      tactic: json['tactic'] ?? 'OTHER',
      severityScore: (json['severity_score'] as num?)?.toDouble() ?? 0.0,
      explanation: json['explanation'] ?? '',
      suggestedAction: json['suggested_action'] ?? '',
      phishingConfidence: (json['phishing_confidence'] as num?)?.toDouble(),
      fusedConfidence: (json['fused_confidence'] as num?)?.toDouble(),
      detectorScores: (json['detector_scores'] is List)
          ? (json['detector_scores'] as List)
              .whereType<Map>()
              .map((entry) => Map<String, dynamic>.from(entry))
              .toList()
          : const [],
      indicators: (json['indicators'] is List)
          ? (json['indicators'] as List)
              .whereType<Map>()
              .map((entry) => Map<String, dynamic>.from(entry))
              .toList()
          : const [],
      modelVersion: json['model_version']?.toString(),
    );
  }
}

// ---------------------------------------------------------------------------
// Data Classes
// ---------------------------------------------------------------------------

class FriCheckResult {
  final bool found;
  final int? entryId;
  final String? riskLevel;
  final String? fraudCategory;
  final String? reason;

  FriCheckResult({
    required this.found,
    this.entryId,
    this.riskLevel,
    this.fraudCategory,
    this.reason,
  });

  factory FriCheckResult.fromJson(Map<String, dynamic> json) {
    return FriCheckResult(
      found: json['found'] ?? false,
      entryId: json['entry_id'],
      riskLevel: json['risk_level'],
      fraudCategory: json['fraud_category'],
      reason: json['reason'],
    );
  }
}

class FriBatchItem {
  final String identifierType;
  final String identifierValue;

  FriBatchItem({required this.identifierType, required this.identifierValue});

  Map<String, dynamic> toJson() => {
        'identifier_type': identifierType,
        'identifier_value': identifierValue,
      };
}

class FriBatchResult {
  final String identifierType;
  final String identifierValue;
  final bool found;
  final int? entryId;
  final String? riskLevel;
  final String? fraudCategory;
  final String? reason;

  FriBatchResult({
    required this.identifierType,
    required this.identifierValue,
    required this.found,
    this.entryId,
    this.riskLevel,
    this.fraudCategory,
    this.reason,
  });

  factory FriBatchResult.fromJson(Map<String, dynamic> json) {
    return FriBatchResult(
      identifierType: json['identifier_type'] ?? '',
      identifierValue: json['identifier_value'] ?? '',
      found: json['found'] ?? false,
      entryId: json['entry_id'],
      riskLevel: json['risk_level'],
      fraudCategory: json['fraud_category'],
      reason: json['reason'],
    );
  }
}

class FriIdentifierDetail {
  final String identifierType;
  final String identifierValue;

  FriIdentifierDetail({
    required this.identifierType,
    required this.identifierValue,
  });

  factory FriIdentifierDetail.fromJson(Map<String, dynamic> json) {
    return FriIdentifierDetail(
      identifierType: json['identifier_type'] ?? '',
      identifierValue: json['identifier_value'] ?? '',
    );
  }
}

class FriEntryDetail {
  final int id;
  final String riskLevel;
  final String fraudCategory;
  final String reason;
  final List<FriIdentifierDetail> identifiers;

  FriEntryDetail({
    required this.id,
    required this.riskLevel,
    required this.fraudCategory,
    required this.reason,
    required this.identifiers,
  });

  factory FriEntryDetail.fromJson(Map<String, dynamic> json) {
    return FriEntryDetail(
      id: json['id'],
      riskLevel: json['risk_level'] ?? '',
      fraudCategory: json['fraud_category'] ?? '',
      reason: json['reason'] ?? '',
      identifiers: (json['identifiers'] as List? ?? [])
          .map((i) => FriIdentifierDetail.fromJson(i))
          .toList(),
    );
  }
}

class UrlScanResult {
  final bool isSafe;
  final String? message;
  final double? riskScore;
  final List<String>? flags;

  UrlScanResult({
    required this.isSafe,
    this.message,
    this.riskScore,
    this.flags,
  });

  factory UrlScanResult.fromJson(Map<String, dynamic> json) {
    return UrlScanResult(
      isSafe: json['is_safe'] ?? true,
      message: json['message'],
      riskScore: (json['risk_score'] as num?)?.toDouble(),
      flags: (json['flags'] as List?)?.cast<String>(),
    );
  }
}

class ApkScanResult {
  final String verdict;
  final int riskScore;
  final String? appName;
  final String? packageName;
  final String? certHash;

  ApkScanResult({
    required this.verdict,
    required this.riskScore,
    this.appName,
    this.packageName,
    this.certHash,
  });

  factory ApkScanResult.fromJson(Map<String, dynamic> json) {
    return ApkScanResult(
      verdict: json['verdict'] ?? 'safe',
      riskScore: json['risk_score'] is int ? json['risk_score'] as int : 0,
      appName: json['app_name'],
      packageName: json['package_name'],
      certHash: json['cert_hash'],
    );
  }
}
