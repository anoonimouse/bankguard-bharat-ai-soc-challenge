import 'fri_client.dart';

// ---------------------------------------------------------------------------
// Base Event
// ---------------------------------------------------------------------------

/// Base class for all Bankguard SDK events.
abstract class BankguardEvent {
  final DateTime timestamp;
  BankguardEvent() : timestamp = DateTime.now();
}

// ---------------------------------------------------------------------------
// Device Scan Events
// ---------------------------------------------------------------------------

/// Result of a full device security scan.
class DeviceScanEvent extends BankguardEvent {
  final bool isSecure;
  final List<String> threats;
  final bool unknownSourcesEnabled;
  final bool overlayPermissionEnabled;
  final bool accessibilityEnabled;
  final bool notificationListenerEnabled;
  final bool callScreeningEnabled;

  DeviceScanEvent({
    required this.isSecure,
    required this.threats,
    required this.unknownSourcesEnabled,
    required this.overlayPermissionEnabled,
    required this.accessibilityEnabled,
    required this.notificationListenerEnabled,
    required this.callScreeningEnabled,
  });
}

/// A suspicious or malicious app was detected on device.
class FakeAppEvent extends BankguardEvent {
  final String packageName;
  final String? certHash;
  final String
      threatType; // SUSPICIOUS_PACKAGE, VERIFIED_MALICIOUS, SIGNATURE_MISMATCH
  final String? backendMessage;
  final double riskScore;

  FakeAppEvent({
    required this.packageName,
    this.certHash,
    required this.threatType,
    this.backendMessage,
    this.riskScore = 0.9,
  });
}

/// A dangerous device environment flag was detected.
class EnvironmentEvent extends BankguardEvent {
  final String
      flagType; // UNKNOWN_SOURCES, OVERLAY_PERMISSION, ACCESSIBILITY, SELF_TAMPER
  final String description;

  EnvironmentEvent({
    required this.flagType,
    required this.description,
  });
}

// ---------------------------------------------------------------------------
// Notification & Call Events
// ---------------------------------------------------------------------------

/// A suspicious notification was intercepted and analyzed.
class NotificationThreatEvent extends BankguardEvent {
  final String text;
  final String sourcePackage;
  final String? sender;
  final String? senderFlag;
  final int riskScore;
  final String verdict; // 'none', 'soft', 'hard'
  final String? primaryCategory; // urgency, fear, greed, url_only
  final List<String> categories;
  final List<String>? extractedUrls;
  final List<String>? extractedUpiIds;
  final List<String>? extractedMobiles;
  // FRI enrichment (if identifiers were found and matched)
  final List<FriBatchResult> friHits;
  // LLM analysis
  final String? scamTactic;
  final String? explanation;
  final String? suggestedAction;
  // Local on-device phishing model
  final double? localNlpConfidence;
  final String? localNlpVerdict;
  final String? localNlpModel;
  final List<Map<String, dynamic>> localNlpIndicators;

  NotificationThreatEvent({
    required this.text,
    required this.sourcePackage,
    this.sender,
    this.senderFlag,
    required this.riskScore,
    required this.verdict,
    this.primaryCategory,
    this.categories = const [],
    this.extractedUrls,
    this.extractedUpiIds,
    this.extractedMobiles,
    this.friHits = const [],
    this.scamTactic,
    this.explanation,
    this.suggestedAction,
    this.localNlpConfidence,
    this.localNlpVerdict,
    this.localNlpModel,
    this.localNlpIndicators = const [],
  });
}

/// A suspicious incoming call was detected.
class CallThreatEvent extends BankguardEvent {
  final String phoneNumber;
  final bool isFriHit;
  final String? riskLevel;
  final String? fraudCategory;
  final String? reason;
  final double riskScore;

  CallThreatEvent({
    required this.phoneNumber,
    this.isFriHit = false,
    this.riskLevel,
    this.fraudCategory,
    this.reason,
    this.riskScore = 0.85,
  });
}

// ---------------------------------------------------------------------------
// FRI Events
// ---------------------------------------------------------------------------

/// An FRI database match was found for an identifier.
class FriMatchEvent extends BankguardEvent {
  final String identifierType; // upi, mobile, bank_account
  final String identifierValue;
  final String? riskLevel;
  final String? fraudCategory;
  final String? reason;
  final int? entryId;

  FriMatchEvent({
    required this.identifierType,
    required this.identifierValue,
    this.riskLevel,
    this.fraudCategory,
    this.reason,
    this.entryId,
  });
}

// ---------------------------------------------------------------------------
// URL Threat Events
// ---------------------------------------------------------------------------

/// A URL was determined to be a phishing threat.
class UrlThreatEvent extends BankguardEvent {
  final String url;
  final String source; // sms, notification, shared
  final String? message;
  final double riskScore;

  UrlThreatEvent({
    required this.url,
    required this.source,
    this.message,
    this.riskScore = 0.9,
  });
}

// ---------------------------------------------------------------------------
// General Threat Events
// ---------------------------------------------------------------------------

/// Generic threat event for anything that doesn't fit specific categories.
class GeneralThreatEvent extends BankguardEvent {
  final String threatType;
  final String description;
  final Map<String, dynamic>? metadata;

  GeneralThreatEvent({
    required this.threatType,
    required this.description,
    this.metadata,
  });
}

// ---------------------------------------------------------------------------
// APK Hash Denylist Events (Layer 4B)
// ---------------------------------------------------------------------------

/// An installed package matched the APK hash denylist.
class DenylistMatchEvent extends BankguardEvent {
  final String packageName;
  final String certHash;
  final String source; // 'embedded', 'synced'

  DenylistMatchEvent({
    required this.packageName,
    required this.certHash,
    this.source = 'embedded',
  });
}

// ---------------------------------------------------------------------------
// Unknown Sources State Change (Layer 5)
// ---------------------------------------------------------------------------

/// Fired when the "Unknown Sources" / "Install from Unknown Apps" setting changes.
class UnknownSourcesEvent extends BankguardEvent {
  final bool enabled;
  final int timestampMs;

  UnknownSourcesEvent({
    required this.enabled,
    required this.timestampMs,
  });

  factory UnknownSourcesEvent.fromMap(Map<dynamic, dynamic> map) {
    return UnknownSourcesEvent(
      enabled: map['enabled'] as bool? ?? false,
      timestampMs: (map['timestampMs'] as num?)?.toInt() ?? 0,
    );
  }
}

// ---------------------------------------------------------------------------
// APK Download Detection (Layer 2A)
// ---------------------------------------------------------------------------

/// Fired when an APK download is detected via the DownloadManager.
class ApkDownloadEvent extends BankguardEvent {
  final int downloadId;
  final String uri;
  final String? localFilePath;
  final String? title;
  final int status;
  final int totalBytes;
  final int downloadedBytes;
  final String? mimeType;
  final bool isComplete;

  ApkDownloadEvent({
    required this.downloadId,
    required this.uri,
    this.localFilePath,
    this.title,
    this.status = 0,
    this.totalBytes = 0,
    this.downloadedBytes = 0,
    this.mimeType,
    this.isComplete = false,
  });

  factory ApkDownloadEvent.fromMap(Map<dynamic, dynamic> map) {
    return ApkDownloadEvent(
      downloadId: (map['downloadId'] as num?)?.toInt() ?? 0,
      uri: map['uri'] as String? ?? '',
      localFilePath: map['localFilePath'] as String?,
      title: map['title'] as String?,
      status: (map['status'] as num?)?.toInt() ?? 0,
      totalBytes: (map['totalBytes'] as num?)?.toInt() ?? 0,
      downloadedBytes: (map['downloadedBytes'] as num?)?.toInt() ?? 0,
      mimeType: map['mimeType'] as String?,
      isComplete: map['isComplete'] as bool? ?? false,
    );
  }
}

// ---------------------------------------------------------------------------
// URL Heuristic Scan Result (Layer 1B)
// ---------------------------------------------------------------------------

/// Result of a local, on-device URL phishing heuristic scan.
class UrlHeuristicResult extends BankguardEvent {
  final String url;
  final int score;
  final String verdict; // "none", "soft", "hard"
  final List<String> flags;
  final bool isSafe;

  UrlHeuristicResult({
    required this.url,
    required this.score,
    required this.verdict,
    required this.flags,
    required this.isSafe,
  });

  factory UrlHeuristicResult.fromMap(Map<dynamic, dynamic> map) {
    return UrlHeuristicResult(
      url: map['url'] as String? ?? '',
      score: (map['score'] as num?)?.toInt() ?? 0,
      verdict: map['verdict'] as String? ?? 'none',
      flags: (map['flags'] as List?)?.cast<String>() ?? [],
      isSafe: map['isSafe'] as bool? ?? true,
    );
  }
}

// ---------------------------------------------------------------------------
// APK File Detection (Layer 2B)
// ---------------------------------------------------------------------------

/// Fired when an APK file is detected in the filesystem via MediaStore.
class ApkFileEvent extends BankguardEvent {
  final int id;
  final String displayName;
  final String? filePath;
  final int fileSize;
  final int dateAdded;
  final String? mimeType;
  final String? sourceDirectory;
  final bool isFromWatchedDir;

  // Threat properties populated by static analysis scan
  String? verdict;
  int? riskScore;
  String? packageName;
  String? appName;

  ApkFileEvent({
    required this.id,
    required this.displayName,
    this.filePath,
    this.fileSize = 0,
    this.dateAdded = 0,
    this.mimeType,
    this.sourceDirectory,
    this.isFromWatchedDir = false,
    this.verdict,
    this.riskScore,
    this.packageName,
    this.appName,
  });

  factory ApkFileEvent.fromMap(Map<dynamic, dynamic> map) {
    return ApkFileEvent(
      id: (map['id'] as num?)?.toInt() ?? 0,
      displayName: map['displayName'] as String? ?? 'unknown.apk',
      filePath: map['filePath'] as String?,
      fileSize: (map['fileSize'] as num?)?.toInt() ?? 0,
      dateAdded: (map['dateAdded'] as num?)?.toInt() ?? 0,
      mimeType: map['mimeType'] as String?,
      sourceDirectory: map['sourceDirectory'] as String?,
      isFromWatchedDir: map['isFromWatchedDir'] as bool? ?? false,
      verdict: map['verdict'] as String?,
      riskScore: (map['riskScore'] as num?)?.toInt(),
      packageName: map['packageName'] as String?,
      appName: map['appName'] as String?,
    );
  }
}

// ---------------------------------------------------------------------------
// Behavioral Risk Events
// ---------------------------------------------------------------------------

/// A single event in an app's behavioral timeline.
class BehavioralTimelineEntry {
  final String
      type; // INSTALLED, OVERLAY_GRANTED, ACCESSIBILITY_ENABLED, SMS_GRANTED
  final int timestampMs;
  final String detail;

  BehavioralTimelineEntry({
    required this.type,
    required this.timestampMs,
    this.detail = '',
  });

  factory BehavioralTimelineEntry.fromMap(Map<String, dynamic> map) {
    return BehavioralTimelineEntry(
      type: map['type'] as String? ?? '',
      timestampMs: (map['timestampMs'] as num?)?.toInt() ?? 0,
      detail: map['detail'] as String? ?? '',
    );
  }
}

/// Full behavioral profile for a monitored app - used in threat callbacks.
class BehavioralThreatEvent extends BankguardEvent {
  final String packageName;
  final int installTimestampMs;
  final String installSource;
  final String appLabel;
  final bool hasBankingKeywords;
  final int overlayGrantedMs;
  final int accessibilityEnabledMs;
  final int smsGrantedMs;
  final int currentStage;
  final int lastScore;
  final String lastVerdict;
  final List<BehavioralTimelineEntry> events;

  BehavioralThreatEvent({
    required this.packageName,
    required this.installTimestampMs,
    required this.installSource,
    this.appLabel = '',
    this.hasBankingKeywords = false,
    this.overlayGrantedMs = 0,
    this.accessibilityEnabledMs = 0,
    this.smsGrantedMs = 0,
    this.currentStage = 0,
    this.lastScore = 0,
    this.lastVerdict = 'CLEAN',
    this.events = const [],
  });

  factory BehavioralThreatEvent.fromMap(Map<dynamic, dynamic> map) {
    final eventsList = (map['events'] as List?)
            ?.map((e) => BehavioralTimelineEntry.fromMap(
                Map<String, dynamic>.from(e as Map)))
            .toList() ??
        [];

    return BehavioralThreatEvent(
      packageName: map['packageName'] as String? ?? '',
      installTimestampMs: (map['installTimestampMs'] as num?)?.toInt() ?? 0,
      installSource: map['installSource'] as String? ?? 'unknown',
      appLabel: map['appLabel'] as String? ?? '',
      hasBankingKeywords: map['hasBankingKeywords'] as bool? ?? false,
      overlayGrantedMs: (map['overlayGrantedMs'] as num?)?.toInt() ?? 0,
      accessibilityEnabledMs:
          (map['accessibilityEnabledMs'] as num?)?.toInt() ?? 0,
      smsGrantedMs: (map['smsGrantedMs'] as num?)?.toInt() ?? 0,
      currentStage: (map['currentStage'] as num?)?.toInt() ?? 0,
      lastScore: (map['lastScore'] as num?)?.toInt() ?? 0,
      lastVerdict: map['lastVerdict'] as String? ?? 'CLEAN',
      events: eventsList,
    );
  }
}

/// Lightweight behavioral profile summary for attaching to DeviceScanEvent.
class BehavioralProfileSummary {
  final String packageName;
  final String installSource;
  final int currentStage;
  final int lastScore;
  final String lastVerdict;
  final bool hasBankingKeywords;

  BehavioralProfileSummary({
    required this.packageName,
    required this.installSource,
    required this.currentStage,
    required this.lastScore,
    required this.lastVerdict,
    this.hasBankingKeywords = false,
  });

  factory BehavioralProfileSummary.fromMap(Map<dynamic, dynamic> map) {
    return BehavioralProfileSummary(
      packageName: map['packageName'] as String? ?? '',
      installSource: map['installSource'] as String? ?? 'unknown',
      currentStage: (map['currentStage'] as num?)?.toInt() ?? 0,
      lastScore: (map['lastScore'] as num?)?.toInt() ?? 0,
      lastVerdict: map['lastVerdict'] as String? ?? 'CLEAN',
      hasBankingKeywords: map['hasBankingKeywords'] as bool? ?? false,
    );
  }
}

// ---------------------------------------------------------------------------
// QR Scan Result (returned by scanQRPayload)
// ---------------------------------------------------------------------------

/// Result of scanning and verifying a QR code payload.
class QRScanResult {
  final String? payeeAddress;
  final String? payeeName;
  final String? amount;
  final bool isFraud;
  final FriCheckResult? friResult;
  final String? parseError;

  QRScanResult({
    this.payeeAddress,
    this.payeeName,
    this.amount,
    this.isFraud = false,
    this.friResult,
    this.parseError,
  });
}

class ContextualRiskResult {
  final bool isHighRisk;
  final double riskScore;
  final String? tactic;
  final String? explanation;
  final List<String> triggers;

  ContextualRiskResult({
    required this.isHighRisk,
    this.riskScore = 0.0,
    this.tactic,
    this.explanation,
    this.triggers = const [],
  });
}
