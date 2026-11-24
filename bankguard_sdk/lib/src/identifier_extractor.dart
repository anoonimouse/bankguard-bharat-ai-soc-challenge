/// Identifier extraction utilities for the Bankguard SDK.
/// Extracts UPI IDs, mobile numbers, bank accounts, and URLs from text.
/// Also handles UPI URI parsing from QR code payloads.
class IdentifierExtractor {
  /// Extract UPI IDs from text (pattern: word@word, excluding email domains)
  static List<String> extractUpiIds(String text) {
    return RegExp(r'[\w.+-]+@[a-zA-Z]+', caseSensitive: false)
        .allMatches(text)
        .map((m) => m.group(0)!)
        .where((id) => !id.contains('.com') && !id.contains('.in'))
        .toList();
  }

  /// Extract Indian mobile numbers (10-digit, starting with 6/7/8/9)
  static List<String> extractMobileNumbers(String text) {
    return RegExp(r'(?:^|\D)([6-9]\d{9})(?:\D|$)')
        .allMatches(text)
        .map((m) => m.group(1)!)
        .toList();
  }

  /// Extract Indian mobile numbers and toll-free numbers from text
  static List<String> extractCallbackNumbers(String text) {
    final numbers = <String>[];
    
    // 1. Toll-free numbers: 1800-XXX-XXXX or 1800XXXXXX
    final tollFreeMatches = RegExp(r'1800[- ]?\d{3}[- ]?\d{4}')
        .allMatches(text)
        .map((m) => normalizePhoneNumber(m.group(0)!));
    numbers.addAll(tollFreeMatches);
    
    // 2. Mobile numbers: 10-digit starting with 6/7/8/9
    final mobileMatches = RegExp(r'(?:^|\D)([6-9]\d{9})(?:\D|$)')
        .allMatches(text)
        .map((m) => m.group(1)!);
    numbers.addAll(mobileMatches);
    
    return numbers.toSet().toList(); // De-duplicate
  }

  /// Extract potential bank account numbers (9-18 digit sequences)
  static List<String> extractBankAccounts(String text) {
    return RegExp(r'(?:^|\D)(\d{9,18})(?:\D|$)')
        .allMatches(text)
        .map((m) => m.group(1)!)
        .toList();
  }

  /// Extract URLs from text
  static List<String> extractUrls(String text) {
    return RegExp(r'(https?://[^\s]+)', caseSensitive: false)
        .allMatches(text)
        .map((m) => m.group(0)!)
        .toList();
  }

  /// Extract the first URL from text, or null if none found.
  static String? extractFirstUrl(String text) {
    final match =
        RegExp(r'(https?://[^\s]+)', caseSensitive: false).firstMatch(text);
    return match?.group(0);
  }

  /// Normalize a phone number by stripping non-digit/non-plus characters.
  static String normalizePhoneNumber(String number) {
    return number.replaceAll(RegExp(r'[^0-9+]'), '');
  }

  /// Strip the +91/91 country code prefix or leading 0 for FRI lookups.
  static String stripIndianCountryCode(String number) {
    var cleaned = number.replaceAll(RegExp(r'^\+91'), '');
    if (cleaned.startsWith('91') && cleaned.length == 12) {
      cleaned = cleaned.substring(2);
    } else if (cleaned.startsWith('0') && cleaned.length == 11) {
      cleaned = cleaned.substring(1);
    }
    return cleaned;
  }

  /// Parse a UPI URI (e.g. from QR code) into its components.
  /// Returns null if the URI doesn't contain a valid payee address (pa).
  static UpiPayload? parseUpiUri(String uri) {
    if (!uri.contains('upi://pay')) return null;

    try {
      final parsed = Uri.parse(uri);
      final pa = parsed.queryParameters['pa'];
      if (pa == null || pa.isEmpty) return null;

      return UpiPayload(
        payeeAddress: pa,
        payeeName: parsed.queryParameters['pn'],
        amount: parsed.queryParameters['am'],
        transactionNote: parsed.queryParameters['tn'],
        merchantCode: parsed.queryParameters['mc'],
        currency: parsed.queryParameters['cu'] ?? 'INR',
      );
    } catch (_) {
      return null;
    }
  }
}

/// Parsed UPI payment payload from a QR code.
class UpiPayload {
  final String payeeAddress;
  final String? payeeName;
  final String? amount;
  final String? transactionNote;
  final String? merchantCode;
  final String currency;

  UpiPayload({
    required this.payeeAddress,
    this.payeeName,
    this.amount,
    this.transactionNote,
    this.merchantCode,
    this.currency = 'INR',
  });
}
