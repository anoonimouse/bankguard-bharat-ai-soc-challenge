# Changelog

All notable changes to this package will be documented in this file.

## [1.0.1] - 2026-07-02

### Fixed
- Fixed dead null-aware operator warning in behavioral score analysis.
- Cleaned up build cache files from the publication bundle.
- Added support for metadata version tracking on the root API route.

## [1.0.0] - 2025-03-27

### Added
- Device security scanning - unknown sources, overlay detection, accessibility abuse detection
- APK signature verification against known banking app certificates
- Social engineering detection in notifications across 6 Indian languages (English, Hindi, Tamil, Telugu, Bengali, Marathi)
- Financial Fraud Risk Indicator (FRI) database integration with single and batch lookups
- UPI ID, mobile number, and bank account fraud checking
- QR code payload analysis and UPI fraud verification
- URL phishing heuristic scanning via backend integration
- Call screening with FRI intelligence lookups
- Real-time threat event callbacks via typed event classes
- Multi-language security alert strings
- Configuration-driven initialization with feature flags
- Threat overlay widget for in-app security alerts
- Threat reporting to backend intelligence system
- Fail-open semantics for all network-dependent checks
