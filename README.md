# TrustYONO SDK & App Run Guide

This repository has been upgraded from a UI simulation to a functional native security SDK.

## Project Structure
1. `backend/`: FastAPI mock intelligence server.
2. `frontend/`: Next.js Web Verify Portal and Threat Dashboard.
3. `trustyono_sdk/`: The core Flutter Plugin containing native Kotlin OS-level API calls to scan installed packages, enable states, and fetch SHA-256 certificate hashes.
4. `mobile_app/`: The Mock SBI YONO app that successfully implements the `trustyono_sdk` package to protect its login portal.
5. `spoof_app/`: A fake malware application designed to harvest permissions and trigger the native SDK block screen.

## How to Test the Full Demo Flow

### 1. Start the Backend & Frontend (Required for telemetry)
See the previous instructions or run:
- `cd backend && python main.py`
- `cd frontend && npm run dev`

### 2. Run the Mobile App
Because the SDK relies on native Android `PackageManager` APIs, this code **must** be executed on an Android Emulator or a Physical Android device. It will fail on Flutter Web or Windows Desktop.

```bash
cd mobile_app
flutter run -d android
```

### 3. Run the Malicious Spoof App (To trigger the real block)
Open a new terminal to install the fake malware:
```bash
cd spoof_app
flutter run -d android
```
Notice how it aggressively asks for SMS, Contacts, Location, and Camera permissions, presenting a fake KYC update screen.

### 4. Understanding the Live SDK Block
Now that the Spoof App is installed on your emulator/device, fully close and re-open the official `mobile_app`. 

The Splash Screen calls:
`TrustyonoSdk().runFullSecurityScan()`

This executes the following real operations:
1. Calls Kotlin `isUnknownSourcesEnabled()` to read OS settings.
2. Calls Kotlin `getCertificateHash()` to read its *own* APK signature.
3. Compares the hash. *Note: As this is a debug build on your emulator, it uses a dummy variable for demonstration. Long-press the version number (v1.0.0) on the splash screen to trigger a simulated "Signature Mismatch" (Tamper Detection).*
4. Calls Kotlin `getInstalledPackages()` to get a list of every app on your phone.
5. If any package matches the "SBI" heuristic, it hashes *that* app's certificate and POSTs it to the local FastAPI backend to verify if it's the real app or a phishing app. 

*If a threat is detected, the SDK intercepts the navigation and throws the red Security Alert overlay.*
