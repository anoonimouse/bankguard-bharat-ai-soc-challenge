# BankGuard Security Operations Center (SOC) Frontend

A modern Next.js 14 web application providing a centralized dashboard for security teams, fraud analysts, and regulatory compliance monitors.

## Features

- **Live Threat Telemetry**: Real-time display of incoming phishing link intercepts and malicious APK detections.
- **Fraud Risk Indicator (FRI) Management**: Search, register, and update flagged UPI IDs, suspicious mobile numbers, and mule bank accounts.
- **Device & Package Registry**: Overview of registered banking app instances and verified certificate fingerprints.
- **Responsive Security UI**: Built with TailwindCSS and Lucide React icons for intuitive security operations.

## Tech Stack

- **Framework**: Next.js 14 (App Router)
- **Language**: TypeScript
- **Styling**: TailwindCSS
- **State & Data Fetching**: React Hooks, Fetch API

## Getting Started

### 1. Install Dependencies
```bash
cd frontend
npm install
```

### 2. Configure Environment
Copy `.env.example` to `.env.local` and set the backend API endpoint:
```env
NEXT_PUBLIC_API_URL=http://localhost:8000
```

### 3. Run Development Server
```bash
npm run dev
```

Open `http://localhost:3000` in your browser.
