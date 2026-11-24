"use client";

import { useState } from 'react';
import { 
  BookOpen, 
  Server, 
  Smartphone, 
  Layers, 
  Code, 
  ArrowRight, 
  Terminal, 
  Globe, 
  FileText,
  Shield,
  Activity,
  UserCheck
} from 'lucide-react';

export default function GuideManual() {
  const [activeTab, setActiveTab] = useState<'api' | 'pages' | 'mobile'>('api');
  const [expandedEndpoint, setExpandedEndpoint] = useState<string | null>(null);

  const apiEndpoints = [
    {
      group: "Core Security & Phishing Detection",
      items: [
        {
          id: "check-url",
          method: "POST",
          path: "/api/check-url",
          desc: "Analyzes URL structures against lookalike domains, suspicious TLDs, or via the static ML phishing detection classifier. Malicious domains are stored in the blocking cache and logged.",
          req: "{\n  \"url\": \"https://sbi-kyc-verify.xyz\"\n}",
          res: "{\n  \"url\": \"https://sbi-kyc-verify.xyz\",\n  \"is_safe\": false,\n  \"risk_score\": 0.95,\n  \"threat_type\": \"Phishing/Lookalike Domain\",\n  \"message\": \"High risk! This URL mimics official SBI domains.\",\n  \"ml_analysis\": null\n}"
        },
        {
          id: "analyze-message",
          method: "POST",
          path: "/api/analyze-message",
          desc: "Classifies SMS/WhatsApp phishing scam tactics from incoming notification text. Uses the integrated Cloud AI model (Llama-3.1-8B-Instruct) with a deterministic local fallback to categorize threat types.",
          req: "{\n  \"text\": \"Your SBI account is blocked. Verify KYC immediately at link\",\n  \"sender\": \"+919876543210\"\n}",
          res: "{\n  \"tactic\": \"KYC_EXPIRY\",\n  \"severity_score\": 0.95,\n  \"explanation\": \"Message uses urgency and impersonates SBI to steal login details.\",\n  \"suggested_action\": \"Do not open links. Verify directly with your branch.\"\n}"
        },
        {
          id: "scan-apk",
          method: "POST",
          path: "/api/scan-apk",
          desc: "Accepts binary files (multipart/form-data) to perform deep static analysis, parsing the internal package name, permissions structure, and validating signature hashes against registered certificates.",
          req: "Multipart Form File: \"file\" (binary APK)",
          res: "{\n  \"verdict\": \"malicious\",\n  \"risk_score\": 100,\n  \"app_name\": \"SBI Quick Support\",\n  \"package_name\": \"com.sbi.support.fake\",\n  \"cert_hash\": \"a1b2c3d4...\",\n  \"checks\": [\n    {\n      \"check_name\": \"Target TLD Mapping\",\n      \"status\": \"fail\",\n      \"message\": \"Application targets dangerous unofficial servers.\"\n    }\n  ]\n}"
        },
        {
          id: "verify-apk",
          method: "POST",
          path: "/api/verify-apk",
          desc: "Performs quick online certificate hash matching to confirm if an installed package matches registered official assets.",
          req: "{\n  \"package_name\": \"com.sbi.yono\",\n  \"cert_hash\": \"c78f1a8e9...\"\n}",
          res: "{\n  \"package_name\": \"com.sbi.yono\",\n  \"is_official\": true,\n  \"message\": \"Signature matches official SBI registry.\"\n}"
        },
        {
          id: "scan-file-magic",
          method: "POST",
          path: "/api/scan-file/magic-bytes",
          desc: "Logs an alert when the SDK's file scanner detects a file extension/mime mismatch (polyglot file payload spoofing).",
          req: "{\n  \"file_name\": \"KYC_Form.pdf\",\n  \"detected_mime\": \"application/vnd.android.package-archive\",\n  \"declared_mime\": \"application/pdf\",\n  \"is_polyglot\": true,\n  \"risk_score\": 1.0,\n  \"source\": \"com.bankguard.app\"\n}",
          res: "{\n  \"success\": true,\n  \"message\": \"Polyglot scan threat logged successfully.\"\n}"
        }
      ]
    },
    {
      group: "Device Binding & Local VPN Proxy Security",
      items: [
        {
          id: "device-bind",
          method: "POST",
          path: "/api/device/bind",
          desc: "Enrolls a new hardware key baseline by mapping a customer ID, a DER-encoded public key generated in the device Keystore, and a SIM IMSI hash configuration.",
          req: "{\n  \"customer_id\": \"89012345678\",\n  \"device_key_pub\": \"MIIBSzCCAQ...\",\n  \"sim_hash\": \"d5f8c6e2...\"\n}",
          res: "{\n  \"success\": true,\n  \"message\": \"Device cryptographically bound successfully.\"\n}"
        },
        {
          id: "device-verify",
          method: "POST",
          path: "/api/device/verify",
          desc: "Validates cryptographic device binding by verifying ECDSA signatures over verification payloads using the registered device public key.",
          req: "{\n  \"customer_id\": \"89012345678\",\n  \"sim_hash\": \"d5f8c6e2...\",\n  \"signature\": \"MEQCIE...\",\n  \"payload\": \"verification_nonce\"\n}",
          res: "{\n  \"verified\": true,\n  \"is_locked\": false,\n  \"message\": \"Device validation passed.\"\n}"
        },
        {
          id: "silent-sms-challenge",
          method: "POST",
          path: "/api/device/silent-sms/challenge",
          desc: "Triggers a cryptographically random challenge (nonce) and expiration window to authorize a background SIM verification handshake.",
          req: "{\n  \"customer_id\": \"89012345678\"\n}",
          res: "{\n  \"success\": true,\n  \"nonce\": \"a4f9b2d8...\",\n  \"expires_at\": \"2026-06-30T12:45:00Z\",\n  \"message\": \"Challenge generated successfully.\"\n}"
        },
        {
          id: "silent-sms-verify",
          method: "POST",
          path: "/api/device/silent-sms/verify",
          desc: "Checks the ECDSA-signed challenge nonce returned by the background verification agent to lock/unlock device authorization status.",
          req: "{\n  \"customer_id\": \"89012345678\",\n  \"nonce\": \"a4f9b2d8...\",\n  \"signature\": \"MEYCIQ...\"\n}",
          res: "{\n  \"success\": true,\n  \"status\": \"verified\",\n  \"message\": \"SIM verification succeeded. Device unlocked.\"\n}"
        },
        {
          id: "vpn-dns-threat",
          method: "POST",
          path: "/api/vpn/dns-threat",
          desc: "Logs an alert when a device's VPN sinkhole intercepts and blocks a blacklisted DNS query.",
          req: "{\n  \"domain_name\": \"sbi-yono-verify.xyz\",\n  \"verdict\": \"blocked\",\n  \"risk_score\": 0.95,\n  \"source\": \"com.bankguard.app\"\n}",
          res: "{\n  \"success\": true,\n  \"message\": \"VPN DNS threat logged successfully.\"\n}"
        }
      ]
    },
    {
      group: "Government DOT & Chakshu Integrations",
      items: [
        {
          id: "dot-compile",
          method: "GET",
          path: "/api/dot/compile-response-kit/{report_id}",
          desc: "Aggregates forensic report indicators (SSL certificate fingerprints, file structure checksums, domain registrar lookups, IP resolutions) into an official response kit model.",
          req: "URL Parameter: report_id (integer)",
          res: "{\n  \"report_id\": 42,\n  \"threat_type\": \"URL\",\n  \"indicators\": {\n    \"resolved_ips\": [\"104.21.32.148\"],\n    \"registrar\": \"NameCheap Inc.\",\n    \"ssl_serial\": \"03ef7a8...\"\n  }\n}"
        },
        {
          id: "dot-chakshu",
          method: "POST",
          path: "/api/dot/chakshu-report",
          desc: "Transmits compiled response kit evidence to the Department of Telecommunications (DOT) Sanchar Saathi database, returning a government reference tracking ID.",
          req: "{\n  \"report_type\": \"URL\",\n  \"content\": \"https://sbi-kyc-verify.xyz\",\n  \"risk_score\": 0.95,\n  \"reported_at\": \"2026-06-30T12:00:00Z\",\n  \"dossier_data\": {}\n}",
          res: "{\n  \"success\": true,\n  \"reference_id\": \"CHAKSHU-20260630-9841\",\n  \"message\": \"Forensic telemetry successfully synced with DOT portal.\",\n  \"timestamp\": \"2026-06-30T12:35:42Z\"\n}"
        }
      ]
    }
  ];

  const appPages = [
    {
      path: "/",
      name: "Homepage Portal",
      desc: "Central gateway for BankGuard. Features direct access to the customer Link Verification tool, File Upload scanner, and link to the administrative terminal.",
      access: "Public"
    },
    {
      path: "/verify",
      name: "Verify Portal",
      desc: "Public-facing portal for customers to input suspicious messages, lookalike URLs, or WhatsApp SMS payloads to instantly check for lookalike and spoofing threats.",
      access: "Public"
    },
    {
      path: "/scan",
      name: "File Scan Portal",
      desc: "Public file analysis portal. Allows users to upload document attachments (PDFs, DOCX) or application bundles (APKs) to run magic bytes checks and static code scans.",
      access: "Public"
    },
    {
      path: "/report",
      name: "Report Fraud Portal",
      desc: "Direct submission form for customer-intercepted scam phone numbers, phishing messages, or malicious app details. Populates the database telemetry feed.",
      access: "Public"
    },
    {
      path: "/health",
      name: "Ecosystem Health",
      desc: "System status grid visualizing uptime for crucial nodes including local database clusters, government DOT API connections, and device binding enrollment key registries.",
      access: "Public/Operator"
    },
    {
      path: "/backend",
      name: "Backend Status Tool",
      desc: "Lightweight diagnostic panel verifying active internet connectivity and response latency directly to the backend FastAPI server.",
      access: "Public/Operator"
    },
    {
      path: "/dashboard",
      name: "Security Dashboard",
      desc: "Operator management terminal. Displays isolated domain signatures, real-time incoming reports, AI threat insights generated by LLM, DOT compilation previews, and Chakshu transmitters.",
      access: "Operator (Hidden tab)"
    },
    {
      path: "/guide",
      name: "Ecosystem Reference Guide",
      desc: "This hidden developer manual page. Provides complete documentation over backend REST routes, web routing layouts, and mobile code interactions.",
      access: "Developer (Hidden)"
    }
  ];

  const mobileScreens = [
    {
      file: "splash_screen.dart",
      feature: "First-Launch Cryptographic Binding",
      desc: "Examines if device Keystore contains the registered EC key pair. If missing, requests SIM read permissions, baselines identity, enrolls binding via `/api/device/bind`, and auto-starts the Local DNS Sinkhole VPN."
    },
    {
      file: "login_screen.dart",
      feature: "Baseline Authentication",
      desc: "Secures mock user login credentials, wrapping payloads with ECDSA device signatures to guarantee message integrity to the banking gateway."
    },
    {
      file: "home_screen.dart",
      feature: "Mock Operations Center",
      desc: "Serves as the simulated hub for mock banking (accounts, deposits, UPI checkouts). Integrates Telco lab controls to toggle spoof calls and SMS simulation."
    },
    {
      file: "upi_payment_screen.dart",
      feature: "Contextual Risk Check (UPI)",
      desc: "Intercepts transfer confirmations. Queries the SDK contextual risk engine to confirm if the payee UPI ID was parsed from any suspicious message received within the last 15 minutes. Renders high-friction confirm overlays if flagged."
    },
    {
      file: "fund_transfer_screen.dart",
      feature: "Contextual Risk Check (IMPS/NEFT)",
      desc: "Runs identical threat window scans matching target bank accounts or mobile numbers against intercepted SMS records prior to committing transfers."
    },
    {
      file: "telco_lab_screen.dart",
      feature: "Attack Simulator Tab",
      desc: "Developer sandbox. Generates simulated phishing SMS notification feeds, triggers mock call spoof warnings, and mock downloads APKs/Polyglots to test observer event hooks."
    },
    {
      file: "verify_link_screen.dart",
      feature: "In-App Browser Shield",
      desc: "Secures in-app web views. Halts execution and mounts full-screen warnings if the browser navigates to lookalike domains marked in the quarantined DNS cache."
    },
    {
      file: "transaction_history_screen.dart",
      feature: "Audit Ledger",
      desc: "Displays completed banking transaction history, explicitly logging blocked payment attempts."
    }
  ];

  return (
    <div className="h-full flex flex-col py-6 max-w-6xl mx-auto px-4 animate-in fade-in duration-500">
      
      {/* Header */}
      <div className="flex items-center gap-3 mb-6 border-b border-themeLight/30 pb-4">
        <div className="bg-themeMid/10 p-3 rounded-2xl text-themeMid border border-themeMid/20">
          <BookOpen className="w-8 h-8" />
        </div>
        <div>
          <h1 className="text-3xl font-extrabold text-themeDark">Ecosystem Directory</h1>
          <p className="text-themeDark/60 text-sm">Internal operations handbook detailing pages, backend endpoints, and mobile source structures.</p>
        </div>
      </div>

      {/* Tabs Menu */}
      <div className="flex gap-2 mb-6 border-b border-themeLight/30 pb-2">
        <button
          onClick={() => setActiveTab('api')}
          className={`px-4 py-2 font-semibold text-sm rounded-lg transition-all flex items-center gap-2 ${
            activeTab === 'api' ? 'bg-themeMid text-white shadow-sm' : 'text-themeDark/60 hover:bg-white/40'
          }`}
        >
          <Server className="w-4 h-4" />
          Backend API Endpoints
        </button>
        <button
          onClick={() => setActiveTab('pages')}
          className={`px-4 py-2 font-semibold text-sm rounded-lg transition-all flex items-center gap-2 ${
            activeTab === 'pages' ? 'bg-themeMid text-white shadow-sm' : 'text-themeDark/60 hover:bg-white/40'
          }`}
        >
          <Layers className="w-4 h-4" />
          Frontend Page Routes
        </button>
        <button
          onClick={() => setActiveTab('mobile')}
          className={`px-4 py-2 font-semibold text-sm rounded-lg transition-all flex items-center gap-2 ${
            activeTab === 'mobile' ? 'bg-themeMid text-white shadow-sm' : 'text-themeDark/60 hover:bg-white/40'
          }`}
        >
          <Smartphone className="w-4 h-4" />
          Mobile Simulator Screens
        </button>
      </div>

      {/* Content Area */}
      <div className="flex-1 min-h-0">
        
        {/* Tab 1: API Reference */}
        {activeTab === 'api' && (
          <div className="space-y-6 animate-in fade-in duration-300">
            {apiEndpoints.map((group, groupIndex) => (
              <div key={groupIndex} className="glass-card p-6 shadow-sm border border-themeLight/40">
                <h2 className="text-lg font-bold text-themeDark mb-4 flex items-center gap-2 border-b border-themeLight/30 pb-2">
                  <Code className="w-5 h-5 text-themeMid" />
                  {group.group}
                </h2>
                
                <div className="space-y-3">
                  {group.items.map((item) => (
                    <div 
                      key={item.id} 
                      className="border border-themeLight/30 rounded-xl overflow-hidden bg-white/40 hover:border-themeMid/30 transition-all"
                    >
                      <button
                        onClick={() => setExpandedEndpoint(expandedEndpoint === item.id ? null : item.id)}
                        className="w-full text-left p-4 flex items-center justify-between gap-4"
                      >
                        <div className="flex items-center gap-3 flex-wrap">
                          <span className={`text-[10px] font-bold px-2.5 py-1 rounded border ${
                            item.method === 'POST' ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-blue-50 text-blue-700 border-blue-200'
                          }`}>
                            {item.method}
                          </span>
                          <span className="font-mono text-sm font-bold text-themeDark">{item.path}</span>
                        </div>
                        <span className="text-themeMid text-xs font-semibold flex items-center gap-1">
                          {expandedEndpoint === item.id ? 'Hide Details' : 'Show Details'}
                          <ArrowRight className={`w-3.5 h-3.5 transition-transform ${expandedEndpoint === item.id ? 'rotate-90' : ''}`} />
                        </span>
                      </button>

                      {expandedEndpoint === item.id && (
                        <div className="px-4 pb-4 pt-2 border-t border-themeLight/20 bg-themeBg/50 text-sm space-y-4">
                          <p className="text-themeDark/75">{item.desc}</p>
                          
                          <div className="grid md:grid-cols-2 gap-4">
                            <div>
                              <span className="text-[10px] uppercase font-bold tracking-wider text-themeDark/50 block mb-1">Payload Example</span>
                              <pre className="bg-themeDark text-[#50fa7b] p-3 rounded-lg font-mono text-xs overflow-x-auto border border-themeDark/50 max-h-[160px] custom-scrollbar">
                                {item.req}
                              </pre>
                            </div>
                            <div>
                              <span className="text-[10px] uppercase font-bold tracking-wider text-themeDark/50 block mb-1">Response Example</span>
                              <pre className="bg-themeDark text-sky-300 p-3 rounded-lg font-mono text-xs overflow-x-auto border border-themeDark/50 max-h-[160px] custom-scrollbar">
                                {item.res}
                              </pre>
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Tab 2: Frontend Pages */}
        {activeTab === 'pages' && (
          <div className="grid md:grid-cols-2 gap-4 animate-in fade-in duration-300">
            {appPages.map((page, index) => (
              <div 
                key={index}
                className="glass-card p-5 hover:bg-white/80 transition-all hover:border-themeMid/30 flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <span className="font-mono text-xs font-bold text-themeMid bg-themeLight/40 px-2.5 py-1 rounded">
                      {page.path}
                    </span>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                      page.access === 'Public' ? 'bg-emerald-50 text-emerald-700' : 'bg-amber-50 text-amber-700'
                    }`}>
                      {page.access}
                    </span>
                  </div>
                  <h3 className="text-lg font-bold text-themeDark mb-1.5">{page.name}</h3>
                  <p className="text-themeDark/60 text-xs leading-relaxed">{page.desc}</p>
                </div>
                
                <div className="flex items-center gap-1 text-[10px] font-bold text-themeDark/40 uppercase tracking-wide mt-4 border-t border-themeLight/30 pt-2">
                  <Globe className="w-3.5 h-3.5" />
                  App Router Page
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Tab 3: Mobile Simulator Screens */}
        {activeTab === 'mobile' && (
          <div className="space-y-4 animate-in fade-in duration-300">
            <div className="glass-card p-6 shadow-sm border border-themeLight/40">
              <h2 className="text-lg font-bold text-themeDark mb-1 flex items-center gap-2">
                <Smartphone className="w-5 h-5 text-themeMid" />
                BankGuard Simulator Architecture
              </h2>
              <p className="text-xs text-themeDark/50 mb-5">Source file hierarchy mapped to operational security checks inside the Flutter container.</p>
              
              <div className="space-y-3">
                {mobileScreens.map((screen, index) => (
                  <div 
                    key={index} 
                    className="p-4 rounded-xl border border-themeLight/30 bg-white/40 hover:bg-white/60 transition-all flex items-start gap-4 flex-col md:flex-row md:items-center justify-between"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-sm font-bold text-themeDark">{screen.file}</span>
                        <span className="text-[10px] text-themeDark/40 font-semibold">|</span>
                        <span className="text-xs font-bold text-themeMid">{screen.feature}</span>
                      </div>
                      <p className="text-themeDark/60 text-xs">{screen.desc}</p>
                    </div>

                    <div className="flex items-center gap-1.5 text-[10px] font-bold text-themeDark/40 uppercase tracking-wide shrink-0">
                      <FileText className="w-3.5 h-3.5" />
                      Flutter Widget
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

      </div>
    </div>
  );
}
