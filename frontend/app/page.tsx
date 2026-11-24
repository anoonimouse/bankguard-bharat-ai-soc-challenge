"use client";

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { 
  ShieldAlert, 
  Activity, 
  Search, 
  ShieldCheck, 
  Fingerprint, 
  Lock, 
  Smartphone, 
  Cpu, 
  Server, 
  ArrowRight,
  ChevronDown,
  CheckCircle,
  HelpCircle,
  FileCode,
  FileSpreadsheet
} from 'lucide-react';

export default function Home() {
  const [stats, setStats] = useState({
    totalIntercepts: 142,
    activeThreats: 8,
    simVerifications: 28,
    systemStatus: 'Optimal'
  });
  const [loading, setLoading] = useState(true);
  const [activeFaq, setActiveFaq] = useState<number | null>(null);

  useEffect(() => {
    async function fetchStats() {
      try {
        const apiUrl = (process.env.NEXT_PUBLIC_API_URL || 'https://api.doy.codes').replace(/\/$/, '');
        const [reportsRes, devicesRes, domainsRes] = await Promise.all([
          fetch(`${apiUrl}/api/reports`),
          fetch(`${apiUrl}/api/admin/devices`),
          fetch(`${apiUrl}/api/suspicious-domains`)
        ]);
        
        if (reportsRes.ok && devicesRes.ok && domainsRes.ok) {
          const reports = await reportsRes.json();
          const devices = await devicesRes.json();
          const domains = await domainsRes.json();
          
          setStats({
            totalIntercepts: Array.isArray(reports) ? reports.length : 142,
            activeThreats: Array.isArray(domains) ? domains.length : 8,
            simVerifications: Array.isArray(devices) ? devices.length : 28,
            systemStatus: 'Optimal'
          });
        }
      } catch (err) {
        console.error("Error fetching stats for landing page:", err);
      } finally {
        setLoading(false);
      }
    }
    fetchStats();
  }, []);

  const faqs = [
    {
      q: "How does BankGuard detect fake YONO apps?",
      a: "BankGuard monitors Android side-loading signatures, package hash checksums, and compared brand identity assets. If a look-alike YONO package is installed from unverified sources (WhatsApp, SMS links, third-party APKs), the SDK blocks authentication and alerts the security center."
    },
    {
      q: "What is the Sanchar Saathi (Chakshu) reporting integration?",
      a: "When a malicious domain, scam message header, or fake APK signature is intercepted, the administrative dashboard compiles a complete digital forensic evidence kit (URLs, IPs, spoofed headers, APK payload hashes) and allows direct transmission to the Ministry of Communications' Sanchar Saathi (Chakshu) portal database for immediate cellular/domain takedown."
    },
    {
      q: "How does SIM Baseline and hardware binding work?",
      a: "The BankGuard SDK binds the customer's account to the physical hardware ID and active SIM card IMSI. Any attempt of session hijacking, SIM cloning, or running in virtual emulators will trigger a verification failure, protecting the user from remote takeovers."
    },
    {
      q: "Does this require any special user permissions?",
      a: "No, BankGuard is designed to operate natively and transparently. It verifies signatures cryptographically and relies on system-level indicators without asking for intrusive personal privacy permissions, maintaining absolute user trust."
    }
  ];

  return (
    <div className="flex flex-col items-center w-full py-4 space-y-16 max-w-5xl mx-auto">
      
      {/* Hero Section */}
      <section className="flex flex-col items-center text-center space-y-6 pt-4">
        <div className="relative mb-2 group">
          <div className="absolute inset-0 bg-themeLight/50 rounded-full blur-2xl scale-125 animate-pulse" />
          <div className="relative bg-white/80 p-5 rounded-full border border-themeLight shadow-sm">
            <ShieldAlert className="w-16 h-16 text-themeMid" strokeWidth={1.5} />
          </div>
        </div>
        
        <h1 className="text-4xl md:text-6xl font-extrabold tracking-tight text-themeDark">
          Bank<span className="text-themeMid">Guard</span>
        </h1>
        
        <p className="text-lg text-themeDark/70 max-w-2xl font-light leading-relaxed">
          A seamless, centralized approach to digital protection. Detecting and preventing fraud natively across your secure banking ecosystem.
        </p>
      </section>

      {/* Live Telemetry Bar */}
      <section className="w-full grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: "Total Intercepts", value: loading ? '...' : stats.totalIntercepts, icon: Activity, color: "text-themeMid" },
          { label: "Active Vectors", value: loading ? '...' : stats.activeThreats, icon: ShieldAlert, color: "text-dangerRed" },
          { label: "SIM Baselines", value: loading ? '...' : stats.simVerifications, icon: Fingerprint, color: "text-successGreen" },
          { label: "Security Level", value: "Strict", icon: Lock, color: "text-themeDark" }
        ].map((item, idx) => (
          <div key={idx} className="glass-card p-4 flex items-center justify-between shadow-sm">
            <div>
              <p className="text-[10px] font-bold text-themeDark/50 uppercase tracking-wider">{item.label}</p>
              <p className="text-2xl font-black text-themeDark mt-1">{item.value}</p>
            </div>
            <div className={`p-2.5 rounded-xl bg-slate-50 border border-themeLight ${item.color}`}>
              <item.icon className="w-5 h-5" />
            </div>
          </div>
        ))}
      </section>

      {/* Main Feature / Actions Grid */}
      <section className="w-full space-y-6">
        <div className="text-center md:text-left">
          <h2 className="text-2xl font-bold text-themeDark">Ecosystem Portals</h2>
          <p className="text-sm text-themeDark/60 mt-1">Access the administrative toolkits, verification suites, and developer resources.</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <Link href="/dashboard" className="glass-card p-6 hover:bg-white/95 hover:shadow-md transition-all duration-300 group flex flex-col justify-between hover:border-themeMid/50">
            <div>
              <div className="bg-themeLight/40 p-3 rounded-2xl w-fit mb-4">
                <Activity className="w-8 h-8 text-themeMid" />
              </div>
              <h3 className="text-xl font-bold text-themeDark mb-2 flex items-center justify-between">
                Security Operations Dashboard
                <ArrowRight className="w-4 h-4 text-themeMid transition-transform group-hover:translate-x-1" />
              </h3>
              <p className="text-themeDark/60 text-sm leading-relaxed">
                Monitor live threat vectors on the India network map, scrub threat timelines, analyze intercepts with the SecOps chatbot, and submit campaigns directly to government databases.
              </p>
            </div>
          </Link>

          <Link href="/verify" className="glass-card p-6 hover:bg-white/95 hover:shadow-md transition-all duration-300 group flex flex-col justify-between hover:border-themeMid/50">
            <div>
              <div className="bg-themeLight/40 p-3 rounded-2xl w-fit mb-4">
                <Search className="w-8 h-8 text-themeMid" />
              </div>
              <h3 className="text-xl font-bold text-themeDark mb-2 flex items-center justify-between">
                Link & Text Verification Portal
                <ArrowRight className="w-4 h-4 text-themeMid transition-transform group-hover:translate-x-1" />
              </h3>
              <p className="text-themeDark/60 text-sm leading-relaxed">
                Instantly scan URLs or copy-paste SMS/WhatsApp text to run safe-browsing analysis and check for phishing cues, KYC urgencies, or rewards scam patterns before users fall prey.
              </p>
            </div>
          </Link>

          <Link href="/scan" className="glass-card p-6 hover:bg-white/95 hover:shadow-md transition-all duration-300 group flex flex-col justify-between hover:border-themeMid/50">
            <div>
              <div className="bg-themeLight/40 p-3 rounded-2xl w-fit mb-4">
                <Cpu className="w-8 h-8 text-themeMid" />
              </div>
              <h3 className="text-xl font-bold text-themeDark mb-2 flex items-center justify-between">
                Malicious APK Sandbox Scanner
                <ArrowRight className="w-4 h-4 text-themeMid transition-transform group-hover:translate-x-1" />
              </h3>
              <p className="text-themeDark/60 text-sm leading-relaxed">
                Upload side-loaded Android APK files to extract permissions, check structural certificates, and inspect for brand impersonation tactics using the backend sandbox scanner.
              </p>
            </div>
          </Link>

          <Link href="/devkit" className="glass-card p-6 hover:bg-white/95 hover:shadow-md transition-all duration-300 group flex flex-col justify-between hover:border-themeMid/50">
            <div>
              <div className="bg-themeLight/40 p-3 rounded-2xl w-fit mb-4">
                <FileCode className="w-8 h-8 text-themeMid" />
              </div>
              <h3 className="text-xl font-bold text-themeDark mb-2 flex items-center justify-between">
                Developer Integration Kit
                <ArrowRight className="w-4 h-4 text-themeMid transition-transform group-hover:translate-x-1" />
              </h3>
              <p className="text-themeDark/60 text-sm leading-relaxed">
                Access integration guidelines, generate public/private key pairs, and copy Android Kotlin code blocks for securing mobile app integrity, SIM baseline validation, and secure sessions.
              </p>
            </div>
          </Link>
        </div>
      </section>

      {/* How It Works Block */}
      <section className="w-full bg-white/40 border border-themeLight/50 p-6 sm:p-8 rounded-3xl space-y-8">
        <div className="text-center max-w-xl mx-auto space-y-2">
          <h2 className="text-2xl font-bold text-themeDark">Comprehensive Protection Workflow</h2>
          <p className="text-sm text-themeDark/60">How BankGuard protects State Bank of India customers from the device level to national reporting.</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 relative">
          {[
            { step: "01", title: "Device Intercept", desc: "The native Kotlin SDK monitors package verification, airplane mode, and active SIM baselines on startup, preventing cloned credentials." },
            { step: "02", title: "Cloud AI Verification", desc: "Telemetry details are matched in the backend using ML models and advanced Cloud AI to identify campaigns and blacklist malicious URLs." },
            { step: "03", title: "Chakshu Reporting", desc: "Forensic evidence kits containing attack coordinates are reported directly to the Ministry of Communications portal for carrier-level blocking." }
          ].map((w, idx) => (
            <div key={idx} className="relative space-y-3 z-10">
              <span className="text-4xl font-black text-themeLight/80 block">{w.step}</span>
              <h3 className="text-lg font-bold text-themeDark">{w.title}</h3>
              <p className="text-xs text-themeDark/60 leading-relaxed">{w.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Feature Highlights Grid */}
      <section className="w-full grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="flex flex-col items-center text-center p-4 space-y-2.5">
          <div className="p-3 bg-white border border-themeLight/50 rounded-2xl shadow-sm">
            <ShieldCheck className="w-8 h-8 text-themeMid" strokeWidth={1.5} />
          </div>
          <h3 className="text-lg font-semibold text-themeDark">Native SDK Integrity</h3>
          <p className="text-xs text-themeDark/60 leading-relaxed max-w-xs">
            Directly binds app authentication to user hardware, blocking virtual machine emulators, remote access screen sharing, and session hijackers.
          </p>
        </div>

        <div className="flex flex-col items-center text-center p-4 space-y-2.5">
          <div className="p-3 bg-white border border-themeLight/50 rounded-2xl shadow-sm">
            <Fingerprint className="w-8 h-8 text-themeMid" strokeWidth={1.5} />
          </div>
          <h3 className="text-lg font-semibold text-themeDark">Cryptographic Verification</h3>
          <p className="text-xs text-themeDark/60 leading-relaxed max-w-xs">
            Requires hardware-backed ECDSA key challenges on registration and verification, creating a zero-trust model for all client-server requests.
          </p>
        </div>

        <div className="flex flex-col items-center text-center p-4 space-y-2.5">
          <div className="p-3 bg-white border border-themeLight/50 rounded-2xl shadow-sm">
            <Lock className="w-8 h-8 text-themeMid" strokeWidth={1.5} />
          </div>
          <h3 className="text-lg font-semibold text-themeDark">SIM Swapping Defense</h3>
          <p className="text-xs text-themeDark/60 leading-relaxed max-w-xs">
            Ensures authentication request origins match the device IMSI baseline recorded during account creation, preventing SMS forwarding takeovers.
          </p>
        </div>
      </section>

      {/* FAQ & Awareness Accordion */}
      <section className="w-full space-y-6">
        <div className="text-center max-w-xl mx-auto space-y-2">
          <div className="inline-flex p-2 bg-themeLight/30 rounded-xl text-themeMid mb-1">
            <HelpCircle className="w-6 h-6" />
          </div>
          <h2 className="text-2xl font-bold text-themeDark">Frequently Asked Questions</h2>
          <p className="text-sm text-themeDark/60">Learn more about BankGuard\'s defense mechanisms and sanchar saathi (Chakshu) integration.</p>
        </div>

        <div className="max-w-3xl mx-auto space-y-3">
          {faqs.map((faq, idx) => {
            const isOpen = activeFaq === idx;
            return (
              <div key={idx} className="bg-white/50 border border-themeLight/50 rounded-2xl overflow-hidden transition-all duration-200">
                <button
                  onClick={() => setActiveFaq(isOpen ? null : idx)}
                  className="w-full flex items-center justify-between p-4 sm:p-5 text-left text-sm font-semibold text-themeDark hover:bg-white/30 transition-colors"
                >
                  <span>{faq.q}</span>
                  <ChevronDown className={`w-4 h-4 text-themeDark/50 transition-transform duration-200 ${isOpen ? 'transform rotate-180' : ''}`} />
                </button>
                {isOpen && (
                  <div className="p-4 sm:p-5 pt-0 text-xs text-themeDark/70 leading-relaxed border-t border-slate-50/50 bg-slate-50/30">
                    {faq.a}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </section>

      {/* Footer Branding */}
      <footer className="text-center pt-8 border-t border-themeLight/30 w-full text-xs text-themeDark/40 font-medium">
        BankGuard &copy; {new Date().getFullYear()} State Bank of India Cybersecurity Initiative. All rights reserved.
      </footer>

    </div>
  );
}
