'use client';

import { useState, useEffect } from 'react';

const BASE_API = 'https://api.doy.codes';

// ──────────────────────────────────────────────────────────────────
// DATA
// ──────────────────────────────────────────────────────────────────

const CURL_COMMANDS = [
  {
    id: 'health',
    label: 'Health Check',
    tag: 'GET',
    tagColor: 'bg-emerald-600',
    cmd: `curl -s ${BASE_API}/health | python -m json.tool`,
  },
  {
    id: 'url_safe',
    label: 'URL Scanner — safe domain',
    tag: 'POST',
    tagColor: 'bg-blue-600',
    cmd: `curl -s -X POST ${BASE_API}/api/check-url \\
  -H "Content-Type: application/json" \\
  -d '{"url":"https://www.onlinesbi.sbi/"}' | python -m json.tool`,
  },
  {
    id: 'url_phish',
    label: 'URL Scanner — phishing URL',
    tag: 'POST',
    tagColor: 'bg-blue-600',
    cmd: `curl -s -X POST ${BASE_API}/api/check-url \\
  -H "Content-Type: application/json" \\
  -d '{"url":"https://sbi-kyc-update.xyz/verify?id=88231"}' | python -m json.tool`,
  },
  {
    id: 'url_apk',
    label: 'URL Scanner — APK download link',
    tag: 'POST',
    tagColor: 'bg-blue-600',
    cmd: `curl -s -X POST ${BASE_API}/api/check-url \\
  -H "Content-Type: application/json" \\
  -d '{"url":"http://sbifreeapp.in/yono-v3.apk"}' | python -m json.tool`,
  },
  {
    id: 'msg_arrest',
    label: 'Message Analyzer — Digital Arrest (EN)',
    tag: 'POST',
    tagColor: 'bg-purple-600',
    cmd: `curl -s -X POST ${BASE_API}/api/analyze-message \\
  -H "Content-Type: application/json" \\
  -d '{"text":"This is Inspector Sharma from CBI. You are under digital arrest. Do not leave your house.","sender":"WhatsApp","preferred_language":"en"}' | python -m json.tool`,
  },
  {
    id: 'msg_otp',
    label: 'Message Analyzer — OTP Request (HI)',
    tag: 'POST',
    tagColor: 'bg-purple-600',
    cmd: `curl -s -X POST ${BASE_API}/api/analyze-message \\
  -H "Content-Type: application/json" \\
  -d '{"text":"SBI refund process mein OTP batayein please. Abhi aaya OTP share karein.","sender":"SMS","preferred_language":"hi"}' | python -m json.tool`,
  },
  {
    id: 'msg_remote',
    label: 'Message Analyzer — Remote Access Scam',
    tag: 'POST',
    tagColor: 'bg-purple-600',
    cmd: `curl -s -X POST ${BASE_API}/api/analyze-message \\
  -H "Content-Type: application/json" \\
  -d '{"text":"Please download AnyDesk and share your screen. Partner ID: 892341567","sender":"WhatsApp","preferred_language":"en"}' | python -m json.tool`,
  },
  {
    id: 'msg_mule',
    label: 'Message Analyzer — Money Mule',
    tag: 'POST',
    tagColor: 'bg-purple-600',
    cmd: `curl -s -X POST ${BASE_API}/api/analyze-message \\
  -H "Content-Type: application/json" \\
  -d '{"text":"Earn commission by receiving money in your bank account and transferring it forward. Rent your bank account for easy money.","sender":"WhatsApp","preferred_language":"en"}' | python -m json.tool`,
  },
  {
    id: 'msg_apk_link',
    label: 'Message Analyzer — APK Distribution (with link)',
    tag: 'POST',
    tagColor: 'bg-purple-600',
    cmd: `curl -s -X POST ${BASE_API}/api/analyze-message \\
  -H "Content-Type: application/json" \\
  -d '{"text":"URGENT: Download YONO latest APK from http://sbifreeapp.in/yono-v3.apk to avoid suspension","sender":"SMS","preferred_language":"en"}' | python -m json.tool`,
  },
  {
    id: 'fri_batch',
    label: 'FRI Batch Check — bad + clean mix',
    tag: 'POST',
    tagColor: 'bg-orange-600',
    cmd: `curl -s -X POST ${BASE_API}/api/fri/batch-check \\
  -H "Content-Type: application/json" \\
  -d '{"items":[{"identifier_type":"upi","identifier_value":"fraud.test@paytm"},{"identifier_type":"phone","identifier_value":"9876543210"},{"identifier_type":"upi","identifier_value":"legit.user@sbi"}]}' | python -m json.tool`,
  },
  {
    id: 'apk_fake',
    label: 'APK Scan — Fake YONO APK',
    tag: 'POST',
    tagColor: 'bg-red-600',
    cmd: `# Download fake_yono.apk first, then:
curl -s -X POST ${BASE_API}/api/scan-apk \\
  -F "file=@fake_yono.apk" | python -m json.tool`,
  },
  {
    id: 'apk_poly',
    label: 'APK Scan — Polyglot File',
    tag: 'POST',
    tagColor: 'bg-red-600',
    cmd: `# Download polyglot_image.apk first, then:
curl -s -X POST ${BASE_API}/api/scan-apk \\
  -F "file=@polyglot_image.apk" | python -m json.tool`,
  },
  {
    id: 'apk_legit',
    label: 'APK Scan — Legit Reference (should be clean)',
    tag: 'POST',
    tagColor: 'bg-red-600',
    cmd: `# Download legit_yono_reference.apk first, then:
curl -s -X POST ${BASE_API}/api/scan-apk \\
  -F "file=@legit_yono_reference.apk" | python -m json.tool`,
  },
  {
    id: 'report',
    label: 'Fraud Report Submission',
    tag: 'POST',
    tagColor: 'bg-yellow-600',
    cmd: `curl -s -X POST ${BASE_API}/api/report-fraud \\
  -H "Content-Type: application/json" \\
  -d '{"url":"https://sbi-kyc-update.xyz/verify","scam_tactic":"KYC_EXPIRY","description":"Fake KYC SMS with phishing link"}' | python -m json.tool`,
  },
];

const TEST_MESSAGES = [
  { id: 'MSG_01', category: 'APK Distribution', hasLink: true, lang: 'EN', text: 'URGENT: Your YONO SBI app is outdated. Download the latest secure version now to avoid account suspension: http://sbifreeapp.in/yono-v3.apk - SBI Team' },
  { id: 'MSG_02', category: 'KYC Expiry', hasLink: true, lang: 'EN', text: 'Dear SBI customer, your KYC is expiring today. Update immediately to avoid account block: https://sbi-kyc-update.xyz/verify?id=88231 - SBI Helpdesk' },
  { id: 'MSG_03', category: 'KYC Expiry', hasLink: true, lang: 'HI', text: 'प्रिय SBI ग्राहक, आपका KYC आज समाप्त हो रहा है। तुरंत अपडेट करें: https://sbi-kyc-verify.xyz/hi?ref=99123' },
  { id: 'MSG_04', category: 'Reward Points', hasLink: true, lang: 'EN', text: 'Congratulations! Your SBI account has accumulated 9800 reward points worth Rs.980. Redeem now: https://sbi-rewardpoints.club/redeem?token=XY98Z' },
  { id: 'MSG_05', category: 'Electricity Scam', hasLink: true, lang: 'HI', text: 'आपके बिजली कनेक्शन का बिल बकाया है। आज रात 9:30 बजे कट होगा: https://electricity-pay-now.in/up?ref=12345' },
  { id: 'MSG_06', category: 'Traffic Challan', hasLink: true, lang: 'EN', text: 'Traffic Challan Notice: Your vehicle MH12AB1234 has an overdue e-Challan of Rs.5000. Pay within 24 hrs: https://echallan-india.xyz/pay?id=MC88123' },
  { id: 'MSG_07', category: 'Digital Arrest', hasLink: false, lang: 'EN', text: 'This is Inspector Sharma from CBI Cyber Crime Unit. Your Aadhaar number has been used in illegal transactions. You are under digital arrest. Do not leave your house or contact anyone.' },
  { id: 'MSG_08', category: 'Digital Arrest', hasLink: false, lang: 'HI', text: 'मैं साइबर क्राइम पुलिस से बोल रहा हूं। आपके आधार कार्ड से मनी लॉन्ड्रिंग हुई है। डिजिटल गिरफ्तारी जारी की जाती है। वीडियो कॉल पर आएं।' },
  { id: 'MSG_09', category: 'Remote Access', hasLink: false, lang: 'EN', text: 'Hello, I am calling from SBI tech support. Please download AnyDesk app and share your screen with me. Your partner ID is 892341567.' },
  { id: 'MSG_10', category: 'OTP Request', hasLink: false, lang: 'EN', text: 'SBI Agent: We are processing your refund of Rs.8500. To complete the transfer, please tell me the OTP you just received on your registered mobile number.' },
  { id: 'MSG_11', category: 'OTP Request', hasLink: false, lang: 'HI', text: 'SBI रिफंड प्रक्रिया: Rs.6800 रिफंड हो रहा है। प्रक्रिया पूरी करने के लिए अभी आपके फोन पर आया OTP बताएं।' },
  { id: 'MSG_12', category: 'Money Mule', hasLink: false, lang: 'EN', text: 'Part time job offer: Earn Rs.25,000/month. Receive money in your bank account and transfer it forward. 10% commission. Rent your bank account for easy money.' },
  { id: 'MSG_13', category: 'Job / Task Scam', hasLink: false, lang: 'EN', text: 'Hiring for YouTube task work. Like 10 videos daily, earn Rs.500/day. Simple work from home. Send your name, account number, and IFSC to start.' },
  { id: 'MSG_14', category: 'Vishing / Callback', hasLink: false, lang: 'EN', text: 'Your SBI debit card has been temporarily blocked. Call our 24/7 support on 1800-XXX-8899 to unblock. Have your card number and OTP ready.' },
  { id: 'MSG_15', category: 'Govt Scheme Fraud', hasLink: false, lang: 'HI', text: 'PM-Kisan Yojana: सरकार आपके खाते में Rs.6000 भेजने वाली है। अभी अपना आधार और बैंक खाता अपडेट करें। पंजीकरण: 9988776655' },
];

const TEST_URLS = {
  'Safe / Whitelisted': [
    'https://www.onlinesbi.sbi/',
    'https://retail.onlinesbi.sbi/retail/login.htm',
    'https://yonomobile.sbi.co.in/',
    'https://www.sbi.co.in/web/personal-banking',
    'https://parivahan.gov.in/parivahan/',
    'https://www.npci.org.in/',
  ],
  'Phishing / Squatting': [
    'https://sbi-kyc-update.xyz/verify',
    'https://onIinesbi.sbi.co.in.malicious.ru/login',
    'https://yono-sbi-india.net/',
    'https://sbionline.bank.in.scam.xyz/kyc',
    'https://sbi-rewardpoints.club/redeem?token=abc123',
    'https://yono.sbi.co.in.phish.tk/login.php',
  ],
  'Edge Cases': [
    'https://sbi.co.in.bank.in/',
    'https://retail.onlinesbi.sbi.net/',
    'https://sbimobileapp.in/download.apk',
    'http://bit.ly/YONO-SBI-latest',
    'https://drive.google.com/uc?id=FAKEYONODOWNLOAD',
    'https://t.me/yono_sbi_official',
    'https://wa.me/message/SBIBANKOFFICIAL',
    'https://m.facebook.com/SBIYONOofficialpage',
  ],
  'APK Direct Links': [
    'http://185.234.219.12/yono-sbi-v2.6.1.apk',
    'https://apkmirror-sbi.xyz/download/yono-latest.apk',
    'https://dl.sbifreeapp.in/yono.apk',
  ],
};

// APK files are served via the backend API endpoint
const APK_FILES = [
  {
    name: 'fake_yono.apk',
    label: 'Fake YONO APK',
    desc: 'Valid ZIP/APK structure, package com.sbi.yono, dangerous permissions, no real SBI cert, embedded phishing URLs in DEX stub.',
    badge: 'MALICIOUS',
    badgeColor: 'bg-red-700',
    endpoint: `${BASE_API}/devkit/files/fake_yono.apk`,
  },
  {
    name: 'polyglot_image.apk',
    label: 'Polyglot File',
    desc: 'Starts with JPEG magic bytes but is also a valid ZIP. Tests dual-format / polyglot file detection.',
    badge: 'POLYGLOT',
    badgeColor: 'bg-orange-700',
    endpoint: `${BASE_API}/devkit/files/polyglot_image.apk`,
  },
  {
    name: 'legit_yono_reference.apk',
    label: 'Legit Reference APK',
    desc: 'Correct package com.sbi.lotusintouch, minimal safe permissions. Should return clean — use as baseline.',
    badge: 'CLEAN',
    badgeColor: 'bg-emerald-700',
    endpoint: `${BASE_API}/devkit/files/legit_yono_reference.apk`,
  },
];

// ──────────────────────────────────────────────────────────────────
// COMPONENTS
// ──────────────────────────────────────────────────────────────────

function CopyButton({ text, className = '' }: { text: string; className?: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };
  return (
    <button
      onClick={copy}
      className={`px-3 py-1 text-xs rounded font-mono transition-all duration-150 ${
        copied
          ? 'bg-emerald-600 text-white'
          : 'bg-slate-600 hover:bg-slate-500 text-slate-200'
      } ${className}`}
    >
      {copied ? 'Copied!' : 'Copy'}
    </button>
  );
}

function Section({ title, icon, children }: { title: string; icon: string; children: React.ReactNode }) {
  return (
    <section className="mb-10">
      <h2 className="text-lg font-bold text-slate-100 mb-4 flex items-center gap-2 tracking-wide uppercase">
        <span className="text-xl">{icon}</span>
        {title}
      </h2>
      {children}
    </section>
  );
}

// ──────────────────────────────────────────────────────────────────
// PAGE
// ──────────────────────────────────────────────────────────────────

export default function DevKit() {
  const [activeCmdTab, setActiveCmdTab] = useState<string>('health');
  const [activeMsgIdx, setActiveMsgIdx] = useState(0);
  const [activeUrlGroup, setActiveUrlGroup] = useState<string>('Safe / Whitelisted');

  // Call simulator states
  const [sessions, setSessions] = useState<any[]>([]);
  const [customerId, setCustomerId] = useState('89012345678');
  const [callingNumber, setCallingNumber] = useState('18001234');
  const [agentName, setAgentName] = useState('SBI Agent Sharma');
  const [isActive, setIsActive] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [statusMsg, setStatusMsg] = useState('');

  useEffect(() => {
    fetchSessions();
  }, []);

  const fetchSessions = async () => {
    try {
      const res = await fetch(`${BASE_API}/api/calls/sessions`);
      if (res.ok) {
        const data = await res.json();
        setSessions(data);
      }
    } catch (e) {
      console.error('Failed to fetch call sessions:', e);
    }
  };

  const handleSaveSession = async () => {
    setActionLoading(true);
    setStatusMsg('');
    try {
      const res = await fetch(`${BASE_API}/api/calls/toggle-session`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          customer_id: customerId,
          calling_number: callingNumber,
          is_active: isActive,
          agent_name: agentName,
        }),
      });
      if (res.ok) {
        setStatusMsg('Session saved successfully!');
        fetchSessions();
        setTimeout(() => setStatusMsg(''), 3000);
      } else {
        setStatusMsg('Failed to save session');
      }
    } catch (e) {
      setStatusMsg('Error saving session');
      console.error(e);
    } finally {
      setActionLoading(false);
    }
  };

  const handleToggleSessionState = async (session: any) => {
    try {
      const res = await fetch(`${BASE_API}/api/calls/toggle-session`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          customer_id: session.customer_id,
          calling_number: session.calling_number,
          is_active: !session.is_active,
          agent_name: session.agent_name,
        }),
      });
      if (res.ok) {
        fetchSessions();
      }
    } catch (e) {
      console.error('Failed to toggle session state:', e);
    }
  };

  const activeCmd = CURL_COMMANDS.find(c => c.id === activeCmdTab) ?? CURL_COMMANDS[0];
  const activeMsg = TEST_MESSAGES[activeMsgIdx];

  return (
    <div className="min-h-screen bg-[#0a0f1e] text-slate-200 font-mono px-4 py-10 max-w-6xl mx-auto">
      {/* Header */}
      <div className="mb-10 border-b border-slate-700 pb-6">
        <div className="flex items-center gap-3 mb-2">
          <span className="text-2xl">🛠</span>
          <h1 className="text-2xl font-bold text-white tracking-tight">BankGuard DevKit</h1>
          <span className="ml-2 px-2 py-0.5 text-xs bg-slate-700 text-slate-400 rounded">hidden route</span>
        </div>
        <p className="text-slate-400 text-sm">
          Internal test toolkit for live API testing at{' '}
          <a href={BASE_API} target="_blank" className="text-blue-400 hover:underline">{BASE_API}</a>.
          Not linked from the navbar. Bookmark this page.
        </p>
        <div className="mt-3 flex flex-wrap gap-2 text-xs">
          {[
            { label: 'URL Scanner', color: 'bg-blue-900 text-blue-300' },
            { label: 'Message Analyzer', color: 'bg-purple-900 text-purple-300' },
            { label: 'APK Scanner', color: 'bg-red-900 text-red-300' },
            { label: 'FRI Batch Check', color: 'bg-orange-900 text-orange-300' },
            { label: 'Fraud Reports', color: 'bg-yellow-900 text-yellow-300' },
          ].map(b => (
            <span key={b.label} className={`px-2 py-0.5 rounded ${b.color}`}>{b.label}</span>
          ))}
        </div>
      </div>

      {/* CURL COMMANDS */}
      <Section title="curl Commands" icon="⚡">
        <div className="grid grid-cols-1 lg:grid-cols-[280px_1fr] gap-4">
          {/* Sidebar list */}
          <div className="space-y-1 max-h-[520px] overflow-y-auto pr-1 no-scrollbar">
            {CURL_COMMANDS.map(cmd => (
              <button
                key={cmd.id}
                onClick={() => setActiveCmdTab(cmd.id)}
                className={`w-full text-left px-3 py-2 rounded-lg text-xs flex items-start gap-2 transition-colors ${
                  activeCmdTab === cmd.id
                    ? 'bg-slate-700 text-white'
                    : 'hover:bg-slate-800 text-slate-400'
                }`}
              >
                <span className={`mt-0.5 px-1.5 py-0.5 rounded text-[10px] font-bold text-white shrink-0 ${cmd.tagColor}`}>
                  {cmd.tag}
                </span>
                <span className="leading-snug">{cmd.label}</span>
              </button>
            ))}
          </div>

          {/* Command display */}
          <div className="bg-[#0d1525] border border-slate-700 rounded-xl overflow-hidden">
            <div className="flex items-center justify-between px-4 py-2 bg-slate-800 border-b border-slate-700">
              <div className="flex items-center gap-2">
                <span className={`px-2 py-0.5 rounded text-[10px] font-bold text-white ${activeCmd.tagColor}`}>
                  {activeCmd.tag}
                </span>
                <span className="text-slate-300 text-xs">{activeCmd.label}</span>
              </div>
              <CopyButton text={activeCmd.cmd} />
            </div>
            <pre className="text-sm text-green-400 p-4 overflow-x-auto whitespace-pre-wrap leading-relaxed">
              {activeCmd.cmd}
            </pre>
          </div>
        </div>
      </Section>

      {/* TEST MESSAGES */}
      <Section title="Test Messages" icon="💬">
        <div className="grid grid-cols-1 lg:grid-cols-[260px_1fr] gap-4">
          {/* Message list */}
          <div className="space-y-1 max-h-[480px] overflow-y-auto pr-1 no-scrollbar">
            {TEST_MESSAGES.map((msg, i) => (
              <button
                key={msg.id}
                onClick={() => setActiveMsgIdx(i)}
                className={`w-full text-left px-3 py-2 rounded-lg text-xs flex items-start gap-2 transition-colors ${
                  activeMsgIdx === i ? 'bg-slate-700 text-white' : 'hover:bg-slate-800 text-slate-400'
                }`}
              >
                <span className={`mt-0.5 px-1.5 py-0.5 rounded text-[10px] shrink-0 ${
                  msg.hasLink ? 'bg-blue-800 text-blue-200' : 'bg-slate-700 text-slate-300'
                }`}>
                  {msg.lang}
                </span>
                <span className="leading-snug">{msg.category}</span>
              </button>
            ))}
          </div>

          {/* Message display */}
          <div className="bg-[#0d1525] border border-slate-700 rounded-xl overflow-hidden">
            <div className="flex items-center justify-between px-4 py-2 bg-slate-800 border-b border-slate-700">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-slate-200 text-xs font-bold">{activeMsg.id}</span>
                <span className="text-slate-400 text-xs">{activeMsg.category}</span>
                <span className={`px-1.5 py-0.5 rounded text-[10px] ${
                  activeMsg.hasLink ? 'bg-blue-800 text-blue-200' : 'bg-slate-700 text-slate-400'
                }`}>
                  {activeMsg.hasLink ? 'Has Link' : 'No Link'}
                </span>
                <span className="px-1.5 py-0.5 rounded text-[10px] bg-slate-700 text-slate-400">
                  {activeMsg.lang}
                </span>
              </div>
              <CopyButton text={activeMsg.text} />
            </div>
            <div className="p-4">
              <p className="text-slate-200 text-sm leading-relaxed whitespace-pre-wrap break-words">
                {activeMsg.text}
              </p>
              <div className="mt-4 pt-3 border-t border-slate-700">
                <p className="text-slate-500 text-xs mb-1">Use in Message Analyzer:</p>
                <CopyButton
                  text={`curl -s -X POST ${BASE_API}/api/analyze-message -H "Content-Type: application/json" -d '{"text":"${activeMsg.text.replace(/'/g, "'\\''")}","sender":"WhatsApp","preferred_language":"${activeMsg.lang.toLowerCase()}"}' | python -m json.tool`}
                  className="mt-1"
                />
              </div>
            </div>
          </div>
        </div>
      </Section>

      {/* TEST URLS */}
      <Section title="Test URLs" icon="🔗">
        <div className="grid grid-cols-1 lg:grid-cols-[220px_1fr] gap-4">
          {/* Group tabs */}
          <div className="flex flex-col gap-1">
            {Object.keys(TEST_URLS).map(group => (
              <button
                key={group}
                onClick={() => setActiveUrlGroup(group)}
                className={`text-left px-3 py-2 rounded-lg text-xs transition-colors ${
                  activeUrlGroup === group ? 'bg-slate-700 text-white' : 'hover:bg-slate-800 text-slate-400'
                }`}
              >
                {group}
              </button>
            ))}
          </div>

          {/* URL list */}
          <div className="bg-[#0d1525] border border-slate-700 rounded-xl overflow-hidden">
            <div className="px-4 py-2 bg-slate-800 border-b border-slate-700 flex items-center justify-between">
              <span className="text-xs text-slate-300">{activeUrlGroup}</span>
              <CopyButton text={TEST_URLS[activeUrlGroup as keyof typeof TEST_URLS].join('\n')} />
            </div>
            <div className="p-3 space-y-2">
              {TEST_URLS[activeUrlGroup as keyof typeof TEST_URLS].map(url => (
                <div
                  key={url}
                  className="flex items-center justify-between gap-2 bg-slate-800/50 rounded-lg px-3 py-2"
                >
                  <span className="text-green-400 text-xs break-all flex-1">{url}</span>
                  <div className="flex gap-2 shrink-0">
                    <CopyButton text={url} />
                    <CopyButton
                      text={`curl -s -X POST ${BASE_API}/api/check-url -H "Content-Type: application/json" -d '{"url":"${url}"}' | python -m json.tool`}
                      className="bg-blue-800 hover:bg-blue-700 text-blue-100"
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </Section>

      {/* APK FILES */}
      <Section title="APK Test Files" icon="📦">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {APK_FILES.map(f => (
            <div key={f.name} className="bg-[#0d1525] border border-slate-700 rounded-xl p-4 flex flex-col gap-3">
              <div className="flex items-center justify-between">
                <span className={`px-2 py-0.5 rounded text-[10px] font-bold text-white ${f.badgeColor}`}>
                  {f.badge}
                </span>
              </div>
              <div>
                <p className="text-white text-sm font-bold mb-1">{f.label}</p>
                <p className="text-slate-400 text-xs leading-relaxed">{f.desc}</p>
              </div>
              <div className="mt-auto space-y-2">
                <div className="bg-slate-800 rounded px-2 py-1.5">
                  <p className="text-slate-500 text-[10px] mb-0.5">filename</p>
                  <p className="text-green-400 text-xs break-all">{f.name}</p>
                </div>
                <div className="flex gap-2">
                  <a
                    href={f.endpoint}
                    download={f.name}
                    className="flex-1 text-center px-3 py-1.5 text-xs bg-slate-600 hover:bg-slate-500 text-white rounded transition-colors"
                  >
                    Download
                  </a>
                  <CopyButton
                    text={`curl -s -X POST ${BASE_API}/api/scan-apk -F "file=@${f.name}" | python -m json.tool`}
                    className="flex-1 text-center"
                  />
                </div>
              </div>
            </div>
          ))}
        </div>
        <p className="text-slate-500 text-xs mt-3">
          APK files are served from the backend at <code className="text-slate-400">{BASE_API}/devkit/files/</code>.
          See next section to wire up the backend file-serving endpoint.
        </p>
      </Section>

      {/* FRI SEED DATA */}
      <Section title="FRI Test Identifiers" icon="🗄️">
        <div className="bg-[#0d1525] border border-slate-700 rounded-xl overflow-hidden">
          <div className="px-4 py-2 bg-slate-800 border-b border-slate-700 flex items-center justify-between">
            <span className="text-xs text-slate-300">Known-bad identifiers for FRI batch-check testing</span>
          </div>
          <div className="p-3 space-y-2">
            {[
              { type: 'UPI', value: 'fraud.test@paytm', category: 'PHISHING', reports: 87, expect: 'HIT' },
              { type: 'UPI', value: 'scamtest123@ybl', category: 'APK_DISTRIBUTION', reports: 34, expect: 'HIT' },
              { type: 'PHONE', value: '9876543210', category: 'VISHING', reports: 212, expect: 'HIT' },
              { type: 'PHONE', value: '18001234567', category: 'DIGITAL_ARREST', reports: 45, expect: 'HIT' },
              { type: 'BANK_ACCOUNT', value: '123456789012', category: 'MONEY_MULE', reports: 19, expect: 'HIT' },
              { type: 'UPI', value: 'legit.user@sbi', category: '—', reports: 0, expect: 'MISS' },
              { type: 'PHONE', value: '9000000001', category: '—', reports: 0, expect: 'MISS' },
            ].map(entry => (
              <div
                key={entry.value}
                className="flex items-center gap-3 bg-slate-800/50 rounded-lg px-3 py-2"
              >
                <span className="text-slate-500 text-[10px] w-20 shrink-0">{entry.type}</span>
                <span className="text-green-400 text-xs flex-1 break-all">{entry.value}</span>
                <span className="text-slate-400 text-xs w-28 shrink-0">{entry.category}</span>
                <span className={`px-2 py-0.5 rounded text-[10px] font-bold w-10 text-center shrink-0 ${
                  entry.expect === 'HIT'
                    ? 'bg-red-900 text-red-300'
                    : 'bg-emerald-900 text-emerald-300'
                }`}>
                  {entry.expect}
                </span>
                <CopyButton
                  text={`curl -s -X POST ${BASE_API}/api/fri/batch-check -H "Content-Type: application/json" -d '{"items":[{"identifier_type":"${entry.type.toLowerCase()}","identifier_value":"${entry.value}"}]}' | python -m json.tool`}
                />
              </div>
            ))}
          </div>
        </div>
      </Section>

      {/* ACTIVE CALL SIMULATOR */}
      <Section title="Vishing Verification Simulator" icon="📞">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 bg-[#0d1525] border border-slate-700 rounded-xl p-6">
          {/* Form Side */}
          <div>
            <h3 className="text-sm font-bold text-white mb-4">Register/Toggle Bank Call Session</h3>
            <div className="space-y-4">
              <div>
                <label className="block text-xs text-slate-400 mb-1">Customer ID (CIF)</label>
                <input
                  type="text"
                  value={customerId}
                  onChange={(e) => setCustomerId(e.target.value)}
                  className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-blue-500 font-mono"
                  placeholder="e.g. 89012345678"
                />
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1">Phone Number (Calling Number)</label>
                <input
                  type="text"
                  value={callingNumber}
                  onChange={(e) => setCallingNumber(e.target.value)}
                  className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-blue-500 font-mono"
                  placeholder="e.g. 18001234"
                />
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1">Agent Name</label>
                <input
                  type="text"
                  value={agentName}
                  onChange={(e) => setAgentName(e.target.value)}
                  className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-blue-500 font-mono"
                  placeholder="e.g. SBI Agent Sharma"
                />
              </div>
              <div className="flex items-center justify-between py-2">
                <div>
                  <span className="block text-xs text-slate-400">Call Session Status</span>
                  <span className="text-[10px] text-slate-500">Enable to simulate a genuine outbound bank call</span>
                </div>
                <button
                  type="button"
                  onClick={() => setIsActive(!isActive)}
                  className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                    isActive ? 'bg-emerald-600' : 'bg-slate-700'
                  }`}
                >
                  <span
                    className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                      isActive ? 'translate-x-5' : 'translate-x-0'
                    }`}
                  />
                </button>
              </div>

              <button
                onClick={handleSaveSession}
                disabled={actionLoading}
                className="w-full py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-xs font-bold transition-colors disabled:opacity-50"
              >
                {actionLoading ? 'Saving...' : 'Save Call Session'}
              </button>

              {statusMsg && (
                <p className="text-xs text-emerald-400 mt-2 text-center">{statusMsg}</p>
              )}
            </div>
          </div>

          {/* List Side */}
          <div className="border-t lg:border-t-0 lg:border-l border-slate-700 pt-6 lg:pt-0 lg:pl-6 flex flex-col">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-bold text-white">Active Database Sessions</h3>
              <button
                onClick={fetchSessions}
                className="text-[10px] bg-slate-800 hover:bg-slate-700 text-slate-300 px-2 py-1 rounded"
              >
                Refresh
              </button>
            </div>
            
            <div className="space-y-2 max-h-[300px] overflow-y-auto pr-1 no-scrollbar flex-1">
              {sessions.length === 0 ? (
                <p className="text-xs text-slate-500 italic text-center py-8">No active call sessions found in DB.</p>
              ) : (
                sessions.map((s: any) => (
                  <div key={s.id} className="bg-slate-800/40 rounded-lg p-3 border border-slate-700 flex items-center justify-between gap-3">
                    <div className="min-w-0 flex-1">
                      <p className="text-xs text-slate-400 font-bold break-all">Number: <span className="text-green-400 font-mono">{s.calling_number}</span></p>
                      <p className="text-[10px] text-slate-500 break-all">Customer: {s.customer_id}</p>
                      <p className="text-[10px] text-slate-500">Agent: {s.agent_name}</p>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className={`px-2 py-0.5 rounded text-[9px] font-bold ${
                        s.is_active ? 'bg-emerald-950 text-emerald-400' : 'bg-slate-900 text-slate-400'
                      }`}>
                        {s.is_active ? 'ACTIVE' : 'INACTIVE'}
                      </span>
                      <button
                        onClick={() => handleToggleSessionState(s)}
                        className={`px-2 py-1 rounded text-[9px] font-bold ${
                          s.is_active ? 'bg-red-950 text-red-400 hover:bg-red-900' : 'bg-emerald-950 text-emerald-400 hover:bg-emerald-950'
                        }`}
                      >
                        {s.is_active ? 'Disable' : 'Enable'}
                      </button>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </Section>

      {/* Footer */}
      <div className="border-t border-slate-800 pt-6 text-slate-600 text-xs">
        BankGuard DevKit — internal use only. Not indexed, not linked from navbar.
        All test content is synthetic and harmless.
      </div>
    </div>
  );
}
