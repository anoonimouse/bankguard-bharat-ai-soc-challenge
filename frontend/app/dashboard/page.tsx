"use client";

import { useEffect, useState, useRef } from 'react';
import { 
  ShieldAlert, 
  AlertTriangle, 
  Activity, 
  Wifi, 
  Send, 
  FileJson, 
  CheckCircle2, 
  X, 
  BarChart2, 
  RefreshCw, 
  AlertCircle,
  Smartphone,
  Play,
  Pause,
  User,
  Bot,
  FileText,
  Copy
} from 'lucide-react';

import { INDIA_STATE_MAP } from './india_states_data';

const STATE_COORDINATES: { [key: string]: { x: number, y: number, name: string } } = {
  "Andaman and Nicobar": { x: 78.0, y: 83.4, name: "Andaman and Nicobar" },
  "Telangana": { x: 39.9, y: 64.4, name: "Telangana" },
  "Andhra Pradesh": { x: 42.8, y: 70.0, name: "Andhra Pradesh" },
  "Arunachal Pradesh": { x: 83.2, y: 34.4, name: "Arunachal Pradesh" },
  "Assam": { x: 76.5, y: 39.9, name: "Assam" },
  "Bihar": { x: 58.0, y: 40.8, name: "Bihar" },
  "Chandigarh": { x: 33.5, y: 25.5, name: "Chandigarh" },
  "Chhattisgarh": { x: 47.8, y: 54.5, name: "Chhattisgarh" },
  "Dādra and Nagar Haveli and Damān and Diu": { x: 23.4, y: 57.5, name: "Dādra and Nagar Haveli and Damān and Diu" },
  "Delhi": { x: 34.4, y: 32.1, name: "Delhi" },
  "Goa": { x: 26.0, y: 71.4, name: "Goa" },
  "Gujarat": { x: 18.8, y: 50.7, name: "Gujarat" },
  "Haryana": { x: 32.4, y: 30.4, name: "Haryana" },
  "Himachal Pradesh": { x: 35.1, y: 21.4, name: "Himachal Pradesh" },
  "Jharkhand": { x: 58.1, y: 47.3, name: "Jharkhand" },
  "Karnataka": { x: 32.8, y: 72.7, name: "Karnataka" },
  "Kerala": { x: 32.0, y: 84.1, name: "Kerala" },
  "Madhya Pradesh": { x: 37.6, y: 46.1, name: "Madhya Pradesh" },
  "Maharashtra": { x: 32.3, y: 60.0, name: "Maharashtra" },
  "Manipur": { x: 80.3, y: 44.0, name: "Manipur" },
  "Meghalaya": { x: 73.2, y: 41.5, name: "Meghalaya" },
  "Mizoram": { x: 77.3, y: 48.1, name: "Mizoram" },
  "Nagaland": { x: 81.7, y: 40.1, name: "Nagaland" },
  "Odisha": { x: 53.8, y: 57.3, name: "Odisha" },
  "Puducherry": { x: 39.0, y: 80.6, name: "Puducherry" },
  "Punjab": { x: 30.3, y: 25.0, name: "Punjab" },
  "Rajasthan": { x: 28.9, y: 40.3, name: "Rajasthan" },
  "Sikkim": { x: 65.5, y: 35.4, name: "Sikkim" },
  "Tamil Nadu": { x: 38.0, y: 83.3, name: "Tamil Nadu" },
  "Tripura": { x: 74.8, y: 46.9, name: "Tripura" },
  "Uttar Pradesh": { x: 42.8, y: 38.6, name: "Uttar Pradesh" },
  "Uttarakhand": { x: 40.1, y: 27.6, name: "Uttarakhand" },
  "West Bengal": { x: 65.4, y: 48.3, name: "West Bengal" },
  "Lakshadweep": { x: 22.8, y: 85.2, name: "Lakshadweep" },
  "Jammu & Kashmir": { x: 29.7, y: 15.6, name: "Jammu & Kashmir" },
  "Ladakh": { x: 32.9, y: 13.1, name: "Ladakh" }
};

const CONNECTIONS = [
  ["Jammu & Kashmir", "Himachal Pradesh"],
  ["Himachal Pradesh", "Punjab"],
  ["Himachal Pradesh", "Uttarakhand"],
  ["Punjab", "Haryana"],
  ["Haryana", "Delhi"],
  ["Haryana", "Rajasthan"],
  ["Delhi", "Uttar Pradesh"],
  ["Uttar Pradesh", "Bihar"],
  ["Bihar", "Jharkhand"],
  ["Jharkhand", "West Bengal"],
  ["Bihar", "West Bengal"],
  ["Rajasthan", "Gujarat"],
  ["Gujarat", "Maharashtra"],
  ["Maharashtra", "Madhya Pradesh"],
  ["Madhya Pradesh", "Uttar Pradesh"],
  ["Madhya Pradesh", "Chhattisgarh"],
  ["Chhattisgarh", "Odisha"],
  ["Odisha", "Jharkhand"],
  ["Odisha", "West Bengal"],
  ["Maharashtra", "Telangana"],
  ["Telangana", "Andhra Pradesh"],
  ["Maharashtra", "Karnataka"],
  ["Karnataka", "Goa"],
  ["Karnataka", "Kerala"],
  ["Karnataka", "Tamil Nadu"],
  ["Tamil Nadu", "Andhra Pradesh"],
  ["Kerala", "Tamil Nadu"],
  ["West Bengal", "Assam"],
  ["Assam", "Meghalaya"],
  ["Assam", "Arunachal Pradesh"],
  ["Arunachal Pradesh", "Nagaland"],
  ["Nagaland", "Manipur"],
  ["Manipur", "Mizoram"],
  ["Mizoram", "Tripura"],
  ["Tripura", "Assam"]
];

const normalizeStateName = (name: string): string => {
  if (!name) return "";
  const n = name.trim();
  if (n === "Orissa") return "Odisha";
  if (n === "Uttaranchal") return "Uttarakhand";
  if (n === "Jammu and Kashmir") return "Jammu & Kashmir";
  return n;
};

export default function SecurityDashboard() {
  const [reports, setReports] = useState<any[]>([]);
  const [domains, setDomains] = useState<any[]>([]);
  const [devices, setDevices] = useState<any[]>([]);
  const [regionalThreats, setRegionalThreats] = useState<any[]>([]);
  const [selectedState, setSelectedState] = useState<string | null>(null);
  const [inspectedReport, setInspectedReport] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState("logs"); // "logs", "triage", or "devices"

  // Timeline playback state
  const [isPlaying, setIsPlaying] = useState(false);
  const [playbackDay, setPlaybackDay] = useState(0);

  // Live telemetry ticker state
  const [lastReportId, setLastReportId] = useState<number | null>(null);
  const [tickerIndex, setTickerIndex] = useState(0);
  const [flashAlert, setFlashAlert] = useState(false);
  const [activeAlert, setActiveAlert] = useState<any>(null);

  // AI Analyst state
  const [chatInput, setChatInput] = useState("");
  const [chatMessages, setChatMessages] = useState<any[]>([
    { role: 'assistant', text: `Hello! I am your BankGuard SecOps Analyst. I've analyzed our telemetry database. Ask me about specific state counts (e.g. "Scams in Kerala"), attack tactics, or request an overall threat summary!` }
  ]);
  const [chatLoading, setChatLoading] = useState(false);
  const chatEndRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (chatEndRef.current) {
      chatEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [chatMessages]);

  // Chakshu Modal State
  const [selectedReport, setSelectedReport] = useState<any>(null);
  const [dossierData, setDossierData] = useState<any>(null);
  const [dossierLoading, setDossierLoading] = useState(false);
  const [submittingChakshu, setSubmittingChakshu] = useState(false);
  const [chakshuResult, setChakshuResult] = useState<any>(null);

  // Triage Insights State
  const [triageData, setTriageData] = useState<any>(null);
  const [triageLoading, setTriageLoading] = useState(false);
  const [triageLimit, setTriageLimit] = useState(50);
  const [deployedDefenses, setDeployedDefenses] = useState<string[]>([]);
  const [deployingCampaign, setDeployingCampaign] = useState<string | null>(null);

  // Triage Response Dossier State
  const [selectedDossierCampaign, setSelectedDossierCampaign] = useState<any>(null);
  const [dossierResult, setDossierResult] = useState<any>(null);
  const [dossierLoadingResponse, setDossierLoadingResponse] = useState(false);
  const [copiedField, setCopiedField] = useState<string | null>(null);

  const fetchData = async () => {
    try {
      const apiUrl = (process.env.NEXT_PUBLIC_API_URL || 'https://api.doy.codes').replace(/\/$/, '');
      const [reportsRes, domainsRes, devicesRes, regionalRes] = await Promise.all([
        fetch(`${apiUrl}/api/reports`),
        fetch(`${apiUrl}/api/suspicious-domains`),
        fetch(`${apiUrl}/api/admin/devices`),
        fetch(`${apiUrl}/api/admin/regional-threats`)
      ]);
      
      const reportsData = await reportsRes.json();
      const domainsData = await domainsRes.json();
      const devicesData = await devicesRes.json();
      const regionalData = await regionalRes.json();
      
      setReports(Array.isArray(reportsData) ? reportsData : []);
      setDomains(Array.isArray(domainsData) ? domainsData : []);
      setDevices(Array.isArray(devicesData) ? devicesData : []);
      setRegionalThreats(Array.isArray(regionalData) ? regionalData : []);
    } catch (error) {
      console.error("Dashboard fetch error:", error);
    } finally {
      setLoading(false);
    }
  };

  const fetchTriage = async (customLimit?: number) => {
    const limitToUse = customLimit ?? triageLimit;
    setTriageLoading(true);
    try {
      const apiUrl = (process.env.NEXT_PUBLIC_API_URL || 'https://api.doy.codes').replace(/\/$/, '');
      const res = await fetch(`${apiUrl}/api/admin/triage-insights?limit=${limitToUse}`);
      if (res.ok) {
        const data = await res.json();
        setTriageData(data);
      }
    } catch (err) {
      console.error("Error fetching triage insights:", err);
    } finally {
      setTriageLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 4000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (activeTab === "triage") {
      fetchTriage(triageLimit);
    }
  }, [activeTab, triageLimit]);

  // Timeline automatic playback effect
  useEffect(() => {
    let timer: any;
    if (isPlaying) {
      timer = setInterval(() => {
        setPlaybackDay(prev => (prev + 1) % 7);
      }, 1000);
    }
    return () => {
      if (timer) clearInterval(timer);
    };
  }, [isPlaying]);

  // Live Telemetry stream listener
  useEffect(() => {
    const reportsArr = Array.isArray(reports) ? reports : [];
    if (reportsArr.length > 0) {
      const latest = reportsArr[0];
      if (lastReportId === null) {
        setLastReportId(latest.id);
        setActiveAlert(latest);
      } else if (latest.id > lastReportId) {
        setLastReportId(latest.id);
        setActiveAlert(latest);
        setFlashAlert(true);
        const timer = setTimeout(() => setFlashAlert(false), 5000);
        return () => clearTimeout(timer);
      }
    }
  }, [reports, lastReportId]);

  // Fallback ticker cycling
  useEffect(() => {
    const reportsArr = Array.isArray(reports) ? reports : [];
    if (!flashAlert && reportsArr.length > 0) {
      const timer = setInterval(() => {
        setTickerIndex(prev => (prev + 1) % Math.min(reportsArr.length, 5));
      }, 4000);
      return () => clearInterval(timer);
    }
  }, [reports, flashAlert]);

  const getReportDayDelta = (createdAtStr: string): number => {
    try {
      const reportDate = new Date(createdAtStr);
      const today = new Date();
      today.setHours(0, 0, 0, 0);
      const reportDay = new Date(reportDate);
      reportDay.setHours(0, 0, 0, 0);
      const diffTime = today.getTime() - reportDay.getTime();
      return Math.max(0, Math.floor(diffTime / (1000 * 60 * 60 * 24)));
    } catch {
      return 0;
    }
  };

  const generateAIResponse = (query: string): string => {
    const q = query.toLowerCase().trim();
    const reportsArr = Array.isArray(reports) ? reports : [];
    
    const totalReports = reportsArr.length;
    const vpnReports = reportsArr.filter(r => r.report_type === "VPN_DNS_BLOCK" || r.threat_type?.includes("VPN")).length;
    const apkReports = reportsArr.filter(r => r.report_type === "POLYGLOT_APK" || r.report_type === "APK" || r.threat_type?.includes("APK")).length;
    const scamReports = reportsArr.filter(r => r.report_type === "NOTIFICATION_SCAM" || r.report_type === "SMS/WhatsApp" || r.threat_type?.includes("SCAM")).length;
    const urlReports = reportsArr.filter(r => r.report_type === "NOTIFICATION_URL" || r.report_type === "URL" || r.threat_type?.includes("URL")).length;

    const stateCounts: { [key: string]: number } = {};
    reportsArr.forEach(r => {
      if (r.state_region) {
        stateCounts[r.state_region] = (stateCounts[r.state_region] || 0) + 1;
      }
    });
    const sorted = Object.entries(stateCounts).sort((a, b) => b[1] - a[1]);
    const topStateName = sorted[0] ? `${sorted[0][0]} (${sorted[0][1]} alerts)` : "None";

    // 1. Specific Indian States detection
    const statesList = [
      "kerala", "gujarat", "maharashtra", "telangana", "andhra pradesh", "karnataka", 
      "tamil nadu", "delhi", "haryana", "punjab", "bihar", "west bengal", "jharkhand", 
      "chhattisgarh", "rajasthan", "odisha", "uttar pradesh", "madhya pradesh", "assam"
    ];
    const queriedState = statesList.find(s => q.includes(s));
    if (queriedState) {
      const stateNameNorm = queriedState.split(' ').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
      const stateLogs = reportsArr.filter(r => r.state_region && r.state_region.toLowerCase().includes(queriedState));
      const count = stateLogs.length;
      if (count === 0) {
        return `No active threat telemetry logs recorded for **${stateNameNorm}** in our database. The region is currently flagged as **SAFE**.`;
      }
      
      const apkC = stateLogs.filter(r => r.report_type?.includes("APK") || r.threat_type?.includes("APK")).length;
      const urlC = stateLogs.filter(r => r.report_type?.includes("URL") || r.threat_type?.includes("URL")).length;
      const scamC = stateLogs.filter(r => r.report_type?.includes("SCAM") || r.report_type?.includes("WhatsApp") || r.threat_type?.includes("SCAM")).length;

      const recentList = stateLogs.slice(0, 5).map(r => `* [${r.report_type}] **${r.content?.slice(0, 80)}** (Tactic: *${r.scam_tactic || 'N/A'}*, Status: *${r.status}*)`).join('\n');

      return `### Regional Threat Intelligence: ${stateNameNorm}
* **Total Alerts**: ${count} incident telemetry records in database
* **Threat Vector Breakdown**:
  * Polyglot APK Sideloads: ${apkC}
  * Phishing URL Intercepts: ${urlC}
  * SMS/WhatsApp Social Engineering: ${scamC}

#### Recent Regional Log entries:
${recentList}

**Analyst Recommendation**: Telemetry points to lookalike YONO app distributions. Implement a local DNS sinkhole configuration on connected user nodes.`;
    }

    // 2. Tactic keyword matching
    const commonKeywords = ["electricity", "bill", "kyc", "lottery", "rewards", "blocked", "update", "gift", "loan", "support", "refund", "card"];
    const queriedKeyword = commonKeywords.find(kw => q.includes(kw));
    if (queriedKeyword) {
      const matchingLogs = reportsArr.filter(r => 
        (r.content || "").toLowerCase().includes(queriedKeyword) || 
        (r.scam_tactic || "").toLowerCase().includes(queriedKeyword)
      );
      const count = matchingLogs.length;
      if (count > 0) {
        const recentList = matchingLogs.slice(0, 5).map(r => `* [${r.report_type} | ${r.state_region || 'Unknown'}] **${r.content?.slice(0, 80)}** (Status: *${r.status}*)`).join('\n');
        return `### Threat Signature Search: "${queriedKeyword.toUpperCase()}"
Found **${count}** matching reports in the live telemetry feed.

#### Recent matching incidents:
${recentList}

**Remediation Protocol**: Deploy immediate domain blacklist defenses or block outbound callback numbers.`;
      }
    }

    // 3. Attack vector deep-dives
    if (q.includes("apk") || q.includes("sideload") || q.includes("file")) {
      const recentList = reportsArr.filter(r => r.report_type?.includes("APK") || r.threat_type?.includes("APK")).slice(0, 5).map(r => `* [${r.state_region || 'Unknown'}] **${r.content?.slice(0, 80)}**`).join('\n');
      return `### Vector Deep-Dive: Sideloaded APKs
* **Intercepted APKs**: We have recorded **${apkReports}** polyglot APK installations.
* **Key Tactics Detected**:
  * Impersonating State Bank of India YONO app packaging.
  * Zip Central Directory manipulation to bypass normal Android PackageInstaller checks.

#### Recent Sideload Intercepts:
${recentList}

**Remediation**: Ensure that the mobile SDK has the broadcast receiver running for \`Intent.ACTION_PACKAGE_ADDED\` to block unauthorized packages post-sideload.`;
    }

    if (q.includes("scam") || q.includes("message") || q.includes("whatsapp") || q.includes("sms") || q.includes("tactic")) {
      const recentList = reportsArr.filter(r => r.report_type?.includes("SCAM") || r.report_type?.includes("WhatsApp") || r.threat_type?.includes("SCAM")).slice(0, 5).map(r => `* [${r.state_region || 'Unknown'}] **${r.content?.slice(0, 80)}**`).join('\n');
      return `### Social Engineering Analysis: SMS/WhatsApp Heuristics
* **Interceptions**: We've detected **${scamReports}** messages containing high-risk phishing urgencies.
* **Common Tactics Found**:
  * *KYC Expiry Urgency*: e.g., *"Dear customer your SBI Netbanking account block today update KYC click here..."*
  * *Rewards/Points Redemption*: e.g., *"SBI Reward points worth Rs. 9,850 expired redeem now..."*

#### Recent Scam Intercepts:
${recentList}

**AI Verdict**: 89.4% of these messages lead directly to malicious APK downloads. Dynamic warning overlays successfully nudge users to abort checkout.`;
    }

    // 4. Default Overall Summary
    const statesSummary = sorted.slice(0, 5).map(([st, c]) => `**${st}** (${c} alerts)`).join(', ');
    return `### Telemetry Summary Report
* **Total Database Intercepts**: **${totalReports}** records
* **Top Regional Hotspot**: ${topStateName}
* **Critical Hotspot Areas**: ${statesSummary}
* **Active Threat Channels**:
  * SMS/WhatsApp Scams: **${scamReports}** alerts
  * Phishing URLs: **${urlReports}** logs
  * Sideloaded APK Blocks: **${apkReports}** intercepts
  * DNS Sinkhole Blocks: **${vpnReports}** blocks

What specific telemetry state or vector would you like me to analyze next?`;
  };

  const renderMarkdown = (text: string) => {
    const lines = text.split('\n');
    const result: React.ReactNode[] = [];
    let i = 0;
    while (i < lines.length) {
      const line = lines[i];
      // Blank line
      if (line.trim() === '') { result.push(<br key={i} />); i++; continue; }
      // Headers matching #, ##, ###, ####, #####, ######
      const headerMatch = line.match(/^(#{1,6})\s+(.*)$/);
      if (headerMatch) {
        const level = headerMatch[1].length;
        const content = headerMatch[2];
        let className = "font-bold text-themeDark mt-3 mb-1 ";
        if (level === 1) className += "text-sm";
        else if (level === 2) className += "text-[12px]";
        else if (level === 3) className += "text-[11px] uppercase tracking-wide";
        else className += "text-[10px] uppercase tracking-wider opacity-85";
        
        result.push(<p key={i} className={className}>{inlineFormat(content)}</p>);
        i++; continue;
      }
      // Unordered list item
      if (line.match(/^[*-] /)) {
        const items: React.ReactNode[] = [];
        while (i < lines.length && lines[i].match(/^[*-] /)) {
          const sub = lines[i].slice(2);
          // Sub-item (2-space indent)
          items.push(<li key={i} className="ml-3 list-disc">{inlineFormat(sub)}</li>);
          i++;
        }
        result.push(<ul key={`ul-${i}`} className="space-y-0.5 my-1 text-[11px]">{items}</ul>);
        continue;
      }
      // Indented sub-list
      if (line.match(/^  [*-] /)) {
        result.push(<li key={i} className="ml-6 list-circle text-[11px]">{inlineFormat(line.slice(4))}</li>);
        i++; continue;
      }
      // Normal paragraph
      result.push(<p key={i} className="text-[11px] leading-relaxed">{inlineFormat(line)}</p>);
      i++;
    }
    return result;
  };

  const inlineFormat = (text: string): React.ReactNode => {
    const parts = text.split(/(\*\*[^*]+\*\*|\*[^*]+\*|`[^`]+`)/);
    return parts.map((part, idx) => {
      if (part.startsWith('**') && part.endsWith('**')) {
        return <strong key={idx} className="font-semibold text-themeDark">{part.slice(2, -2)}</strong>;
      }
      if (part.startsWith('*') && part.endsWith('*') && part.length > 2) {
        return <em key={idx} className="italic text-themeDark/80">{part.slice(1, -1)}</em>;
      }
      if (part.startsWith('`') && part.endsWith('`')) {
        return <code key={idx} className="font-mono bg-slate-100 text-themeDark/80 px-1 rounded text-[10px]">{part.slice(1, -1)}</code>;
      }
      return part;
    });
  };

  const handleChatSubmit = async (e: React.FormEvent, overrideQuery?: string) => {
    e.preventDefault();
    const query = (overrideQuery ?? chatInput).trim();
    if (!query) return;

    const userMsg = { role: 'user', text: query };
    setChatMessages(prev => [...prev, userMsg]);
    setChatInput('');
    setChatLoading(true);

    const apiUrl = (process.env.NEXT_PUBLIC_API_URL || 'https://api.doy.codes').replace(/\/$/, '');

    try {
      const res = await fetch(`${apiUrl}/api/analyst-chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: `HTTP ${res.status}` }));
        throw new Error(err.detail ?? `Request failed with status ${res.status}`);
      }
      const data = await res.json();
      setChatMessages(prev => [...prev, { role: 'assistant', text: data.response ?? 'No response from AI.' }]);
    } catch (err: any) {
      console.warn("Backend AI Chat failed, falling back to local database engine:", err);
      const fallbackText = generateAIResponse(query);
      setChatMessages(prev => [...prev, { role: 'assistant', text: fallbackText }]);
    } finally {
      setChatLoading(false);
    }
  };

  const getCampaignAnalytics = (campaignName: string, recommendedAction: string) => {
    const lowerName = campaignName.toLowerCase();
    const matchingReports = reports.filter(r => {
      const content = (r.content || "").toLowerCase();
      const type = (r.report_type || "").toLowerCase();
      
      if (lowerName.includes("arrest") || lowerName.includes("police")) {
        return content.includes("arrest") || content.includes("police") || content.includes("cbi") || content.includes("custody");
      }
      if (lowerName.includes("electricity") || lowerName.includes("utility")) {
        return content.includes("electricity") || content.includes("power") || content.includes("bill");
      }
      if (lowerName.includes("kyc") || lowerName.includes("block")) {
        return content.includes("kyc") || content.includes("block") || content.includes("expire");
      }
      if (lowerName.includes("reward") || lowerName.includes("points")) {
        return content.includes("reward") || content.includes("gift") || content.includes("points") || content.includes("cashback");
      }
      if (lowerName.includes("apk") || lowerName.includes("sideload") || type.includes("apk")) {
        return type.includes("apk") || content.includes("apk") || content.includes(".apk");
      }
      return false;
    });

    const states = Array.from(new Set(matchingReports.map(r => r.state_region).filter(Boolean)));
    
    let identifierToDeploy = "";
    for (const r of matchingReports) {
      if (r.report_type === "URL" || r.report_type === "NOTIFICATION_URL") {
        try {
          const cleanUrl = r.content.replace(/https?:\/\//i, '').split('/')[0];
          if (cleanUrl) {
            identifierToDeploy = cleanUrl;
            break;
          }
        } catch (e) {}
      }
    }
    
    if (!identifierToDeploy) {
      const mockDomain = campaignName.toLowerCase().replace(/[^a-z0-9]/g, '-') + "-sinkhole.net";
      identifierToDeploy = mockDomain;
    }

    return {
      states: states.length > 0 ? states.slice(0, 3) : ["Delhi", "Maharashtra"],
      identifier: identifierToDeploy,
      matchCount: matchingReports.length || 1
    };
  };

  const handleExecuteDefense = async (campaignName: string, identifier: string) => {
    setDeployingCampaign(campaignName);
    try {
      const apiUrl = (process.env.NEXT_PUBLIC_API_URL || 'https://api.doy.codes').replace(/\/$/, '');
      const res = await fetch(`${apiUrl}/api/suspicious-domains`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          domain_name: identifier,
          threat_level: "HIGH"
        })
      });
      if (res.ok) {
        setDeployedDefenses(prev => [...prev, campaignName]);
        fetchData();
      }
    } catch (err) {
      console.error("Error executing defense:", err);
    } finally {
      setDeployingCampaign(null);
    }
  };

  const fetchTriageDossier = async (campaignName: string, category: string, identifier: string, states: string[]) => {
    setSelectedDossierCampaign({ campaignName, category, identifier, states });
    setDossierLoadingResponse(true);
    setDossierResult(null);
    try {
      const apiUrl = (process.env.NEXT_PUBLIC_API_URL || 'https://api.doy.codes').replace(/\/$/, '');
      const res = await fetch(`${apiUrl}/api/admin/triage-dossier`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          campaign_name: campaignName,
          threat_category: category,
          target_identifier: identifier,
          affected_states: states
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setDossierResult(data);
      }
    } catch (err) {
      console.error("Error fetching triage dossier:", err);
    } finally {
      setDossierLoadingResponse(false);
    }
  };

  const handleCopyToClipboard = (text: string, field: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => {
      setCopiedField(null);
    }, 2000);
  };


  // Threat Counts
  const notificationScams = reports.filter((r: any) => r.report_type === "SMS/WhatsApp" || r.report_type === "NOTIFICATION_SCAM").length;
  const phishingUrls = reports.filter((r: any) => r.report_type === "URL" || r.report_type === "NOTIFICATION_URL").length;
  const vpnBlocks = reports.filter((r: any) => r.report_type === "VPN_DNS_BLOCK").length;
  const polyglotApks = reports.filter((r: any) => r.report_type === "POLYGLOT_APK" || r.report_type === "APK").length;
  const callSpoofs = reports.filter((r: any) => r.report_type === "CALL_SPOOF" || r.report_type === "CALL_FRAUD").length;

  const safetyScore = Math.max(100 - (reports.filter((r: any) => r.status === "verified").length * 5) - (reports.filter((r: any) => r.status === "pending").length * 2), 42);

  const filteredReports = isPlaying || playbackDay > 0
    ? reports.filter((r: any) => getReportDayDelta(r.created_at) === playbackDay)
    : reports;

  const getFilteredStateCounts = () => {
    const counts: { [key: string]: number } = {};
    filteredReports.forEach((r: any) => {
      if (r.state_region) {
        counts[r.state_region] = (counts[r.state_region] || 0) + 1;
      }
    });
    return counts;
  };
  const filteredStateCounts = getFilteredStateCounts();

  const getTrendData = () => {
    const trend = [];
    const now = new Date();
    for (let i = 6; i >= 0; i--) {
      const d = new Date();
      d.setDate(now.getDate() - i);
      const dateStr = d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
      
      const dateStart = new Date(d.getFullYear(), d.getMonth(), d.getDate(), 0, 0, 0, 0);
      const dateEnd = new Date(d.getFullYear(), d.getMonth(), d.getDate(), 23, 59, 59, 999);
      
      const count = reports.filter((r: any) => {
        const repDate = new Date(r.reported_at);
        return repDate >= dateStart && repDate <= dateEnd;
      }).length;
      
      trend.push({ date: dateStr, count });
    }
    return trend;
  };

  const renderTrendChart = () => {
    const trendData = getTrendData();
    const maxCount = Math.max(...trendData.map(d => d.count), 5);
    
    const paddingLeft = 30;
    const paddingRight = 10;
    const paddingTop = 15;
    const paddingBottom = 25;
    const chartWidth = 500 - paddingLeft - paddingRight;
    const chartHeight = 180 - paddingTop - paddingBottom;
    
    const points = trendData.map((d, index) => {
      const x = paddingLeft + (index * (chartWidth / (trendData.length - 1)));
      const y = paddingTop + chartHeight - (d.count / maxCount) * chartHeight;
      return { x, y, ...d };
    });
    
    const linePath = points.length > 0 
      ? `M ${points[0].x} ${points[0].y} ` + points.slice(1).map(p => `L ${p.x} ${p.y}`).join(' ')
      : '';
      
    const areaPath = points.length > 0
      ? `${linePath} L ${points[points.length-1].x} ${paddingTop + chartHeight} L ${points[0].x} ${paddingTop + chartHeight} Z`
      : '';
      
    return (
      <svg className="w-full h-full" viewBox="0 0 500 180" preserveAspectRatio="none">
        <defs>
          <linearGradient id="trendAreaGradient" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#3b82f6" stopOpacity="0.2" />
            <stop offset="100%" stopColor="#3b82f6" stopOpacity="0.0" />
          </linearGradient>
        </defs>
        
        {/* Y Axis Grid lines */}
        {[0, 0.25, 0.5, 0.75, 1].map((ratio, idx) => {
          const y = paddingTop + chartHeight - ratio * chartHeight;
          const val = Math.round(ratio * maxCount);
          return (
            <g key={idx}>
              <line x1={paddingLeft} y1={y} x2={500 - paddingRight} y2={y} stroke="#f1f5f9" strokeWidth="1" />
              <text x={paddingLeft - 8} y={y + 3} textAnchor="end" className="text-[9px] fill-themeDark/40 font-semibold">{val}</text>
            </g>
          );
        })}
        
        {/* Fill Area */}
        {areaPath && <path d={areaPath} fill="url(#trendAreaGradient)" />}
        
        {/* Line Path */}
        {linePath && <path d={linePath} fill="none" stroke="#3b82f6" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />}
        
        {/* Data points & X axis */}
        {points.map((p, idx) => (
          <g key={idx}>
            <circle cx={p.x} cy={p.y} r="3" fill="#ffffff" stroke="#3b82f6" strokeWidth="2" />
            <text x={p.x} y={paddingTop + chartHeight + 15} textAnchor="middle" className="text-[9px] fill-themeDark/50 font-bold">{p.date}</text>
          </g>
        ))}
      </svg>
    );
  };

  const renderIndiaNetworkMap = () => {
    return (
      <svg viewBox="0 0 110 105" className="w-full h-full max-h-[350px]">
        {/* Map Grid Pattern background */}
        <defs>
          <pattern id="mapGrid" width="10" height="10" patternUnits="userSpaceOnUse">
            <path d="M 10 0 L 0 0 0 10" fill="none" stroke="#f1f5f9" strokeWidth="0.5" />
          </pattern>
        </defs>
        <rect width="110" height="105" fill="url(#mapGrid)" rx="8" />

        {/* India Map Outline / State Shapes */}
        <g transform="scale(0.1)">
          {Object.entries(INDIA_STATE_MAP).map(([origName, stateInfo]) => {
            const normName = normalizeStateName(origName);
            const stateRecord = (Array.isArray(regionalThreats) ? regionalThreats : []).find(
              (t: any) => normalizeStateName(t.state) === normName
            );
            const count = isPlaying || playbackDay > 0
              ? (filteredStateCounts[normName] || 0)
              : (stateRecord ? stateRecord.count : 0);
            const isSelected = selectedState === normName;

            let fill = "#f8fafc";
            let stroke = "#cbd5e1";

            if (count > 50) {
              fill = "#fee2e2"; // red-100
              stroke = "#f87171"; // red-400
            } else if (count > 20) {
              fill = "#ffe4e6"; // rose-100
              stroke = "#fb7185"; // rose-400
            } else if (count > 0) {
              fill = "#fff1f2"; // rose-50
              stroke = "#fda4af"; // rose-300
            }

            if (isSelected) {
              fill = "#fecdd3"; // rose-200
              stroke = "#e11d48"; // rose-600
            }

            return (
              <path
                key={stateInfo.id}
                d={stateInfo.d}
                fill={fill}
                stroke={stroke}
                strokeWidth={3}
                strokeLinejoin="round"
                className="transition-colors duration-300 hover:fill-slate-100 cursor-pointer"
                onClick={() => setSelectedState(selectedState === normName ? null : normName)}
              >
                <title>{`${normName}: ${count} threat alerts`}</title>
              </path>
            );
          })}
        </g>

        {/* Faint network connections */}
        {CONNECTIONS.map(([fromState, toState], idx) => {
          const fromCoord = STATE_COORDINATES[fromState];
          const toCoord = STATE_COORDINATES[toState];
          if (!fromCoord || !toCoord) return null;
          return (
            <line 
              key={idx}
              x1={fromCoord.x} 
              y1={fromCoord.y} 
              x2={toCoord.x} 
              y2={toCoord.y} 
              stroke="#cbd5e1" 
              strokeWidth="0.2" 
              strokeDasharray="1,1" 
              opacity={0.3}
            />
          );
        })}

        {/* State nodes */}
        {Object.entries(STATE_COORDINATES).map(([state, coord]) => {
          const stateRecord = (Array.isArray(regionalThreats) ? regionalThreats : []).find(t => t.state === state);
          const count = isPlaying || playbackDay > 0
            ? (filteredStateCounts[state] || 0)
            : (stateRecord ? stateRecord.count : 0);
          const isSelected = selectedState === state;
          
          const size = 1.0 + Math.min(count * 0.05, 2.0);
          
          let fillColor = "#cbd5e1"; // slate-300
          let strokeColor = "#94a3b8"; // slate-400
          
          if (count > 50) {
            fillColor = "#f43f5e"; // rose-500
            strokeColor = "#e11d48"; // rose-600
          } else if (count > 20) {
            fillColor = "#fb7185"; // rose-400
            strokeColor = "#f43f5e"; // rose-500
          } else if (count > 0) {
            fillColor = "#fecdd3"; // rose-200
            strokeColor = "#fda4af"; // rose-300
          }
          
          return (
            <g 
              key={state} 
              className="cursor-pointer group" 
              onClick={() => setSelectedState(selectedState === state ? null : state)}
            >
              {isSelected && (
                <circle 
                  cx={coord.x} 
                  cy={coord.y} 
                  r={size + 1.5} 
                  fill="none" 
                  stroke={strokeColor} 
                  strokeWidth="0.3" 
                  strokeDasharray="1,1"
                  opacity={0.5}
                  className="animate-spin"
                  style={{ transformOrigin: `${coord.x}px ${coord.y}px` }}
                />
              )}
              
              <circle 
                cx={coord.x} 
                cy={coord.y} 
                r={size} 
                fill={fillColor} 
                stroke={isSelected ? "#1e293b" : strokeColor} 
                strokeWidth={isSelected ? "0.75" : "0.3"} 
                opacity={count > 0 ? 0.7 : 0.3}
                className="transition-all duration-300 group-hover:scale-125"
                style={{ transformOrigin: `${coord.x}px ${coord.y}px` }}
              />
              
              <title>{`${state}: ${count} threat alerts`}</title>
              
              {/* Overlay minimal label on hover */}
              <text
                x={coord.x}
                y={coord.y - size - 2}
                textAnchor="middle"
                className="text-[3.5px] font-bold fill-slate-800 opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none bg-white px-1"
              >
                {state} ({count})
              </text>
            </g>
          );
        })}
      </svg>
    );
  };

  // Sort regional threats by count descending for side listing
  const sortedStates = Object.keys(STATE_COORDINATES)
    .map(state => {
      const rec = (Array.isArray(regionalThreats) ? regionalThreats : []).find(t => t.state === state);
      return [state, rec ? rec.count : 0];
    })
    .filter(([_, count]) => count > 0)
    .sort((a, b) => (b[1] as number) - (a[1] as number));

  const totalRegionalCount = (Array.isArray(regionalThreats) ? regionalThreats : []).reduce((acc: number, t: any) => acc + t.count, 0);

  const openChakshuModal = async (report: any) => {
    setSelectedReport(report);
    setDossierLoading(true);
    setChakshuResult(null);
    setDossierData(null);
    try {
      const apiUrl = (process.env.NEXT_PUBLIC_API_URL || 'https://api.doy.codes').replace(/\/$/, '');
      const res = await fetch(`${apiUrl}/api/dot/compile-dossier/${report.id}`);
      if (res.ok) {
        const data = await res.json();
        setDossierData(data);
      }
    } catch (err) {
      console.error("Error compiling dossier:", err);
    } finally {
      setDossierLoading(false);
    }
  };

  const submitToChakshu = async () => {
    if (!selectedReport) return;
    setSubmittingChakshu(true);
    try {
      const apiUrl = (process.env.NEXT_PUBLIC_API_URL || 'https://api.doy.codes').replace(/\/$/, '');
      const payload = {
        report_type: selectedReport.report_type,
        content: selectedReport.content,
        risk_score: selectedReport.risk_score,
        reported_at: selectedReport.reported_at,
        dossier_data: dossierData
      };
      
      const res = await fetch(`${apiUrl}/api/dot/chakshu-report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      
      if (res.ok) {
        const data = await res.json();
        setChakshuResult(data);
        
        // Refresh local data list
        fetchData();
      }
    } catch (err) {
      console.error("Error submitting to Chakshu:", err);
    } finally {
      setSubmittingChakshu(false);
    }
  };

  return (
    <div className="h-full flex flex-col py-4 animate-in fade-in duration-500 max-w-6xl mx-auto px-4">
      
      {/* Header Area */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 mb-4">
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold text-themeDark flex items-center gap-2 mb-1">
            <ShieldAlert className="w-5 h-5 sm:w-6 sm:h-6 text-themeMid" />
            Ecosystem Health
          </h1>
          <p className="text-themeDark/60 text-xs sm:text-sm">Monitoring system telemetry, threat isolation, and regulatory integrations.</p>
        </div>
        <div className="glass-card px-3 py-2 flex items-center gap-2 self-start sm:self-auto">
           <div className="relative flex h-2 w-2">
             <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-successGreen opacity-75"></span>
             <span className="relative inline-flex rounded-full h-2 w-2 bg-successGreen"></span>
           </div>
           <span className="text-xs font-semibold text-themeDark flex items-center gap-1">
             <Wifi className="w-3 h-3 text-successGreen" />
             Live Sync
           </span>
        </div>
      </div>

      {/* Tab Selectors — horizontally scrollable on mobile */}
      <div className="flex overflow-x-auto no-scrollbar gap-2 mb-6 border-b border-themeLight/30 pb-2 -mx-4 px-4 sm:mx-0 sm:px-0 sm:flex-wrap">
        <button 
          onClick={() => setActiveTab("logs")}
          className={`px-3 sm:px-4 py-2 font-semibold text-xs sm:text-sm rounded-lg transition-all flex items-center gap-1.5 shrink-0 ${activeTab === "logs" ? "bg-themeMid text-white shadow-sm" : "text-themeDark/60 hover:bg-white/40"}`}
        >
          <Activity className="w-3.5 h-3.5 sm:w-4 sm:h-4" />
          Incident Telemetry
        </button>
        <button 
          onClick={() => setActiveTab("triage")}
          className={`px-3 sm:px-4 py-2 font-semibold text-xs sm:text-sm rounded-lg transition-all flex items-center gap-1.5 shrink-0 ${activeTab === "triage" ? "bg-themeMid text-white shadow-sm" : "text-themeDark/60 hover:bg-white/40"}`}
        >
          <BarChart2 className="w-3.5 h-3.5 sm:w-4 sm:h-4" />
          AI Insights
        </button>
        <button 
          onClick={() => setActiveTab("devices")}
          className={`px-3 sm:px-4 py-2 font-semibold text-xs sm:text-sm rounded-lg transition-all flex items-center gap-1.5 shrink-0 ${activeTab === "devices" ? "bg-themeMid text-white shadow-sm" : "text-themeDark/60 hover:bg-white/40"}`}
        >
          <Smartphone className="w-3.5 h-3.5 sm:w-4 sm:h-4" />
          Devices
        </button>
        <button 
          onClick={() => setActiveTab("analyst")}
          className={`px-3 sm:px-4 py-2 font-semibold text-xs sm:text-sm rounded-lg transition-all flex items-center gap-1.5 shrink-0 ${activeTab === "analyst" ? "bg-themeMid text-white shadow-sm" : "text-themeDark/60 hover:bg-white/40"}`}
        >
          <Bot className="w-3.5 h-3.5 sm:w-4 sm:h-4" />
          SecOps Analyst
        </button>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
        <div className="glass-card p-5 flex items-center justify-between shadow-sm">
          <div>
            <h3 className="text-themeDark/60 font-medium text-xs uppercase tracking-wider mb-2">Total Intercepts</h3>
            <p className="text-4xl font-extrabold text-themeDark">{loading ? '-' : reports.length}</p>
          </div>
          <div className="bg-themeLight/50 p-3 rounded-xl border border-themeLight">
              <Activity className="w-6 h-6 text-themeMid" />
          </div>
        </div>
        
        <div className="glass-card p-5 flex items-center justify-between shadow-sm">
          <div>
            <h3 className="text-themeDark/60 font-medium text-xs uppercase tracking-wider mb-2">Isolated Signatures</h3>
            <p className="text-4xl font-extrabold text-themeDark">{loading ? '-' : domains.length}</p>
          </div>
          <div className="bg-dangerRed/10 p-3 rounded-xl border border-dangerRed/20">
              <ShieldAlertIcon className="w-6 h-6 text-dangerRed" />
          </div>
        </div>
        
        <div className="glass-card p-5 flex items-center justify-between shadow-sm">
          <div>
            <h3 className="text-themeDark/60 font-medium text-xs uppercase tracking-wider mb-2">Active Threats</h3>
            <p className="text-4xl font-extrabold text-themeDark">{loading ? '-' : domains.filter((d: any) => d.is_active).length}</p>
          </div>
          <div className="bg-warningYellow/10 p-3 rounded-xl border border-warningYellow/20">
              <AlertTriangle className="w-6 h-6 text-warningYellow" />
          </div>
        </div>
      </div>
      {/* Tab 1: Incident Log Views */}
      {activeTab === "logs" && (
        <div className="space-y-6 flex-1 min-h-0 flex flex-col">
          {/* Visual Metrics Panel */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            
            {/* Column 1: Ecosystem Safety Gauge */}
            <div className="glass-card p-5 flex flex-col h-[280px]">
              <h2 className="text-xs font-bold text-themeDark/60 uppercase tracking-wider mb-4">Ecosystem Safety Indicator</h2>
              <div className="flex items-center justify-around flex-1 gap-2">
                {/* Safety Score Radial Gauge */}
                <div className="flex flex-col items-center">
                  <div className="relative flex items-center justify-center w-28 h-28">
                    <svg className="w-full h-full transform -rotate-90">
                      <circle cx="56" cy="56" r="48" stroke="#f1f5f9" strokeWidth="8" fill="transparent" />
                      <circle cx="56" cy="56" r="48" stroke={safetyScore >= 85 ? "#10b981" : safetyScore >= 70 ? "#f59e0b" : "#f43f5e"} strokeWidth="8" fill="transparent"
                        strokeDasharray={2 * Math.PI * 48}
                        strokeDashoffset={2 * Math.PI * 48 * (1 - safetyScore / 100)}
                        strokeLinecap="round"
                        className="transition-all duration-1000 ease-out"
                      />
                    </svg>
                    <div className="absolute text-center">
                      <span className="text-2xl font-black text-themeDark block">{safetyScore}%</span>
                      <span className="text-[9px] font-bold text-themeDark/50 tracking-wider uppercase">
                        {safetyScore >= 85 ? "SECURE" : safetyScore >= 70 ? "VIGILANT" : "CRITICAL"}
                      </span>
                    </div>
                  </div>
                </div>
                
                {/* Threat Vector legend */}
                <div className="flex-1 space-y-2.5 pl-2">
                  <div className="flex items-center justify-between text-xs border-b border-slate-100 pb-1">
                    <div className="flex items-center gap-1.5 text-themeDark/70">
                      <div className="w-2.5 h-2.5 rounded-full bg-rose-500"></div>
                      <span>SMS/WA</span>
                    </div>
                    <strong className="text-themeDark font-bold">{notificationScams}</strong>
                  </div>
                  <div className="flex items-center justify-between text-xs border-b border-slate-100 pb-1">
                    <div className="flex items-center gap-1.5 text-themeDark/70">
                      <div className="w-2.5 h-2.5 rounded-full bg-amber-500"></div>
                      <span>Phishing URL</span>
                    </div>
                    <strong className="text-themeDark font-bold">{phishingUrls}</strong>
                  </div>
                  <div className="flex items-center justify-between text-xs border-b border-slate-100 pb-1">
                    <div className="flex items-center gap-1.5 text-themeDark/70">
                      <div className="w-2.5 h-2.5 rounded-full bg-teal-500"></div>
                      <span>VPN Block</span>
                    </div>
                    <strong className="text-themeDark font-bold">{vpnBlocks}</strong>
                  </div>
                  <div className="flex items-center justify-between text-xs border-b border-slate-100 pb-1">
                    <div className="flex items-center gap-1.5 text-themeDark/70">
                      <div className="w-2.5 h-2.5 rounded-full bg-indigo-500"></div>
                      <span>Polyglot APK</span>
                    </div>
                    <strong className="text-themeDark font-bold">{polyglotApks}</strong>
                  </div>
                </div>
              </div>
            </div>

            {/* Column 2: Threat Activity Trend Chart */}
            <div className="glass-card p-5 flex flex-col h-[280px] md:col-span-2">
              <div className="flex justify-between items-center mb-2">
                <h2 className="text-xs font-bold text-themeDark/60 uppercase tracking-wider">Threat Vector Trend (Last 7 Days)</h2>
                <span className="text-[10px] text-themeDark/50 font-bold uppercase tracking-wider">Daily incident rate</span>
              </div>
              <div className="flex-1 w-full relative">
                {renderTrendChart()}
              </div>
            </div>

          </div>

          {/* Regional Threat Map Section */}
          <div className="glass-card p-4 sm:p-5 flex flex-col lg:flex-row gap-4 sm:gap-6">
            <div className="flex-1 flex flex-col">
              <div className="flex justify-between items-center mb-3">
                <div>
                  <h2 className="text-xs font-bold text-themeDark/60 uppercase tracking-wider">Regional Threat Operations Map (India)</h2>
                  <p className="text-xs text-themeDark/50">Geolocated target vectors by State/UT. Click state nodes or risk ratings to filter logs.</p>
                </div>
                {selectedState && (
                  <button 
                    onClick={() => setSelectedState(null)}
                    className="text-xs font-semibold text-dangerRed bg-dangerRed/10 px-2.5 py-1 rounded-lg border border-dangerRed/20 hover:bg-dangerRed/20 transition-all flex items-center gap-1"
                  >
                    Clear Filter: {selectedState} <X className="w-3 h-3" />
                  </button>
                )}
              </div>

              {/* Live Telemetry Banner */}
              {(() => {
                const reportsArr = Array.isArray(reports) ? reports : [];
                const displayReport = flashAlert ? activeAlert : reportsArr[tickerIndex];
                if (!displayReport) return null;
                const typeLabel = displayReport.report_type === "VPN_DNS_BLOCK"
                  ? "DNS Sinkhole"
                  : displayReport.report_type === "POLYGLOT_APK" || displayReport.report_type === "APK"
                    ? "APK Block"
                    : displayReport.report_type === "NOTIFICATION_SCAM" || displayReport.report_type === "SMS/WhatsApp"
                      ? "Scam Message"
                      : "URL Intercept";
                const regionLabel = displayReport.state_region || "Unknown Region";
                const contentSnippet = displayReport.content ? displayReport.content.substring(0, 60) + (displayReport.content.length > 60 ? "..." : "") : "Telemetry payload received";
                return (
                  <div className={`flex items-center gap-2 mb-2 px-3 py-2 rounded-lg border text-xs font-medium transition-all duration-300 overflow-hidden ${
                    flashAlert
                      ? "bg-dangerRed/10 border-dangerRed/30 text-dangerRed animate-pulse"
                      : "bg-slate-50 border-themeLight/40 text-themeDark/70"
                  }`}>
                    <div className="flex items-center gap-1.5 shrink-0">
                      <span className={`relative flex h-1.5 w-1.5 shrink-0`}>
                        <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${flashAlert ? "bg-dangerRed" : "bg-successGreen"}`}></span>
                        <span className={`relative inline-flex rounded-full h-1.5 w-1.5 ${flashAlert ? "bg-dangerRed" : "bg-successGreen"}`}></span>
                      </span>
                      <span className={`font-bold uppercase tracking-wider text-[9px] ${flashAlert ? "text-dangerRed" : "text-successGreen"}`}>
                        {flashAlert ? "LIVE INTERCEPT" : "STREAM"}
                      </span>
                    </div>
                    <span className="text-themeDark/40 shrink-0 hidden sm:inline">|</span>
                    <span className="font-bold shrink-0">{regionLabel}</span>
                    <span className="text-themeDark/40 shrink-0 hidden sm:inline">&mdash;</span>
                    <span className="font-mono bg-slate-100 text-themeDark/70 px-1.5 py-0.5 rounded text-[9px] shrink-0">{typeLabel}</span>
                    <span className="truncate text-themeDark/60 hidden sm:block">{contentSnippet}</span>
                  </div>
                );
              })()}

              <div className="flex-1 min-h-[260px] sm:min-h-[320px] relative border border-themeLight/30 rounded-xl bg-slate-50/30 p-2 flex items-center justify-center overflow-hidden">
                {renderIndiaNetworkMap()}
              </div>

              {/* Timeline Playback Controls */}
              <div className="mt-3 flex items-center gap-3">
                <button
                  onClick={() => {
                    if (isPlaying) {
                      setIsPlaying(false);
                    } else {
                      setPlaybackDay(0);
                      setIsPlaying(true);
                    }
                  }}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-themeLight text-xs font-semibold text-themeDark bg-white/60 hover:bg-white/90 transition-all shrink-0"
                >
                  {isPlaying ? <Pause className="w-3 h-3" /> : <Play className="w-3 h-3" />}
                  {isPlaying ? "Pause" : "Play Timeline"}
                </button>

                <div className="flex-1 flex flex-col gap-0.5">
                  <input
                    type="range"
                    min={0}
                    max={6}
                    value={playbackDay}
                    onChange={e => {
                      setIsPlaying(false);
                      setPlaybackDay(Number(e.target.value));
                    }}
                    className="w-full accent-themeMid h-1.5 cursor-pointer"
                  />
                  <div className="flex justify-between text-[9px] text-themeDark/40 font-medium px-0.5">
                    <span>Today</span>
                    {[1,2,3,4,5].map(d => <span key={d}>{d}d ago</span>)}
                    <span>6d ago</span>
                  </div>
                </div>

                <span className="text-[10px] font-bold text-themeDark/50 shrink-0 w-16 text-right">
                  {playbackDay === 0 ? "Today" : `${playbackDay}d ago`}
                  {(isPlaying || playbackDay > 0) && (
                    <span className="ml-1 text-themeMid">
                      ({filteredReports.length} events)
                    </span>
                  )}
                </span>

                {(isPlaying || playbackDay > 0) && (
                  <button
                    onClick={() => { setIsPlaying(false); setPlaybackDay(0); }}
                    className="text-[10px] text-themeDark/40 hover:text-dangerRed transition-colors shrink-0"
                  >
                    <X className="w-3 h-3" />
                  </button>
                )}
              </div>
            </div>

            {/* Top Threat States List */}
            <div className="w-full lg:w-72 flex flex-col">
              <h3 className="text-xs font-bold text-themeDark/60 uppercase tracking-wider mb-3">Risk Ratings By Region</h3>
              <div className="flex-1 overflow-y-auto space-y-2 max-h-[350px] pr-1 custom-scrollbar">
                {sortedStates.map(([state, count]: any) => {
                  const percent = totalRegionalCount > 0 ? Math.round((count / totalRegionalCount) * 100) : 0;
                  return (
                    <button 
                      key={state}
                      onClick={() => setSelectedState(selectedState === state ? null : state)}
                      className={`w-full text-left p-3 rounded-xl border transition-all flex justify-between items-center ${selectedState === state ? 'bg-themeMid/10 border-themeMid shadow-sm' : 'bg-white/40 border-themeLight hover:bg-white/70'}`}
                    >
                      <div className="flex-1 pr-4">
                        <div className="flex justify-between text-xs font-bold text-themeDark mb-1">
                          <span>{state}</span>
                          <span>{count} alerts</span>
                        </div>
                        <div className="w-full bg-slate-100 h-1.5 rounded-full overflow-hidden">
                          <div className={`h-full rounded-full ${count > 50 ? 'bg-dangerRed' : count > 20 ? 'bg-warningYellow' : 'bg-themeMid'}`} style={{ width: `${percent}%` }}></div>
                        </div>
                      </div>
                      <span className="text-[10px] font-bold text-themeDark/40 font-mono pl-2">{percent}%</span>
                    </button>
                  );
                })}
                {sortedStates.length === 0 && (
                  <p className="text-center text-xs text-themeDark/50 py-12">No regional data recorded.</p>
                )}
              </div>
            </div>
          </div>

          {/* Incident Log Tables */}
          <div className="flex-1 grid grid-cols-1 lg:grid-cols-2 gap-4 min-h-0">
            {/* Reports Table */}
            <div className="glass-card flex flex-col h-full overflow-hidden">
              <div className="bg-white/40 p-4 border-b border-themeLight/50 flex justify-between items-center">
                <div className="flex items-center gap-2">
                  <h2 className="text-sm font-bold text-themeDark tracking-wide">Incident Activity Log</h2>
                  {selectedState && (
                    <span className="text-xs bg-themeMid/10 text-themeMid border border-themeMid/20 px-2 py-0.5 rounded-full font-semibold">
                      Filtered: {selectedState}
                    </span>
                  )}
                </div>
              </div>
              <div className="overflow-y-auto flex-1 custom-scrollbar overflow-x-auto w-full">
                <table className="w-full text-left text-sm min-w-[550px]">
                  <thead className="sticky top-0 bg-white/95 backdrop-blur-sm z-10 border-b border-themeLight/50 shadow-sm">
                    <tr>
                      <th className="px-5 py-3 text-themeDark/60 font-medium text-xs uppercase tracking-wider">Vector</th>
                      <th className="px-5 py-3 text-themeDark/60 font-medium text-xs uppercase tracking-wider">Payload Data</th>
                      <th className="px-5 py-3 text-themeDark/60 font-medium text-xs uppercase tracking-wider">Severity</th>
                      <th className="px-5 py-3 text-themeDark/60 font-medium text-xs uppercase tracking-wider text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-themeLight/30">
                    {(selectedState ? reports.filter((r: any) => r.state_region === selectedState) : reports).slice(0, 15).map((report: any) => (
                      <tr 
                        key={report.id} 
                        onClick={(e) => {
                          if ((e.target as HTMLElement).closest('button')) return;
                          setInspectedReport(report);
                        }}
                        className="hover:bg-slate-50 cursor-pointer transition-colors"
                      >
                        <td className="px-5 py-3">
                           <span className="text-xs font-mono bg-themeLight/50 text-themeDark px-2 py-1 rounded">{report.report_type}</span>
                        </td>
                        <td className="px-5 py-3 text-themeDark/80 truncate max-w-[150px]" title={report.content}>
                          {report.content}
                        </td>
                        <td className="px-5 py-3">
                           <span className={`text-xs font-bold px-2 py-1 rounded inline-block min-w-[3rem] text-center ${report.risk_score > 0.8 ? 'bg-dangerRed/10 text-dangerRed' : 'bg-warningYellow/10 text-warningYellow'}`}>
                              {(report.risk_score * 100).toFixed(0)}%
                           </span>
                        </td>
                        <td className="px-5 py-3 text-right">
                          {report.status === "reported_to_chakshu" ? (
                            <span className="text-xs font-semibold text-successGreen bg-successGreen/10 px-2.5 py-1 rounded-full inline-flex items-center gap-1">
                              <CheckCircle2 className="w-3.5 h-3.5" />
                              Reported
                            </span>
                          ) : (
                            <button
                              onClick={() => openChakshuModal(report)}
                              className="text-xs font-semibold text-themeMid hover:text-white bg-themeMid/10 hover:bg-themeMid px-3 py-1.5 rounded-lg transition-all inline-flex items-center gap-1 border border-themeMid/20"
                            >
                              <Send className="w-3.5 h-3.5" />
                              Report
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                    {(selectedState ? reports.filter((r: any) => r.state_region === selectedState) : reports).length === 0 && !loading && (
                      <tr>
                        <td colSpan={4} className="p-8 text-center text-themeDark/50">Listening for telemetry securely...</td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Domains Table */}
            <div className="glass-card flex flex-col h-full overflow-hidden">
              <div className="bg-white/40 p-4 border-b border-themeLight/50 flex justify-between items-center">
                <h2 className="text-sm font-bold text-themeDark tracking-wide">Quarantined Signatures</h2>
              </div>
              <div className="overflow-y-auto flex-1 custom-scrollbar overflow-x-auto w-full">
                <table className="w-full text-left text-sm min-w-[400px]">
                  <thead className="sticky top-0 bg-white/95 backdrop-blur-sm z-10 border-b border-themeLight/50 shadow-sm">
                    <tr>
                      <th className="px-5 py-3 text-themeDark/60 font-medium text-xs uppercase tracking-wider">Identifier</th>
                      <th className="px-5 py-3 text-themeDark/60 font-medium text-xs uppercase tracking-wider text-right">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-themeLight/30">
                    {domains.slice(0, 15).map((domain: any) => (
                      <tr key={domain.id} className="hover:bg-white/50 transition-colors">
                        <td className="px-5 py-3 text-themeDark/80 font-mono text-xs">{domain.domain_name}</td>
                        <td className="px-5 py-3 text-right">
                           <span className={`text-xs font-bold tracking-widest ${domain.threat_level === 'HIGH' ? 'text-dangerRed' : 'text-warningYellow'}`}>
                              {domain.threat_level}
                           </span>
                        </td>
                      </tr>
                    ))}
                    {domains.length === 0 && !loading && (
                      <tr>
                        <td colSpan={2} className="p-8 text-center text-themeDark/50">No signatures detected.</td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: AI Triage Insights */}
      {activeTab === "triage" && (
        <div className="glass-card p-6 flex flex-col flex-1 shadow-sm relative">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 mb-6 border-b border-themeLight/30 pb-3">
            <div>
              <h2 className="text-xl font-bold text-themeDark flex items-center gap-2">
                <FileJson className="w-5 h-5 text-themeMid" />
                AI Threat Analysis
              </h2>
              <p className="text-xs text-themeDark/60 mt-0.5">Analyzing threat feeds and matching fraud campaigns automatically.</p>
            </div>
            <div className="flex items-center gap-3 self-start sm:self-auto">
              <div className="flex items-center gap-1.5 bg-white/40 border border-themeLight/60 px-2 py-1.5 rounded-lg">
                <span className="text-[10px] font-bold text-themeDark/60 uppercase">Scope:</span>
                <select
                  value={triageLimit}
                  onChange={e => setTriageLimit(Number(e.target.value))}
                  disabled={triageLoading}
                  className="bg-transparent text-xs font-semibold text-themeDark outline-none cursor-pointer"
                >
                  <option value={10}>Last 10 reports</option>
                  <option value={20}>Last 20 reports</option>
                  <option value={50}>Last 50 reports</option>
                  <option value={100}>Last 100 reports</option>
                  <option value={250}>Last 250 reports</option>
                </select>
              </div>
              <button 
                onClick={() => fetchTriage(triageLimit)}
                disabled={triageLoading}
                className="text-xs font-semibold text-themeDark hover:bg-white/60 bg-white/30 border border-themeLight/50 px-3 py-1.5 rounded-lg transition-all inline-flex items-center gap-1.5 disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${triageLoading ? 'animate-spin' : ''}`} />
                Refresh Insights
              </button>
            </div>
          </div>

          {triageLoading && (
            <div className="flex-1 flex flex-col items-center justify-center py-20 text-themeDark/50">
              <RefreshCw className="w-8 h-8 animate-spin text-themeMid mb-3" />
              <p className="text-sm font-medium">Processing reports with AI...</p>
            </div>
          )}

          {!triageLoading && triageData && (
            <div className="flex-1 flex flex-col min-h-0 animate-in fade-in duration-300">
              
              {/* Triage Summary Cards */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-6">
                <div className="bg-white/40 border border-themeLight/50 rounded-xl p-4 flex items-center gap-3">
                  <div className="p-2.5 bg-themeLight/50 rounded-lg text-themeMid">
                    <Activity className="w-5 h-5" />
                  </div>
                  <div>
                    <span className="text-[10px] uppercase font-semibold tracking-wider text-themeDark/50 block">Reports Evaluated</span>
                    <span className="text-xl font-bold text-themeDark">{triageData.summary?.total_analyzed}</span>
                  </div>
                </div>
                <div className="bg-white/40 border border-themeLight/50 rounded-xl p-4 flex items-center gap-3">
                  <div className="p-2.5 bg-dangerRed/10 rounded-lg text-dangerRed">
                    <AlertCircle className="w-5 h-5" />
                  </div>
                  <div>
                    <span className="text-[10px] uppercase font-semibold tracking-wider text-themeDark/50 block">High Risk Campaigns</span>
                    <span className="text-xl font-bold text-dangerRed">{triageData.summary?.high_risk_campaigns}</span>
                  </div>
                </div>

                {/* Severity Ratio Visuals */}
                {(() => {
                  const campaigns = triageData.campaigns || [];
                  const total = campaigns.length || 1;
                  const high = campaigns.filter((c: any) => c.severity === 'HIGH').length;
                  const med = campaigns.filter((c: any) => c.severity === 'MEDIUM').length;
                  const low = campaigns.filter((c: any) => c.severity === 'LOW').length;
                  
                  return (
                    <div className="bg-white/40 border border-themeLight/50 rounded-xl p-4 flex flex-col justify-center gap-1.5">
                      <span className="text-[10px] uppercase font-semibold tracking-wider text-themeDark/50 block">AI Severity Ratio</span>
                      <div className="w-full bg-slate-100 rounded-full h-2 overflow-hidden flex">
                        <div className="bg-dangerRed h-full transition-all" style={{ width: `${(high / total) * 100}%` }} title={`High Risk: ${high}`} />
                        <div className="bg-warningYellow h-full transition-all" style={{ width: `${(med / total) * 100}%` }} title={`Medium Risk: ${med}`} />
                        <div className="bg-successGreen h-full transition-all" style={{ width: `${(low / total) * 100}%` }} title={`Low Risk: ${low}`} />
                      </div>
                      <div className="flex justify-between text-[9px] font-bold text-themeDark/60 mt-0.5">
                        <span className="flex items-center gap-0.5"><span className="w-1.5 h-1.5 rounded-full bg-dangerRed inline-block" /> High ({high})</span>
                        <span className="flex items-center gap-0.5"><span className="w-1.5 h-1.5 rounded-full bg-warningYellow inline-block" /> Med ({med})</span>
                        <span className="flex items-center gap-0.5"><span className="w-1.5 h-1.5 rounded-full bg-successGreen inline-block" /> Low ({low})</span>
                      </div>
                    </div>
                  );
                })()}
              </div>

              {/* Campaigns List */}
              <div className="flex-1 overflow-y-auto custom-scrollbar pr-1 space-y-4">
                {triageData.campaigns?.map((c: any, index: number) => {
                  const analytics = getCampaignAnalytics(c.campaign_name, c.recommended_action);
                  const isDeployed = deployedDefenses.includes(c.campaign_name);
                  
                  return (
                    <div key={index} className="bg-white/50 border border-themeLight/40 rounded-xl p-4 hover:border-themeMid/30 transition-all">
                      <div className="flex items-start justify-between mb-2">
                        <div>
                          <h4 className="font-bold text-base text-themeDark leading-tight">{c.campaign_name}</h4>
                          <span className="text-xs text-themeDark/50 font-medium block mt-0.5">Category: {c.threat_category}</span>
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                          <span className="text-[10px] bg-themeLight/60 text-themeDark/80 px-2 py-0.5 rounded font-mono">
                            {analytics.matchCount} matched
                          </span>
                          <span className={`text-[10px] font-extrabold px-2 py-0.5 rounded tracking-wide ${c.severity === 'HIGH' ? 'bg-dangerRed/10 text-dangerRed' : c.severity === 'MEDIUM' ? 'bg-warningYellow/15 text-warningYellow' : 'bg-successGreen/10 text-successGreen'}`}>
                            {c.severity}
                          </span>
                        </div>
                      </div>

                      {/* State Exposure Checklist */}
                      <div className="mb-3 flex items-center flex-wrap gap-1.5">
                        <span className="text-[9px] font-bold text-themeDark/45 uppercase tracking-wider">Affected States:</span>
                        {analytics.states.map((s: string) => (
                          <span key={s} className="text-[9px] font-bold text-themeDark/75 bg-slate-100/80 border border-themeLight px-1.5 py-0.5 rounded-full">
                            {s}
                          </span>
                        ))}
                      </div>

                      <div className="bg-white/60 border border-themeLight/30 rounded-lg p-3 text-xs text-themeDark/80 flex flex-col gap-1">
                        <strong className="text-themeDark/60 font-semibold block uppercase text-[9px] tracking-wider">Recommended Defense</strong>
                        <p>{c.recommended_action}</p>
                        <div className="mt-1 flex items-center justify-between text-[10px] text-themeDark/50 bg-slate-50/50 p-1.5 rounded border border-themeLight/30 font-mono">
                          <span>Blacklist Target:</span>
                          <span className="font-bold text-themeDark">{analytics.identifier}</span>
                        </div>
                      </div>

                      {/* Interactive Defense Execution */}
                      <div className="flex gap-2.5 mt-3">
                        <button
                          onClick={() => handleExecuteDefense(c.campaign_name, analytics.identifier)}
                          disabled={isDeployed || deployingCampaign === c.campaign_name}
                          className={`flex-1 py-2 rounded-lg border text-xs font-bold transition-all flex items-center justify-center gap-1.5 ${
                            isDeployed
                              ? "bg-successGreen/15 border-successGreen/30 text-successGreen cursor-default"
                              : deployingCampaign === c.campaign_name
                                ? "bg-slate-100 border-themeLight text-themeDark/60 cursor-wait"
                                : "bg-themeMid text-white hover:bg-themeDark border-themeMid/20 hover:scale-[1.005] shadow-xs"
                          }`}
                        >
                          {isDeployed ? (
                            <>
                              <CheckCircle2 className="w-3.5 h-3.5 text-successGreen" />
                              Deployed
                            </>
                          ) : deployingCampaign === c.campaign_name ? (
                            <>
                              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                              Deploying...
                            </>
                          ) : (
                            <>
                              <ShieldAlert className="w-3.5 h-3.5" />
                              Deploy Defense
                            </>
                          )}
                        </button>

                        <button
                          onClick={() => fetchTriageDossier(c.campaign_name, c.threat_category, analytics.identifier, analytics.states)}
                          className="flex-1 py-2 rounded-lg border border-themeLight text-xs font-bold text-themeDark hover:bg-slate-50 transition-all flex items-center justify-center gap-1.5 bg-white shadow-xs"
                        >
                          <FileText className="w-3.5 h-3.5 text-themeMid" />
                          Response Kit
                        </button>
                      </div>
                    </div>
                  );
                })}
                {(!triageData.campaigns || triageData.campaigns.length === 0) && (
                  <p className="text-center text-sm text-themeDark/50 py-10">No threat insights available yet.</p>
                )}
              </div>
            </div>
          )}

          {!triageLoading && !triageData && (
            <div className="flex-1 flex flex-col items-center justify-center py-20 text-themeDark/50 border-2 border-dashed border-themeLight/50 rounded-xl bg-white/20">
              <FileJson className="w-10 h-10 text-themeMid/40 mb-3" />
              <p className="text-sm font-medium mb-1">Threat insights have not been compiled yet.</p>
              <button 
                onClick={() => fetchTriage(triageLimit)}
                className="text-xs font-semibold text-white bg-themeMid hover:bg-themeDark px-4 py-2 rounded-lg transition-all mt-2 shadow-sm"
              >
                Compile Now
              </button>
            </div>
          )}
        </div>
      )}

      {/* Tab 3: Device Bindings */}
      {activeTab === "devices" && (
        <div className="glass-card p-6 flex flex-col flex-1 shadow-sm relative min-h-[400px]">
          <div className="flex items-center justify-between mb-6 border-b border-themeLight/30 pb-3">
            <div>
              <h2 className="text-xl font-bold text-themeDark flex items-center gap-2">
                <Smartphone className="w-5 h-5 text-themeMid" />
                Registered Devices & SIM Baselines
              </h2>
              <p className="text-xs text-themeDark/60 mt-0.5">Secure hardware-backed device bindings to prevent session hijacking and SIM swapping.</p>
            </div>
            <button 
              onClick={fetchData}
              disabled={loading}
              className="text-xs font-semibold text-themeDark hover:bg-white/60 bg-white/30 border border-themeLight/50 px-3 py-1.5 rounded-lg transition-all inline-flex items-center gap-1.5 disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              Refresh Devices
            </button>
          </div>

          <div className="overflow-y-auto flex-1 custom-scrollbar overflow-x-auto w-full">
            <table className="w-full text-left text-sm min-w-[700px]">
              <thead className="sticky top-0 bg-white/95 backdrop-blur-sm z-10 border-b border-themeLight/50 shadow-sm">
                <tr>
                  <th className="px-5 py-3 text-themeDark/60 font-medium text-xs uppercase tracking-wider">Customer ID</th>
                  <th className="px-5 py-3 text-themeDark/60 font-medium text-xs uppercase tracking-wider">Public Key Baseline</th>
                  <th className="px-5 py-3 text-themeDark/60 font-medium text-xs uppercase tracking-wider">SIM Baseline Hash</th>
                  <th className="px-5 py-3 text-themeDark/60 font-medium text-xs uppercase tracking-wider">Last Seen IP</th>
                  <th className="px-5 py-3 text-themeDark/60 font-medium text-xs uppercase tracking-wider">Last Active</th>
                  <th className="px-5 py-3 text-themeDark/60 font-medium text-xs uppercase tracking-wider text-right">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-themeLight/30">
                {devices.map((dev: any) => (
                  <tr key={dev.id} className="hover:bg-white/50 transition-colors">
                    <td className="px-5 py-3 font-semibold text-themeDark">{dev.customer_id}</td>
                    <td className="px-5 py-3 text-themeDark/80 font-mono text-xs truncate max-w-[150px]" title={dev.device_key_pub}>
                      {dev.device_key_pub}
                    </td>
                    <td className="px-5 py-3 text-themeDark/80 font-mono text-xs truncate max-w-[150px]" title={dev.sim_hash_baseline}>
                      {dev.sim_hash_baseline}
                    </td>
                    <td className="px-5 py-3 text-themeDark/80 font-mono text-xs">{dev.last_seen_ip || 'unknown'}</td>
                    <td className="px-5 py-3 text-themeDark/80 text-xs">
                      {new Date(dev.last_active).toLocaleString()}
                    </td>
                    <td className="px-5 py-3 text-right">
                      <span className={`text-xs font-bold px-2.5 py-1 rounded-full ${dev.is_locked ? 'bg-dangerRed/10 text-dangerRed' : 'bg-successGreen/10 text-successGreen'}`}>
                        {dev.is_locked ? 'LOCKED' : 'VERIFIED ACTIVE'}
                      </span>
                    </td>
                  </tr>
                ))}
                {devices.length === 0 && !loading && (
                  <tr>
                    <td colSpan={6} className="p-8 text-center text-themeDark/50">No device profiles bound yet. Run the BankGuard mobile app to register device baseline.</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Chakshu Portal Report Modal */}
      {selectedReport && (
        <div className="fixed inset-0 bg-themeDark/45 backdrop-blur-sm flex items-center justify-center z-50 animate-in fade-in duration-200">
          <div className="glass-card w-full max-w-xl p-6 mx-4 shadow-2xl relative flex flex-col max-h-[85vh] animate-in zoom-in-95 duration-300 bg-white/95">
            
            {/* Modal Header */}
            <div className="flex items-center justify-between border-b border-themeLight/50 pb-3 mb-4">
              <div className="flex items-center gap-2">
                <FileJson className="w-5 h-5 text-themeMid" />
                <h3 className="text-lg font-bold text-themeDark">Government Portal Transmission Preview</h3>
              </div>
              <button 
                onClick={() => setSelectedReport(null)}
                className="text-themeDark/50 hover:text-themeDark p-1 hover:bg-themeLight rounded-lg transition-all"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="flex-1 overflow-y-auto pr-1 text-sm text-themeDark/80 custom-scrollbar mb-4">
              
              {!chakshuResult && (
                <>
                  <div className="bg-warningYellow/10 border border-warningYellow/20 rounded-xl p-3.5 text-xs text-themeDark flex items-start gap-2.5 mb-4">
                    <AlertCircle className="w-4 h-4 text-warningYellow shrink-0 mt-0.5" />
                    <div>
                      <strong className="font-semibold block mb-0.5">Verify Evidence Kit</strong>
                      Please inspect the raw payload metadata that will be compiled and uploaded to the Ministry of Communications Sanchar Saathi (Chakshu) portal database.
                    </div>
                  </div>

                  {dossierLoading ? (
                    <div className="py-12 flex flex-col items-center justify-center text-themeDark/50">
                      <RefreshCw className="w-7 h-7 animate-spin text-themeMid mb-3" />
                      <span className="text-xs">Compiling forensic evidence...</span>
                    </div>
                  ) : dossierData ? (
                    <div>
                      <span className="text-xs font-semibold text-themeDark/60 block mb-1.5 uppercase tracking-wide">Raw JSON Payload</span>
                      <pre className="bg-themeDark text-[#50fa7b] p-4 rounded-xl font-mono text-xs overflow-x-auto border border-themeDark/50 max-h-[300px] shadow-inner custom-scrollbar">
                        {JSON.stringify(dossierData, null, 2)}
                      </pre>
                    </div>
                  ) : (
                    <p className="text-center text-xs text-dangerRed py-6">Failed to compile threat evidence. Please try again.</p>
                  )}
                </>
              )}

              {chakshuResult && (
                <div className="py-6 flex flex-col items-center justify-center text-center animate-in zoom-in-95 duration-300">
                  <div className="p-4 bg-successGreen/15 rounded-full border border-successGreen/25 text-successGreen mb-4 shadow-sm">
                    <CheckCircle2 className="w-12 h-12" />
                  </div>
                  <h4 className="text-xl font-bold text-successGreen mb-2">TRANSMITTED SUCCESSFULLY</h4>
                  <p className="text-themeDark/80 text-sm max-w-sm mb-4">{chakshuResult.message}</p>
                  
                  <div className="bg-themeLight/50 border border-themeLight/80 rounded-xl p-4 w-full font-mono text-xs text-themeDark text-left max-w-md shadow-sm">
                    <div className="flex justify-between py-1 border-b border-themeLight/40">
                      <span className="text-themeDark/50 font-semibold">REFERENCE ID:</span>
                      <span className="font-bold text-themeMid">{chakshuResult.reference_id}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-themeLight/40">
                      <span className="text-themeDark/50 font-semibold">STATUS:</span>
                      <span className="font-bold text-successGreen uppercase">LOGGED & SYNCED</span>
                    </div>
                    <div className="flex justify-between py-1">
                      <span className="text-themeDark/50 font-semibold">TIMESTAMP:</span>
                      <span>{new Date(chakshuResult.timestamp).toLocaleString()}</span>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div className="border-t border-themeLight/50 pt-3 flex justify-end gap-2.5">
              {!chakshuResult ? (
                <>
                  <button 
                    onClick={() => setSelectedReport(null)}
                    className="px-4 py-2 text-xs font-semibold text-themeDark bg-themeLight/70 hover:bg-themeLight rounded-lg transition-all"
                  >
                    Cancel
                  </button>
                  <button 
                    onClick={submitToChakshu}
                    disabled={dossierLoading || submittingChakshu || !dossierData}
                    className="px-4 py-2 text-xs font-semibold text-white bg-themeMid hover:bg-themeDark rounded-lg transition-all flex items-center gap-1.5 shadow-sm disabled:opacity-50"
                  >
                    {submittingChakshu ? 'Transmitting...' : 'Confirm & Transmit'}
                  </button>
                </>
              ) : (
                <button 
                  onClick={() => setSelectedReport(null)}
                  className="px-5 py-2 text-xs font-semibold text-white bg-themeMid hover:bg-themeDark rounded-lg transition-all shadow-sm"
                >
                  Close
                </button>
              )}
            </div>

          </div>
        </div>
      )}
      {selectedDossierCampaign && (
        <div className="fixed inset-0 bg-themeDark/45 backdrop-blur-sm flex items-center justify-center z-50 animate-in fade-in duration-200">
          <div className="glass-card w-full max-w-2xl p-6 mx-4 shadow-2xl relative flex flex-col max-h-[85vh] animate-in zoom-in-95 duration-300 bg-white/95">
            
            {/* Modal Header */}
            <div className="flex items-center justify-between border-b border-themeLight/50 pb-3 mb-4">
              <div className="flex items-center gap-2">
                <FileText className="w-5 h-5 text-themeMid" />
                <h3 className="text-lg font-bold text-themeDark">AI Incident Response Kit</h3>
              </div>
              <button 
                onClick={() => setSelectedDossierCampaign(null)}
                className="text-themeDark/50 hover:text-themeDark p-1 hover:bg-themeLight rounded-lg transition-all"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="flex-1 overflow-y-auto pr-1 text-sm text-themeDark/80 custom-scrollbar mb-4 space-y-4">
              <div className="bg-slate-50 border border-themeLight/40 rounded-xl p-3 flex flex-col gap-1">
                <div className="flex justify-between text-xs">
                  <span className="font-bold text-themeDark">{selectedDossierCampaign.campaignName}</span>
                  <span className="text-[10px] bg-themeLight px-1.5 py-0.5 rounded font-mono text-themeDark/60">{selectedDossierCampaign.category}</span>
                </div>
                <span className="text-[10px] text-themeDark/50 font-mono mt-0.5">Target: {selectedDossierCampaign.identifier}</span>
              </div>

              {dossierLoadingResponse ? (
                <div className="py-16 flex flex-col items-center justify-center text-themeDark/50">
                  <RefreshCw className="w-8 h-8 animate-spin text-themeMid mb-3" />
                  <span className="text-xs font-semibold">Generating customized Response Kit...</span>
                </div>
              ) : dossierResult ? (
                <div className="space-y-4 animate-in fade-in duration-200">
                  
                  {/* Item 1: Registrar Abuse Notice */}
                  <div className="border border-themeLight/50 rounded-xl overflow-hidden bg-white/40">
                    <div className="bg-slate-100/70 px-4 py-2 border-b border-themeLight/50 flex justify-between items-center">
                      <span className="text-xs font-bold text-themeDark">1. Host Abuse Takedown Notice</span>
                      <button
                        onClick={() => handleCopyToClipboard(dossierResult.takedown_email, 'takedown')}
                        className="text-xs font-semibold text-themeMid hover:text-themeDark flex items-center gap-1 transition-all"
                      >
                        {copiedField === 'takedown' ? (
                          <span className="text-successGreen font-bold">Copied!</span>
                        ) : (
                          <>
                            <Copy className="w-3 h-3" />
                            Copy Notice
                          </>
                        )}
                      </button>
                    </div>
                    <div className="p-3">
                      <textarea
                        readOnly
                        value={dossierResult.takedown_email}
                        className="w-full h-32 bg-slate-50 border border-themeLight/30 p-2.5 rounded-lg font-mono text-xs text-themeDark outline-none resize-none"
                      />
                    </div>
                  </div>

                  {/* Item 2: Regex Signature Block */}
                  <div className="border border-themeLight/50 rounded-xl overflow-hidden bg-white/40">
                    <div className="bg-slate-100/70 px-4 py-2 border-b border-themeLight/50 flex justify-between items-center">
                      <span className="text-xs font-bold text-themeDark">2. Telco SMS Filter Signature (Regex)</span>
                      <button
                        onClick={() => handleCopyToClipboard(dossierResult.regex_rule, 'regex')}
                        className="text-xs font-semibold text-themeMid hover:text-themeDark flex items-center gap-1 transition-all"
                      >
                        {copiedField === 'regex' ? (
                          <span className="text-successGreen font-bold">Copied!</span>
                        ) : (
                          <>
                            <Copy className="w-3 h-3" />
                            Copy Regex
                          </>
                        )}
                      </button>
                    </div>
                    <div className="p-3 flex items-center gap-2">
                      <code className="flex-1 bg-slate-100 border border-themeLight/30 p-2 rounded text-xs font-mono text-[#e91e63] truncate">
                        {dossierResult.regex_rule}
                      </code>
                    </div>
                  </div>

                  {/* Item 3: Localized Push Warning */}
                  <div className="border border-themeLight/50 rounded-xl overflow-hidden bg-white/40">
                    <div className="bg-slate-100/70 px-4 py-2 border-b border-themeLight/50 flex justify-between items-center">
                      <span className="text-xs font-bold text-themeDark">3. Localized Push Notification Alert</span>
                      <button
                        onClick={() => handleCopyToClipboard(dossierResult.push_notification_draft, 'push')}
                        className="text-xs font-semibold text-themeMid hover:text-themeDark flex items-center gap-1 transition-all"
                      >
                        {copiedField === 'push' ? (
                          <span className="text-successGreen font-bold">Copied!</span>
                        ) : (
                          <>
                            <Copy className="w-3 h-3" />
                            Copy Warning
                          </>
                        )}
                      </button>
                    </div>
                    <div className="p-3">
                      <p className="bg-slate-50 border border-themeLight/30 p-3 rounded-lg text-xs italic text-themeDark">
                        "{dossierResult.push_notification_draft}"
                      </p>
                    </div>
                  </div>

                  {/* Item 4: DOT Chakshu Submission Payload */}
                  <div className="border border-themeLight/50 rounded-xl overflow-hidden bg-white/40">
                    <div className="bg-slate-100/70 px-4 py-2 border-b border-themeLight/50 flex justify-between items-center">
                      <span className="text-xs font-bold text-themeDark">4. Gov Sanchar Saathi (Chakshu) Dispatch</span>
                      <button
                        onClick={() => handleCopyToClipboard(dossierResult.chakshu_payload, 'chakshu')}
                        className="text-xs font-semibold text-themeMid hover:text-themeDark flex items-center gap-1 transition-all"
                      >
                        {copiedField === 'chakshu' ? (
                          <span className="text-successGreen font-bold">Copied!</span>
                        ) : (
                          <>
                            <Copy className="w-3 h-3" />
                            Copy Payload
                          </>
                        )}
                      </button>
                    </div>
                    <div className="p-3">
                      <pre className="bg-themeDark text-[#50fa7b] p-3 rounded-lg font-mono text-[10px] overflow-x-auto max-h-[160px] custom-scrollbar border border-themeDark/50">
                        {dossierResult.chakshu_payload}
                      </pre>
                    </div>
                  </div>

                </div>
              ) : (
                <p className="text-center text-xs text-dangerRed py-8">Failed to generate response kit. Please try again.</p>
              )}
            </div>

            {/* Modal Footer */}
            <div className="border-t border-themeLight/50 pt-3 flex justify-end gap-2.5">
              <button 
                onClick={() => setSelectedDossierCampaign(null)}
                className="px-5 py-2 text-xs font-semibold text-white bg-themeMid hover:bg-themeDark rounded-lg transition-all shadow-sm"
              >
                Close
              </button>
            </div>

          </div>
        </div>
      )}

      {/* Tab 4: SecOps AI Analyst Chat */}
      {activeTab === "analyst" && (() => {
        const reportsArr = Array.isArray(reports) ? reports : [];
        const totalCount = reportsArr.length;
        const stateCounts: { [k: string]: number } = {};
        reportsArr.forEach((r: any) => {
          if (r.state_region) stateCounts[r.state_region] = (stateCounts[r.state_region] || 0) + 1;
        });
        const sortedStateEntries = Object.entries(stateCounts).sort((a, b) => b[1] - a[1]);
        const topState = sortedStateEntries[0];
        const scamCount = reportsArr.filter((r: any) => r.report_type === "NOTIFICATION_SCAM" || r.report_type === "SMS/WhatsApp").length;
        const apkCount = reportsArr.filter((r: any) => r.report_type === "POLYGLOT_APK" || r.report_type === "APK").length;
        const urlCount = reportsArr.filter((r: any) => r.report_type === "NOTIFICATION_URL" || r.report_type === "URL").length;
        const vpnCount = reportsArr.filter((r: any) => r.report_type === "VPN_DNS_BLOCK").length;
        const topVector = [
          { label: "SMS/WA Scams", count: scamCount },
          { label: "Phishing URLs", count: urlCount },
          { label: "Sideloaded APKs", count: apkCount },
          { label: "DNS Sinkhole", count: vpnCount },
        ].sort((a, b) => b.count - a.count)[0];

        return (
          <div className="glass-card p-4 sm:p-6 flex flex-col flex-1 shadow-sm">
            <div className="flex items-center justify-between mb-5 border-b border-themeLight/30 pb-3">
              <div>
                <h2 className="text-xl font-bold text-themeDark flex items-center gap-2">
                  <Bot className="w-5 h-5 text-themeMid" />
                  SecOps Analyst
                </h2>
                <p className="text-xs text-themeDark/60 mt-0.5">AI analysis powered by live telemetry database. Ask about states, vectors, or request a summary.</p>
              </div>
            </div>

            <div className="flex flex-col lg:flex-row gap-6 flex-1 min-h-0">

              {/* Left: Auto-Summary Panel — horizontal scroll on mobile, sidebar on lg */}
              <div className="w-full lg:w-56 xl:w-64 shrink-0 space-y-3">
                <h3 className="text-[10px] font-bold text-themeDark/50 uppercase tracking-wider">Live Telemetry Summary</h3>

                <div className="bg-white/50 border border-themeLight/50 rounded-xl p-3 space-y-2.5">
                  <div className="flex justify-between items-center text-xs">
                    <span className="text-themeDark/60 font-medium">Total Intercepts</span>
                    <span className="font-bold text-themeDark">{totalCount}</span>
                  </div>
                  <div className="flex justify-between items-center text-xs">
                    <span className="text-themeDark/60 font-medium">Top Hotspot</span>
                    <span className="font-bold text-dangerRed truncate max-w-[100px] text-right">
                      {topState ? `${topState[0]} (${topState[1]})` : "None"}
                    </span>
                  </div>
                  <div className="flex justify-between items-center text-xs">
                    <span className="text-themeDark/60 font-medium">Primary Vector</span>
                    <span className="font-bold text-themeDark">{topVector?.label ?? "N/A"}</span>
                  </div>
                </div>

                <h3 className="text-[10px] font-bold text-themeDark/50 uppercase tracking-wider pt-1">Vector Breakdown</h3>
                <div className="bg-white/50 border border-themeLight/50 rounded-xl p-3 space-y-2">
                  {[
                    { label: "SMS/WA Scams", count: scamCount, color: "bg-rose-500" },
                    { label: "Phishing URLs", count: urlCount, color: "bg-amber-500" },
                    { label: "Sideloaded APKs", count: apkCount, color: "bg-indigo-500" },
                    { label: "DNS Sinkhole", count: vpnCount, color: "bg-teal-500" },
                  ].map(v => (
                    <div key={v.label}>
                      <div className="flex justify-between text-xs mb-1">
                        <span className="text-themeDark/70 font-medium">{v.label}</span>
                        <span className="font-bold text-themeDark">{v.count}</span>
                      </div>
                      <div className="w-full bg-slate-100 rounded-full h-1">
                        <div
                          className={`${v.color} h-1 rounded-full transition-all duration-700`}
                          style={{ width: totalCount > 0 ? `${Math.round((v.count / totalCount) * 100)}%` : "0%" }}
                        />
                      </div>
                    </div>
                  ))}
                </div>

                <h3 className="text-[10px] font-bold text-themeDark/50 uppercase tracking-wider pt-1">Top States</h3>
                <div className="bg-white/50 border border-themeLight/50 rounded-xl p-3 space-y-1.5">
                  {sortedStateEntries.slice(0, 5).map(([state, count]) => (
                    <div key={state} className="flex justify-between items-center text-xs">
                      <span className="text-themeDark/70 font-medium truncate">{state}</span>
                      <span className="font-bold text-themeDark ml-2 shrink-0">{count} alerts</span>
                    </div>
                  ))}
                  {sortedStateEntries.length === 0 && (
                    <p className="text-xs text-themeDark/40">No regional data yet.</p>
                  )}
                </div>
              </div>

              {/* Right: Chat Interface */}
              <div className="flex-1 flex flex-col min-h-[320px] sm:min-h-0 border border-themeLight/40 rounded-xl overflow-hidden bg-white/30">
                {/* Messages */}
                <div className="overflow-y-auto p-4 space-y-3 custom-scrollbar h-[350px] sm:h-[450px]">
                  {chatMessages.map((msg: any, i: number) => (
                    <div key={i} className={`flex gap-2.5 ${msg.role === "user" ? "justify-end" : "justify-start"}`}>
                      {msg.role === "assistant" && (
                        <div className="w-6 h-6 rounded-full bg-themeMid/10 flex items-center justify-center shrink-0 mt-0.5">
                          <Bot className="w-3.5 h-3.5 text-themeMid" />
                        </div>
                      )}
                      <div className={`max-w-[80%] px-3 py-2.5 rounded-xl leading-relaxed ${
                        msg.role === "user"
                          ? "bg-themeMid text-white rounded-br-none text-xs whitespace-pre-wrap"
                          : "bg-white border border-themeLight/50 text-themeDark/80 rounded-bl-none space-y-0.5"
                      }`}>
                        {msg.role === "user" ? msg.text : renderMarkdown(msg.text)}
                      </div>
                      {msg.role === "user" && (
                        <div className="w-6 h-6 rounded-full bg-slate-200 flex items-center justify-center shrink-0 mt-0.5">
                          <User className="w-3.5 h-3.5 text-themeDark/60" />
                        </div>
                      )}
                    </div>
                  ))}
                  {chatLoading && (
                    <div className="flex gap-2.5 justify-start">
                      <div className="w-6 h-6 rounded-full bg-themeMid/10 flex items-center justify-center shrink-0">
                        <Bot className="w-3.5 h-3.5 text-themeMid" />
                      </div>
                      <div className="bg-white border border-themeLight/50 rounded-xl rounded-bl-none px-3 py-2 text-xs text-themeDark/40 flex items-center gap-1">
                        <span className="animate-bounce inline-block w-1 h-1 bg-themeDark/30 rounded-full" style={{ animationDelay: "0ms" }} />
                        <span className="animate-bounce inline-block w-1 h-1 bg-themeDark/30 rounded-full" style={{ animationDelay: "150ms" }} />
                        <span className="animate-bounce inline-block w-1 h-1 bg-themeDark/30 rounded-full" style={{ animationDelay: "300ms" }} />
                      </div>
                    </div>
                  )}
                  <div ref={chatEndRef} />
                </div>

                {/* Suggested Queries */}
                <div className="px-3 pb-2 flex gap-2 flex-wrap border-t border-themeLight/30 pt-2 bg-slate-50/60">
                  {["Give me a summary", "Top attack tactics?", "Which state has most alerts?", "APK intercept breakdown?"].map(q => (
                    <button
                      key={q}
                      disabled={chatLoading}
                      onClick={e => handleChatSubmit(e as any, q)}
                      className="text-[10px] font-medium px-2 py-1 rounded-lg bg-white border border-themeLight/60 text-themeDark/60 hover:bg-themeLight/40 transition-all disabled:opacity-40"
                    >
                      {q}
                    </button>
                  ))}
                </div>

                {/* Input */}
                <form onSubmit={handleChatSubmit} className="flex items-center gap-2 p-3 border-t border-themeLight/40 bg-white/60">
                  <input
                    type="text"
                    value={chatInput}
                    onChange={e => setChatInput(e.target.value)}
                    placeholder="Ask about states, vectors, or threat tactics..."
                    className="flex-1 text-xs bg-white/80 border border-themeLight/50 rounded-lg px-3 py-2 outline-none focus:border-themeMid/50 text-themeDark placeholder:text-themeDark/30 transition-all"
                  />
                  <button
                    type="submit"
                    disabled={!chatInput.trim() || chatLoading}
                    className="p-2 bg-themeMid text-white rounded-lg hover:bg-themeDark transition-all disabled:opacity-40 shrink-0"
                  >
                    <Send className="w-3.5 h-3.5" />
                  </button>
                </form>
              </div>

            </div>
          </div>
        );
      })()}

      {/* Forensic Details Inspector Drawer */}
      {inspectedReport && (
        <div className="fixed inset-0 z-50 flex justify-end">
          {/* Overlay Backdrop */}
          <div 
            onClick={() => setInspectedReport(null)}
            className="absolute inset-0 bg-themeDark/30 backdrop-blur-xs transition-opacity animate-in fade-in duration-200"
          />
          
          {/* Drawer Body */}
          <div className="relative w-full max-w-full sm:max-w-lg bg-white h-full shadow-2xl flex flex-col z-10 animate-in slide-in-from-right duration-300 border-l border-themeLight bg-white/98 backdrop-blur-md">
            {/* Header */}
            <div className="p-6 border-b border-themeLight/80 flex justify-between items-center bg-slate-50">
              <div>
                <span className="text-[10px] font-bold text-themeMid bg-themeMid/10 px-2 py-0.5 rounded uppercase tracking-wider">
                  Threat Forensic Report
                </span>
                <h3 className="text-lg font-bold text-themeDark mt-1">Incident Details</h3>
              </div>
              <button 
                onClick={() => setInspectedReport(null)}
                className="text-themeDark/50 hover:text-themeDark p-1.5 hover:bg-themeLight rounded-lg transition-all"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
            
            {/* Content */}
            <div className="flex-1 overflow-y-auto p-6 space-y-6 custom-scrollbar text-sm">
              
              {/* Primary Stats Grid */}
              <div className="grid grid-cols-2 gap-4 bg-slate-50/50 p-4 rounded-xl border border-themeLight/50">
                <div>
                  <span className="text-[10px] font-bold text-themeDark/40 uppercase tracking-wider block">Threat Vector</span>
                  <span className="font-semibold text-themeDark text-xs font-mono">{inspectedReport.report_type}</span>
                </div>
                <div>
                  <span className="text-[10px] font-bold text-themeDark/40 uppercase tracking-wider block">Risk Severity</span>
                  <span className={`text-xs font-bold px-2 py-0.5 rounded inline-block ${inspectedReport.risk_score > 0.8 ? 'bg-dangerRed/10 text-dangerRed' : 'bg-warningYellow/10 text-warningYellow'}`}>
                    {(inspectedReport.risk_score * 100).toFixed(0)}% Risk
                  </span>
                </div>
                <div>
                  <span className="text-[10px] font-bold text-themeDark/40 uppercase tracking-wider block">Reported At</span>
                  <span className="text-themeDark/80 text-xs">{new Date(inspectedReport.reported_at).toLocaleString()}</span>
                </div>
                <div>
                  <span className="text-[10px] font-bold text-themeDark/40 uppercase tracking-wider block">Estimated State</span>
                  <span className="text-themeDark/80 font-bold text-xs">{inspectedReport.state_region || 'Unknown'}</span>
                </div>
              </div>

              {/* Source Details */}
              <div className="space-y-1">
                <h4 className="text-xs font-bold text-themeDark/60 uppercase tracking-wider">Source Package / Sender</h4>
                <div className="bg-slate-50 p-3 rounded-lg border border-themeLight/30 font-mono text-xs text-themeDark">
                  {inspectedReport.source || 'com.bankguard.app (SDK)'}
                </div>
              </div>

              {/* Intercepted Content */}
              <div className="space-y-1">
                <h4 className="text-xs font-bold text-themeDark/60 uppercase tracking-wider">Payload Data</h4>
                <div className="bg-slate-900 text-slate-100 p-4 rounded-xl font-mono text-xs break-all max-h-[150px] overflow-y-auto custom-scrollbar border border-slate-900 shadow-inner">
                  {inspectedReport.content}
                </div>
              </div>

              {/* Threat Classification & AI Insights */}
              {inspectedReport.scam_tactic && (
                <div className="space-y-2">
                  <h4 className="text-xs font-bold text-themeDark/60 uppercase tracking-wider">AI Classification</h4>
                  <div className="bg-[#fdf2f8] border border-pink-100 rounded-xl p-4">
                    <span className="text-xs font-bold text-pink-700 block mb-1">
                      Scam Tactic: {inspectedReport.scam_tactic}
                    </span>
                    <p className="text-xs text-themeDark/70 leading-relaxed">
                      This threat matches known behavior profiles for {inspectedReport.scam_tactic.replace(/_/g, ' ')}. SBI recommends immediate isolation and regulatory submission.
                    </p>
                  </div>
                </div>
              )}

              {/* Remediation & Mitigation Protocols */}
              <div className="space-y-2">
                <h4 className="text-xs font-bold text-themeDark/60 uppercase tracking-wider">Remediation Guidelines</h4>
                <div className="bg-slate-50 border border-themeLight/40 rounded-xl p-4 space-y-2.5">
                  <div className="flex gap-2">
                    <div className="w-1.5 h-1.5 rounded-full bg-themeMid mt-1.5 shrink-0"></div>
                    <p className="text-xs text-themeDark/80"><strong>Isolate Signature:</strong> Push signature payload hash to all bound client device VPN sinkholes.</p>
                  </div>
                  <div className="flex gap-2">
                    <div className="w-1.5 h-1.5 rounded-full bg-themeMid mt-1.5 shrink-0"></div>
                    <p className="text-xs text-themeDark/80"><strong>DOT Action:</strong> Compile dossier and transmit incident data to Chakshu Govt portal.</p>
                  </div>
                  <div className="flex gap-2">
                    <div className="w-1.5 h-1.5 rounded-full bg-themeMid mt-1.5 shrink-0"></div>
                    <p className="text-xs text-themeDark/80"><strong>Audit Status:</strong> Current incident is classified as <strong>{inspectedReport.status}</strong>.</p>
                  </div>
                </div>
              </div>

            </div>
            
            {/* Footer / Action Bar */}
            <div className="p-4 border-t border-themeLight bg-slate-50 flex gap-3">
              <button 
                onClick={() => {
                  setInspectedReport(null);
                  openChakshuModal(inspectedReport);
                }}
                className="flex-1 text-xs font-semibold bg-themeMid hover:bg-themeMid/90 text-white py-2.5 rounded-lg transition-all flex items-center justify-center gap-1.5 shadow-sm"
              >
                <Send className="w-3.5 h-3.5" />
                Report to Sanchar Saathi
              </button>
              <button 
                onClick={() => setInspectedReport(null)}
                className="px-4 text-xs font-semibold text-themeDark bg-white hover:bg-slate-100 py-2.5 rounded-lg transition-all border border-themeLight"
              >
                Dismiss
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}

// Inline icons since ShieldAlertIcon was misspelled in original
function ShieldAlertIcon(props: any) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      {...props}
    >
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10" />
      <path d="M12 8v4" />
      <path d="M12 16h.01" />
    </svg>
  );
}

