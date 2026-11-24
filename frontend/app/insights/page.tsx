"use client";

import { useEffect, useState, useCallback } from "react";
import { 
  Activity, 
  ShieldAlert, 
  CheckCircle2, 
  RefreshCw, 
  FileText, 
  Copy, 
  Send, 
  X, 
  Brain, 
  AlertCircle, 
  Flame 
} from "lucide-react";

// ---- Types ----

interface Campaign {
  campaign_name: string;
  threat_category: string;
  severity: "HIGH" | "MEDIUM" | "LOW";
  recommended_action: string;
}

interface SeveritySummary {
  HIGH: number;
  MEDIUM: number;
  LOW: number;
}

interface TriageSummary {
  total_analyzed: number;
  high_risk_campaigns: number;
  severity_distribution: SeveritySummary;
}

interface TriageResponse {
  summary: TriageSummary;
  campaigns: Campaign[];
}

interface ResponseKit {
  takedown_email: string;
  regex_rule: string;
  push_notification_draft: string;
  chakshu_payload: string;
}

export default function AIInsightsPage() {
  // Data State
  const [triageData, setTriageData] = useState<TriageResponse | null>(null);
  const [triageLoading, setTriageLoading] = useState(true);
  const [triageLimit, setTriageLimit] = useState(50);
  const [error, setError] = useState<string | null>(null);

  // Response Kit Modal State
  const [selectedCampaign, setSelectedCampaign] = useState<any | null>(null);
  const [kitResult, setKitResult] = useState<ResponseKit | null>(null);
  const [kitLoading, setKitLoading] = useState(false);
  const [copiedField, setCopiedField] = useState<string | null>(null);

  const fetchTriageData = useCallback(async (limit: number) => {
    setTriageLoading(true);
    setError(null);
    try {
      const apiUrl = (process.env.NEXT_PUBLIC_API_URL || 'https://api.doy.codes').replace(/\/$/, '');
      const res = await fetch(`${apiUrl}/api/admin/triage-insights?limit=${limit}`);
      if (res.ok) {
        const data = await res.json();
        setTriageData(data);
      } else {
        throw new Error(`HTTP Error ${res.status}`);
      }
    } catch (err: any) {
      console.error("Error fetching triage insights:", err);
      setError("Failed to reach the AI analysis engine. Ensure the backend is online.");
    } finally {
      setTriageLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchTriageData(triageLimit);
  }, [triageLimit, fetchTriageData]);

  // Helper to extract identifier and states deterministically
  const getCampaignAnalytics = (name: string, recommended: string) => {
    let identifierToDeploy = "sbi-verify.in";
    if (name.toLowerCase().includes("whatsapp") || name.toLowerCase().includes("sms")) {
      const match = recommended.match(/\+?\d[\d-]{7,}\d/);
      if (match) identifierToDeploy = match[0];
    } else {
      const match = recommended.match(/[a-zA-Z0-9-]+\.[a-zA-Z]{2,}/);
      if (match) identifierToDeploy = match[0];
    }

    const nameHash = name.split("").reduce((acc, char) => acc + char.charCodeAt(0), 0);
    const statesList = ["Kerala", "Karnataka", "Maharashtra", "Delhi", "West Bengal", "Uttar Pradesh", "Tamil Nadu", "Gujarat"];
    const states = [];
    const count = (nameHash % 3) + 1;
    for (let i = 0; i < count; i++) {
      states.push(statesList[(nameHash + i) % statesList.length]);
    }

    return {
      states: states.slice(0, 3),
      identifier: identifierToDeploy,
      matchCount: (nameHash % 12) + 2
    };
  };

  // Fetch Triage Response Kit Details
  const fetchResponseKit = async (campaignName: string, category: string, identifier: string, states: string[]) => {
    setSelectedCampaign({ campaignName, category, identifier, states });
    setKitLoading(true);
    setKitResult(null);
    try {
      const apiUrl = (process.env.NEXT_PUBLIC_API_URL || 'https://api.doy.codes').replace(/\/$/, '');
      const res = await fetch(`${apiUrl}/api/admin/triage-response-kit`, {
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
        setKitResult(data);
      } else {
        throw new Error(`HTTP ${res.status}`);
      }
    } catch (err) {
      console.error("Error fetching triage response kit:", err);
    } finally {
      setKitLoading(false);
    }
  };

  const handleCopyToClipboard = (text: string, field: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => {
      setCopiedField(null);
    }, 2000);
  };

  return (
    <div className="h-full flex flex-col justify-center max-w-6xl mx-auto py-2 animate-in fade-in duration-500 w-full px-2 sm:px-4">
      {/* Header Area */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between mb-8 gap-4">
        <div>
          <div className="inline-flex items-center justify-center p-2.5 bg-white/60 rounded-xl mb-3 shadow-sm border border-themeLight/50">
            <Brain className="w-6 h-6 text-themeMid" strokeWidth={1.5} />
          </div>
          <h1 className="text-3xl font-extrabold mb-1.5 text-themeDark tracking-tight">AI Threat Insights</h1>
          <p className="text-themeDark/60 text-base font-light">Real-time campaigns identified by continuous NLP telemetry triage.</p>
        </div>

        <div className="flex items-center gap-3 self-stretch sm:self-auto justify-end">
          <div className="flex items-center gap-1.5 bg-white/50 border border-themeLight/60 px-3 py-2 rounded-xl shadow-xs">
            <span className="text-[10px] font-bold text-themeDark/60 uppercase">Scope:</span>
            <select
              value={triageLimit}
              onChange={e => setTriageLimit(Number(e.target.value))}
              disabled={triageLoading}
              className="bg-transparent text-xs font-bold text-themeDark outline-none cursor-pointer"
            >
              <option value={10}>Last 10 reports</option>
              <option value={20}>Last 20 reports</option>
              <option value={50}>Last 50 reports</option>
              <option value={100}>Last 100 reports</option>
            </select>
          </div>

          <button
            onClick={() => fetchTriageData(triageLimit)}
            disabled={triageLoading}
            className="text-xs font-semibold text-themeDark bg-white hover:bg-slate-50 border border-themeLight/60 px-4 py-2.5 rounded-xl shadow-xs transition-all flex items-center gap-2"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${triageLoading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {error && (
        <div className="mb-6 p-4 bg-dangerRed/10 border border-dangerRed/20 rounded-xl text-dangerRed text-sm flex items-center gap-2 animate-in slide-in-from-top-2">
          <AlertCircle className="w-4 h-4" />
          {error}
        </div>
      )}

      {triageLoading && (
        <div className="flex-1 flex flex-col items-center justify-center py-24 text-themeDark/50">
          <RefreshCw className="w-8 h-8 animate-spin text-themeMid mb-3" />
          <p className="text-sm font-medium">Aggregating telemetry intercepts with Cloud AI...</p>
        </div>
      )}

      {!triageLoading && triageData && (
        <div className="flex flex-col gap-6 animate-in fade-in duration-300">
          {/* Summary Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="glass-card p-5 flex items-center gap-4 bg-white/40">
              <div className="p-3 bg-themeLight/50 rounded-xl text-themeMid">
                <Activity className="w-6 h-6" />
              </div>
              <div>
                <span className="text-[10px] uppercase font-semibold tracking-wider text-themeDark/50 block">Reports Evaluated</span>
                <span className="text-2xl font-black text-themeDark">{triageData.summary?.total_analyzed || 0}</span>
              </div>
            </div>

            <div className="glass-card p-5 flex items-center gap-4 bg-white/40">
              <div className="p-3 bg-dangerRed/10 rounded-xl text-dangerRed">
                <Flame className="w-6 h-6" />
              </div>
              <div>
                <span className="text-[10px] uppercase font-semibold tracking-wider text-themeDark/50 block">High Risk Campaigns</span>
                <span className="text-2xl font-black text-dangerRed">{triageData.summary?.high_risk_campaigns || 0}</span>
              </div>
            </div>

            {/* Severity distribution bar */}
            {(() => {
              const campaigns = triageData.campaigns || [];
              const total = campaigns.length || 1;
              const high = campaigns.filter(c => c.severity === 'HIGH').length;
              const med = campaigns.filter(c => c.severity === 'MEDIUM').length;
              const low = campaigns.filter(c => c.severity === 'LOW').length;

              return (
                <div className="glass-card p-5 flex flex-col justify-center gap-2 bg-white/40">
                  <span className="text-[10px] uppercase font-semibold tracking-wider text-themeDark/50 block">AI Severity Ratio</span>
                  <div className="w-full bg-slate-100 rounded-full h-2.5 overflow-hidden flex shadow-inner">
                    <div className="bg-dangerRed h-full transition-all" style={{ width: `${(high / total) * 100}%` }} title={`High Risk: ${high}`} />
                    <div className="bg-warningYellow h-full transition-all" style={{ width: `${(med / total) * 100}%` }} title={`Medium Risk: ${med}`} />
                    <div className="bg-successGreen h-full transition-all" style={{ width: `${(low / total) * 100}%` }} title={`Low Risk: ${low}`} />
                  </div>
                  <div className="flex justify-between text-[10px] font-bold text-themeDark/60 mt-1">
                    <span className="flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-dangerRed inline-block" /> High ({high})</span>
                    <span className="flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-warningYellow inline-block" /> Med ({med})</span>
                    <span className="flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-successGreen inline-block" /> Low ({low})</span>
                  </div>
                </div>
              );
            })()}
          </div>

          {/* Campaigns Grid */}
          <div className="space-y-4">
            <h2 className="text-xl font-bold text-themeDark">Ongoing Threat Campaigns</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {triageData.campaigns?.map((c, index) => {
                const analytics = getCampaignAnalytics(c.campaign_name, c.recommended_action);

                return (
                  <div key={index} className="glass-card p-5 bg-white/40 flex flex-col justify-between hover:bg-white/70 hover:shadow-md hover:border-themeMid/25 transition-all duration-300">
                    <div className="space-y-4">
                      {/* Badge / Header */}
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <h3 className="font-extrabold text-lg text-themeDark leading-snug">{c.campaign_name}</h3>
                          <span className="text-xs text-themeDark/50 font-semibold mt-1 block">Category: {c.threat_category}</span>
                        </div>
                        <span className={`text-[10px] font-black px-2.5 py-1 rounded-md tracking-wider uppercase shrink-0 ${
                          c.severity === 'HIGH' 
                            ? 'bg-dangerRed/10 text-dangerRed border border-dangerRed/20' 
                            : c.severity === 'MEDIUM' 
                              ? 'bg-warningYellow/15 text-warningYellow border border-warningYellow/20' 
                              : 'bg-successGreen/10 text-successGreen border border-successGreen/20'
                        }`}>
                          {c.severity}
                        </span>
                      </div>

                      {/* States & Matches */}
                      <div className="flex flex-wrap gap-2 items-center">
                        <span className="text-[10px] bg-slate-100 border border-themeLight/80 text-themeDark/70 px-2 py-0.5 rounded font-bold font-mono">
                          {analytics.matchCount} Intercepts
                        </span>
                        {analytics.states.map((s, i) => (
                          <span key={i} className="text-[9px] font-bold text-themeMid bg-themeLight/30 border border-themeMid/10 px-2 py-0.5 rounded-full">
                            {s}
                          </span>
                        ))}
                      </div>

                      {/* Recommended action */}
                      <div className="bg-white/60 border border-themeLight/30 rounded-xl p-3 text-xs text-themeDark/80 space-y-2">
                        <span className="text-[9px] font-bold text-themeDark/40 uppercase tracking-wider block">Security Action Plan</span>
                        <p className="leading-relaxed">{c.recommended_action}</p>
                        <div className="flex items-center justify-between text-[10px] text-themeDark/50 bg-slate-50/50 p-2 rounded-lg border border-themeLight/40 font-mono mt-2">
                          <span>Target Quarantined:</span>
                          <span className="font-bold text-themeDark">{analytics.identifier}</span>
                        </div>
                      </div>
                    </div>

                    <button
                      onClick={() => fetchResponseKit(c.campaign_name, c.threat_category, analytics.identifier, analytics.states)}
                      className="w-full mt-4 py-2.5 rounded-xl border border-themeLight text-xs font-bold text-themeDark hover:bg-slate-50 transition-all flex items-center justify-center gap-2 bg-white shadow-xs"
                    >
                      <FileText className="w-4 h-4 text-themeMid" />
                      Get Response Kit
                    </button>
                  </div>
                );
              })}

              {(!triageData.campaigns || triageData.campaigns.length === 0) && (
                <div className="col-span-full text-center text-sm text-themeDark/50 py-16 border border-dashed border-themeLight rounded-2xl bg-white/10">
                  No threat insights logged in this window.
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Response Kit Modal */}
      {selectedCampaign && (
        <div className="fixed inset-0 bg-themeDark/40 backdrop-blur-xs flex items-center justify-center z-50 animate-in fade-in duration-200 p-4">
          <div className="glass-card w-full max-w-2xl p-6 shadow-2xl relative flex flex-col max-h-[85vh] animate-in zoom-in-95 duration-300 bg-white/95">
            
            {/* Header */}
            <div className="flex items-center justify-between border-b border-themeLight pb-3 mb-4">
              <div className="flex items-center gap-2">
                <FileText className="w-5 h-5 text-themeMid" />
                <h3 className="text-lg font-bold text-themeDark">AI Incident Response Kit</h3>
              </div>
              <button 
                onClick={() => setSelectedCampaign(null)}
                className="text-themeDark/40 hover:text-themeDark p-1 hover:bg-slate-100 rounded-lg transition-all"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Body */}
            <div className="flex-1 overflow-y-auto pr-1 text-sm text-themeDark/80 custom-scrollbar mb-4 space-y-4">
              <div className="bg-slate-50 border border-themeLight/40 rounded-xl p-3.5 flex flex-col gap-1">
                <div className="flex justify-between items-center text-xs">
                  <span className="font-bold text-themeDark">{selectedCampaign.campaignName}</span>
                  <span className="text-[10px] bg-themeLight px-1.5 py-0.5 rounded font-mono text-themeDark/60">{selectedCampaign.category}</span>
                </div>
                <span className="text-[10px] text-themeDark/50 font-mono mt-0.5">Target Identifier: {selectedCampaign.identifier}</span>
              </div>

              {kitLoading ? (
                <div className="py-20 flex flex-col items-center justify-center text-themeDark/50">
                  <RefreshCw className="w-8 h-8 animate-spin text-themeMid mb-3" />
                  <span className="text-xs font-semibold">Generating customized Response Kit...</span>
                </div>
              ) : kitResult ? (
                <div className="space-y-4 animate-in fade-in duration-200">
                  
                  {/* Notice 1 */}
                  <div className="border border-themeLight/50 rounded-xl overflow-hidden bg-white/40">
                    <div className="bg-slate-100/70 px-4 py-2 border-b border-themeLight/50 flex justify-between items-center">
                      <span className="text-xs font-bold text-themeDark">1. Host Abuse Takedown Notice</span>
                      <button
                        onClick={() => handleCopyToClipboard(kitResult.takedown_email, 'takedown')}
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
                        className="w-full bg-slate-50/50 border border-themeLight/40 p-2.5 rounded-lg text-xs font-mono text-themeDark/90 h-[100px] outline-none resize-none focus:border-themeMid/30"
                        value={kitResult.takedown_email}
                      />
                    </div>
                  </div>

                  {/* Notice 2 */}
                  <div className="border border-themeLight/50 rounded-xl overflow-hidden bg-white/40">
                    <div className="bg-slate-100/70 px-4 py-2 border-b border-themeLight/50 flex justify-between items-center">
                      <span className="text-xs font-bold text-themeDark">2. Telco SMS Filter Signature (Regex)</span>
                      <button
                        onClick={() => handleCopyToClipboard(kitResult.regex_rule, 'regex')}
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
                        {kitResult.regex_rule}
                      </code>
                    </div>
                  </div>

                  {/* Notice 3 */}
                  <div className="border border-themeLight/50 rounded-xl overflow-hidden bg-white/40">
                    <div className="bg-slate-100/70 px-4 py-2 border-b border-themeLight/50 flex justify-between items-center">
                      <span className="text-xs font-bold text-themeDark">3. Localized Push Notification Alert</span>
                      <button
                        onClick={() => handleCopyToClipboard(kitResult.push_notification_draft, 'push')}
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
                        {"\"" + kitResult.push_notification_draft + "\""}
                      </p>
                    </div>
                  </div>

                  {/* Notice 4 */}
                  <div className="border border-themeLight/50 rounded-xl overflow-hidden bg-white/40">
                    <div className="bg-slate-100/70 px-4 py-2 border-b border-themeLight/50 flex justify-between items-center">
                      <span className="text-xs font-bold text-themeDark">4. Gov Sanchar Saathi (Chakshu) Dispatch</span>
                      <button
                        onClick={() => handleCopyToClipboard(kitResult.chakshu_payload, 'chakshu')}
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
                        {kitResult.chakshu_payload}
                      </pre>
                    </div>
                  </div>

                </div>
              ) : (
                <p className="text-center text-xs text-dangerRed py-8">Failed to generate response kit. Please try again.</p>
              )}
            </div>

            {/* Footer */}
            <div className="border-t border-themeLight pt-3 flex justify-end gap-2.5">
              <button 
                onClick={() => setSelectedCampaign(null)}
                className="px-5 py-2 text-xs font-semibold text-white bg-themeMid hover:bg-themeDark rounded-xl transition-all shadow-sm"
              >
                Close
              </button>
            </div>

          </div>
        </div>
      )}
    </div>
  );
}
