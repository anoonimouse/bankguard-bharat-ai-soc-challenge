"use client";

import { useEffect, useState, useCallback } from "react";
import {
  Activity,
  Database,
  Brain,
  Globe,
  Radio,
  ScanLine,
  Shield,
  FileText,
  Server,
  RefreshCw,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  Search,
  Zap,
  ShieldCheck,
} from "lucide-react";

// ---- Types ----

interface HealthPing {
  status: string;
  version: string;
  uptime_seconds: number;
  uptime_formatted: string;
  python_version: string;
  timestamp: string;
}

interface FriEntryRow {
  id: number;
  risk_level: string;
  fraud_category: string;
  reason: string;
  created_at: string | null;
  identifiers: { type: string; value: string }[];
}

interface DatabaseHealth {
  connected: boolean;
  engine: string;
  database_name: string;
  tables: Record<string, number>;
  total_records: number;
  last_insert_timestamp: string | null;
  fri_entries: FriEntryRow[];
}

interface ModelHealth {
  model_loaded: boolean;
  text_model_loaded: boolean;
  model_version: string | null;
  training_date: string | null;
  feature_count: number;
  optimal_threshold: number | null;
  performance: Record<string, number | boolean>;
  artifacts_present: Record<string, boolean>;
  model_file_size_mb: number;
}

interface URLIntelligence {
  layers: Record<string, Record<string, unknown>>;
  whitelist_entries: Record<string, number>;
}

interface TelemetryHealth {
  endpoint_active: boolean;
  total_events_received: number;
  events_last_24h: number;
  last_event_timestamp: string | null;
  recent_events: {
    id: number;
    event_type: string;
    source: string;
    content: string;
    risk_score: number;
    timestamp: string | null;
  }[];
}

interface APKScannerHealth {
  androguard_available: boolean;
  androguard_version: string | null;
  endpoint_active: boolean;
  total_apks_scanned: number;
  recent_scans: {
    package_name: string;
    verdict: string;
    risk_score: number;
    timestamp: string | null;
  }[];
}

interface FRISummary {
  total_entries: number;
  by_risk_level: Record<string, number>;
  by_fraud_category: Record<string, number>;
  by_identifier_type: Record<string, number>;
}

interface FraudReportsHealth {
  total_reports: number;
  reports_last_24h: number;
  recent_reports: {
    id: number;
    report_type: string;
    url_or_identifier: string;
    source: string;
    timestamp: string | null;
  }[];
}

interface EnvironmentHealth {
  python_version: string;
  os: string;
  ml_artifacts_directory: string;
  ml_artifacts: Record<
    string,
    { present: boolean; size: string | null; modified: string | null }
  >;
  xgboost_version: string | null;
  androguard_version: string | null;
}

// ---- Helpers ----

const API = process.env.NEXT_PUBLIC_API_URL as string;
const REFRESH_INTERVAL = 90;

function StatusDot({ status }: { status: "green" | "yellow" | "red" }) {
  const colors = {
    green: "bg-successGreen",
    yellow: "bg-warningYellow",
    red: "bg-dangerRed",
  };
  return (
    <span className="relative flex h-2.5 w-2.5">
      <span
        className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-60 ${colors[status]}`}
      />
      <span
        className={`relative inline-flex rounded-full h-2.5 w-2.5 ${colors[status]}`}
      />
    </span>
  );
}

function SectionCard({
  title,
  icon: Icon,
  status,
  lastChecked,
  error,
  children,
}: {
  title: string;
  icon: React.ElementType;
  status: "green" | "yellow" | "red";
  lastChecked: string | null;
  error?: string | null;
  children: React.ReactNode;
}) {
  return (
    <div className="glass-card flex flex-col overflow-hidden">
      <div className="bg-white/40 p-4 border-b border-themeLight/50 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Icon className="w-4 h-4 text-themeMid" />
          <h2 className="text-sm font-bold text-themeDark tracking-wide">
            {title}
          </h2>
        </div>
        <div className="flex items-center gap-2">
          <StatusDot status={status} />
          {lastChecked && (
            <span className="text-[10px] text-themeDark/40 font-mono">
              {new Date(lastChecked).toLocaleTimeString()}
            </span>
          )}
        </div>
      </div>
      <div className="p-4 flex-1">
        {error && (
          <div className="text-xs text-dangerRed bg-dangerRed/10 rounded-lg p-2 mb-3 font-mono">
            {error}
          </div>
        )}
        {children}
      </div>
    </div>
  );
}

function MetricBox({
  label,
  value,
  sub,
}: {
  label: string;
  value: string | number;
  sub?: string;
}) {
  return (
    <div className="bg-themeLight/20 rounded-lg p-3 text-center">
      <span className="block text-[10px] text-themeDark/50 font-semibold uppercase tracking-wider mb-1">
        {label}
      </span>
      <span className="text-xl font-bold text-themeDark">{value}</span>
      {sub && (
        <span className="block text-[10px] text-themeDark/40 mt-0.5">
          {sub}
        </span>
      )}
    </div>
  );
}

function riskColor(level: string) {
  const l = level.toLowerCase();
  if (l.includes("very high") || l.includes("very_high")) return "text-dangerRed bg-dangerRed/10";
  if (l.includes("high")) return "text-warningYellow bg-warningYellow/10";
  if (l.includes("medium")) return "text-yellow-500 bg-yellow-500/10";
  return "text-themeDark/60 bg-themeLight/30";
}

function verdictColor(v: string) {
  const lower = v.toLowerCase();
  if (lower === "malicious") return "text-dangerRed bg-dangerRed/10";
  if (lower === "suspicious") return "text-warningYellow bg-warningYellow/10";
  return "text-successGreen bg-successGreen/10";
}

// ---- Main Page ----

export default function SystemHealthPage() {
  // Data states
  const [ping, setPing] = useState<HealthPing | null>(null);
  const [pingMs, setPingMs] = useState<number | null>(null);
  const [dbHealth, setDbHealth] = useState<DatabaseHealth | null>(null);
  const [model, setModel] = useState<ModelHealth | null>(null);
  const [urlIntel, setUrlIntel] = useState<URLIntelligence | null>(null);
  const [telemetry, setTelemetry] = useState<TelemetryHealth | null>(null);
  const [apk, setApk] = useState<APKScannerHealth | null>(null);
  const [friSummary, setFriSummary] = useState<FRISummary | null>(null);
  const [fraudReports, setFraudReports] = useState<FraudReportsHealth | null>(null);
  const [env, setEnv] = useState<EnvironmentHealth | null>(null);

  // UI states
  const [countdown, setCountdown] = useState(REFRESH_INTERVAL);
  const [loading, setLoading] = useState(true);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [lastRefresh, setLastRefresh] = useState<string | null>(null);

  // FRI table pagination
  const [friPage, setFriPage] = useState(0);
  const [friSearch, setFriSearch] = useState("");
  const FRI_PAGE_SIZE = 10;

  // Live model test
  const [liveTestRunning, setLiveTestRunning] = useState(false);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [liveTestResults, setLiveTestResults] = useState<any[]>([]);

  // ---- Data fetching ----
  const fetchAll = useCallback(async () => {
    setLoading(true);
    const newErrors: Record<string, string> = {};
    const timestamp = new Date().toISOString();

    // helper to fetch a single endpoint with error capture
    const grab = async <T,>(path: string, key: string): Promise<T | null> => {
      try {
        const start = performance.now();
        const res = await fetch(`${API}${path}`, { cache: "no-store" });
        const elapsed = performance.now() - start;
        if (key === "ping") setPingMs(Math.round(elapsed));
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return (await res.json()) as T;
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : "Unknown error";
        newErrors[key] = msg;
        return null;
      }
    };

    const [p, d, m, u, t, a, f, fr, e] = await Promise.all([
      grab<HealthPing>("/health", "ping"),
      grab<DatabaseHealth>("/health/database", "database"),
      grab<ModelHealth>("/health/model", "model"),
      grab<URLIntelligence>("/health/url-intelligence", "urlIntel"),
      grab<TelemetryHealth>("/health/telemetry", "telemetry"),
      grab<APKScannerHealth>("/health/apk-scanner", "apk"),
      grab<FRISummary>("/health/fri-summary", "friSummary"),
      grab<FraudReportsHealth>("/health/fraud-reports", "fraudReports"),
      grab<EnvironmentHealth>("/health/environment", "env"),
    ]);

    if (p) setPing(p);
    if (d) setDbHealth(d);
    if (m) setModel(m);
    if (u) setUrlIntel(u);
    if (t) setTelemetry(t);
    if (a) setApk(a);
    if (f) setFriSummary(f);
    if (fr) setFraudReports(fr);
    if (e) setEnv(e);

    setErrors(newErrors);
    setLastRefresh(timestamp);
    setLoading(false);
    setCountdown(REFRESH_INTERVAL);
  }, []);

  // initial fetch + auto-refresh
  useEffect(() => {
    fetchAll();
    const interval = setInterval(fetchAll, REFRESH_INTERVAL * 1000);
    return () => clearInterval(interval);
  }, [fetchAll]);

  // countdown timer
  useEffect(() => {
    const tick = setInterval(() => {
      setCountdown((c) => (c <= 1 ? REFRESH_INTERVAL : c - 1));
    }, 1000);
    return () => clearInterval(tick);
  }, []);

  // ---- Health score calc ----
  const healthScore = (() => {
    let score = 0;
    const total = 11;
    if (ping) score++; // backend up
    if (dbHealth?.connected) score++; // db connected
    if (dbHealth && dbHealth.tables?.fri_entries > 0) score++; // fri seeded
    if (model?.model_loaded) score++; // url xgboost model loaded
    if (model?.text_model_loaded) score++; // hf nlp model loaded
    if (model && Object.values(model.artifacts_present || {}).every(Boolean)) score++; // all artifacts
    if (urlIntel?.layers?.phishdestroy && (urlIntel.layers.phishdestroy as Record<string, unknown>).reachable) score++; // phishdestroy
    if (urlIntel?.layers?.google_safe_browsing && (urlIntel.layers.google_safe_browsing as Record<string, unknown>).reachable) score++; // gsb
    if (telemetry?.endpoint_active) score++; // telemetry
    if (apk?.androguard_available) score++; // apk scanner
    if (fraudReports !== null && !errors.fraudReports) score++; // fraud reporting
    return { score, total };
  })();

  const overallStatus =
    healthScore.score >= 10
      ? "HEALTHY"
      : healthScore.score >= 7
      ? "DEGRADED"
      : "CRITICAL";
  const overallColor =
    overallStatus === "HEALTHY"
      ? "bg-successGreen text-white"
      : overallStatus === "DEGRADED"
      ? "bg-warningYellow text-white"
      : "bg-dangerRed text-white";

  // ---- Live model test ----
  const runLiveTest = async () => {
    setLiveTestRunning(true);
    setLiveTestResults([]);
    const testUrls = [
      "http://yonosbi-update.xyz/login",
      "https://sbi.bank.in/",
    ];
    const results = [];
    for (const testUrl of testUrls) {
      try {
        const res = await fetch(`${API}/api/check-url`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: testUrl }),
        });
        const data = await res.json();
        results.push({ url: testUrl, ...data });
      } catch {
        results.push({ url: testUrl, error: "Failed to reach backend" });
      }
    }
    setLiveTestResults(results);
    setLiveTestRunning(false);
  };

  // ---- FRI table filtering + pagination ----
  const filteredFri = (dbHealth?.fri_entries || []).filter((e) => {
    if (!friSearch) return true;
    const q = friSearch.toLowerCase();
    return (
      e.risk_level.toLowerCase().includes(q) ||
      e.fraud_category.toLowerCase().includes(q) ||
      e.reason.toLowerCase().includes(q) ||
      e.identifiers.some(
        (i) =>
          i.type.toLowerCase().includes(q) ||
          i.value.toLowerCase().includes(q)
      )
    );
  });
  // sort by risk level: Very High > High > Medium
  const riskOrder: Record<string, number> = { "Very High": 0, High: 1, Medium: 2 };
  const sortedFri = [...filteredFri].sort(
    (a, b) => (riskOrder[a.risk_level] ?? 3) - (riskOrder[b.risk_level] ?? 3)
  );
  const friTotalPages = Math.max(1, Math.ceil(sortedFri.length / FRI_PAGE_SIZE));
  const friBatch = sortedFri.slice(
    friPage * FRI_PAGE_SIZE,
    (friPage + 1) * FRI_PAGE_SIZE
  );

  // ---- Render ----
  return (
    <div className="h-full flex flex-col py-4 animate-in fade-in duration-500 max-w-7xl mx-auto w-full">
      {/* ========== HEADER ========== */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between mb-6 gap-4">
        <div>
          <h1 className="text-3xl font-bold text-themeDark flex items-center gap-2 mb-1">
            <Activity className="w-6 h-6 text-themeMid" />
            BankGuard System Health
          </h1>
          <p className="text-themeDark/60 text-sm">
            Real-time birds-eye view of every system component.
          </p>
        </div>
        <div className="flex items-center gap-3">
          {/* Overall badge */}
          <div
            className={`px-4 py-2 rounded-full font-bold text-sm tracking-wide shadow-sm ${overallColor}`}
          >
            {overallStatus} -- {healthScore.score} / {healthScore.total}
          </div>

          {/* Countdown */}
          <div className="glass-card px-3 py-2 flex items-center gap-2 text-xs font-mono text-themeDark/60">
            <RefreshCw
              className={`w-3 h-3 ${loading ? "animate-spin text-themeMid" : ""}`}
            />
            {countdown}s
          </div>

          {/* Refresh button */}
          <button
            onClick={fetchAll}
            disabled={loading}
            className="bg-themeMid hover:bg-themeDark text-white px-4 py-2 rounded-lg text-sm font-medium transition-all disabled:opacity-50 flex items-center gap-1.5 shadow-sm"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
        </div>
      </div>

      {/* Last checked */}
      {lastRefresh && (
        <p className="text-[10px] text-themeDark/40 font-mono mb-4 -mt-4">
          Last checked: {new Date(lastRefresh).toLocaleString()}
        </p>
      )}

      {/* ========== GRID ========== */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4 mb-6">
        {/* ---- 1. Backend API Health ---- */}
        <SectionCard
          title="Backend API"
          icon={Server}
          status={ping ? "green" : "red"}
          lastChecked={ping?.timestamp || null}
          error={errors.ping}
        >
          {ping ? (
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold text-successGreen bg-successGreen/10 px-2 py-1 rounded">
                  UP
                </span>
                {pingMs !== null && (
                  <span className="text-xs text-themeDark/50 font-mono">
                    {pingMs}ms latency
                  </span>
                )}
              </div>
              <div className="grid grid-cols-2 gap-2">
                <MetricBox label="Version" value={ping.version} />
                <MetricBox label="Uptime" value={ping.uptime_formatted} />
                <MetricBox label="Python" value={ping.python_version} />
                <MetricBox
                  label="Status"
                  value={ping.status.toUpperCase()}
                />
              </div>
            </div>
          ) : (
            <div className="text-center py-4">
              <span className="text-xs font-bold text-dangerRed bg-dangerRed/10 px-3 py-1 rounded">
                DOWN
              </span>
              <p className="text-xs text-themeDark/50 mt-2">
                Unable to reach backend
              </p>
            </div>
          )}
        </SectionCard>

        {/* ---- 2. Database Health ---- */}
        <SectionCard
          title="Database"
          icon={Database}
          status={dbHealth?.connected ? "green" : "red"}
          lastChecked={lastRefresh}
          error={errors.database}
        >
          {dbHealth ? (
            <div className="space-y-3">
              <div className="flex items-center gap-2 mb-2">
                <span
                  className={`text-xs font-bold px-2 py-1 rounded ${
                    dbHealth.connected
                      ? "text-successGreen bg-successGreen/10"
                      : "text-dangerRed bg-dangerRed/10"
                  }`}
                >
                  {dbHealth.connected ? "CONNECTED" : "DISCONNECTED"}
                </span>
                <span className="text-xs text-themeDark/50 font-mono">
                  {dbHealth.engine}
                </span>
              </div>
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-themeLight/50">
                    <th className="text-left py-1 text-themeDark/50 font-medium uppercase tracking-wider">
                      Table
                    </th>
                    <th className="text-right py-1 text-themeDark/50 font-medium uppercase tracking-wider">
                      Records
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(dbHealth.tables).map(([name, count]) => (
                    <tr
                      key={name}
                      className="border-b border-themeLight/30"
                    >
                      <td className="py-1.5 font-mono text-themeDark/80">
                        {name}
                      </td>
                      <td className="py-1.5 text-right font-bold text-themeDark">
                        {count}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <div className="flex justify-between text-xs pt-1">
                <span className="text-themeDark/50">Total</span>
                <span className="font-bold text-themeDark">
                  {dbHealth.total_records}
                </span>
              </div>
            </div>
          ) : (
            <p className="text-xs text-themeDark/50">No data available</p>
          )}
        </SectionCard>

        {/* ---- 4. URL Intelligence ---- */}
        <SectionCard
          title="URL Intelligence Layers"
          icon={Globe}
          status={
            urlIntel
              ? Object.values(urlIntel.layers).every(
                  (l) => (l as Record<string, unknown>).reachable || (l as Record<string, unknown>).loaded
                )
                ? "green"
                : Object.values(urlIntel.layers).some(
                    (l) => (l as Record<string, unknown>).reachable || (l as Record<string, unknown>).loaded
                  )
                ? "yellow"
                : "red"
              : "red"
          }
          lastChecked={lastRefresh}
          error={errors.urlIntel}
        >
          {urlIntel ? (
            <div className="space-y-3">
              {/* Layer rows */}
              {Object.entries(urlIntel.layers).map(([name, info]) => {
                const data = info as Record<string, unknown>;
                const isUp = !!(data.reachable || data.loaded);
                return (
                  <div
                    key={name}
                    className="flex items-center justify-between text-xs"
                  >
                    <div className="flex items-center gap-2">
                      <StatusDot status={isUp ? "green" : "red"} />
                      <span className="font-medium text-themeDark capitalize">
                        {name.replace(/_/g, " ")}
                      </span>
                    </div>
                    <span 
                      className="text-themeDark/50 font-mono cursor-help" 
                      title={data.error ? String(data.error) : undefined}
                    >
                      {data.response_time_ms
                        ? `${data.response_time_ms}ms`
                        : data.inference_time_ms
                        ? `${data.inference_time_ms}ms`
                        : isUp
                        ? "OK"
                        : data.error
                        ? "Degraded"
                        : "N/A"}
                    </span>
                  </div>
                );
              })}
              {/* Whitelist */}
              <div className="border-t border-themeLight/50 pt-2 mt-2">
                <span className="text-[10px] text-themeDark/50 font-semibold uppercase tracking-wider">
                  Whitelist
                </span>
                <div className="grid grid-cols-4 gap-1 mt-1">
                  <MetricBox
                    label="Tier 1"
                    value={urlIntel.whitelist_entries.tier1_count}
                  />
                  <MetricBox
                    label="Tier 2"
                    value={urlIntel.whitelist_entries.tier2_count}
                  />
                  <MetricBox
                    label="Tier 3"
                    value={urlIntel.whitelist_entries.tier3_count}
                  />
                  <MetricBox
                    label="Total"
                    value={urlIntel.whitelist_entries.total}
                  />
                </div>
              </div>
            </div>
          ) : (
            <p className="text-xs text-themeDark/50">No data available</p>
          )}
        </SectionCard>

        {/* ---- 5. Telemetry Feed ---- */}
        <SectionCard
          title="Telemetry Feed"
          icon={Radio}
          status={telemetry?.endpoint_active ? "green" : "red"}
          lastChecked={lastRefresh}
          error={errors.telemetry}
        >
          {telemetry ? (
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-successGreen opacity-75" />
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-successGreen" />
                </span>
                <span className="text-[10px] font-bold text-successGreen uppercase tracking-widest">
                  Live
                </span>
              </div>
              <div className="grid grid-cols-3 gap-2">
                <MetricBox
                  label="Total Events"
                  value={telemetry.total_events_received}
                />
                <MetricBox
                  label="Last 24h"
                  value={telemetry.events_last_24h}
                />
                <MetricBox
                  label="Last Event"
                  value={
                    telemetry.last_event_timestamp
                      ? new Date(
                          telemetry.last_event_timestamp
                        ).toLocaleDateString()
                      : "None"
                  }
                />
              </div>
              {telemetry.recent_events.length > 0 ? (
                <div className="overflow-x-auto mt-2">
                  <table className="w-full text-[11px]">
                    <thead>
                      <tr className="border-b border-themeLight/50">
                        <th className="text-left py-1 text-themeDark/50 font-medium">
                          Type
                        </th>
                        <th className="text-left py-1 text-themeDark/50 font-medium">
                          Content
                        </th>
                        <th className="text-right py-1 text-themeDark/50 font-medium">
                          Risk
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {telemetry.recent_events.slice(0, 5).map((ev) => (
                        <tr
                          key={ev.id}
                          className="border-b border-themeLight/20"
                        >
                          <td className="py-1.5">
                            <span className="font-mono bg-themeLight/50 px-1.5 py-0.5 rounded text-themeDark">
                              {ev.event_type}
                            </span>
                          </td>
                          <td className="py-1.5 text-themeDark/70 truncate max-w-[120px]">
                            {ev.content}
                          </td>
                          <td className="py-1.5 text-right">
                            <span
                              className={`font-bold px-1.5 py-0.5 rounded ${
                                ev.risk_score > 0.8
                                  ? "text-dangerRed bg-dangerRed/10"
                                  : "text-warningYellow bg-warningYellow/10"
                              }`}
                            >
                              {(ev.risk_score * 100).toFixed(0)}%
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="text-xs text-themeDark/40 text-center py-2">
                  No events recorded yet
                </p>
              )}
            </div>
          ) : (
            <p className="text-xs text-themeDark/50">No data available</p>
          )}
        </SectionCard>

        {/* ---- 6. APK Scanner ---- */}
        <SectionCard
          title="APK Scanner"
          icon={ScanLine}
          status={apk?.androguard_available ? "green" : "yellow"}
          lastChecked={lastRefresh}
          error={errors.apk}
        >
          {apk ? (
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <StatusDot
                  status={apk.androguard_available ? "green" : "red"}
                />
                <span className="text-xs font-medium text-themeDark">
                  Androguard{" "}
                  {apk.androguard_available
                    ? `v${apk.androguard_version}`
                    : "Not Installed"}
                </span>
              </div>
              <MetricBox
                label="APKs Scanned"
                value={apk.total_apks_scanned}
              />
              {apk.recent_scans.length > 0 ? (
                <div className="space-y-1.5 mt-2">
                  {apk.recent_scans.map((s, i) => (
                    <div
                      key={i}
                      className="flex items-center justify-between text-xs"
                    >
                      <span className="font-mono text-themeDark/70 truncate max-w-[150px]">
                        {s.package_name}
                      </span>
                      <span
                        className={`font-bold px-2 py-0.5 rounded text-[10px] ${verdictColor(
                          s.verdict
                        )}`}
                      >
                        {s.verdict}
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-themeDark/40 text-center py-1">
                  No recent scans
                </p>
              )}
            </div>
          ) : (
            <p className="text-xs text-themeDark/50">No data available</p>
          )}
        </SectionCard>

        {/* ---- 8. Fraud Reports ---- */}
        <SectionCard
          title="Fraud Reports"
          icon={FileText}
          status={fraudReports ? "green" : "red"}
          lastChecked={lastRefresh}
          error={errors.fraudReports}
        >
          {fraudReports ? (
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-2">
                <MetricBox
                  label="Total Reports"
                  value={fraudReports.total_reports}
                />
                <MetricBox
                  label="Last 24h"
                  value={fraudReports.reports_last_24h}
                />
              </div>
              {fraudReports.recent_reports.length > 0 ? (
                <div className="space-y-1.5 mt-2">
                  {fraudReports.recent_reports.map((r) => (
                    <div
                      key={r.id}
                      className="flex items-center justify-between text-xs border-b border-themeLight/20 pb-1"
                    >
                      <div className="flex items-center gap-2">
                        <span className="font-mono bg-themeLight/50 px-1.5 py-0.5 rounded">
                          {r.report_type}
                        </span>
                        <span className="text-themeDark/70 truncate max-w-[120px]">
                          {r.url_or_identifier}
                        </span>
                      </div>
                      <span className="text-themeDark/40 font-mono text-[10px]">
                        {r.timestamp
                          ? new Date(r.timestamp).toLocaleDateString()
                          : ""}
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-themeDark/40 text-center py-1">
                  No reports yet
                </p>
              )}
            </div>
          ) : (
            <p className="text-xs text-themeDark/50">No data available</p>
          )}
        </SectionCard>
      </div>

      {/* ========== ML MODEL (full width) ========== */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4 mb-6">
        <SectionCard
          title="ML Model Health"
          icon={Brain}
          status={
            model
              ? model.model_loaded && model.text_model_loaded
                ? "green"
                : model.model_loaded || model.text_model_loaded
                ? "yellow"
                : "red"
              : "red"
          }
          lastChecked={lastRefresh}
          error={errors.model}
        >
          {model ? (
            <div className="space-y-4">
              <div className="flex flex-col sm:flex-row gap-4 sm:gap-6">
                <div className="flex items-center gap-2">
                  <StatusDot status={model.model_loaded ? "green" : "red"} />
                  <span className="text-xs font-medium text-themeDark">
                    URL XGBoost Model: {model.model_loaded ? "Active" : "Inactive"}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <StatusDot status={model.text_model_loaded ? "green" : "red"} />
                  <span className="text-xs font-medium text-themeDark">
                    Hugging Face NLP API: {model.text_model_loaded ? "Active" : "Inactive"}
                  </span>
                </div>
              </div>
              <div className="grid grid-cols-3 gap-2">
                <MetricBox
                  label="Version"
                  value={model.model_version || "N/A"}
                />
                <MetricBox
                  label="Features"
                  value={model.feature_count}
                />
                <MetricBox
                  label="Threshold"
                  value={model.optimal_threshold?.toFixed(2) || "N/A"}
                />
              </div>

              {/* Performance metrics */}
              {model.performance &&
                Object.keys(model.performance).length > 0 && (
                  <div>
                    <span className="text-[10px] text-themeDark/50 font-semibold uppercase tracking-wider">
                      Performance Metrics
                    </span>
                    <div className="grid grid-cols-4 gap-2 mt-1">
                      {Object.entries(model.performance)
                        .filter(([, v]) => typeof v === "number")
                        .slice(0, 8)
                        .map(([key, val]) => (
                          <MetricBox
                            key={key}
                            label={key.replace(/_/g, " ")}
                            value={
                              typeof val === "number"
                                ? val < 1
                                  ? (val as number).toFixed(4)
                                  : String(val)
                                : String(val)
                            }
                          />
                        ))}
                    </div>
                  </div>
                )}

              {/* Artifacts checklist */}
              <div>
                <span className="text-[10px] text-themeDark/50 font-semibold uppercase tracking-wider">
                  Artifacts
                </span>
                <div className="grid grid-cols-2 gap-1 mt-1">
                  {Object.entries(model.artifacts_present).map(
                    ([fname, present]) => (
                      <div
                        key={fname}
                        className="flex items-center gap-1.5 text-xs"
                      >
                        {present ? (
                          <CheckCircle2 className="w-3.5 h-3.5 text-successGreen flex-shrink-0" />
                        ) : (
                          <XCircle className="w-3.5 h-3.5 text-dangerRed flex-shrink-0" />
                        )}
                        <span className="font-mono text-themeDark/70 truncate">
                          {fname}
                        </span>
                      </div>
                    )
                  )}
                </div>
                <div className="text-[10px] text-themeDark/40 mt-1">
                  Model size: {model.model_file_size_mb} MB
                </div>
              </div>
            </div>
          ) : (
            <p className="text-xs text-themeDark/50">No data available</p>
          )}
        </SectionCard>

        {/* Live Model Test */}
        <SectionCard
          title="Live Model Test"
          icon={Zap}
          status={
            liveTestResults.length > 0
              ? liveTestResults.every((r) => !r.error)
                ? "green"
                : "yellow"
              : "yellow"
          }
          lastChecked={lastRefresh}
        >
          <div className="space-y-3">
            <p className="text-xs text-themeDark/60">
              Run the ML model against two hardcoded test URLs to verify
              inference is working end-to-end.
            </p>
            <div className="space-y-1 text-xs font-mono">
              <div className="bg-dangerRed/5 px-2 py-1 rounded text-dangerRed/80 truncate">
                http://yonosbi-update.xyz/login
              </div>
              <div className="bg-successGreen/5 px-2 py-1 rounded text-successGreen/80 truncate">
                https://sbi.bank.in/
              </div>
            </div>
            <button
              onClick={runLiveTest}
              disabled={liveTestRunning}
              className="w-full bg-themeMid hover:bg-themeDark text-white py-2 rounded-lg text-sm font-medium transition-all disabled:opacity-50 flex items-center justify-center gap-2 shadow-sm"
            >
              {liveTestRunning ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" /> Running...
                </>
              ) : (
                <>
                  <Zap className="w-3.5 h-3.5" /> Run Live Test
                </>
              )}
            </button>
            {liveTestResults.length > 0 && (
              <div className="space-y-2 mt-2">
                {liveTestResults.map((r, i) => (
                  <div
                    key={i}
                    className={`p-3 rounded-lg border-l-4 text-xs ${
                      r.error
                        ? "border-dangerRed bg-dangerRed/5"
                        : r.is_safe
                        ? "border-successGreen bg-successGreen/5"
                        : "border-dangerRed bg-dangerRed/5"
                    }`}
                  >
                    <div className="font-mono text-themeDark/70 truncate mb-1">
                      {r.url}
                    </div>
                    {r.error ? (
                      <span className="text-dangerRed">{r.error}</span>
                    ) : (
                      <div className="flex items-center gap-3">
                        <span
                          className={`font-bold ${
                            r.is_safe ? "text-successGreen" : "text-dangerRed"
                          }`}
                        >
                          {r.is_safe ? "SAFE" : "THREAT"}
                        </span>
                        <span className="text-themeDark/50">
                          Risk: {(r.risk_score * 100).toFixed(0)}%
                        </span>
                        {r.ml_analysis && (
                          <span className="text-themeDark/50">
                            Confidence: {r.ml_analysis.model_confidence}%
                          </span>
                        )}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </SectionCard>
      </div>

      {/* ========== FRI SUMMARY + ENVIRONMENT (full width) ========== */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4 mb-6">
        {/* ---- 7. FRI Summary ---- */}
        <SectionCard
          title="FRI Intelligence Summary"
          icon={Shield}
          status={
            friSummary && friSummary.total_entries > 0 ? "green" : "yellow"
          }
          lastChecked={lastRefresh}
          error={errors.friSummary}
        >
          {friSummary ? (
            <div className="space-y-4">
              <MetricBox
                label="Total FRI Entries"
                value={friSummary.total_entries}
              />

              {/* Risk level bar */}
              {Object.keys(friSummary.by_risk_level).length > 0 && (
                <div>
                  <span className="text-[10px] text-themeDark/50 font-semibold uppercase tracking-wider">
                    Risk Distribution
                  </span>
                  <div className="flex h-4 rounded-full overflow-hidden mt-1">
                    {Object.entries(friSummary.by_risk_level).map(
                      ([level, count]) => {
                        const pct =
                          friSummary.total_entries > 0
                            ? (count / friSummary.total_entries) * 100
                            : 0;
                        const color = level.includes("very_high")
                          ? "bg-dangerRed"
                          : level.includes("high")
                          ? "bg-warningYellow"
                          : "bg-yellow-400";
                        return (
                          <div
                            key={level}
                            className={`${color} relative group`}
                            style={{ width: `${pct}%` }}
                            title={`${level}: ${count}`}
                          />
                        );
                      }
                    )}
                  </div>
                  <div className="flex gap-3 mt-1 text-[10px]">
                    {Object.entries(friSummary.by_risk_level).map(
                      ([level, count]) => (
                        <span key={level} className="text-themeDark/50">
                          {level.replace(/_/g, " ")}: {count}
                        </span>
                      )
                    )}
                  </div>
                </div>
              )}

              {/* Category breakdown */}
              {Object.keys(friSummary.by_fraud_category).length > 0 && (
                <div>
                  <span className="text-[10px] text-themeDark/50 font-semibold uppercase tracking-wider">
                    Top Categories
                  </span>
                  <div className="space-y-1 mt-1">
                    {Object.entries(friSummary.by_fraud_category)
                      .sort(([, a], [, b]) => b - a)
                      .slice(0, 6)
                      .map(([cat, count]) => (
                        <div
                          key={cat}
                          className="flex items-center justify-between text-xs"
                        >
                          <span className="text-themeDark/70 capitalize">
                            {cat.replace(/_/g, " ")}
                          </span>
                          <span className="font-bold text-themeDark">
                            {count}
                          </span>
                        </div>
                      ))}
                  </div>
                </div>
              )}

              {/* Identifier types */}
              {Object.keys(friSummary.by_identifier_type).length > 0 && (
                <div>
                  <span className="text-[10px] text-themeDark/50 font-semibold uppercase tracking-wider">
                    Identifier Coverage
                  </span>
                  <div className="grid grid-cols-3 gap-1 mt-1">
                    {Object.entries(friSummary.by_identifier_type).map(
                      ([itype, count]) => (
                        <MetricBox
                          key={itype}
                          label={itype}
                          value={count}
                        />
                      )
                    )}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <p className="text-xs text-themeDark/50">No data available</p>
          )}
        </SectionCard>

        {/* ---- 9. System Environment ---- */}
        <SectionCard
          title="System Environment"
          icon={ShieldCheck}
          status={env ? "green" : "red"}
          lastChecked={lastRefresh}
          error={errors.env}
        >
          {env ? (
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-2">
                <MetricBox label="Python" value={env.python_version} />
                <MetricBox label="OS" value={env.os} />
                <MetricBox
                  label="XGBoost"
                  value={env.xgboost_version || "N/A"}
                />
                <MetricBox
                  label="Androguard"
                  value={env.androguard_version || "N/A"}
                />
              </div>
              <div>
                <span className="text-[10px] text-themeDark/50 font-semibold uppercase tracking-wider">
                  ML Artifacts
                </span>
                <div className="space-y-1 mt-1">
                  {Object.entries(env.ml_artifacts).map(([fname, info]) => (
                    <div
                      key={fname}
                      className="flex items-center justify-between text-xs"
                    >
                      <div className="flex items-center gap-1.5">
                        {info.present ? (
                          <CheckCircle2 className="w-3 h-3 text-successGreen flex-shrink-0" />
                        ) : (
                          <XCircle className="w-3 h-3 text-dangerRed flex-shrink-0" />
                        )}
                        <span className="font-mono text-themeDark/70">
                          {fname}
                        </span>
                      </div>
                      <span className="text-themeDark/40 font-mono">
                        {info.size || ""}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <p className="text-xs text-themeDark/50">No data available</p>
          )}
        </SectionCard>
      </div>

      {/* ========== FRI ENTRIES TABLE (full width) ========== */}
      <div className="glass-card overflow-hidden mb-6">
        <div className="bg-white/40 p-4 border-b border-themeLight/50 flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-themeMid" />
            <h2 className="text-sm font-bold text-themeDark tracking-wide">
              FRI Database Entries
            </h2>
            <span className="text-[10px] text-themeDark/40 font-mono">
              ({sortedFri.length} results)
            </span>
          </div>
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-themeDark/40" />
            <input
              type="text"
              placeholder="Search entries..."
              value={friSearch}
              onChange={(e) => {
                setFriSearch(e.target.value);
                setFriPage(0); // reset to page 1 on search
              }}
              className="pl-8 pr-3 py-1.5 text-xs rounded-lg bg-white/60 border border-themeLight/50 focus:outline-none focus:border-themeMid/50 w-56"
            />
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead className="bg-white/80 border-b border-themeLight/50">
              <tr>
                <th className="px-4 py-2.5 text-left text-themeDark/60 font-medium uppercase tracking-wider">
                  ID
                </th>
                <th className="px-4 py-2.5 text-left text-themeDark/60 font-medium uppercase tracking-wider">
                  Risk Level
                </th>
                <th className="px-4 py-2.5 text-left text-themeDark/60 font-medium uppercase tracking-wider">
                  Category
                </th>
                <th className="px-4 py-2.5 text-left text-themeDark/60 font-medium uppercase tracking-wider">
                  Identifiers
                </th>
                <th className="px-4 py-2.5 text-left text-themeDark/60 font-medium uppercase tracking-wider">
                  Created
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-themeLight/30">
              {friBatch.length > 0 ? (
                friBatch.map((entry) => (
                  <tr
                    key={entry.id}
                    className="hover:bg-white/50 transition-colors"
                  >
                    <td className="px-4 py-2.5 font-mono text-themeDark/70">
                      #{entry.id}
                    </td>
                    <td className="px-4 py-2.5">
                      <span
                        className={`text-[10px] font-bold px-2 py-0.5 rounded ${riskColor(
                          entry.risk_level
                        )}`}
                      >
                        {entry.risk_level}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-themeDark/80">
                      {entry.fraud_category}
                    </td>
                    <td className="px-4 py-2.5">
                      <div className="flex flex-wrap gap-1">
                        {entry.identifiers.map((ident, i) => (
                          <span
                            key={i}
                            className="text-[10px] bg-themeLight/50 text-themeDark/60 px-1.5 py-0.5 rounded font-medium"
                          >
                            {ident.type}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="px-4 py-2.5 text-themeDark/50 font-mono">
                      {entry.created_at
                        ? new Date(entry.created_at).toLocaleDateString()
                        : "N/A"}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td
                    colSpan={5}
                    className="px-4 py-8 text-center text-themeDark/40"
                  >
                    {friSearch
                      ? "No entries match your search"
                      : "No FRI entries in database"}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        {/* Pagination */}
        {sortedFri.length > FRI_PAGE_SIZE && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-themeLight/50 bg-white/30">
            <span className="text-xs text-themeDark/50">
              Page {friPage + 1} of {friTotalPages}
            </span>
            <div className="flex gap-1">
              <button
                onClick={() => setFriPage((p) => Math.max(0, p - 1))}
                disabled={friPage === 0}
                className="p-1.5 rounded-lg hover:bg-themeLight/50 disabled:opacity-30 transition-colors"
              >
                <ChevronLeft className="w-4 h-4 text-themeDark" />
              </button>
              <button
                onClick={() =>
                  setFriPage((p) => Math.min(friTotalPages - 1, p + 1))
                }
                disabled={friPage >= friTotalPages - 1}
                className="p-1.5 rounded-lg hover:bg-themeLight/50 disabled:opacity-30 transition-colors"
              >
                <ChevronRight className="w-4 h-4 text-themeDark" />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
