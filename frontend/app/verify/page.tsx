"use client";

import { useState } from 'react';
import { Search, CheckCircle2, ShieldX, ScanLine, Brain, TrendingUp } from 'lucide-react';

// Types
interface MLFeature {
  feature: string;
  importance: number;
}

interface MLAnalysis {
  model_confidence: number;
  raw_probability: number;
  top_features: MLFeature[];
  threshold_used: number;
  model_version: string;
}

interface URLCheckResult {
  url: string;
  is_safe: boolean;
  risk_score: number;
  threat_type: string | null;
  message: string;
  ml_analysis: MLAnalysis | null;
}

// Human-readable feature name labels
const featureLabels: Record<string, string> = {
  url_length: "URL Length",
  domain_length: "Domain Length",
  path_length: "Path Length",
  num_dots: "Dot Count",
  num_hyphens: "Hyphen Count",
  num_digits: "Digit Count",
  digit_ratio: "Digit Ratio",
  subdomain_count: "Subdomain Count",
  has_ip_address: "IP Address Host",
  tld_is_high_risk: "High-Risk TLD",
  domain_has_digits: "Digits in Domain",
  domain_has_hyphen: "Hyphen in Domain",
  is_url_shortener: "URL Shortener",
  url_entropy: "URL Entropy",
  domain_entropy: "Domain Entropy",
  path_entropy: "Path Entropy",
  lev_dist_sbi: "Distance to 'SBI'",
  lev_dist_onlinesbi: "Distance to 'OnlineSBI'",
  lev_dist_yono: "Distance to 'YONO'",
  lev_dist_sbifreedom: "Distance to 'SBI Freedom'",
  contains_sbi_keyword: "Contains SBI Keyword",
  contains_banking_keyword: "Contains Banking Keyword",
  contains_kyc_keyword: "Contains KYC Keyword",
  contains_urgency_keyword: "Contains Urgency Keyword",
  contains_reward_keyword: "Contains Reward Keyword",
  contains_apk_keyword: "Contains APK Keyword",
  has_at_symbol: "@ Symbol Present",
  has_double_slash_redirect: "Double-Slash Redirect",
  path_depth: "Path Depth",
  has_login_path: "Login Path Detected",
  has_suspicious_tld_combo: "Brand + Risky TLD Combo",
  consonant_vowel_ratio: "Consonant/Vowel Ratio",
  longest_word_length: "Longest Domain Token",
  average_token_length: "Avg Token Length",
};

function getFeatureLabel(name: string): string {
  return featureLabels[name] || name.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

export default function VerifyPortal() {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState<URLCheckResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    
    if (!url || url.trim().length === 0) {
      setError('Please enter a valid URL or domain to scan.');
      return;
    }
    
    let processedUrl = url.trim();
    // More robust protocol prefixing
    if (!/^https?:\/\//i.test(processedUrl)) {
      processedUrl = `https://${processedUrl}`;
    }
    
    setLoading(true);
    setResult(null);
    try {
      // Robust API URL handling
      const apiUrl = (process.env.NEXT_PUBLIC_API_URL || 'https://api.doy.codes').replace(/\/$/, '');
      const response = await fetch(`${apiUrl}/api/check-url`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: processedUrl }),
      });
      
      if (!response.ok) throw new Error('Backend response error');
      
      const data = await response.json();
      setTimeout(() => {
          setResult(data);
          setLoading(false);
      }, 600);
    } catch (err) {
      console.error(err);
      setError('Connection failed. Please ensure the security engine is reachable.');
      setLoading(false);
    }
  };

  return (
    <div className="h-full flex flex-col justify-center max-w-3xl mx-auto py-2 animate-in fade-in duration-500">
      <div className="text-center mb-6">
        <div className="inline-flex items-center justify-center p-3 bg-white/60 rounded-xl mb-4 shadow-sm border border-themeLight/50">
           <ScanLine className="w-6 h-6 text-themeMid" strokeWidth={1.5} />
        </div>
        <h1 className="text-3xl font-extrabold mb-2 text-themeDark tracking-tight">Verification Portal</h1>
        <p className="text-themeDark/60 text-lg font-light">Ensure your links and apps are secure and verified.</p>
      </div>

      <div className="glass-card mb-6 overflow-hidden p-2 sm:p-0 bg-white/40">
        <form onSubmit={handleVerify} className="flex flex-col sm:flex-row items-stretch sm:items-center relative">
          <div className="relative flex-1 flex items-center">
            <Search className="absolute left-4 text-themeMid/60 w-5 h-5" />
            <input 
              type="text" 
              placeholder="e.g., bankguard-update.in/login"
              className="w-full bg-white/20 sm:bg-transparent border-none py-4 pl-12 pr-4 sm:pr-36 text-themeDark placeholder:text-themeDark/40 focus:outline-none focus:bg-white/80 text-lg transition-colors border-0 ring-0 rounded-lg sm:rounded-none"
              value={url}
              onChange={(e) => {
                setUrl(e.target.value);
                if (error) setError(null);
              }}
              autoComplete="off"
            />
          </div>
          <button 
            type="submit" 
            disabled={loading}
            className="mt-2 sm:mt-0 sm:absolute sm:right-2 bg-themeMid hover:bg-themeDark text-white px-6 py-3 sm:py-2 rounded-lg font-medium transition-all disabled:opacity-50 flex items-center justify-center gap-2 shadow-sm"
          >
            {loading ? 'Scanning...' : 'Verify'}
          </button>
        </form>
      </div>

      {error && (
        <div className="mb-6 p-4 bg-dangerRed/10 border border-dangerRed/20 rounded-xl text-dangerRed text-sm flex items-center gap-2 animate-in slide-in-from-top-2">
          <ShieldX className="w-4 h-4" />
          {error}
        </div>
      )}

      {result && (
        <div className={`glass-card p-6 transition-all animate-in zoom-in-95 duration-300 border-l-4 ${result.is_safe ? 'border-l-successGreen bg-successGreen/5' : 'border-l-dangerRed bg-dangerRed/5'}`}>
          <div className="flex flex-col sm:flex-row items-center sm:items-start gap-5 text-center sm:text-left">
            <div className={`p-4 rounded-xl shadow-sm shrink-0 ${result.is_safe ? 'bg-white text-successGreen border border-successGreen/20' : 'bg-white text-dangerRed border border-dangerRed/20'}`}>
              {result.is_safe ? (
                <CheckCircle2 className="w-8 h-8" strokeWidth={2} />
              ) : (
                <ShieldX className="w-8 h-8 animate-pulse" strokeWidth={2} />
              )}
            </div>
            <div className="flex-1 w-full">
              <h3 className={`text-2xl font-bold mb-1 ${result.is_safe ? 'text-successGreen' : 'text-dangerRed'}`}>
                {result.is_safe ? 'SAFE & VERIFIED' : 'THREAT DETECTED'}
              </h3>
              <p className="text-themeDark/70 mb-4">{result.message}</p>
              
              {!result.is_safe && (
                <div className="bg-white/80 rounded-xl p-4 shadow-sm border border-dangerRed/10">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div>
                      <span className="block text-themeDark/50 text-xs font-semibold uppercase mb-1">Threat Type</span> 
                      <span className="text-themeDark font-medium bg-dangerRed/10 px-2 py-1 rounded-md">{result.threat_type}</span>
                    </div>
                    <div>
                      <span className="block text-themeDark/50 text-xs font-semibold uppercase mb-1">Confidence</span>
                      <div className="flex items-center gap-3">
                        <div className="flex-1 bg-themeLight/50 rounded-full h-2 overflow-hidden">
                          <div className="bg-dangerRed h-full rounded-full" style={{ width: `${result.risk_score * 100}%` }}></div>
                        </div>
                        <span className="text-dangerRed font-bold">{(result.risk_score * 100).toFixed(0)}%</span>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* ML Analysis Section */}
              {result.ml_analysis && (
                <div className="mt-4 bg-white/80 rounded-xl p-4 shadow-sm border border-themeMid/10">
                  <div className="flex items-center gap-2 mb-3 justify-center sm:justify-start">
                    <Brain className="w-4 h-4 text-themeMid" />
                    <span className="text-sm font-bold text-themeDark uppercase tracking-wide">
                      ML Analysis - Why this URL was flagged
                    </span>
                  </div>
                  
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-4">
                    <div className="bg-themeLight/20 rounded-lg p-3 text-center">
                      <span className="block text-xs text-themeDark/50 font-semibold uppercase">Model Confidence</span>
                      <span className="text-2xl font-bold text-themeDark">{result.ml_analysis.model_confidence}%</span>
                    </div>
                    <div className="bg-themeLight/20 rounded-lg p-3 text-center">
                      <span className="block text-xs text-themeDark/50 font-semibold uppercase">Raw Probability</span>
                      <span className="text-2xl font-bold text-themeDark">{result.ml_analysis.raw_probability.toFixed(3)}</span>
                    </div>
                    <div className="bg-themeLight/20 rounded-lg p-3 text-center">
                      <span className="block text-xs text-themeDark/50 font-semibold uppercase">Threshold</span>
                      <span className="text-2xl font-bold text-themeDark">{result.ml_analysis.threshold_used.toFixed(2)}</span>
                    </div>
                  </div>

                  {result.ml_analysis.top_features.length > 0 && (
                    <div className="text-left">
                      <div className="flex items-center gap-1 mb-2">
                        <TrendingUp className="w-3 h-3 text-themeMid" />
                        <span className="text-xs font-semibold text-themeDark/60 uppercase">Top Decision Factors</span>
                      </div>
                      <div className="space-y-1.5">
                        {result.ml_analysis.top_features.map((feat, i) => (
                          <div key={i} className="flex items-center gap-3">
                            <span className="text-xs font-mono text-themeDark/40 w-4">#{i + 1}</span>
                            <span className="text-sm text-themeDark flex-1">{getFeatureLabel(feat.feature)}</span>
                            <div className="hidden sm:block w-24 bg-themeLight/30 rounded-full h-1.5 overflow-hidden">
                              <div 
                                className="bg-themeMid h-full rounded-full transition-all" 
                                style={{ width: `${Math.min(feat.importance * 200, 100)}%` }}
                              ></div>
                            </div>
                            <span className="text-xs font-mono text-themeDark/60 w-12 text-right">
                              {(feat.importance * 100).toFixed(1)}%
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  <div className="mt-3 pt-2 border-t border-themeLight/30 text-left">
                    <span className="text-[10px] text-themeDark/30 font-mono">
                      Model v{result.ml_analysis.model_version} - XGBoost
                    </span>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
