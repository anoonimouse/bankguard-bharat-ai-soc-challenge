"use client";

import { useState, useRef } from 'react';
import { ScanLine, UploadCloud, FileCheck, FileWarning, ShieldX, Terminal, Search, Trash2 } from 'lucide-react';

export default function APKScanner() {
  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const droppedFile = e.dataTransfer.files[0];
      if (droppedFile.name.endsWith('.apk')) {
        setFile(droppedFile);
        setResult(null);
      } else {
        alert('Please drop an .apk file only.');
      }
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      const selectedFile = e.target.files[0];
      if (selectedFile.name.endsWith('.apk')) {
        setFile(selectedFile);
        setResult(null);
      } else {
        alert('Please select an .apk file.');
      }
    }
  };

  const handleScan = async () => {
    if (!file) return;
    
    // Check file size limit (e.g. 150MB)
    if (file.size > 150 * 1024 * 1024) {
      alert("File is too large. Maximum size is 150MB.");
      return;
    }

    setLoading(true);
    setResult(null);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL as string;
      const response = await fetch(`${apiUrl}/api/scan-apk`, {
        method: 'POST',
        body: formData,
      });
      
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || 'Scan failed');
      }
      setResult(data);
    } catch (error) {
      console.error(error);
      alert(error instanceof Error ? error.message : 'Analysis failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="h-full flex flex-col justify-center max-w-4xl mx-auto py-2 animate-in fade-in duration-500">
      <div className="text-center mb-8">
        <div className="inline-flex items-center justify-center p-3 bg-white/60 rounded-xl mb-4 shadow-sm border border-themeLight/50">
           <Search className="w-6 h-6 text-themeMid" strokeWidth={1.5} />
        </div>
        <h1 className="text-3xl font-extrabold mb-2 text-themeDark tracking-tight">APK Scanner (Malware Detective)</h1>
        <p className="text-themeDark/60 text-lg font-light">Upload any suspicious Android app (.apk) forwarded via WhatsApp or SMS to instantly verify its safety without installing it.</p>
      </div>

      <div className="glass-card mb-6 overflow-hidden">
        {!file ? (
          <div 
            className={`border-2 border-dashed rounded-xl p-12 text-center transition-all ${dragging ? 'border-themeMid bg-themeMid/5 flex scale-[1.01]' : 'border-themeDark/20 bg-white/40 hover:bg-white/60'}`}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
          >
            <input 
              type="file" 
              accept=".apk"
              ref={fileInputRef} 
              className="hidden" 
              onChange={handleFileChange} 
            />
            <div className="flex flex-col items-center cursor-pointer">
              <div className="p-4 bg-themeLight/30 rounded-full mb-4">
                <UploadCloud className="w-10 h-10 text-themeMid" />
              </div>
              <h3 className="text-xl font-bold text-themeDark mb-1">Upload suspicious APK</h3>
              <p className="text-themeDark/50 mb-4">Drag and drop file here or click to browse</p>
              <div className="text-xs text-themeDark/40 uppercase font-semibold tracking-wider bg-black/5 px-3 py-1 rounded-full">Max 150MB Limit</div>
            </div>
          </div>
        ) : (
          <div className="p-6 bg-white/60">
            <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4">
              <div className="flex items-center gap-4">
                <div className="p-3 bg-themeMid/10 rounded-lg shrink-0">
                  <ScanLine className="w-8 h-8 text-themeMid" />
                </div>
                <div>
                  <h3 className="font-bold text-lg text-themeDark break-all">{file.name}</h3>
                  <p className="text-sm text-themeDark/60">{(file.size / 1024 / 1024).toFixed(2)} MB</p>
                </div>
              </div>
              <div className="flex items-center justify-end sm:justify-start gap-3 w-full sm:w-auto">
                <button 
                  onClick={() => {setFile(null); setResult(null);}}
                  className="p-2 text-themeDark/40 hover:text-dangerRed transition-colors shrink-0"
                  disabled={loading}
                  title="Remove file"
                >
                  <Trash2 className="w-5 h-5" />
                </button>
                <button 
                  onClick={handleScan}
                  disabled={loading}
                  className="flex-1 sm:flex-none justify-center bg-themeMid hover:bg-themeDark text-white px-8 py-3 rounded-lg font-medium transition-all disabled:opacity-50 flex items-center gap-2 shadow-sm"
                >
                  {loading ? (
                    <>
                      <Terminal className="w-5 h-5 animate-pulse" />
                      Decompiling Binary...
                    </>
                  ) : (
                    'Run Deep Scan'
                  )}
                </button>
              </div>
            </div>
            
            {loading && (
              <div className="mt-6 pt-6 border-t border-themeLight/50 flex flex-col items-center animate-in slide-in-from-top-4">
                <div className="flex justify-center gap-2 mb-4">
                  <div className="w-3 h-3 bg-themeMid rounded-full animate-bounce" style={{ animationDelay: '0ms' }}></div>
                  <div className="w-3 h-3 bg-themeMid rounded-full animate-bounce" style={{ animationDelay: '150ms' }}></div>
                  <div className="w-3 h-3 bg-themeMid rounded-full animate-bounce" style={{ animationDelay: '300ms' }}></div>
                </div>
                <p className="text-themeDark/60 font-medium">Extracting package manifests & signature certificates...</p>
                <div className="w-full bg-themeLight/50 h-2 mt-4 rounded-full overflow-hidden relative">
                  <div className="absolute top-0 left-0 h-full bg-themeMid rounded-full animate-pulse w-[70%]"></div>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {result && (
        <div className={`glass-card p-6 md:p-8 transition-all animate-in zoom-in-95 duration-300 border-l-4 ${
          result.verdict === 'safe' 
            ? 'border-l-successGreen bg-successGreen/5' 
            : result.verdict === 'unrelated'
            ? 'border-l-blue-500 bg-blue-500/5'
            : result.verdict === 'suspicious'
            ? 'border-l-yellow-500 bg-yellow-500/5'
            : 'border-l-dangerRed bg-dangerRed/5'
        }`}>
          {/* Top Verdict Header */}
          <div className="flex flex-col sm:flex-row items-center sm:items-start gap-5 mb-8 text-center sm:text-left">
            <div className={`p-4 rounded-xl shadow-sm bg-white border shrink-0 ${
              result.verdict === 'safe' 
                ? 'text-successGreen border-successGreen/20' 
                : result.verdict === 'unrelated'
                ? 'text-blue-500 border-blue-500/20'
                : result.verdict === 'suspicious'
                ? 'text-yellow-500 border-yellow-500/20'
                : 'text-dangerRed border-dangerRed/20'
            }`}>
              {result.verdict === 'safe' ? <FileCheck className="w-10 h-10" /> 
               : result.verdict === 'unrelated' ? <ScanLine className="w-10 h-10" />
               : result.verdict === 'suspicious' ? <FileWarning className="w-10 h-10" /> 
               : <ShieldX className="w-10 h-10" />}
            </div>
            <div className="flex-1 w-full">
              <div className="flex flex-col sm:flex-row items-center sm:items-start justify-between gap-4">
                <div className="flex-1">
                  <h3 className={`text-3xl font-extrabold mb-1 uppercase ${
                    result.verdict === 'safe' ? 'text-successGreen'
                    : result.verdict === 'unrelated' ? 'text-blue-600'
                    : result.verdict === 'suspicious' ? 'text-yellow-600'
                    : 'text-dangerRed'
                  }`}>
                    {result.verdict === 'unrelated' ? 'DOES NOT IMPERSONATE BANKGUARD' : `${result.verdict} APP DETECTED`}
                  </h3>
                  <p className="text-themeDark/70 text-lg">
                    {result.verdict === 'safe' ? 'This application is officially signed by BankGuard.'
                     : result.verdict === 'unrelated' ? 'This app has no obvious relation to BankGuard. Use your own judgment.'
                     : result.verdict === 'suspicious' ? 'This app mimics BankGuard but has warning signs. Do not install.'
                     : 'Highly malicious fake banking app. Do not install.'}
                  </p>
                </div>
                <div className="text-center bg-white p-3 rounded-lg shadow-sm border border-themeLight shrink-0 w-full sm:w-auto">
                  <span className="block text-xs font-bold text-themeDark/50 uppercase mb-1 tracking-wider">Risk Score</span>
                  <div className={`text-2xl font-black ${result.risk_score > 75 ? 'text-dangerRed' : result.risk_score > 25 ? 'text-yellow-600' : 'text-successGreen'}`}>
                    {result.risk_score} <span className="text-sm font-medium text-themeDark/40">/ 100</span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="grid md:grid-cols-2 gap-6">
            {/* App Meta Details */}
            <div className="bg-white/70 rounded-xl p-5 shadow-sm border border-themeLight/50">
              <h4 className="text-sm font-bold text-themeDark/50 uppercase tracking-wider mb-4 border-b border-themeLight pb-2">Extracted Metadata</h4>
              
              <div className="space-y-4">
                <div>
                  <div className="text-xs font-semibold text-themeDark/50 uppercase mb-1">App Name</div>
                  <div className="font-medium text-themeDark truncate">{result.app_name || 'Unknown'}</div>
                </div>
                <div>
                  <div className="text-xs font-semibold text-themeDark/50 uppercase mb-1">Package Name</div>
                  <div className="font-mono text-sm text-themeDark truncate p-2 bg-black/5 rounded">{result.package_name || 'N/A'}</div>
                </div>
                <div>
                  <div className="text-xs font-semibold text-themeDark/50 uppercase mb-1">Cert Signature Hash (SHA-256)</div>
                  <div className="font-mono text-xs text-themeDark/70 break-all p-2 bg-black/5 rounded">
                    {result.cert_hash || 'Unsigned or Extraction Failed'}
                  </div>
                </div>
              </div>
            </div>

            {/* Individual Checks Feed */}
            <div className="bg-white/70 rounded-xl p-5 shadow-sm border border-themeLight/50 flex flex-col gap-3">
              <h4 className="text-sm font-bold text-themeDark/50 uppercase tracking-wider mb-2 border-b border-themeLight pb-2">Analysis Breakdown</h4>
              
              {/* eslint-disable-next-line @typescript-eslint/no-explicit-any */}
              {result.checks.map((c: any, i: number) => (
                <div key={i} className={`p-3 rounded-lg border-l-4 ${
                  c.status === 'pass' ? 'bg-successGreen/10 border-successGreen'
                  : c.status === 'fail' ? 'bg-dangerRed/10 border-dangerRed'
                  : 'bg-yellow-500/10 border-yellow-500'
                }`}>
                  <div className="flex justify-between items-center mb-1">
                    <span className="font-bold text-sm text-themeDark">{c.check_name}</span>
                    <span className={`text-xs font-bold uppercase px-2 py-0.5 rounded-full ${
                      c.status === 'pass' ? 'bg-successGreen/20 text-successGreen'
                      : c.status === 'fail' ? 'bg-dangerRed/20 text-dangerRed'
                      : 'bg-yellow-500/20 text-yellow-600'
                    }`}>
                      {c.status}
                    </span>
                  </div>
                  <p className="text-sm text-themeDark/80">{c.message}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
