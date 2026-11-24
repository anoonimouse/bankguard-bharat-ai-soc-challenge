"use client";

import { useState, useEffect } from 'react';
import { Activity, ShieldCheck, ShieldAlert, Wifi, WifiOff, Loader2 } from 'lucide-react';

export default function BackendStatus() {
  const [status, setStatus] = useState<'checking' | 'online' | 'offline'>('checking');
  const [apiUrl, setApiUrl] = useState('');
  const [details, setDetails] = useState<any>(null);

  useEffect(() => {
    const url = process.env.NEXT_PUBLIC_API_URL || 'Not Set';
    setApiUrl(url);
    checkHealth();
  }, []);

  const checkHealth = async () => {
    setStatus('checking');
    try {
      const liveUrl = process.env.NEXT_PUBLIC_API_URL as string;
      const res = await fetch(`${liveUrl}/api/reports`, { 
        method: 'GET',
        cache: 'no-store' 
      });
      
      if (res.ok) {
        const data = await res.json();
        setDetails(data);
        setStatus('online');
      } else {
        setStatus('offline');
      }
    } catch (error) {
      console.error(error);
      setStatus('offline');
    }
  };

  return (
    <div className="h-full flex flex-col items-center justify-center p-6 animate-in fade-in duration-700">
      <div className="glass-card p-8 max-w-md w-full text-center border-t-4 shadow-xl box-border transition-all">
        <div className={`mx-auto w-20 h-20 rounded-2xl flex items-center justify-center mb-6 shadow-inner ${
          status === 'online' ? 'bg-successGreen/20 text-successGreen shadow-successGreen/10' : 
          status === 'offline' ? 'bg-dangerRed/20 text-dangerRed shadow-dangerRed/10' : 
          'bg-themeMid/20 text-themeMid animate-pulse'
        }`}>
          {status === 'online' ? <ShieldCheck size={48} /> : 
           status === 'offline' ? <ShieldAlert size={48} /> : 
           <Loader2 size={48} className="animate-spin" />}
        </div>

        <h1 className="text-3xl font-extrabold text-themeDark mb-2">System Health</h1>
        <p className="text-themeDark/60 mb-8 font-light">Real-time status of the BankGuard Intelligence Engine</p>

        <div className="bg-themeLight/30 rounded-xl p-5 mb-8 text-left border border-white/40">
          <div className="flex items-center justify-between mb-4 pb-4 border-b border-themeMid/10">
            <span className="text-themeDark/50 text-xs font-bold uppercase tracking-wider">Status</span>
            <div className="flex items-center gap-2">
              <span className={`w-2 h-2 rounded-full ${status === 'online' ? 'bg-successGreen animate-pulse' : 'bg-dangerRed'}`}></span>
              <span className={`text-sm font-bold ${status === 'online' ? 'text-successGreen' : 'text-dangerRed'}`}>
                {status.toUpperCase()}
              </span>
            </div>
          </div>
          
          <div className="space-y-3">
            <div>
              <span className="block text-themeDark/50 text-[10px] font-bold uppercase mb-1">Target Endpoint</span>
              <code className="text-xs text-themeMid font-mono break-all bg-white/50 px-2 py-1 rounded">{apiUrl}</code>
            </div>
          </div>
        </div>

        <button 
          onClick={checkHealth}
          disabled={status === 'checking'}
          className="w-full bg-themeMid hover:bg-themeDark text-white py-4 rounded-xl font-bold transition-all shadow-lg active:scale-95 disabled:opacity-50 flex items-center justify-center gap-2"
        >
          {status === 'checking' ? <Loader2 size={18} className="animate-spin" /> : <Activity size={18} />}
          RE-SCAN BACKEND
        </button>
      </div>
    </div>
  );
}
