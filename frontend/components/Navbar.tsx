"use client";

import { useState } from 'react';
import Link from 'next/link';
import { ShieldAlert, Fingerprint, Menu, X } from 'lucide-react';

export default function Navbar() {
  const [isOpen, setIsOpen] = useState(false);

  return (
    <nav className="fixed top-0 w-full z-50 bg-white/70 backdrop-blur-md border-b border-themeLight/50 px-6 py-3 flex items-center justify-between shadow-sm">
      <Link href="/" className="flex items-center gap-2 group">
        <div className="bg-themeLight/30 p-2 rounded-xl group-hover:bg-themeLight/60 transition-all">
          <ShieldAlert className="w-5 h-5 text-themeMid group-hover:scale-110 transition-transform duration-300" />
        </div>
        <span className="text-xl font-semibold tracking-tight text-themeDark">Bank<span className="text-themeMid">Guard</span></span>
      </Link>

      {/* Desktop Navigation Links */}
      <div className="hidden md:flex gap-6 font-medium text-sm items-center">
        <Link href="/" className="text-themeDark/80 hover:text-themeMid transition-colors">
          Home
        </Link>
        <Link href="/verify" className="text-themeDark/80 hover:text-themeMid transition-colors">
          Verify Portal
        </Link>
        <Link href="/scan" className="text-themeDark/80 hover:text-themeMid transition-colors">
          APK Scanner
        </Link>
        <Link href="/insights" className="text-themeDark/80 hover:text-themeMid transition-colors">
          AI Insights
        </Link>
        <Link href="/health" className="text-themeDark/80 hover:text-themeMid transition-colors">
          System Health
        </Link>
        <Link href="/dashboard" className="text-white bg-themeMid hover:bg-themeDark px-4 py-2 rounded-full transition-all flex items-center gap-2 shadow-sm">
           <Fingerprint className="w-4 h-4" />
           Dashboard
        </Link>
      </div>

      {/* Mobile Toggle Button */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="p-2 text-themeDark/60 hover:text-themeMid rounded-xl hover:bg-themeLight/30 md:hidden transition-all focus:outline-none"
        aria-label="Toggle menu"
      >
        {isOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
      </button>

      {/* Mobile Navigation Dropdown */}
      {isOpen && (
        <div className="absolute top-full left-0 w-full bg-white/95 backdrop-blur-md border-b border-themeLight/50 px-6 py-4 flex flex-col gap-4 md:hidden shadow-lg animate-in slide-in-from-top-5 duration-200">
          <Link 
            href="/" 
            onClick={() => setIsOpen(false)} 
            className="text-themeDark/80 hover:text-themeMid transition-colors py-1.5 border-b border-themeLight/20 font-medium text-sm"
          >
            Home
          </Link>
          <Link 
            href="/verify" 
            onClick={() => setIsOpen(false)} 
            className="text-themeDark/80 hover:text-themeMid transition-colors py-1.5 border-b border-themeLight/20 font-medium text-sm"
          >
            Verify Portal
          </Link>
          <Link 
            href="/scan" 
            onClick={() => setIsOpen(false)} 
            className="text-themeDark/80 hover:text-themeMid transition-colors py-1.5 border-b border-themeLight/20 font-medium text-sm"
          >
            APK Scanner
          </Link>
          <Link 
            href="/health" 
            onClick={() => setIsOpen(false)} 
            className="text-themeDark/80 hover:text-themeMid transition-colors py-1.5 border-b border-themeLight/20 font-medium text-sm"
          >
            System Health
          </Link>
          <Link 
            href="/dashboard" 
            onClick={() => setIsOpen(false)} 
            className="text-white bg-themeMid hover:bg-themeDark px-4 py-3 rounded-xl transition-all flex items-center justify-center gap-2 shadow-sm font-semibold text-sm"
          >
             <Fingerprint className="w-4 h-4" />
             Dashboard
          </Link>
        </div>
      )}
    </nav>
  );
}
