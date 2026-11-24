"use client";

import { useState } from 'react';
import { QrCode, Phone, Mail, FileText, CheckCircle2, ShieldX, Copy, Check } from 'lucide-react';

interface TestVector {
  id: string;
  type: 'upi' | 'mobile' | 'email' | 'bank_account';
  value: string;
  label: string;
  risk: 'Very High' | 'High' | 'Safe';
  category: string;
  scenario: string;
  qrPayload?: string;
}

const testVectors: TestVector[] = [
  // --- UPI QRs ---
  {
    id: 'VEC001',
    type: 'upi',
    value: 'fake.reward@ybl',
    label: 'Jio/UPI Fake Reward Claim',
    risk: 'Very High',
    category: 'UPI Fraud',
    scenario: 'Associated with fraudulent reward messages sent via SMS/WhatsApp pretending to be reward redemption links.',
    qrPayload: 'upi://pay?pa=fake.reward@ybl&pn=SBI%20Reward%20Point&am=100&cu=INR&tn=SBI%20Reward%20Redemption'
  },
  {
    id: 'VEC002',
    type: 'upi',
    value: 'reward.claim@ybl',
    label: 'Reward Point Scam Handle',
    risk: 'Very High',
    category: 'UPI Fraud',
    scenario: 'Used as direct collection handles in SMS phishing campaigns targeting rural and semi-urban bank users.',
    qrPayload: 'upi://pay?pa=reward.claim@ybl&pn=Cashback%20Reward&am=250&cu=INR&tn=Redeem%20Cashback'
  },
  {
    id: 'VEC003',
    type: 'upi',
    value: 'kyc-verify@oksbi',
    label: 'Phishing KYC Verification Handle',
    risk: 'High',
    category: 'Fake KYC',
    scenario: 'Used in credential-harvesting phishing campaigns impersonating the bank\'s official KYC procedures.',
    qrPayload: 'upi://pay?pa=kyc-verify@oksbi&pn=SBI%20KYC%20Verification&am=1&cu=INR&tn=KYC%20Verification%20Fee'
  },
  {
    id: 'VEC004',
    type: 'upi',
    value: 'jiomoney@ybl',
    label: 'Fake Jio Prepaid Recharge (Matches TXN010)',
    risk: 'High',
    category: 'UPI Fraud',
    scenario: 'Impersonates Jio prepaid channel. Used in campaigns where users are charged but receive no recharge.',
    qrPayload: 'upi://pay?pa=jiomoney@ybl&pn=Jio%20Prepaid%20Recharge&am=399&cu=INR&tn=Recharge%20Jio%20Prepaid'
  },
  {
    id: 'VEC005',
    type: 'upi',
    value: 'pharmeasy@paytm',
    label: 'Fake PharmEasy Medicine Deals (Matches TXN020)',
    risk: 'High',
    category: 'UPI Fraud',
    scenario: 'Impersonates PharmEasy handle. Advertises steep social media discounts to collect payment details.',
    qrPayload: 'upi://pay?pa=pharmeasy@paytm&pn=PharmEasy%20Order&am=856&cu=INR&tn=Medicine%20Delivery%20Payment'
  },
  {
    id: 'VEC006',
    type: 'upi',
    value: 'legitimate@oksbi',
    label: 'Legitimate Merchant (Safe Test)',
    risk: 'Safe',
    category: 'N/A',
    scenario: 'A clean, official merchant QR code to test the successful path with no warnings.',
    qrPayload: 'upi://pay?pa=legitimate@oksbi&pn=Official%20Legit%20Store&am=200&cu=INR&tn=Purchase%20Receipt'
  },
  // --- Mobile Numbers ---
  {
    id: 'VEC007',
    type: 'mobile',
    value: '9876543210',
    label: 'Amit Kumar Mule Account (Matches TXN007)',
    risk: 'Very High',
    category: 'Vishing',
    scenario: 'Mobile number linked to an active money-mule network. Receives funds via IMPS from digital arrest victims.'
  },
  {
    id: 'VEC008',
    type: 'mobile',
    value: '+919123456789',
    label: 'SMS KYC Phishing Sender',
    risk: 'High',
    category: 'Fake KYC',
    scenario: 'Used to send automated bulk SMS messages containing urgency-based KYC expiry warning links.'
  },
  {
    id: 'VEC009',
    type: 'mobile',
    value: '9999911111',
    label: 'SIM Swap Suspect Number',
    risk: 'High',
    category: 'SIM Swap',
    scenario: 'Linked to porting requests and spoofing requests targeting SIM swap fraud.'
  },
  // --- Emails & Accounts ---
  {
    id: 'VEC010',
    type: 'email',
    value: 'kyc.support@gmail-fake.com',
    label: 'Fake KYC Helpdesk Email',
    risk: 'High',
    category: 'Fake KYC',
    scenario: 'Email sender address used in document-harvesting scams asking for identity cards and bank details.'
  },
  {
    id: 'VEC011',
    type: 'email',
    value: 'attacker.c2@secure-mail.xyz',
    label: 'Malicious APK C2 Destination',
    risk: 'Very High',
    category: 'OTP Theft',
    scenario: 'Destination address for credentials and OTPs sent by side-loaded lookalike apps.'
  },
  {
    id: 'VEC012',
    type: 'bank_account',
    value: '9876543210123',
    label: 'Mahesh Agarwal (Matches TXN003)',
    risk: 'High',
    category: 'Vishing',
    scenario: 'Identified money-mule bank account used to transfer funds out of scam victim accounts.'
  },
  {
    id: 'VEC013',
    type: 'bank_account',
    value: '1234567890456',
    label: 'LIC of India (Matches TXN012)',
    risk: 'Safe',
    category: 'N/A',
    scenario: 'Safe insurance premium collection account. Tests clean verification path.'
  },
  {
    id: 'VEC014',
    type: 'bank_account',
    value: '38901234567890',
    label: 'SBI Auto Loan (Matches TXN024)',
    risk: 'Safe',
    category: 'N/A',
    scenario: 'Official bank auto loan EMI account. Tests clean verification path.'
  }
];

export default function DummyFriPage() {
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'all' | 'upi' | 'mobile' | 'other'>('all');

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const filteredVectors = testVectors.filter(vec => {
    if (activeTab === 'all') return true;
    if (activeTab === 'upi') return vec.type === 'upi';
    if (activeTab === 'mobile') return vec.type === 'mobile';
    return vec.type === 'email' || vec.type === 'bank_account';
  });

  return (
    <div className="h-full flex flex-col justify-center max-w-5xl mx-auto py-2 animate-in fade-in duration-500">
      
      {/* Header */}
      <div className="text-center mb-8">
        <div className="inline-flex items-center justify-center p-3 bg-white/60 rounded-xl mb-4 shadow-sm border border-themeLight/50">
          <QrCode className="w-6 h-6 text-themeMid" strokeWidth={1.5} />
        </div>
        <h1 className="text-3xl font-extrabold mb-2 text-themeDark tracking-tight">FRI Sandbox & Testing Hub</h1>
        <p className="text-themeDark/60 text-lg font-light max-w-2xl mx-auto">
          Scan the QR codes using your BankGuard mobile app scanner or copy the identifiers to test the fund transfer warnings.
        </p>
      </div>

      {/* Tabs */}
      <div className="flex flex-wrap justify-center gap-1.5 sm:gap-2 mb-8 bg-white/50 p-1.5 rounded-xl border border-themeLight/30 max-w-md mx-auto shadow-sm">
        <button
          onClick={() => setActiveTab('all')}
          className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${activeTab === 'all' ? 'bg-themeMid text-white shadow-sm' : 'text-themeDark/60 hover:text-themeDark hover:bg-white/40'}`}
        >
          All
        </button>
        <button
          onClick={() => setActiveTab('upi')}
          className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${activeTab === 'upi' ? 'bg-themeMid text-white shadow-sm' : 'text-themeDark/60 hover:text-themeDark hover:bg-white/40'}`}
        >
          UPI QRs
        </button>
        <button
          onClick={() => setActiveTab('mobile')}
          className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${activeTab === 'mobile' ? 'bg-themeMid text-white shadow-sm' : 'text-themeDark/60 hover:text-themeDark hover:bg-white/40'}`}
        >
          Mobiles
        </button>
        <button
          onClick={() => setActiveTab('other')}
          className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${activeTab === 'other' ? 'bg-themeMid text-white shadow-sm' : 'text-themeDark/60 hover:text-themeDark hover:bg-white/40'}`}
        >
          Emails & Accounts
        </button>
      </div>

      {/* Vectors Grid */}
      <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
        {filteredVectors.map((vec) => {
          const isSafe = vec.risk === 'Safe';
          const isVeryHigh = vec.risk === 'Very High';
          const badgeColor = isSafe 
            ? 'bg-successGreen/10 text-successGreen border-successGreen/20' 
            : isVeryHigh 
              ? 'bg-dangerRed/10 text-dangerRed border-dangerRed/20' 
              : 'bg-warningYellow/10 text-warningYellow border-warningYellow/20';

          return (
            <div 
              key={vec.id} 
              className={`glass-card p-5 flex flex-col justify-between hover:scale-[1.01] hover:bg-white/95 transition-all duration-300 ${!isSafe ? 'border-t-2 ' + (isVeryHigh ? 'border-t-dangerRed' : 'border-t-warningYellow') : ''}`}
            >
              <div>
                {/* Header Row */}
                <div className="flex items-start justify-between gap-2 mb-3">
                  <span className={`text-[10px] uppercase font-mono tracking-wider px-2 py-0.5 rounded-full border ${badgeColor}`}>
                    {vec.risk === 'Safe' ? 'Verified Safe' : `${vec.risk} Risk`}
                  </span>
                  <span className="text-[10px] text-themeDark/30 font-mono">#{vec.id}</span>
                </div>

                {/* Vector Details */}
                <h3 className="text-base font-bold text-themeDark mb-1">{vec.label}</h3>
                <p className="text-xs text-themeDark/40 font-mono mb-3 bg-themeLight/20 px-2.5 py-1.5 rounded-lg flex items-center justify-between gap-1 overflow-x-auto whitespace-nowrap">
                  <span>{vec.value}</span>
                  <button 
                    onClick={() => copyToClipboard(vec.value, vec.id)}
                    className="hover:text-themeMid p-0.5 rounded transition-colors bg-white/60 border border-themeLight/50"
                    title="Copy identifier value"
                  >
                    {copiedId === vec.id ? <Check className="w-3.5 h-3.5 text-successGreen" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </p>

                {/* Scenario details */}
                <div className="space-y-1.5 mb-4">
                  {vec.category !== 'N/A' && (
                    <div className="text-xs flex gap-2">
                      <span className="text-themeDark/40 w-16">Category:</span>
                      <span className="font-semibold text-themeDark/75">{vec.category}</span>
                    </div>
                  )}
                  <p className="text-xs text-themeDark/60 leading-relaxed font-light">{vec.scenario}</p>
                </div>
              </div>

              {/* Action / QR Area */}
              <div className="mt-auto pt-3 border-t border-themeLight/30 flex flex-col items-center">
                {vec.type === 'upi' && vec.qrPayload ? (
                  <div className="w-full flex flex-col items-center">
                    <div className="bg-white p-2 rounded-xl border border-themeLight/60 shadow-sm mb-3">
                      <img 
                        src={`https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=${encodeURIComponent(vec.qrPayload)}`} 
                        alt={vec.label}
                        className="w-36 h-36 select-none"
                      />
                    </div>
                    <button
                      onClick={() => copyToClipboard(vec.qrPayload!, `${vec.id}-qr`)}
                      className="w-full py-1.5 bg-themeLight/30 hover:bg-themeLight/60 border border-themeLight text-themeDark/70 hover:text-themeDark text-xs font-semibold rounded-lg flex items-center justify-center gap-1.5 transition-all"
                    >
                      {copiedId === `${vec.id}-qr` ? (
                        <>
                          <Check className="w-3.5 h-3.5 text-successGreen" />
                          Copied QR URI
                        </>
                      ) : (
                        <>
                          <QrCode className="w-3.5 h-3.5 text-themeMid" />
                          Copy QR URI
                        </>
                      )}
                    </button>
                  </div>
                ) : (
                  <div className="w-full flex items-center justify-center gap-2 py-3 bg-themeLight/10 rounded-lg text-themeDark/40">
                    {vec.type === 'mobile' ? (
                      <Phone className="w-4 h-4 text-themeMid/50" />
                    ) : vec.type === 'email' ? (
                      <Mail className="w-4 h-4 text-themeMid/50" />
                    ) : (
                      <FileText className="w-4 h-4 text-themeMid/50" />
                    )}
                    <span className="text-xs">Copy value to test manual entry</span>
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
