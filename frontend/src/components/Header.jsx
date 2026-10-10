import React from 'react';
import { ShieldAlert, Activity, AlertOctagon, Terminal } from 'lucide-react';

export default function Header({ captureStatus }) {
  const isCapturing = captureStatus?.is_capturing;
  const npcapAvailable = captureStatus?.npcap_available;
  const errorMessage = captureStatus?.error_message;

  return (
    <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur-md sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-3.5 flex flex-wrap items-center justify-between gap-4">
        {/* Brand */}
        <div className="flex items-center gap-3">
          <div className="p-2 bg-cyan-500/10 border border-cyan-500/30 rounded-lg text-cyan-400">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div>
            <h1 className="font-bold text-lg text-slate-100 tracking-tight flex items-center gap-2">
              AegisDNS
              <span className="text-xs px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800/50 font-mono">
                v1.0.0
              </span>
            </h1>
            <p className="text-xs text-slate-400">
              DNS Tunneling, Exfiltration & C2 Beacon Detection Engine
            </p>
          </div>
        </div>

        {/* Live Sniffer Status Badge */}
        <div className="flex items-center gap-3">
          <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full border text-xs font-medium ${
            isCapturing
              ? 'bg-emerald-950/60 border-emerald-500/40 text-emerald-300 animate-pulse'
              : 'bg-slate-800/60 border-slate-700 text-slate-400'
          }`}>
            <Activity className={`w-3.5 h-3.5 ${isCapturing ? 'text-emerald-400' : 'text-slate-500'}`} />
            <span>{isCapturing ? 'LIVE SNIFFER ACTIVE (PORT 53)' : 'SNIFFER IDLE'}</span>
          </div>

          <div className="text-xs text-slate-400 hidden sm:block font-mono bg-slate-900 px-2.5 py-1 rounded border border-slate-800">
            127.0.0.1:8000
          </div>
        </div>
      </div>

      {/* Npcap / Permission Warning Banner if missing on Windows */}
      {!npcapAvailable && (
        <div className="bg-rose-950/60 border-y border-rose-500/30 px-4 py-2 text-xs text-rose-200 flex items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <AlertOctagon className="w-4 h-4 text-rose-400 shrink-0" />
            <span>
              <strong>Windows Sniffer Notice:</strong> Live capture requires Npcap with 'WinPcap API Compatibility' mode. PCAP upload mode remains fully operational.
            </span>
          </div>
          <a
            href="https://npcap.com/"
            target="_blank"
            rel="noopener noreferrer"
            className="underline text-rose-300 hover:text-white shrink-0 font-medium"
          >
            Download Npcap
          </a>
        </div>
      )}
    </header>
  );
}
