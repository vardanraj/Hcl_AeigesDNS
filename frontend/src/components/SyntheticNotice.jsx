import React from 'react';
import { AlertTriangle, Info } from 'lucide-react';

export default function SyntheticNotice({ isSynthetic }) {
  if (!isSynthetic) return null;

  return (
    <div className="bg-amber-950/40 border border-amber-500/40 rounded-lg p-3 text-amber-200 text-xs sm:text-sm flex items-start gap-3 shadow-md backdrop-blur-sm">
      <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
      <div className="space-y-1">
        <div className="font-semibold flex items-center gap-2 text-amber-300">
          <span>Synthetic Dataset Mode Active</span>
          <span className="bg-amber-500/20 text-amber-300 text-[10px] font-mono px-2 py-0.5 rounded border border-amber-500/30 uppercase tracking-wider">
            LABELED SYNTHETIC
          </span>
        </div>
        <p className="text-amber-200/80 leading-relaxed">
          The current analysis results are generated using the AegisDNS synthetic traffic generator containing simulated DNS tunneling, C2 beacons, and high-entropy hard-benign samples.
        </p>
      </div>
    </div>
  );
}
