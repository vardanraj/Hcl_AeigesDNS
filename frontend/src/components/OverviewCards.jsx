import React from 'react';
import { Database, AlertTriangle, Radio, HardDriveDownload, Gauge } from 'lucide-react';

export default function OverviewCards({ summary }) {
  if (!summary) return null;

  const formatBytes = (bytes) => {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  };

  const cards = [
    {
      title: 'Total DNS Queries',
      value: summary.total_queries?.toLocaleString() || 0,
      sub: `${summary.unique_domains_count || 0} Domains | ${summary.unique_src_ips_count || 0} IPs`,
      icon: Database,
      color: 'text-cyan-400',
      borderColor: 'border-cyan-500/20',
      bgGlow: 'bg-cyan-500/5',
    },
    {
      title: 'Incidents Detected',
      value: summary.total_incidents || 0,
      sub: `Critical: ${summary.severity_breakdown?.Critical || 0} | High: ${summary.severity_breakdown?.High || 0}`,
      icon: AlertTriangle,
      color: summary.total_incidents > 0 ? 'text-amber-400' : 'text-slate-400',
      borderColor: summary.total_incidents > 0 ? 'border-amber-500/30' : 'border-slate-800',
      bgGlow: 'bg-amber-500/5',
    },
    {
      title: 'C2 Heartbeat Beacons',
      value: summary.c2_beacon_count || 0,
      sub: 'Low-jitter periodic timing',
      icon: Radio,
      color: summary.c2_beacon_count > 0 ? 'text-rose-400' : 'text-slate-400',
      borderColor: summary.c2_beacon_count > 0 ? 'border-rose-500/30' : 'border-slate-800',
      bgGlow: 'bg-rose-500/5',
    },
    {
      title: 'Payload Exfiltrated',
      value: formatBytes(summary.total_exfil_bytes || 0),
      sub: 'Cumulative payload volume',
      icon: HardDriveDownload,
      color: 'text-purple-400',
      borderColor: 'border-purple-500/20',
      bgGlow: 'bg-purple-500/5',
    },
    {
      title: 'Mean Entropy',
      value: `${summary.avg_entropy || 0.0} bits`,
      sub: 'Calculated Shannon Entropy',
      icon: Gauge,
      color: summary.avg_entropy > 3.8 ? 'text-amber-400' : 'text-emerald-400',
      borderColor: 'border-slate-800',
      bgGlow: 'bg-emerald-500/5',
    },
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
      {cards.map((card, idx) => {
        const Icon = card.icon;
        return (
          <div
            key={idx}
            className={`bg-slate-900/90 border ${card.borderColor} ${card.bgGlow} rounded-xl p-4 flex flex-col justify-between shadow-lg transition-all hover:border-slate-700`}
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-slate-400 tracking-wide uppercase">
                {card.title}
              </span>
              <Icon className={`w-4 h-4 ${card.color}`} />
            </div>
            <div className="mt-3">
              <div className={`text-2xl font-bold font-mono tracking-tight text-slate-100`}>
                {card.value}
              </div>
              <div className="text-[11px] text-slate-400 mt-1 truncate">
                {card.sub}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
