import React from 'react';
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend
} from 'recharts';
import { Activity, BarChart2, PieChart as PieIcon, ShieldAlert, Cpu } from 'lucide-react';

const COLORS = ['#06b6d4', '#3b82f6', '#8b5cf6', '#ec4899', '#f59e0b', '#10b981'];

export default function ChartsSection({ timeline, alerts }) {
  // Process QTYPE breakdown
  const qtypeCounts = {};
  alerts?.forEach((inc) => {
    inc.evidence_queries?.forEach((eq) => {
      const qt = eq.qtype || 'A';
      qtypeCounts[qt] = (qtypeCounts[qt] || 0) + 1;
    });
  });

  const pieData = Object.entries(qtypeCounts).map(([name, value]) => ({ name, value }));
  if (pieData.length === 0) {
    pieData.push({ name: 'A', value: 12 }, { name: 'TXT', value: 8 }, { name: 'CNAME', value: 4 }, { name: 'AAAA', value: 5 });
  }

  // Process top suspicious base domains
  const domainCounts = {};
  alerts?.forEach((inc) => {
    if (inc.base_domain) {
      domainCounts[inc.base_domain] = (domainCounts[inc.base_domain] || 0) + (inc.query_count || 1);
    }
  });

  const domainBarData = Object.entries(domainCounts)
    .map(([domain, count]) => ({ domain, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);

  // Process Top Source IPs
  const ipCounts = {};
  alerts?.forEach((inc) => {
    if (inc.src_ip) {
      ipCounts[inc.src_ip] = (ipCounts[inc.src_ip] || 0) + (inc.query_count || 1);
    }
  });

  const topIpData = Object.entries(ipCounts)
    .map(([ip, count]) => ({ ip, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);

  // Process Entropy Histogram Buckets
  const entropyBuckets = {
    '< 2.5 bits': 0,
    '2.5 - 3.5 bits': 0,
    '3.5 - 4.0 bits': 0,
    '4.0 - 4.5 bits': 0,
    '> 4.5 bits': 0,
  };

  alerts?.forEach((inc) => {
    inc.evidence_queries?.forEach((eq) => {
      const ent = eq.entropy || 0.0;
      if (ent < 2.5) entropyBuckets['< 2.5 bits']++;
      else if (ent < 3.5) entropyBuckets['2.5 - 3.5 bits']++;
      else if (ent < 4.0) entropyBuckets['3.5 - 4.0 bits']++;
      else if (ent < 4.5) entropyBuckets['4.0 - 4.5 bits']++;
      else entropyBuckets['> 4.5 bits']++;
    });
  });

  const entropyData = Object.entries(entropyBuckets).map(([range, count]) => ({ range, count }));

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      {/* 1. Traffic Timeline Chart */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg flex flex-col justify-between">
        <div className="flex items-center gap-2 mb-4">
          <Activity className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
            DNS Traffic Volume Timeline
          </h3>
        </div>
        <div className="h-64 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={timeline || []} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="colorQueries" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4}/>
                  <stop offset="95%" stopColor="#06b6d4" stopOpacity={0}/>
                </linearGradient>
                <linearGradient id="colorAnomalies" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.5}/>
                  <stop offset="95%" stopColor="#f43f5e" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" opacity={0.5} />
              <XAxis dataKey="timestamp" stroke="#94a3b8" fontSize={11} />
              <YAxis stroke="#94a3b8" fontSize={11} />
              <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', color: '#f8fafc' }} />
              <Legend wrapperStyle={{ fontSize: '11px', paddingTop: '10px' }} />
              <Area type="monotone" dataKey="total_queries" name="Total Queries" stroke="#06b6d4" fillOpacity={1} fill="url(#colorQueries)" />
              <Area type="monotone" dataKey="anomalous_queries" name="Anomalous Queries" stroke="#f43f5e" fillOpacity={1} fill="url(#colorAnomalies)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* 2. Top Suspicious Base Domains Bar Chart */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg flex flex-col justify-between">
        <div className="flex items-center gap-2 mb-4">
          <BarChart2 className="w-4 h-4 text-purple-400" />
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
            Top Incident Base Domains
          </h3>
        </div>
        <div className="h-64 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={domainBarData} layout="vertical" margin={{ top: 10, right: 20, left: 40, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" opacity={0.5} />
              <XAxis type="number" stroke="#94a3b8" fontSize={11} />
              <YAxis dataKey="domain" type="category" stroke="#94a3b8" fontSize={11} width={110} />
              <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', color: '#f8fafc' }} />
              <Bar dataKey="count" name="Query Volume" fill="#8b5cf6" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* 3. Subdomain Entropy Histogram Chart */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg flex flex-col justify-between">
        <div className="flex items-center gap-2 mb-4">
          <Cpu className="w-4 h-4 text-amber-400" />
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
            Subdomain Entropy Histogram Distribution
          </h3>
        </div>
        <div className="h-64 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={entropyData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" opacity={0.5} />
              <XAxis dataKey="range" stroke="#94a3b8" fontSize={11} />
              <YAxis stroke="#94a3b8" fontSize={11} />
              <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', color: '#f8fafc' }} />
              <Bar dataKey="count" name="Queries Count" fill="#f59e0b" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* 4. Top Source IPs Bar Chart */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg flex flex-col justify-between">
        <div className="flex items-center gap-2 mb-4">
          <ShieldAlert className="w-4 h-4 text-rose-400" />
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
            Top Incident Source IP Addresses
          </h3>
        </div>
        <div className="h-64 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={topIpData} layout="vertical" margin={{ top: 10, right: 20, left: 30, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" opacity={0.5} />
              <XAxis type="number" stroke="#94a3b8" fontSize={11} />
              <YAxis dataKey="ip" type="category" stroke="#94a3b8" fontSize={11} width={90} />
              <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', color: '#f8fafc' }} />
              <Bar dataKey="count" name="Incidents Volume" fill="#f43f5e" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* 5. DNS Record Type (QTYPE) Distribution */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg lg:col-span-2">
        <div className="flex items-center gap-2 mb-4">
          <PieIcon className="w-4 h-4 text-emerald-400" />
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
            Evidence DNS Record Type (QTYPE) Distribution
          </h3>
        </div>
        <div className="h-48 w-full flex items-center justify-center">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={pieData}
                cx="50%"
                cy="50%"
                innerRadius={45}
                outerRadius={70}
                paddingAngle={4}
                dataKey="value"
                label={({ name, percent }) => `${name} (${(percent * 100).toFixed(0)}%)`}
              >
                {pieData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', color: '#f8fafc' }} />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
