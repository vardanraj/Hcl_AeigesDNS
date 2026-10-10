import React, { useState } from 'react';
import { ShieldAlert, Download, Search, Filter, ChevronRight, X, Terminal, CheckCircle2 } from 'lucide-react';
import { getExportUrl } from '../api';

export default function AlertsTable({ incidents }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('All');
  const [hideLowSingleQuery, setHideLowSingleQuery] = useState(false);
  const [selectedIncident, setSelectedIncident] = useState(null);

  const filteredIncidents = (incidents || []).filter((inc) => {
    const isLowSingleQuery = inc.severity?.toLowerCase() === 'low' && (inc.query_count || 1) <= 1;
    if (hideLowSingleQuery && isLowSingleQuery) return false;

    const matchesSearch =
      inc.base_domain?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      inc.src_ip?.includes(searchTerm) ||
      inc.incident_id?.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesSeverity =
      severityFilter === 'All' || inc.severity?.toLowerCase() === severityFilter.toLowerCase();

    return matchesSearch && matchesSeverity;
  });

  const getSeverityBadge = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return 'bg-rose-950/80 text-rose-300 border-rose-500/40';
      case 'high':
        return 'bg-orange-950/80 text-orange-300 border-orange-500/40';
      case 'medium':
        return 'bg-amber-950/80 text-amber-300 border-amber-500/40';
      default:
        return 'bg-sky-950/80 text-sky-300 border-sky-500/40';
    }
  };

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
      {/* Controls Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-5 h-5 text-cyan-400" />
          <h2 className="text-sm font-semibold text-slate-200 uppercase tracking-wider">
            Incident Alerts ({filteredIncidents.length})
          </h2>
        </div>

        {/* Search, Filter & Downloads */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search domain, IP, ID..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-slate-950 border border-slate-700 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 w-44 sm:w-60"
            />
          </div>

          <div className="flex items-center gap-1 bg-slate-950 border border-slate-700 rounded-lg px-2 py-1.5 text-xs text-slate-300">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-transparent text-xs text-slate-200 focus:outline-none cursor-pointer"
            >
              <option value="All" className="bg-slate-900">All Severities</option>
              <option value="Critical" className="bg-slate-900">Critical</option>
              <option value="High" className="bg-slate-900">High</option>
              <option value="Medium" className="bg-slate-900">Medium</option>
              <option value="Low" className="bg-slate-900">Low</option>
            </select>
          </div>

          {/* Toggle for Low single-query filter */}
          <label className="flex items-center gap-1.5 text-xs text-slate-300 cursor-pointer bg-slate-950 border border-slate-700 px-2.5 py-1.5 rounded-lg select-none hover:border-slate-600 transition-all">
            <input
              type="checkbox"
              checked={hideLowSingleQuery}
              onChange={(e) => setHideLowSingleQuery(e.target.checked)}
              className="rounded accent-cyan-500 cursor-pointer"
            />
            <span>Hide Low single-query alerts</span>
          </label>

          {/* Export Buttons */}
          <div className="flex items-center gap-2">
            <a
              href={getExportUrl('csv')}
              download="aegisdns_incidents.csv"
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg text-xs font-medium text-slate-200 flex items-center gap-1.5 transition-all"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" /> CSV
            </a>
            <a
              href={getExportUrl('json')}
              download="aegisdns_incidents.json"
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg text-xs font-medium text-slate-200 flex items-center gap-1.5 transition-all"
            >
              <Download className="w-3.5 h-3.5 text-purple-400" /> JSON
            </a>
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto rounded-lg border border-slate-800">
        <table className="w-full text-left text-xs text-slate-300">
          <thead className="bg-slate-950 text-slate-400 uppercase tracking-wider border-b border-slate-800 font-mono text-[11px]">
            <tr>
              <th className="px-4 py-3">Incident ID</th>
              <th className="px-4 py-3">Severity</th>
              <th className="px-4 py-3">Risk Score</th>
              <th className="px-4 py-3">Source IP</th>
              <th className="px-4 py-3">Base Domain</th>
              <th className="px-4 py-3">Triggered Rules</th>
              <th className="px-4 py-3 text-right">Details</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 bg-slate-900/40">
            {filteredIncidents.length === 0 ? (
              <tr>
                <td colSpan={7} className="text-center py-8 text-slate-400">
                  No matching incidents found.
                </td>
              </tr>
            ) : (
              filteredIncidents.map((inc) => (
                <tr
                  key={inc.incident_id}
                  onClick={() => setSelectedIncident(inc)}
                  className="hover:bg-slate-800/50 transition-all cursor-pointer group"
                >
                  <td className="px-4 py-3 font-mono font-medium text-cyan-400">
                    {inc.incident_id}
                  </td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${getSeverityBadge(inc.severity)}`}>
                      {inc.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3 font-mono font-bold text-slate-100">
                    {inc.risk_score}
                  </td>
                  <td className="px-4 py-3 font-mono text-slate-300">
                    {inc.src_ip}
                  </td>
                  <td className="px-4 py-3 font-medium text-slate-200">
                    {inc.base_domain}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {inc.triggered_rules?.slice(0, 2).map((r, i) => (
                        <span key={i} className="bg-slate-800 text-slate-300 px-1.5 py-0.5 rounded text-[10px] border border-slate-700">
                          {r}
                        </span>
                      ))}
                      {inc.triggered_rules?.length > 2 && (
                        <span className="text-[10px] text-slate-400">+{inc.triggered_rules.length - 2} more</span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button className="text-cyan-400 group-hover:text-cyan-300 font-medium flex items-center gap-0.5 justify-end ml-auto">
                      View <ChevronRight className="w-3.5 h-3.5" />
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Detail Forensic Modal Drawer */}
      {selectedIncident && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-2xl max-w-2xl w-full p-6 shadow-2xl space-y-5 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div>
                <span className="text-xs font-mono text-cyan-400 uppercase">{selectedIncident.incident_id}</span>
                <h3 className="text-lg font-bold text-slate-100">Forensic Incident Detail</h3>
              </div>
              <button
                onClick={() => setSelectedIncident(null)}
                className="p-1 text-slate-400 hover:text-white rounded-lg bg-slate-800"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Subscores Grid */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-slate-950 p-4 rounded-xl border border-slate-800 text-center">
              <div>
                <span className="text-[10px] text-slate-400 uppercase font-mono">Rule Score</span>
                <div className="text-base font-bold text-cyan-400 font-mono">{selectedIncident.rule_score}</div>
              </div>
              <div>
                <span className="text-[10px] text-slate-400 uppercase font-mono">Beacon Score</span>
                <div className="text-base font-bold text-rose-400 font-mono">{selectedIncident.beacon_score}</div>
              </div>
              <div>
                <span className="text-[10px] text-slate-400 uppercase font-mono">Exfil Score</span>
                <div className="text-base font-bold text-purple-400 font-mono">{selectedIncident.exfiltration_score}</div>
              </div>
              <div>
                <span className="text-[10px] text-slate-400 uppercase font-mono">ML Anomaly Prob</span>
                <div className="text-base font-bold text-amber-400 font-mono">{selectedIncident.ml_probability}</div>
              </div>
            </div>

            {/* Actionable Recommendation */}
            <div className="bg-emerald-950/40 border border-emerald-500/30 p-4 rounded-xl text-xs text-emerald-200 flex items-start gap-3">
              <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
              <div>
                <strong className="text-emerald-300 block mb-0.5">Recommended Remediation Action:</strong>
                {selectedIncident.recommended_action}
              </div>
            </div>

            {/* Evidence Queries Table */}
            <div>
              <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
                Evidence DNS Queries ({selectedIncident.evidence_queries?.length || 0})
              </h4>
              <div className="bg-slate-950 border border-slate-800 rounded-lg overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-slate-900 text-slate-400 border-b border-slate-800">
                    <tr>
                      <th className="p-2">QNAME</th>
                      <th className="p-2">Type</th>
                      <th className="p-2">Entropy</th>
                      <th className="p-2">Subdomain Len</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800 text-slate-300">
                    {selectedIncident.evidence_queries?.map((eq, i) => (
                      <tr key={i}>
                        <td className="p-2 truncate max-w-xs text-cyan-300">{eq.qname}</td>
                        <td className="p-2">{eq.qtype}</td>
                        <td className="p-2">{eq.entropy} bits</td>
                        <td className="p-2">{eq.subdomain_len} chars</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
