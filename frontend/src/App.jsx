import React, { useState, useEffect } from 'react';
import Header from './components/Header';
import SyntheticNotice from './components/SyntheticNotice';
import OverviewCards from './components/OverviewCards';
import ControlPanel from './components/ControlPanel';
import LiveMonitor from './components/LiveMonitor';
import ChartsSection from './components/ChartsSection';
import AlertsTable from './components/AlertsTable';
import ConfigEditor from './components/ConfigEditor';
import EvaluationSection from './components/EvaluationSection';
import {
  fetchSessionToken,
  getCaptureStatus,
  getSummary,
  getAlerts,
  getTimeline
} from './api';
import { AlertCircle, X } from 'lucide-react';

export default function App() {
  const [summary, setSummary] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [timeline, setTimeline] = useState([]);
  const [captureStatus, setCaptureStatus] = useState(null);
  const [errorMessage, setErrorMessage] = useState(null);
  const [isInitialLoading, setIsInitialLoading] = useState(true);

  useEffect(() => {
    initDashboard();
    const interval = setInterval(refreshStatusAndData, 5000);
    return () => clearInterval(interval);
  }, []);

  const initDashboard = async () => {
    setIsInitialLoading(true);
    await fetchSessionToken();
    await refreshStatusAndData();
    setIsInitialLoading(false);
  };

  const refreshStatusAndData = async () => {
    try {
      const [capRes, sumRes, alertsRes, timeRes] = await Promise.all([
        getCaptureStatus().catch(() => null),
        getSummary().catch(() => null),
        getAlerts().catch(() => ({ incidents: [] })),
        getTimeline().catch(() => []),
      ]);

      if (capRes) setCaptureStatus(capRes);
      if (sumRes) setSummary(sumRes);
      if (alertsRes) setAlerts(alertsRes.incidents || []);
      if (timeRes) setTimeline(timeRes);
    } catch (err) {
      console.error("Dashboard refresh error:", err);
    }
  };

  const handleDataUpdated = (newSummary) => {
    if (newSummary) setSummary(newSummary);
    refreshStatusAndData();
  };

  const handleLiveIncidentReceived = (liveIncidents) => {
    setAlerts((prev) => [...liveIncidents, ...prev]);
    refreshStatusAndData();
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      <Header captureStatus={captureStatus} />

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
        {/* Error Alert Banner */}
        {errorMessage && (
          <div className="bg-rose-950/80 border border-rose-500/40 rounded-xl p-4 text-rose-200 text-xs flex items-center justify-between shadow-lg">
            <div className="flex items-center gap-2">
              <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
              <span>{errorMessage}</span>
            </div>
            <button
              onClick={() => setErrorMessage(null)}
              className="p-1 hover:bg-rose-900/50 rounded"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        )}

        {/* Synthetic Data Disclaimer Notice */}
        <SyntheticNotice isSynthetic={summary?.is_synthetic} />

        {/* Top Metric Cards */}
        <OverviewCards summary={summary} />

        {/* Ingestion Control Panel & Live Monitor */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2">
            <ControlPanel
              captureStatus={captureStatus}
              onDataUpdated={handleDataUpdated}
              onError={setErrorMessage}
            />
          </div>
          <div>
            <LiveMonitor onLiveIncidentReceived={handleLiveIncidentReceived} />
          </div>
        </div>

        {/* Recharts Analytics Section */}
        <ChartsSection timeline={timeline} alerts={alerts} />

        {/* 5-Seed Evaluation Section */}
        <EvaluationSection />

        {/* Filterable Incident Alerts Table & Export */}
        <AlertsTable incidents={alerts} />

        {/* Detection Thresholds Editor */}
        <ConfigEditor
          onConfigSaved={() => refreshStatusAndData()}
          onError={setErrorMessage}
        />
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950/80 py-4 text-center text-xs text-slate-400 font-mono">
        AegisDNS Incident Detection Engine &bull; Synthetic Evaluation Dataset Mode &bull; 127.0.0.1:8000
      </footer>
    </div>
  );
}
