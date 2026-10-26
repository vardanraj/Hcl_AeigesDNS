import React, { useState, useEffect, useRef, useCallback } from 'react';
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
  getTimeline,
  clearData,
} from './api';
import { AlertCircle, X, Trash2, Loader2, Database } from 'lucide-react';

const LIVE_POLL_INTERVAL_MS = 5000;

export default function App() {
  const [summary, setSummary] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [timeline, setTimeline] = useState([]);
  const [captureStatus, setCaptureStatus] = useState(null);
  const [errorMessage, setErrorMessage] = useState(null);
  const [isInitialLoading, setIsInitialLoading] = useState(true);
  const [isClearing, setIsClearing] = useState(false);
  const [hasData, setHasData] = useState(false);

  // Refs for live polling
  const livePollingIntervalRef = useRef(null);
  const pendingRefreshRef = useRef(false);

  useEffect(() => {
    initDashboard();
    return () => {
      stopLivePolling();
    };
  }, []);

  const initDashboard = async () => {
    setIsInitialLoading(true);
    await fetchSessionToken();
    await refreshStatusAndData();
    setIsInitialLoading(false);
  };

  const refreshStatusAndData = useCallback(async () => {
    if (pendingRefreshRef.current) return; // skip if previous request still in flight
    pendingRefreshRef.current = true;
    try {
      const [capRes, sumRes, alertsRes, timeRes] = await Promise.all([
        getCaptureStatus().catch(() => null),
        getSummary().catch(() => null),
        getAlerts().catch(() => ({ incidents: [] })),
        getTimeline().catch(() => []),
      ]);

      if (capRes) {
        setCaptureStatus(capRes);
        // Start / stop live polling based on sniffer state
        if (capRes.is_capturing) {
          startLivePolling();
        } else {
          stopLivePolling();
        }
      }
      if (sumRes) {
        setSummary(sumRes);
        setHasData((sumRes.total_queries || 0) > 0);
      }
      if (alertsRes) setAlerts(alertsRes.incidents || []);
      if (timeRes) setTimeline(Array.isArray(timeRes) ? timeRes : []);
    } catch (err) {
      console.error("Dashboard refresh error:", err);
    } finally {
      pendingRefreshRef.current = false;
    }
  }, []);

  /** Start polling /api/summary, /api/timeline, /api/alerts every 5 s while sniffer is active. */
  const startLivePolling = useCallback(() => {
    if (livePollingIntervalRef.current) return; // already polling
    livePollingIntervalRef.current = setInterval(() => {
      refreshStatusAndData();
    }, LIVE_POLL_INTERVAL_MS);
  }, [refreshStatusAndData]);

  /** Stop the live polling interval. */
  const stopLivePolling = useCallback(() => {
    if (livePollingIntervalRef.current) {
      clearInterval(livePollingIntervalRef.current);
      livePollingIntervalRef.current = null;
    }
  }, []);

  const handleDataUpdated = (newSummary) => {
    if (newSummary) {
      setSummary(newSummary);
      setHasData((newSummary.total_queries || 0) > 0);
    }
    refreshStatusAndData();
  };

  const handleLiveIncidentReceived = (liveIncidents) => {
    // Live WS push still prepends incidents to the local list for immediate feedback
    setAlerts((prev) => [...liveIncidents, ...prev]);
    // Full refresh happens via the polling interval
  };

  const handleClearData = async () => {
    setIsClearing(true);
    try {
      await clearData();
      setSummary(null);
      setAlerts([]);
      setTimeline([]);
      setHasData(false);
    } catch (err) {
      setErrorMessage(err.message || "Failed to clear data.");
    } finally {
      setIsClearing(false);
    }
  };

  // ── Empty state ────────────────────────────────────────────────────────────
  const showEmptyState = !isInitialLoading && !hasData;

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

        {/* Top row: Overview Cards + Clear Data button */}
        <div className="flex items-start justify-between gap-4">
          <div className="flex-1 min-w-0">
            <OverviewCards summary={summary} />
          </div>
          {hasData && (
            <button
              onClick={handleClearData}
              disabled={isClearing}
              className="mt-0 shrink-0 flex items-center gap-1.5 px-3 py-2 bg-slate-800 hover:bg-rose-900/60 border border-slate-700 hover:border-rose-500/50 text-slate-300 hover:text-rose-300 rounded-lg text-xs font-medium transition-all"
              title="Clear all loaded data from memory"
            >
              {isClearing ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <Trash2 className="w-3.5 h-3.5" />
              )}
              Clear Data
            </button>
          )}
        </div>

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

        {/* Empty state message */}
        {showEmptyState && (
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-10 flex flex-col items-center justify-center text-center gap-3 shadow-lg">
            <Database className="w-10 h-10 text-slate-600" />
            <p className="text-slate-300 font-medium text-sm">No data yet. Upload a PCAP, start the live sniffer, or generate synthetic traffic.</p>
          </div>
        )}

        {/* Charts — only show when there is data */}
        {hasData && <ChartsSection timeline={timeline} alerts={alerts} />}

        {/* 5-Seed Evaluation Section — always visible */}
        <EvaluationSection />

        {/* Incident Alerts Table — only show when there is data */}
        {hasData && <AlertsTable incidents={alerts} />}

        {/* Detection Thresholds Editor — always visible */}
        <ConfigEditor
          onConfigSaved={() => refreshStatusAndData()}
          onError={setErrorMessage}
        />
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950/80 py-4 text-center text-xs text-slate-400 font-mono">
        AegisDNS Incident Detection Engine &bull; Real-time DNS Tunneling Detection &bull; 127.0.0.1:8000
      </footer>
    </div>
  );
}
