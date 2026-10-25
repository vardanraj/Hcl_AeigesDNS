import React, { useEffect, useState, useRef } from 'react';
import { Activity, Radio, AlertTriangle, ShieldCheck } from 'lucide-react';
import { fetchSessionToken } from '../api';

export default function LiveMonitor({ onLiveIncidentReceived }) {
  const [messages, setMessages] = useState([]);
  const [wsStatus, setWsStatus] = useState('connecting');
  const wsRef = useRef(null);
  const reconnectTimeoutRef = useRef(null);

  useEffect(() => {
    connectWebSocket();

    return () => {
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
      if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
        wsRef.current.close();
      }
    };
  }, []);

  const connectWebSocket = () => {
    const wsUrl = "ws://127.0.0.1:8000/ws/live";
    try {
      setWsStatus('connecting');
      const socket = new WebSocket(wsUrl);
      wsRef.current = socket;

      socket.onopen = async () => {
        try {
          const token = await fetchSessionToken();
          if (socket.readyState === WebSocket.OPEN) {
            socket.send(JSON.stringify({ token: token || "" }));
            setWsStatus('connected');
          }
        } catch (err) {
          console.error("Failed to authenticate WebSocket:", err);
        }
      };

      socket.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          setMessages((prev) => [payload, ...prev].slice(0, 30));
          if (payload.type === 'live_incidents' && payload.incidents?.length > 0) {
            onLiveIncidentReceived?.(payload.incidents);
          }
        } catch (e) {
          console.error("Failed to parse WS payload:", e);
        }
      };

      socket.onerror = () => {
        setWsStatus('reconnecting');
      };

      socket.onclose = () => {
        setWsStatus('reconnecting');
        // Auto reconnect after 3 seconds
        reconnectTimeoutRef.current = setTimeout(() => {
          connectWebSocket();
        }, 3000);
      };
    } catch (err) {
      setWsStatus('reconnecting');
      reconnectTimeoutRef.current = setTimeout(() => {
        connectWebSocket();
      }, 3000);
    }
  };

  const renderStatusText = () => {
    if (wsStatus === 'connected') return "Connected / Waiting for sniffer";
    if (wsStatus === 'connecting') return "Connecting to stream...";
    return "Reconnecting to Live Stream...";
  };

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <Radio className="w-4 h-4 text-cyan-400 animate-pulse" />
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
            Live Stream Feed (/ws/live)
          </h3>
        </div>
        <div className="flex items-center gap-2 text-xs font-mono">
          <span className={`w-2 h-2 rounded-full ${wsStatus === 'connected' ? 'bg-emerald-400 animate-ping' : 'bg-amber-400 animate-pulse'}`} />
          <span className="text-slate-300 font-sans text-[11px] font-medium">{renderStatusText()}</span>
        </div>
      </div>

      <div className="bg-slate-950 border border-slate-800 rounded-lg p-3 font-mono text-xs h-40 overflow-y-auto space-y-2">
        {messages.length === 0 ? (
          <div className="h-full flex items-center justify-center text-slate-400 flex-col gap-1 text-[11px]">
            <ShieldCheck className="w-5 h-5 text-slate-400 opacity-60" />
            <span>Connected / Waiting for sniffer traffic on port 53</span>
          </div>
        ) : (
          messages.map((msg, i) => (
            <div key={i} className="border-b border-slate-800/80 pb-1.5 last:border-0">
              <div className="flex items-center justify-between text-slate-400 text-[11px]">
                <span className="text-cyan-400">[{new Date(msg.timestamp * 1000 || Date.now()).toLocaleTimeString()}]</span>
                <span className="text-amber-400">{msg.incidents?.length || 0} Incidents</span>
              </div>
              {msg.incidents?.map((inc, j) => (
                <div key={j} className="text-slate-200 mt-1 pl-2 border-l-2 border-amber-500 flex items-center gap-2">
                  <AlertTriangle className="w-3 h-3 text-amber-400 shrink-0" />
                  <span>
                    <strong className="text-rose-300">{inc.severity}</strong>: {inc.src_ip} &rarr; {inc.base_domain} (Score: {inc.risk_score})
                  </span>
                </div>
              ))}
            </div>
          ))
        )}
      </div>
    </div>
  );
}
