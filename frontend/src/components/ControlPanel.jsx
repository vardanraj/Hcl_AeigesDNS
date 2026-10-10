import React, { useState } from 'react';
import { UploadCloud, Play, Square, Sparkles, FileText, Loader2, AlertCircle } from 'lucide-react';
import { uploadPcapFile, startLiveCapture, stopLiveCapture, generateSyntheticTraffic } from '../api';

export default function ControlPanel({ captureStatus, onDataUpdated, onError }) {
  const [isUploading, setIsUploading] = useState(false);
  const [isGenerating, setIsGenerating] = useState(false);
  const [isCapturingLoading, setIsCapturingLoading] = useState(false);
  const [dragActive, setDragActive] = useState(false);

  const isCapturing = captureStatus?.is_capturing;

  const handleFileUpload = async (file) => {
    if (!file) return;
    if (file.size > 50 * 1024 * 1024) {
      onError('File size exceeds 50 MB limit.');
      return;
    }

    setIsUploading(true);
    try {
      const res = await uploadPcapFile(file);
      onDataUpdated(res.summary);
    } catch (err) {
      onError(err.message || 'PCAP analysis failed.');
    } finally {
      setIsUploading(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  };

  const handleToggleCapture = async () => {
    setIsCapturingLoading(true);
    try {
      if (isCapturing) {
        await stopLiveCapture();
      } else {
        await startLiveCapture();
      }
      onDataUpdated();
    } catch (err) {
      onError(err.message || 'Failed to toggle live capture.');
    } finally {
      setIsCapturingLoading(false);
    }
  };

  const handleGenerateSynthetic = async () => {
    setIsGenerating(true);
    try {
      const res = await generateSyntheticTraffic(200, 0.30);
      onDataUpdated(res.summary);
    } catch (err) {
      onError(err.message || 'Synthetic generation failed.');
    } finally {
      setIsGenerating(false);
    }
  };

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg">
      <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4 flex items-center gap-2">
        <FileText className="w-4 h-4 text-cyan-400" />
        Data Ingestion & Controls
      </h2>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* 1. File Upload Dropzone */}
        <div
          onDragEnter={(e) => { e.preventDefault(); setDragActive(true); }}
          onDragOver={(e) => { e.preventDefault(); setDragActive(true); }}
          onDragLeave={(e) => { e.preventDefault(); setDragActive(false); }}
          onDrop={handleDrop}
          className={`border-2 border-dashed rounded-lg p-4 flex flex-col items-center justify-center text-center transition-all cursor-pointer relative min-h-[120px] ${
            dragActive
              ? 'border-cyan-400 bg-cyan-950/20'
              : 'border-slate-700 hover:border-slate-600 bg-slate-950/40'
          }`}
        >
          <input
            type="file"
            accept=".pcap,.pcapng"
            onChange={(e) => e.target.files?.[0] && handleFileUpload(e.target.files[0])}
            className="absolute inset-0 opacity-0 cursor-pointer w-full h-full"
            disabled={isUploading}
          />
          {isUploading ? (
            <div className="flex flex-col items-center gap-2 text-cyan-400">
              <Loader2 className="w-6 h-6 animate-spin" />
              <span className="text-xs font-medium">Parsing PCAP & Extracting Features...</span>
            </div>
          ) : (
            <>
              <UploadCloud className="w-8 h-8 text-cyan-400/80 mb-2" />
              <span className="text-xs font-medium text-slate-200">
                Drag & drop PCAP / PCAPNG
              </span>
              <span className="text-[11px] text-slate-400 mt-0.5">
                or click to browse (Max 50 MB)
              </span>
            </>
          )}
        </div>

        {/* 2. Live Capture Toggle */}
        <div className="bg-slate-950/40 border border-slate-800 rounded-lg p-4 flex flex-col justify-between">
          <div>
            <span className="text-xs font-semibold text-slate-300">Live Sniffer (Port 53)</span>
            <p className="text-[11px] text-slate-400 mt-1">
              Sniff DNS traffic directly from network interface on port 53.
            </p>
          </div>
          <button
            onClick={handleToggleCapture}
            disabled={isCapturingLoading}
            className={`mt-3 w-full py-2 px-3 rounded-lg text-xs font-medium flex items-center justify-center gap-2 transition-all ${
              isCapturing
                ? 'bg-rose-600 hover:bg-rose-500 text-white shadow-lg shadow-rose-950/40'
                : 'bg-emerald-600 hover:bg-emerald-500 text-white shadow-lg shadow-emerald-950/40'
            }`}
          >
            {isCapturingLoading ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : isCapturing ? (
              <>
                <Square className="w-4 h-4 fill-current" /> Stop Live Sniffer
              </>
            ) : (
              <>
                <Play className="w-4 h-4 fill-current" /> Start Live Sniffer
              </>
            )}
          </button>
        </div>

        {/* 3. Synthetic Generator Trigger */}
        <div className="bg-slate-950/40 border border-slate-800 rounded-lg p-4 flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-1.5">
              <span className="text-xs font-semibold text-slate-300">Synthetic Traffic Generator</span>
              <span className="bg-cyan-950 text-cyan-300 text-[10px] px-1.5 py-0.5 rounded border border-cyan-800">
                Demo
              </span>
            </div>
            <p className="text-[11px] text-slate-400 mt-1">
              Generate 200 synthetic benign & tunneled DNS queries instantly.
            </p>
          </div>
          <button
            onClick={handleGenerateSynthetic}
            disabled={isGenerating}
            className="mt-3 w-full py-2 px-3 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-medium flex items-center justify-center gap-2 transition-all shadow-lg shadow-cyan-950/40"
          >
            {isGenerating ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <>
                <Sparkles className="w-4 h-4" /> Generate Synthetic Traffic
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}
