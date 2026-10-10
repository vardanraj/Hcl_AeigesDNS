import React, { useState, useEffect } from 'react';
import { Sliders, Save, RotateCcw, Check, AlertCircle, Loader2 } from 'lucide-react';
import { getConfig, updateConfigThresholds, resetConfig } from '../api';

export default function ConfigEditor({ onConfigSaved, onError }) {
  const [thresholds, setThresholds] = useState(null);
  const [isSaving, setIsSaving] = useState(false);
  const [isResetting, setIsResetting] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);

  useEffect(() => {
    loadConfigData();
  }, []);

  const loadConfigData = async () => {
    try {
      const data = await getConfig();
      setThresholds(data.thresholds);
    } catch (err) {
      onError(err.message || 'Failed to load configuration.');
    }
  };

  const handleChange = (field, value) => {
    setThresholds((prev) => ({
      ...prev,
      [field]: parseFloat(value) || value,
    }));
  };

  const handleSave = async (e) => {
    e.preventDefault();
    setIsSaving(true);
    setSaveSuccess(false);
    try {
      const res = await updateConfigThresholds(thresholds);
      setSaveSuccess(true);
      onConfigSaved?.(res.thresholds);
      setTimeout(() => setSaveSuccess(false), 3000);
    } catch (err) {
      onError(err.message || 'Failed to update thresholds.');
    } finally {
      setIsSaving(false);
    }
  };

  const handleReset = async () => {
    setIsResetting(true);
    try {
      const res = await resetConfig();
      setThresholds(res.config.thresholds);
      onConfigSaved?.(res.config.thresholds);
    } catch (err) {
      onError(err.message || 'Failed to reset configuration.');
    } finally {
      setIsResetting(false);
    }
  };

  if (!thresholds) return null;

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Sliders className="w-4 h-4 text-cyan-400" />
          <h2 className="text-sm font-semibold text-slate-200 uppercase tracking-wider">
            Detection Thresholds Editor (config.yaml)
          </h2>
        </div>

        <button
          onClick={handleReset}
          disabled={isResetting}
          type="button"
          className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs flex items-center gap-1.5 transition-all border border-slate-700"
        >
          {isResetting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RotateCcw className="w-3.5 h-3.5" />}
          Reset to Validated Defaults
        </button>
      </div>

      <form onSubmit={handleSave} className="space-y-4">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1">
              Entropy Threshold (bits)
            </label>
            <input
              type="number"
              step="0.1"
              min="0"
              max="8"
              value={thresholds.entropy_threshold}
              onChange={(e) => handleChange('entropy_threshold', e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-100 font-mono focus:border-cyan-500 focus:outline-none"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1">
              Subdomain Length Threshold
            </label>
            <input
              type="number"
              min="1"
              max="255"
              value={thresholds.subdomain_length_threshold}
              onChange={(e) => handleChange('subdomain_length_threshold', e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-100 font-mono focus:border-cyan-500 focus:outline-none"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1">
              QNAME Length Threshold
            </label>
            <input
              type="number"
              min="1"
              max="253"
              value={thresholds.qname_length_threshold}
              onChange={(e) => handleChange('qname_length_threshold', e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-100 font-mono focus:border-cyan-500 focus:outline-none"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1">
              Digit Ratio Threshold
            </label>
            <input
              type="number"
              step="0.05"
              min="0"
              max="1"
              value={thresholds.digit_ratio_threshold}
              onChange={(e) => handleChange('digit_ratio_threshold', e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-100 font-mono focus:border-cyan-500 focus:outline-none"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1">
              Hex Ratio Threshold
            </label>
            <input
              type="number"
              step="0.05"
              min="0"
              max="1"
              value={thresholds.hex_ratio_threshold}
              onChange={(e) => handleChange('hex_ratio_threshold', e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-100 font-mono focus:border-cyan-500 focus:outline-none"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1">
              ML Anomaly Threshold (Calibrated: 0.15)
            </label>
            <input
              type="number"
              step="0.05"
              min="0"
              max="1"
              value={thresholds.ml_anomaly_threshold}
              onChange={(e) => handleChange('ml_anomaly_threshold', e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-100 font-mono focus:border-cyan-500 focus:outline-none"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1">
              Fused Alert Threshold (Evaluated: 0.50)
            </label>
            <input
              type="number"
              step="0.05"
              min="0"
              max="1"
              value={thresholds.fused_threshold}
              onChange={(e) => handleChange('fused_threshold', e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-100 font-mono focus:border-cyan-500 focus:outline-none"
            />
          </div>

          <div className="flex items-end">
            <button
              type="submit"
              disabled={isSaving}
              className="w-full py-2 px-4 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-medium flex items-center justify-center gap-2 transition-all shadow-lg shadow-cyan-950/40"
            >
              {isSaving ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : saveSuccess ? (
                <>
                  <Check className="w-4 h-4 text-emerald-300" /> Saved!
                </>
              ) : (
                <>
                  <Save className="w-4 h-4" /> Save Thresholds
                </>
              )}
            </button>
          </div>
        </div>
      </form>
    </div>
  );
}
