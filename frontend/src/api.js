/**
 * API client helper for AegisDNS backend.
 * Manages per-run X-AegisDNS-Token header and backend requests.
 */

const API_BASE = "http://127.0.0.1:8000";
let sessionToken = null;

export async function fetchSessionToken() {
  try {
    const res = await fetch(`${API_BASE}/api/session`);
    if (res.ok) {
      const data = await res.json();
      sessionToken = data.token;
      return sessionToken;
    }
  } catch (err) {
    console.error("Failed to fetch session token:", err);
  }
  return null;
}

export async function uploadPcapFile(file) {
  const formData = new FormData();
  formData.append("file", file);

  const res = await fetch(`${API_BASE}/api/pcap/upload`, {
    method: "POST",
    body: formData,
  });

  if (!res.ok) {
    const errData = await res.json().catch(() => ({}));
    throw new Error(errData.detail || `Upload failed with status ${res.status}`);
  }
  return res.json();
}

export async function generateSyntheticTraffic(numRecords = 200, tunnelRatio = 0.25) {
  const res = await fetch(`${API_BASE}/api/synthetic/generate?num_records=${numRecords}&tunnel_ratio=${tunnelRatio}`, {
    method: "POST",
  });
  if (!res.ok) {
    throw new Error("Failed to generate synthetic data.");
  }
  return res.json();
}

export async function startLiveCapture(interfaceName = "default") {
  if (!sessionToken) await fetchSessionToken();
  const res = await fetch(`${API_BASE}/api/capture/start`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-AegisDNS-Token": sessionToken || "",
    },
    body: JSON.stringify({ interface: interfaceName }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || "Failed to start live capture.");
  }
  return res.json();
}

export async function stopLiveCapture() {
  if (!sessionToken) await fetchSessionToken();
  const res = await fetch(`${API_BASE}/api/capture/stop`, {
    method: "POST",
    headers: {
      "X-AegisDNS-Token": sessionToken || "",
    },
  });
  if (!res.ok) {
    throw new Error("Failed to stop live capture.");
  }
  return res.json();
}

export async function getCaptureStatus() {
  const res = await fetch(`${API_BASE}/api/capture/status`);
  if (!res.ok) throw new Error("Failed to fetch capture status.");
  return res.json();
}

export async function getAlerts(filters = {}) {
  const params = new URLSearchParams();
  if (filters.severity) params.append("severity", filters.severity);
  if (filters.domain) params.append("domain", filters.domain);
  if (filters.src_ip) params.append("src_ip", filters.src_ip);

  const res = await fetch(`${API_BASE}/api/alerts?${params.toString()}`);
  if (!res.ok) throw new Error("Failed to fetch alerts.");
  return res.json();
}

export async function getSummary() {
  const res = await fetch(`${API_BASE}/api/summary`);
  if (!res.ok) throw new Error("Failed to fetch summary.");
  return res.json();
}

export async function getTimeline() {
  const res = await fetch(`${API_BASE}/api/timeline`);
  if (!res.ok) throw new Error("Failed to fetch timeline data.");
  return res.json();
}

export async function getInvestigateDomain(domain) {
  const res = await fetch(`${API_BASE}/api/investigate/${encodeURIComponent(domain)}`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Domain ${domain} not found.`);
  }
  return res.json();
}

export async function getConfig() {
  const res = await fetch(`${API_BASE}/api/config`);
  if (!res.ok) throw new Error("Failed to fetch configuration.");
  return res.json();
}

export async function updateConfigThresholds(thresholds) {
  if (!sessionToken) await fetchSessionToken();
  const res = await fetch(`${API_BASE}/api/config`, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
      "X-AegisDNS-Token": sessionToken || "",
    },
    body: JSON.stringify(thresholds),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || "Failed to update configuration.");
  }
  return res.json();
}

export async function resetConfig() {
  if (!sessionToken) await fetchSessionToken();
  const res = await fetch(`${API_BASE}/api/config/reset`, {
    method: "POST",
    headers: {
      "X-AegisDNS-Token": sessionToken || "",
    },
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || "Failed to reset configuration.");
  }
  return res.json();
}

export async function getEvaluationMetrics() {
  const res = await fetch(`${API_BASE}/api/evaluation`);
  if (!res.ok) throw new Error("Failed to fetch evaluation metrics.");
  return res.json();
}

export function getExportUrl(format = "csv") {
  return `${API_BASE}/api/incidents/export?format=${format}`;
}
