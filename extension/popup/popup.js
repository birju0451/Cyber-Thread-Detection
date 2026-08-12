/**
 * ABTD Extension — popup.js v2.0
 * ================================
 * Loads current tab analysis, Zero Trust status, incidents, and session stats.
 */

const API = "http://127.0.0.1:5000";

// Session counters stored in chrome.storage.session
let sessionStats = { scans: 0, threats: 0, safe: 0 };

async function init() {
  await loadSessionStats();
  await checkConnection();
  await loadCurrentTab();
  await loadZeroTrustStatus();
  await loadIncidents();
  setupScanBtn();
}

// ── Connection Check ─────────────────────────────────────────
async function checkConnection() {
  const pill = document.getElementById("conn-status");
  const text = document.getElementById("conn-text");
  const api  = document.getElementById("api-status");
  try {
    const res = await fetch(`${API}/api/status`, { signal: AbortSignal.timeout(3000) });
    if (res.ok) {
      pill.classList.remove("offline");
      text.textContent = "Protected";
      api.textContent  = "API: Online";
      api.style.color  = "#22c55e";
    } else { throw new Error(); }
  } catch {
    pill.classList.add("offline");
    text.textContent = "Offline";
    api.textContent  = "API: Offline";
    api.style.color  = "#ef4444";
  }
}

// ── Current Tab Analysis ──────────────────────────────────────
async function loadCurrentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const el    = document.getElementById("current-result");

  if (!tab?.url?.startsWith("http")) {
    el.className = "result-box";
    el.innerHTML = `<span class="result-icon">🔒</span><div class="result-info"><div class="result-cls" style="color:#475569">System Page</div><div class="result-url">Not analyzed</div></div>`;
    return;
  }

  // Try session cache first
  const stored = await chrome.storage.session.get(`tab_${tab.id}`);
  const result = stored[`tab_${tab.id}`];

  if (result) {
    renderCurrentResult(result, tab.url);
  } else {
    // Fetch live
    try {
      const res  = await fetch(`${API}/predict`, {
        method : "POST",
        headers: { "Content-Type": "application/json" },
        body   : JSON.stringify({ url: tab.url }),
        signal : AbortSignal.timeout(8000),
      });
      const data = await res.json();
      renderCurrentResult(data, tab.url);
      await chrome.storage.session.set({ [`tab_${tab.id}`]: data });
    } catch {
      el.className = "result-box";
      el.innerHTML = `<span class="result-icon">❓</span><div class="result-info"><div class="result-cls" style="color:#475569">Cannot connect to ABTD</div><div class="result-url">Make sure the server is running</div></div>`;
    }
  }
}

function renderCurrentResult(result, url) {
  const el  = document.getElementById("current-result");
  const cls = (result.classification || "unknown").toLowerCase();
  const COLORS = { safe:"#22c55e", suspicious:"#f59e0b", malicious:"#ef4444", critical:"#7c3aed" };
  const color  = COLORS[cls] || "#94a3b8";
  const score  = result.threat_score || 0;

  el.className = `result-box ${cls}`;
  el.innerHTML = `
    <span class="result-icon">${result.icon || "❓"}</span>
    <div class="result-info">
      <div class="result-cls" style="color:${color}">${result.classification}</div>
      <div class="result-url">${truncate(url, 40)}</div>
      <div class="score-bar"><div class="score-fill" style="width:${score}%;background:${color}"></div></div>
    </div>
    <div class="result-score" style="color:${color}">${score}</div>`;
}

// ── Quick Scan ────────────────────────────────────────────────
function setupScanBtn() {
  const btn   = document.getElementById("scan-btn");
  const input = document.getElementById("scan-input");
  const res   = document.getElementById("scan-result");

  btn.addEventListener("click", async () => {
    const url = input.value.trim();
    if (!url) return;

    btn.disabled    = true;
    btn.textContent = "…";
    res.innerHTML   = "";

    try {
      const response = await fetch(`${API}/predict`, {
        method : "POST",
        headers: { "Content-Type": "application/json" },
        body   : JSON.stringify({ url }),
        signal : AbortSignal.timeout(10000),
      });
      const data = await response.json();
      renderScanResult(data, res);
      await updateStats(data);
    } catch (e) {
      res.innerHTML = `<div style="color:#ef4444;font-size:11px;margin-top:6px">Scan failed — check connection</div>`;
    } finally {
      btn.disabled    = false;
      btn.textContent = "Scan";
    }
  });

  input.addEventListener("keydown", (e) => { if (e.key === "Enter") btn.click(); });
}

function renderScanResult(r, container) {
  const cls   = (r.classification || "unknown").toLowerCase();
  const COLORS = { safe:"#22c55e", suspicious:"#f59e0b", malicious:"#ef4444", critical:"#7c3aed" };
  const color  = COLORS[cls] || "#94a3b8";
  const score  = r.threat_score || 0;

  container.innerHTML = `
    <div style="margin-top:8px;padding:8px 10px;background:#13192a;border-radius:6px;border:1px solid ${color}44">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <span style="font-weight:700;color:${color}">${r.icon || ""} ${r.classification}</span>
        <span style="font-weight:800;color:${color}">${score}/100</span>
      </div>
      <div style="font-size:10px;color:#475569;margin-top:4px">${(r.reasons || [])[0] || ""}</div>
    </div>`;
}

// ── Session Stats ─────────────────────────────────────────────
async function loadSessionStats() {
  const stored = await chrome.storage.session.get("abtd_stats");
  if (stored.abtd_stats) sessionStats = stored.abtd_stats;
  updateStatsUI();
}

async function updateStats(result) {
  sessionStats.scans++;
  if (["SUSPICIOUS","MALICIOUS","CRITICAL"].includes(result.classification)) {
    sessionStats.threats++;
  } else {
    sessionStats.safe++;
  }
  await chrome.storage.session.set({ abtd_stats: sessionStats });
  updateStatsUI();
}

function updateStatsUI() {
  document.getElementById("stat-scans").textContent   = sessionStats.scans;
  document.getElementById("stat-threats").textContent = sessionStats.threats;
  document.getElementById("stat-safe").textContent    = sessionStats.safe;
}

// ── Zero Trust Status ────────────────────────────────────────
async function loadZeroTrustStatus() {
  try {
    const res = await fetch(`${API}/api/zero-trust/overview`, {
      signal: AbortSignal.timeout(4000)
    });
    if (!res.ok) return;
    const j = await res.json();
    const d = j.data || {};

    // Trust scores
    const sysT  = Math.round(d.overall_trust_score  || 0);
    const devT  = Math.round(d.device_trust          || 0);
    const usrT  = Math.round(d.user_trust            || 0);

    document.getElementById('zt-system-trust').textContent = sysT;
    document.getElementById('zt-device-trust').textContent = devT;
    document.getElementById('zt-user-trust').textContent   = usrT;

    // Color helper
    const tClass = (s) => s >= 75 ? 'trust-high' : s >= 50 ? 'trust-medium' : 'trust-low';
    document.getElementById('zt-system-trust').className = `zt-cell-val ${tClass(sysT)}`;
    document.getElementById('zt-device-trust').className = `zt-cell-val ${tClass(devT)}`;
    document.getElementById('zt-user-trust').className   = `zt-cell-val ${tClass(usrT)}`;

    // ZT decision based on overall trust
    const dec = sysT >= 75 ? 'ALLOW' : sysT >= 55 ? 'MONITOR' : sysT >= 35 ? 'RESTRICT' : 'BLOCK';
    const badge = document.getElementById('zt-decision-badge');
    badge.textContent = dec;
    badge.className   = `zt-decision-badge zt-${dec}`;

    // Risk bar
    const risk = 100 - sysT;
    const rCol = risk <= 25 ? '#22c55e' : risk <= 50 ? '#f59e0b' : '#ef4444';
    document.getElementById('zt-risk-fill').style.width      = risk + '%';
    document.getElementById('zt-risk-fill').style.background = rCol;

    // Check current tab URL risk
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.url?.startsWith('http')) {
      const stored = await chrome.storage.session.get(`tab_${tab.id}`);
      const cached = stored[`tab_${tab.id}`];
      const urlRisk = cached ? (cached.threat_score || 0) : 0;
      document.getElementById('zt-url-trust').textContent = urlRisk;
      document.getElementById('zt-url-trust').className   = `zt-cell-val ${tClass(100 - urlRisk)}`;
    } else {
      document.getElementById('zt-url-trust').textContent = '—';
    }

  } catch(e) {
    // API offline — ZT panel stays as default
  }
}

// ── Incidents ─────────────────────────────────────────────────
async function loadIncidents() {
  try {
    const res = await fetch(`${API}/api/zero-trust/incidents?limit=5`, {
      signal: AbortSignal.timeout(3000)
    });
    if (!res.ok) return;
    const j    = await res.json();
    const open = j.data?.stats?.open || 0;
    const row  = document.getElementById('incidents-row');
    if (open > 0) {
      document.getElementById('incident-count').textContent = open;
      row.style.display = 'flex';
    }
  } catch(e) {}
}

// ── Helpers ───────────────────────────────────────────────────
function truncate(str, n) { return str?.length > n ? str.slice(0, n) + '…' : (str || ''); }

// ── Boot ──────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', init);
