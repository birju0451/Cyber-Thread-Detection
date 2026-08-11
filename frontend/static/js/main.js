/* =========================================================
   ABTD — main.js
   Shared JavaScript utilities — API calls, formatters,
   live clock, status polling, notification toasts
   ========================================================= */

const ABTD = {
  BASE_URL: window.location.origin,

  // ── API helpers ──────────────────────────────────────────
  async get(endpoint) {
    try {
      const res = await fetch(this.BASE_URL + endpoint);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch (e) {
      console.error(`[ABTD] GET ${endpoint} failed:`, e);
      return null;
    }
  },

  async post(endpoint, body) {
    try {
      const res = await fetch(this.BASE_URL + endpoint, {
        method : "POST",
        headers: { "Content-Type": "application/json" },
        body   : JSON.stringify(body),
      });
      return await res.json();
    } catch (e) {
      console.error(`[ABTD] POST ${endpoint} failed:`, e);
      return null;
    }
  },

  // ── Formatters ───────────────────────────────────────────
  formatScore(score) {
    return Math.round(score || 0);
  },

  scoreColor(score) {
    if (score < 25) return "var(--safe)";
    if (score < 50) return "var(--suspicious)";
    if (score < 75) return "var(--malicious)";
    return "var(--critical)";
  },

  classColor(cls) {
    const map = {
      SAFE      : "var(--safe)",
      SUSPICIOUS: "var(--suspicious)",
      MALICIOUS : "var(--malicious)",
      CRITICAL  : "var(--critical)",
    };
    return map[(cls || "").toUpperCase()] || "var(--text-muted)";
  },

  badgeHTML(cls) {
    const c = (cls || "unknown").toLowerCase();
    const icons = { safe:"✅", suspicious:"⚠️", malicious:"🚫", critical:"🔴" };
    return `<span class="badge badge-${c}">${icons[c] || "❓"} ${cls || "Unknown"}</span>`;
  },

  formatTime(iso) {
    if (!iso) return "—";
    try {
      return new Date(iso).toLocaleString("en-IN", {
        day:"2-digit", month:"short", year:"numeric",
        hour:"2-digit", minute:"2-digit",
      });
    } catch { return iso; }
  },

  timeAgo(iso) {
    if (!iso) return "—";
    const diff = Date.now() - new Date(iso).getTime();
    const s = Math.floor(diff / 1000);
    if (s < 60)   return `${s}s ago`;
    if (s < 3600) return `${Math.floor(s/60)}m ago`;
    if (s < 86400)return `${Math.floor(s/3600)}h ago`;
    return `${Math.floor(s/86400)}d ago`;
  },

  truncate(str, len = 60) {
    if (!str) return "—";
    return str.length > len ? str.slice(0, len) + "…" : str;
  },

  // ── Score bar ────────────────────────────────────────────
  renderScoreBar(score) {
    const pct   = Math.min(Math.max(score || 0, 0), 100);
    const color = this.scoreColor(pct);
    return `
      <div class="score-bar-wrap">
        <div class="score-bar">
          <div class="score-bar-fill"
               style="width:${pct}%; background:${color};"
               data-score="${pct}"></div>
        </div>
      </div>`;
  },

  // ── Toast Notifications ──────────────────────────────────
  toast(message, type = "info", duration = 4000) {
    let container = document.getElementById("toast-container");
    if (!container) {
      container = document.createElement("div");
      container.id = "toast-container";
      container.style.cssText = `
        position: fixed; bottom: 24px; right: 24px;
        display: flex; flex-direction: column; gap: 8px;
        z-index: 9999; max-width: 360px;`;
      document.body.appendChild(container);
    }

    const colors = {
      info   : "#3b82f6",
      success: "#22c55e",
      warning: "#f59e0b",
      error  : "#ef4444",
    };

    const icons  = { info:"ℹ️", success:"✅", warning:"⚠️", error:"🚫" };
    const toast  = document.createElement("div");
    toast.style.cssText = `
      background: #13192a;
      border: 1px solid ${colors[type] || colors.info}44;
      border-left: 4px solid ${colors[type] || colors.info};
      border-radius: 8px;
      padding: 12px 16px;
      display: flex; align-items: center; gap: 10px;
      font-size: 13px; color: #f1f5f9;
      animation: slideInRight 0.3s ease;
      box-shadow: 0 4px 20px rgba(0,0,0,0.5);
      cursor: pointer;`;

    toast.innerHTML = `<span>${icons[type] || "ℹ️"}</span><span>${message}</span>`;
    toast.onclick = () => toast.remove();
    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = "0";
      toast.style.transition = "opacity 0.3s ease";
      setTimeout(() => toast.remove(), 300);
    }, duration);
  },

  // ── Navigation active state ──────────────────────────────
  setActiveNav() {
    const path = window.location.pathname;
    document.querySelectorAll(".nav-item").forEach(el => {
      const href = el.getAttribute("href") || "";
      el.classList.toggle("active",
        href !== "/" && path.startsWith(href) ||
        href === "/" && path === "/"
      );
    });
  },

  // ── Live clock ───────────────────────────────────────────
  startClock() {
    const el = document.getElementById("live-clock");
    if (!el) return;
    const tick = () => {
      el.textContent = new Date().toLocaleTimeString("en-IN", {
        hour:"2-digit", minute:"2-digit", second:"2-digit",
      });
    };
    tick();
    setInterval(tick, 1000);
  },

  // ── Status badge updater ─────────────────────────────────
  async updateStatusBadge() {
    const dot  = document.getElementById("status-dot");
    const text = document.getElementById("status-text");
    const data = await this.get("/api/status");
    if (!data) {
      if (dot)  dot.classList.add("offline");
      if (text) text.textContent = "Offline";
      return;
    }
    if (dot)  dot.classList.remove("offline");
    if (text) text.textContent = data.db === "connected" ? "Protected" : "DB Offline";
  },

  // ── Init ─────────────────────────────────────────────────
  init() {
    this.setActiveNav();
    this.startClock();
    this.updateStatusBadge();
    setInterval(() => this.updateStatusBadge(), 30000);
  },
};

document.addEventListener("DOMContentLoaded", () => ABTD.init());
