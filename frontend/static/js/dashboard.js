/* =========================================================
   ABTD — dashboard.js
   Live dashboard: KPI cards, threat timeline chart,
   recent threats table, system info widgets
   ========================================================= */

(async () => {
  // ── Load stats ────────────────────────────────────────────
  async function loadStats() {
    const data = await ABTD.get("/api/stats");
    if (!data) return;

    setText("stat-total-scans",   data.total_scans   ?? 0);
    setText("stat-threats",       data.total_threats ?? 0);
    setText("stat-suspicious",    data.suspicious    ?? 0);
    setText("stat-safe",          data.safe          ?? 0);
    setText("stat-alerts",        data.total_alerts  ?? 0);
    setText("stat-threat-rate",  (data.threat_rate   ?? 0) + "%");

    renderRecentThreats(data.recent_threats || []);
  }

  // ── System info ───────────────────────────────────────────
  async function loadSystemInfo() {
    const data = await ABTD.get("/api/system-info");
    if (!data) return;

    setText("sys-cpu",      data.cpu_percent  + "%");
    setText("sys-ram",      data.ram_percent  + "%");
    setText("sys-disk",     data.disk_percent + "%");
    setText("sys-uptime",   data.uptime_human ?? "—");
    setText("sys-hostname", data.hostname     ?? "—");

    setBar("bar-cpu",  data.cpu_percent);
    setBar("bar-ram",  data.ram_percent);
    setBar("bar-disk", data.disk_percent);
  }

  // ── Timeline chart ────────────────────────────────────────
  async function loadTimeline() {
    const data = await ABTD.get("/api/threats/timeline?days=7");
    if (!data) return;

    const labels = data.map(d => d._id);
    const values = data.map(d => d.count);

    const ctx = document.getElementById("timeline-chart");
    if (!ctx) return;

    if (window._timelineChart) window._timelineChart.destroy();
    window._timelineChart = new Chart(ctx, {
      type: "line",
      data: {
        labels,
        datasets: [{
          label     : "Threats",
          data      : values,
          borderColor: "#ef4444",
          backgroundColor: "rgba(239,68,68,0.1)",
          borderWidth: 2,
          fill       : true,
          tension    : 0.4,
          pointRadius: 4,
          pointBackgroundColor: "#ef4444",
        }],
      },
      options: chartDefaults("Threats per Day"),
    });
  }

  // ── Hourly chart ─────────────────────────────────────────
  async function loadHourly() {
    const data = await ABTD.get("/api/threats/hourly");
    if (!data) return;

    const labels = data.map(d => d._id.slice(-2) + ":00");
    const values = data.map(d => d.count);

    const ctx = document.getElementById("hourly-chart");
    if (!ctx) return;

    if (window._hourlyChart) window._hourlyChart.destroy();
    window._hourlyChart = new Chart(ctx, {
      type: "bar",
      data: {
        labels,
        datasets: [{
          label          : "Hourly Threats",
          data           : values,
          backgroundColor: "rgba(124,58,237,0.6)",
          borderColor    : "#7c3aed",
          borderWidth    : 1,
          borderRadius   : 4,
        }],
      },
      options: chartDefaults("Hourly Activity"),
    });
  }

  // ── Recent threats table ──────────────────────────────────
  function renderRecentThreats(items) {
    const tbody = document.getElementById("recent-threats-body");
    if (!tbody) return;

    if (!items.length) {
      tbody.innerHTML = `<tr><td colspan="5" class="text-center text-muted" style="padding:30px">No threats detected yet</td></tr>`;
      return;
    }

    tbody.innerHTML = items.map(t => {
      const target = t.url || t.file_name || t.process_name || "—";
      return `
        <tr class="fade-in">
          <td class="url-cell" title="${target}">${ABTD.truncate(target, 45)}</td>
          <td><span class="badge badge-${(t.classification||"unknown").toLowerCase()}">${t.classification||"?"}</span></td>
          <td>
            <div class="flex items-center gap-8">
              <span style="font-weight:700;color:${ABTD.scoreColor(t.threat_score)}">${t.threat_score||0}</span>
              ${ABTD.renderScoreBar(t.threat_score)}
            </div>
          </td>
          <td class="text-secondary">${t.target_type||"—"}</td>
          <td class="text-muted">${ABTD.timeAgo(t.timestamp)}</td>
        </tr>`;
    }).join("");
  }

  // ── Chart defaults ────────────────────────────────────────
  function chartDefaults(title) {
    return {
      responsive        : true,
      maintainAspectRatio: false,
      plugins: {
        legend : { display: false },
        tooltip: {
          backgroundColor: "#13192a",
          borderColor    : "rgba(99,179,237,0.2)",
          borderWidth    : 1,
          titleColor     : "#f1f5f9",
          bodyColor      : "#94a3b8",
        },
      },
      scales: {
        x: {
          grid : { color: "rgba(255,255,255,0.05)" },
          ticks: { color: "#475569", font: { size: 11 } },
        },
        y: {
          grid : { color: "rgba(255,255,255,0.05)" },
          ticks: { color: "#475569", font: { size: 11 }, stepSize: 1 },
          beginAtZero: true,
        },
      },
    };
  }

  // ── Helpers ───────────────────────────────────────────────
  function setText(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
  }

  function setBar(id, pct) {
    const el = document.getElementById(id);
    if (el) {
      el.style.width      = pct + "%";
      el.style.background = ABTD.scoreColor(pct);
    }
  }

  // ── Boot ──────────────────────────────────────────────────
  await Promise.all([loadStats(), loadSystemInfo(), loadTimeline(), loadHourly()]);

  // Auto-refresh every 30 seconds
  setInterval(() => {
    loadStats();
    loadSystemInfo();
    loadTimeline();
    loadHourly();
  }, 30000);

})();
