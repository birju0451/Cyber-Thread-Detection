/* =========================================================
   ABTD — scanner.js
   Manual URL/File scanner: form submit, step animation, result render
   ========================================================= */

(async () => {
  const form        = document.getElementById("scan-form");
  const input       = document.getElementById("scan-input");
  const typeSelect  = document.getElementById("scan-type");
  const submitBtn   = document.getElementById("scan-btn");
  const stepsWrap   = document.getElementById("scan-steps");
  const resultWrap  = document.getElementById("scan-result");

  const STEPS = [
    { id: "step-extract",    label: "Extracting 30 structural signal features…", delay: 150 },
    { id: "step-ml",         label: "Evaluating Random Forest classifier…",      delay: 450 },
    { id: "step-anomaly",    label: "Calculating Isolation Forest anomaly score…",delay: 750 },
    { id: "step-rules",      label: "Applying deterministic heuristic rules…",   delay: 950 },
    { id: "step-reputation", label: "Querying WHOIS & DNSBL reputation database…",delay: 1200 },
    { id: "step-fuse",       label: "Fusing multi-signal threat index score…",   delay: 1400 },
  ];

  if (!form) return;

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const target = input.value.trim();
    const type   = typeSelect ? typeSelect.value : "url";

    if (!target) {
      ABTD.toast("Please enter a URL string or absolute file path", "warning");
      return;
    }

    submitBtn.disabled = true;
    submitBtn.innerHTML = `<span class="spinner" style="width:14px;height:14px;border-width:2px;display:inline-block;margin-right:6px"></span> Analyzing…`;
    resultWrap.innerHTML = "";
    showSteps();

    for (const step of STEPS) {
      await delay(step.delay);
      markStep(step.id, "active");
      if (STEPS.indexOf(step) > 0) markStep(STEPS[STEPS.indexOf(step)-1].id, "done");
    }

    const result = await ABTD.post("/api/scan", { target, type });
    STEPS.forEach(s => markStep(s.id, "done"));
    await delay(250);

    submitBtn.disabled = false;
    submitBtn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" style="width:15px;height:15px;stroke-width:2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg> Execute Analysis`;

    if (!result || result.error) {
      ABTD.toast(result?.error || "Analysis failed", "error");
      stepsWrap.innerHTML = "";
      return;
    }

    stepsWrap.innerHTML = "";
    renderResult(result);
  });

  function showSteps() {
    stepsWrap.innerHTML = STEPS.map(s => `
      <div class="scan-step" id="${s.id}" style="display:flex;align-items:center;gap:10px;padding:8px 0;font-size:12.5px;color:var(--accent-muted)">
        <span class="step-icon" style="font-family:var(--font-mono)">[ ]</span>
        <span>${s.label}</span>
      </div>`).join("");
  }

  function markStep(id, state) {
    const el = document.getElementById(id);
    if (!el) return;
    const icon = el.querySelector(".step-icon");
    if (state === "done") {
      el.style.color = "var(--safe)";
      if (icon) icon.textContent = "[✓]";
    } else if (state === "active") {
      el.style.color = "var(--accent-white)";
      if (icon) icon.textContent = "[> ]";
    }
  }

  function renderResult(r) {
    const cls      = (r.classification || "UNKNOWN").toLowerCase();
    const score    = r.threat_score || 0;
    const color    = r.color || ABTD.classColor(r.classification);
    const layers   = r.detection_modules || {};
    const reasons  = r.reasons || [];

    const iconSvg = cls === 'safe'
      ? `<svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>`
      : cls === 'suspicious'
      ? `<svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="2"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`
      : `<svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="2"><polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="17"/></svg>`;

    resultWrap.innerHTML = `
      <div class="scan-result">
        <div class="scan-result-header ${cls}">
          <div style="display:flex;align-items:center;gap:16px">
            <div class="result-icon-box">${iconSvg}</div>
            <div>
              <div class="result-classification" style="color:${color}">${r.classification}</div>
              <div class="text-muted font-mono" style="font-size:12px;margin-top:2px">
                ${r.url || r.file_name || r.process_name || "Target payload"}
              </div>
            </div>
          </div>

          <div style="text-align:right">
            <div class="gauge-score" style="color:${color}">${score}<span style="font-size:14px;color:var(--accent-muted)">/100</span></div>
            <div class="gauge-label">Threat Index</div>
            <div style="margin-top:6px;font-size:11px;color:var(--accent-muted);font-family:var(--font-mono)">
              Latency: ${r.analysis_time_ms}ms
            </div>
          </div>
        </div>

        <div class="scan-result-body">

          <!-- Detection Layer Breakdown -->
          <div class="card-title mb-16">Detection Layer Breakdown</div>
          <div class="detection-layers">
            ${layerCard("L2: Random Forest", layers.random_forest?.score || 0, layers.random_forest?.label || "Supervised Model")}
            ${layerCard("L3: Anomaly Engine", layers.anomaly?.score || 0, layers.anomaly?.label || "Unsupervised Model")}
            ${layerCard("L4: Heuristics", layers.rules?.score || 0, "10 Rule Engines")}
            ${layerCard("L5: Reputation", layers.reputation?.score || 0, "WHOIS & DNSBL")}
          </div>

          <!-- Score Bar -->
          <div class="mb-16">
            <div class="flex-between mb-8" style="font-size:11px;color:var(--accent-muted);text-transform:uppercase;font-weight:700">
              <span>Overall Threat Risk</span><span>${score}/100</span>
            </div>
            <div class="score-bar" style="height:8px">
              <div class="score-bar-fill" style="width:${score}%;background:${color};height:8px"></div>
            </div>
          </div>

          <!-- Reasons List -->
          <div class="card-title mb-16">Telemetry Reasons & Signals</div>
          <ul class="reasons-list">
            ${reasons.length ? reasons.map(reason => `
              <li class="reason-item">
                <span class="reason-bullet" style="color:var(--accent-white)">•</span>
                <span>${reason}</span>
              </li>`).join("") :
            '<li class="reason-item"><span class="reason-bullet" style="color:var(--safe)">✓</span><span>No malicious indicators detected by engine rules</span></li>'}
          </ul>

          <!-- AI Explanation -->
          ${r.ai_explanation ? `
            <div class="ai-explanation mt-16">
              <div class="ai-label">Gemini Neural Explanation</div>
              <p>${r.ai_explanation}</p>
            </div>` : ""}

          <!-- Recommended Action -->
          <div class="alert-box ${cls === 'safe' ? 'success' : cls === 'suspicious' ? 'warning' : 'danger'} mt-16">
            <div><strong>Recommended Mitigation Action:</strong> ${r.recommended_action}</div>
          </div>
        </div>
      </div>`;
  }

  function layerCard(name, score, label) {
    const sc    = Math.round(score || 0);
    const color = ABTD.scoreColor(sc);
    return `
      <div class="layer-card">
        <div class="layer-name">${name}</div>
        <div class="layer-score" style="color:${color}">${sc}</div>
        <div class="layer-label">${label}</div>
        ${ABTD.renderScoreBar(sc)}
      </div>`;
  }

  function delay(ms) { return new Promise(r => setTimeout(r, ms)); }

})();
