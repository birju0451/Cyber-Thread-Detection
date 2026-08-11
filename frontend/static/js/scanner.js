/* =========================================================
   ABTD — scanner.js
   Manual URL/File scanner: form, scan animation, result render
   ========================================================= */

(async () => {
  const form        = document.getElementById("scan-form");
  const input       = document.getElementById("scan-input");
  const typeSelect  = document.getElementById("scan-type");
  const submitBtn   = document.getElementById("scan-btn");
  const stepsWrap   = document.getElementById("scan-steps");
  const resultWrap  = document.getElementById("scan-result");

  const STEPS = [
    { id: "step-extract",    label: "Extracting features…",         delay: 200  },
    { id: "step-ml",         label: "Running ML classifier…",       delay: 600  },
    { id: "step-anomaly",    label: "Anomaly detection…",           delay: 900  },
    { id: "step-rules",      label: "Applying heuristic rules…",    delay: 1100 },
    { id: "step-reputation", label: "Checking reputation…",         delay: 1400 },
    { id: "step-fuse",       label: "Fusing scores…",               delay: 1700 },
  ];

  if (!form) return;

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const target = input.value.trim();
    const type   = typeSelect ? typeSelect.value : "url";

    if (!target) {
      ABTD.toast("Please enter a URL or file path", "warning");
      return;
    }

    // Show animation
    submitBtn.disabled = true;
    submitBtn.textContent = "Scanning…";
    resultWrap.innerHTML = "";
    showSteps();

    // Animate steps
    for (const step of STEPS) {
      await delay(step.delay);
      markStep(step.id, "active");
      if (STEPS.indexOf(step) > 0) markStep(STEPS[STEPS.indexOf(step)-1].id, "done");
    }

    // Call API
    const result = await ABTD.post("/api/scan", { target, type });

    // Mark all steps done
    STEPS.forEach(s => markStep(s.id, "done"));
    await delay(300);

    submitBtn.disabled = false;
    submitBtn.textContent = "Scan Now";

    if (!result || result.error) {
      ABTD.toast(result?.error || "Scan failed", "error");
      stepsWrap.innerHTML = "";
      return;
    }

    stepsWrap.innerHTML = "";
    renderResult(result);
  });

  // ── Steps animation ───────────────────────────────────────
  function showSteps() {
    stepsWrap.innerHTML = STEPS.map(s => `
      <div class="scan-step" id="${s.id}">
        <span class="step-icon">○</span>
        <span>${s.label}</span>
      </div>`).join("");
  }

  function markStep(id, state) {
    const el   = document.getElementById(id);
    if (!el) return;
    const icon = el.querySelector(".step-icon");
    el.className = `scan-step ${state}`;
    if (icon) icon.textContent = state === "done" ? "✓" : state === "active" ? "⟳" : "○";
  }

  // ── Result renderer ───────────────────────────────────────
  function renderResult(r) {
    const cls      = (r.classification || "UNKNOWN").toLowerCase();
    const score    = r.threat_score || 0;
    const color    = r.color || ABTD.classColor(r.classification);
    const layers   = r.detection_modules || {};
    const reasons  = r.reasons || [];

    resultWrap.innerHTML = `
      <div class="scan-result">
        <div class="scan-result-header ${cls}">
          <div>
            <div class="result-icon-large">${r.icon || "❓"}</div>
            <div class="result-classification" style="color:${color}">${r.classification}</div>
            <div class="text-secondary" style="font-size:13px;margin-top:4px">
              ${r.url || r.file_name || r.process_name || "Target analyzed"}
            </div>
          </div>
          <div style="text-align:right">
            <div class="gauge-score" style="color:${color}">${score}<span style="font-size:16px;color:var(--text-muted)">/100</span></div>
            <div class="gauge-label" style="color:var(--text-muted)">Threat Score</div>
            <div style="margin-top:10px;font-size:12px;color:var(--text-muted)">
              ⏱ ${r.analysis_time_ms}ms
            </div>
          </div>
        </div>

        <div class="scan-result-body">

          <!-- Detection Layers -->
          <div class="card-title mb-16">🔬 Detection Layer Scores</div>
          <div class="detection-layers">
            ${layerCard("Random Forest", layers.random_forest?.score || 0, layers.random_forest?.label || "—")}
            ${layerCard("Anomaly", layers.anomaly?.score || 0, layers.anomaly?.label || "—")}
            ${layerCard("Rule Engine", layers.rules?.score || 0, "heuristic")}
            ${layerCard("Reputation", layers.reputation?.score || 0, "domain check")}
          </div>

          <!-- Score bar -->
          <div class="mb-16">
            <div class="flex-between mb-8" style="font-size:12px;color:var(--text-muted)">
              <span>Threat Level</span><span>${score}/100</span>
            </div>
            <div class="score-bar" style="height:10px">
              <div class="score-bar-fill" style="width:${score}%;background:${color};height:10px"></div>
            </div>
          </div>

          <!-- Reasons -->
          <div class="card-title mb-16">⚠️ Detection Reasons</div>
          <ul class="reasons-list">
            ${reasons.length ? reasons.map(reason => `
              <li class="reason-item">
                <span class="reason-bullet">▸</span>
                <span>${reason}</span>
              </li>`).join("") :
            '<li class="reason-item"><span class="reason-bullet">✓</span><span>No threat indicators detected</span></li>'}
          </ul>

          <!-- AI Explanation -->
          ${r.ai_explanation ? `
            <div class="ai-explanation mt-16">
              <div class="ai-label">✨ Gemini AI Explanation</div>
              <p>${r.ai_explanation}</p>
            </div>` : ""}

          <!-- Recommended Action -->
          <div class="alert-box ${cls === 'safe' ? 'success' : cls === 'suspicious' ? 'warning' : 'danger'} mt-16">
            <span>🎯</span>
            <span><strong>Recommended Action:</strong> ${r.recommended_action}</span>
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
