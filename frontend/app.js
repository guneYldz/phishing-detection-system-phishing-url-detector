const API_BASE =
  window.location.protocol === "file:" || (window.location.port && window.location.port !== "8000")
    ? "http://127.0.0.1:8000"
    : "";

let lastBatchData = null;

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function switchTab(tabName) {
  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.tab === tabName);
  });
  document.querySelectorAll(".tab-panel").forEach((panel) => {
    panel.classList.toggle("active", panel.id === "tab-" + tabName);
  });
}

function showError(elemId, msg) {
  const el = document.getElementById(elemId);
  el.style.display = msg ? "block" : "none";
  el.textContent = msg || "";
}

async function loadSystemStatus() {
  const healthBadge = document.getElementById("badge-health");
  try {
    const [healthRes, infoRes] = await Promise.all([
      fetch(API_BASE + "/api/health"),
      fetch(API_BASE + "/api/model-info")
    ]);

    if (healthRes.ok) {
      const h = await healthRes.json();
      if (h.model_loaded) {
        healthBadge.className = "badge badge-ok";
        healthBadge.innerHTML = '<span class="dot"></span> XGBoost Aktif (' + escapeHtml(h.feature_count) + " Özellik)";
      } else {
        healthBadge.className = "badge badge-err";
        healthBadge.innerHTML = '<span class="dot"></span> Model Yüklenemedi';
      }
      if (h.sla_max_latency_ms) {
        document.getElementById("badge-sla").textContent = "SLA: <" + h.sla_max_latency_ms + " ms";
      }
    }

    if (infoRes.ok) {
      const info = await infoRes.json();
      const xg = info.evaluation && info.evaluation.xgboost;
      if (xg) {
        document.getElementById("badge-acc").textContent = "Doğruluk: %" + (xg.accuracy * 100).toFixed(2);
        document.getElementById("badge-f1").textContent = "F1: %" + (xg.f1_score * 100).toFixed(2);
        document.getElementById("badge-fpr").textContent = "FPR: %" + (xg.fpr * 100).toFixed(2);
      }
    }
  } catch (_) {
    healthBadge.className = "badge badge-err";
    healthBadge.innerHTML = '<span class="dot"></span> API Kapalı (Backend Başlatılmalı)';
  }
}

function fillSingleSample(url) {
  document.getElementById("single-url-input").value = url;
  analyzeSingleUrl();
}

async function analyzeSingleUrl() {
  const input = document.getElementById("single-url-input");
  const btn = document.getElementById("btn-single-analyze");
  const url = input.value.trim();
  showError("single-error", "");

  if (!url) {
    showError("single-error", "Lütfen analiz edilecek bir URL girin.");
    return;
  }

  btn.disabled = true;
  btn.textContent = "Analiz Ediliyor...";

  try {
    const resp = await fetch(API_BASE + "/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });
    const data = await resp.json();
    if (!resp.ok) {
      const detail = Array.isArray(data.detail) ? data.detail.map((d) => d.msg).join(", ") : data.detail;
      throw new Error(detail || "Analiz sırasında hata oluştu.");
    }
    renderSingleResult(data);
  } catch (err) {
    if (err instanceof TypeError) {
      showError("single-error", "API sunucusuna bağlanılamadı. FastAPI sunucusunu (127.0.0.1:8000) başlatın.");
    } else {
      showError("single-error", err.message);
    }
  } finally {
    btn.disabled = false;
    btn.textContent = "Analiz Et";
  }
}

function renderSingleResult(data) {
  document.getElementById("single-result-area").classList.remove("hidden");
  const isPhish = data.is_phishing;

  document.getElementById("verdict-box").className = "verdict-box " + (isPhish ? "verdict-phish" : "verdict-safe");
  document.getElementById("verdict-label").textContent = isPhish ? "ZARARLI (PHISHING)" : "GÜVENLİ (BENIGN)";

  const riskPill = document.getElementById("verdict-risk-pill");
  riskPill.textContent = "Risk: " + data.risk_level;
  riskPill.className = "pill " + (isPhish ? "pill-phish" : (data.phishing_probability >= 0.25 ? "pill-warn" : "pill-safe"));

  document.getElementById("verdict-url").textContent = data.url;
  document.getElementById("verdict-phish-prob").textContent = "%" + (data.phishing_probability * 100).toFixed(2);
  document.getElementById("verdict-benign-prob").textContent = "%" + (data.benign_probability * 100).toFixed(2);
  document.getElementById("verdict-latency").textContent = data.latency_ms + " ms";

  const bar = document.getElementById("prob-bar-fill");
  bar.style.width = Math.max(4, Math.min(100, data.phishing_probability * 100)) + "%";
  bar.style.backgroundColor = isPhish ? "#ef4444" : "#10b981";

  const factorsList = document.getElementById("single-factors-list");
  factorsList.innerHTML = "";
  (data.risk_factors || []).forEach((f) => {
    const div = document.createElement("div");
    div.className = "factor-item factor-" + escapeHtml(f.severity || "low");
    div.innerHTML =
      '<div class="factor-title">' + escapeHtml(f.factor) + "</div>" +
      '<div class="factor-desc">' + escapeHtml(f.description) + "</div>";
    factorsList.appendChild(div);
  });

  const featGrid = document.getElementById("single-features-grid");
  featGrid.innerHTML = "";
  Object.entries(data.lexical_features || {}).forEach(([k, v]) => {
    const chip = document.createElement("div");
    chip.className = "feat-chip";
    chip.innerHTML =
      '<span class="feat-name" title="' + escapeHtml(k) + '">' + escapeHtml(k) + "</span>" +
      '<span class="feat-val">' + escapeHtml(v) + "</span>";
    featGrid.appendChild(chip);
  });
}

function fillBatchSample() {
  document.getElementById("batch-urls-input").value = [
    "https://www.google.com/",
    "https://www.firat.edu.tr/",
    "https://www.youtube.com/watch?v=Z7_fQqhQfto",
    "http://192.168.1.105/banking/login.php?session=98123",
    "http://paypal-secure-login.account-update.xyz/verify?user=admin",
    "https://apple-id-support-verify.serveo.net/signin"
  ].join("\n");
}

function clearBatch() {
  document.getElementById("batch-urls-input").value = "";
  document.getElementById("batch-result-area").classList.add("hidden");
  showError("batch-error", "");
  lastBatchData = null;
}

async function analyzeBatchUrls() {
  const raw = document.getElementById("batch-urls-input").value;
  const urls = raw.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const btn = document.getElementById("btn-batch-analyze");
  showError("batch-error", "");

  if (urls.length === 0) {
    showError("batch-error", "Lütfen her satıra en az bir URL girin.");
    return;
  }
  if (urls.length > 100) {
    showError("batch-error", "Tek seferde en fazla 100 URL taranabilir.");
    return;
  }

  btn.disabled = true;
  btn.textContent = "Taranıyor...";

  try {
    const resp = await fetch(API_BASE + "/api/batch-analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ urls })
    });
    const data = await resp.json();
    if (!resp.ok) {
      const detail = Array.isArray(data.detail) ? data.detail.map((d) => d.msg).join(", ") : data.detail;
      throw new Error(detail || "Toplu tarama sırasında hata oluştu.");
    }
    lastBatchData = data;
    renderBatchResults(data);
  } catch (err) {
    if (err instanceof TypeError) {
      showError("batch-error", "API sunucusuna bağlanılamadı. FastAPI sunucusunu (127.0.0.1:8000) başlatın.");
    } else {
      showError("batch-error", err.message);
    }
  } finally {
    btn.disabled = false;
    btn.textContent = "Toplu Taramayı Başlat";
  }
}

function renderBatchResults(data) {
  document.getElementById("batch-result-area").classList.remove("hidden");
  document.getElementById("stat-total").textContent = data.total_urls;
  document.getElementById("stat-phishing").textContent = data.phishing_count;
  document.getElementById("stat-benign").textContent = data.benign_count;
  document.getElementById("stat-avg-latency").textContent = data.avg_latency_per_url_ms + " ms";
  document.getElementById("batch-total-time-info").textContent =
    "Toplam Süre: " + data.total_latency_ms + " ms | SLA (<100 ms/URL): " + (data.meets_latency_sla ? "Sağlandı" : "Aşıldı");

  const tbody = document.getElementById("batch-results-tbody");
  tbody.innerHTML = "";

  (data.results || []).forEach((item, idx) => {
    const tr = document.createElement("tr");
    const isPhish = item.is_phishing;
    const topFactor = (item.risk_factors && item.risk_factors.length > 0) ? item.risk_factors[0].factor : "-";

    tr.innerHTML =
      "<td>" + (idx + 1) + "</td>" +
      '<td class="url-cell">' + escapeHtml(item.url) + "</td>" +
      '<td><span class="pill ' + (isPhish ? "pill-phish" : "pill-safe") + '">' + (isPhish ? "PHISHING" : "BENIGN") + "</span></td>" +
      "<td>" + (item.phishing_probability * 100).toFixed(2) + "%</td>" +
      "<td>" + escapeHtml(item.risk_level) + "</td>" +
      "<td>" + escapeHtml(topFactor) + "</td>" +
      "<td>" + item.latency_ms + "</td>";
    tbody.appendChild(tr);
  });
}

function downloadFile(filename, content, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function exportBatchCSV() {
  if (!lastBatchData || !lastBatchData.results) return;
  const headers = ["Sira", "URL", "Sinif", "Phishing_Olasiligi", "Risk_Seviyesi", "Risk_Faktoru", "Sure_ms"];
  const rows = lastBatchData.results.map((r, i) => {
    const topFactor = (r.risk_factors && r.risk_factors.length > 0) ? r.risk_factors[0].factor : "-";
    return [i + 1, r.url, r.label, r.phishing_probability, r.risk_level, topFactor, r.latency_ms]
      .map((c) => '"' + String(c).replace(/"/g, '""') + '"')
      .join(",");
  });
  downloadFile("phishguard_batch_report.csv", headers.join(",") + "\n" + rows.join("\n"), "text/csv;charset=utf-8;");
}

function exportBatchJSON() {
  if (!lastBatchData) return;
  downloadFile("phishguard_batch_report.json", JSON.stringify(lastBatchData, null, 2), "application/json;charset=utf-8;");
}

document.getElementById("single-url-input").addEventListener("keydown", function (e) {
  if (e.key === "Enter") {
    analyzeSingleUrl();
  }
});

loadSystemStatus();
