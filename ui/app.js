const invoke = window.__TAURI__?.core?.invoke;

const i18n = {
  de: {
    setup_title: "Willkommen bei Stronghold",
    setup_desc: "Einmalige Grundeinrichtung fuer Alltag und Sicherheit.",
    setup_finish: "Setup abschliessen",
    suite_title: "STRONGHOLD SECURITY PLATFORM",
    nav_dashboard: "Dashboard",
    nav_live: "Live Monitor",
    nav_threat: "Threat Center",
    nav_health: "System Health",
    nav_logs: "Logs",
    nav_settings: "Settings",
    dashboard_score: "Sicherheits-Score",
    label_status: "Status",
    label_active_threats: "Aktive Bedrohungen",
    label_network_connections: "Netzwerkverbindungen",
    btn_fullscan: "Vollscan starten",
    btn_seedlogs: "Beispiel-Logs laden",
    btn_snapshot: "Snapshot",
    map_title: "Interaktive Netzwerk-Map",
    live_title: "Live Netzwerk-Feed",
    table_proto: "Proto",
    table_local: "Lokal",
    table_remote: "Remote",
    table_status: "Status",
    table_time: "Zeit",
    table_module: "Modul",
    threat_title: "Threat Center",
    btn_isolate: "Prozess isolieren",
    btn_block_ip: "IP 30 Min blockieren",
    btn_quarantine: "Datei quarantänen",
    btn_rollback: "Registry Rollback",
    placeholder_file: "Pfad zur Datei",
    health_title: "System Health Findings",
    logs_title: "Threat Logs",
    btn_refresh: "Aktualisieren",
    btn_export_csv: "Export CSV",
    btn_export_json: "Export JSON",
    settings_title: "Sicherheits-Einstellungen",
    settings_language: "Sprache",
    settings_cpu: "CPU Alert Threshold (%)",
    settings_memory: "Memory Alert Threshold (%)",
    settings_dry_run: "Response Engine im Dry-Run-Modus",
    settings_autoscan: "Automatischer Scan beim Start",
    btn_save_settings: "Einstellungen speichern",
    btn_reload_settings: "Neu laden",
    status_ready: "Bereit.",
    status_boot_error: "Fehler beim Start:",
    status_no_api: "Tauri API nicht gefunden. Starte die App via Tauri.",
    status_scan_started: "Vollscan gestartet...",
    status_scan_done: "Vollscan abgeschlossen.",
    status_seeded: "Beispiel-Logs eingefügt.",
    status_invalid_pid: "Bitte gueltige PID eingeben.",
    status_invalid_ip: "Bitte IP eingeben.",
    status_invalid_path: "Bitte Dateipfad eingeben.",
    status_invalid_thresholds: "Thresholds muessen zwischen 20 und 95 liegen.",
    status_config_loaded: "Konfiguration geladen.",
    status_config_saved: "Konfiguration gespeichert.",
    confirm_isolate: "Prozess wirklich isolieren?",
    confirm_block_ip: "IP temporaer blockieren?",
    confirm_quarantine: "Datei in Quarantaene verschieben?",
    confirm_rollback: "Registry-Rollback ausfuehren?",
    findings_none: "Keine Findings im letzten Scan.",
  },
  en: {
    setup_title: "Welcome to Stronghold",
    setup_desc: "One-time setup for everyday usability and security.",
    setup_finish: "Finish setup",
    suite_title: "STRONGHOLD SECURITY PLATFORM",
    nav_dashboard: "Dashboard",
    nav_live: "Live Monitor",
    nav_threat: "Threat Center",
    nav_health: "System Health",
    nav_logs: "Logs",
    nav_settings: "Settings",
    dashboard_score: "Security Score",
    label_status: "Status",
    label_active_threats: "Active Threats",
    label_network_connections: "Network Connections",
    btn_fullscan: "Run Full Scan",
    btn_seedlogs: "Load Sample Logs",
    btn_snapshot: "Snapshot",
    map_title: "Interactive Network Map",
    live_title: "Live Network Feed",
    table_proto: "Proto",
    table_local: "Local",
    table_remote: "Remote",
    table_status: "State",
    table_time: "Time",
    table_module: "Module",
    threat_title: "Threat Center",
    btn_isolate: "Isolate process",
    btn_block_ip: "Block IP 30 min",
    btn_quarantine: "Quarantine file",
    btn_rollback: "Registry rollback",
    placeholder_file: "Path to file",
    health_title: "System Health Findings",
    logs_title: "Threat Logs",
    btn_refresh: "Refresh",
    btn_export_csv: "Export CSV",
    btn_export_json: "Export JSON",
    settings_title: "Security Settings",
    settings_language: "Language",
    settings_cpu: "CPU Alert Threshold (%)",
    settings_memory: "Memory Alert Threshold (%)",
    settings_dry_run: "Response engine in dry-run mode",
    settings_autoscan: "Automatic scan on startup",
    btn_save_settings: "Save settings",
    btn_reload_settings: "Reload",
    status_ready: "Ready.",
    status_boot_error: "Startup error:",
    status_no_api: "Tauri API not found. Start app via Tauri.",
    status_scan_started: "Full scan started...",
    status_scan_done: "Full scan finished.",
    status_seeded: "Sample logs inserted.",
    status_invalid_pid: "Enter a valid PID.",
    status_invalid_ip: "Enter an IP address.",
    status_invalid_path: "Enter a file path.",
    status_invalid_thresholds: "Thresholds must be between 20 and 95.",
    status_config_loaded: "Configuration loaded.",
    status_config_saved: "Configuration saved.",
    confirm_isolate: "Really isolate this process?",
    confirm_block_ip: "Temporarily block this IP?",
    confirm_quarantine: "Move this file to quarantine?",
    confirm_rollback: "Execute registry rollback?",
    findings_none: "No findings in the latest scan.",
  },
};

const state = {
  config: null,
  language: "de",
  mapNodes: [],
};

const els = {
  versionBadge: document.getElementById("versionBadge"),
  scoreCircle: document.getElementById("scoreCircle"),
  riskStatus: document.getElementById("riskStatus"),
  activeThreats: document.getElementById("activeThreats"),
  networkConnections: document.getElementById("networkConnections"),
  statusBar: document.getElementById("statusBar"),
  connectionRows: document.getElementById("connectionRows"),
  findingsList: document.getElementById("findingsList"),
  logRows: document.getElementById("logRows"),
  responseOutput: document.getElementById("responseOutput"),
  mapCanvas: document.getElementById("mapCanvas"),
  setupModal: document.getElementById("setupModal"),
  setupLanguageSelect: document.getElementById("setupLanguageSelect"),
  setupCpuInput: document.getElementById("setupCpuInput"),
  setupMemoryInput: document.getElementById("setupMemoryInput"),
  setupDryRunInput: document.getElementById("setupDryRunInput"),
  setupAutoScanInput: document.getElementById("setupAutoScanInput"),
  languageSelect: document.getElementById("languageSelect"),
  cpuThresholdInput: document.getElementById("cpuThresholdInput"),
  memoryThresholdInput: document.getElementById("memoryThresholdInput"),
  dryRunInput: document.getElementById("dryRunInput"),
  autoScanInput: document.getElementById("autoScanInput"),
};

bindNavigation();
bindActions();
boot();

function t(key) {
  return i18n[state.language]?.[key] ?? i18n.de[key] ?? key;
}

function applyI18n() {
  document.documentElement.lang = state.language;
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    const key = el.getAttribute("data-i18n");
    const text = t(key);
    if (el.tagName === "LABEL") {
      if (el.firstChild && el.firstChild.nodeType === Node.TEXT_NODE) {
        el.firstChild.textContent = `${text} `;
      } else {
        el.insertBefore(document.createTextNode(`${text} `), el.firstChild || null);
      }
      return;
    }
    el.textContent = text;
  });
  document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
    el.setAttribute("placeholder", t(el.getAttribute("data-i18n-placeholder")));
  });
}

async function boot() {
  if (!invoke) {
    setStatus(t("status_no_api"));
    return;
  }

  try {
    const version = await invoke("get_version");
    els.versionBadge.textContent = `v${version.string}`;

    await loadConfig();
    applyI18n();
    await refreshDashboard();
    await refreshLive();
    await refreshLogs();

    if (!state.config.first_run_completed) {
      openSetup();
    } else if (state.config.auto_scan_on_start) {
      await runFullScan();
    }
  } catch (err) {
    setStatus(`${t("status_boot_error")} ${err}`);
  }
}

function bindNavigation() {
  document.querySelectorAll(".nav-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".nav-btn").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
      btn.classList.add("active");
      document.getElementById(`view-${btn.dataset.view}`).classList.add("active");
    });
  });
}

function bindActions() {
  document.getElementById("scanBtn").addEventListener("click", runFullScan);

  document.getElementById("seedBtn").addEventListener("click", async () => {
    await invoke("seed_sample_logs");
    setStatus(t("status_seeded"));
    await refreshLogs();
  });

  document.getElementById("snapshotBtn").addEventListener("click", async () => {
    const label = `snapshot-${new Date().toISOString()}`;
    const msg = await invoke("create_snapshot_cmd", { label });
    setStatus(msg);
  });

  document.getElementById("isolateBtn").addEventListener("click", async () => {
    const pid = Number(document.getElementById("pidInput").value);
    if (!Number.isFinite(pid) || pid <= 0) return setStatus(t("status_invalid_pid"));
    if (!window.confirm(`${t("confirm_isolate")} PID ${pid}`)) return;
    const res = await invoke("isolate_process_cmd", { pid });
    printResponse(res);
  });

  document.getElementById("blockIpBtn").addEventListener("click", async () => {
    const ip = document.getElementById("ipInput").value.trim();
    if (!ip) return setStatus(t("status_invalid_ip"));
    if (!window.confirm(`${t("confirm_block_ip")} ${ip}`)) return;
    const res = await invoke("block_ip_cmd", { ip, minutes: 30 });
    printResponse(res);
  });

  document.getElementById("quarantineBtn").addEventListener("click", async () => {
    const path = document.getElementById("fileInput").value.trim();
    if (!path) return setStatus(t("status_invalid_path"));
    if (!window.confirm(`${t("confirm_quarantine")}\n${path}`)) return;
    const res = await invoke("quarantine_file_cmd", { path });
    printResponse(res);
  });

  document.getElementById("rollbackBtn").addEventListener("click", async () => {
    if (!window.confirm(t("confirm_rollback"))) return;
    const res = await invoke("rollback_registry_cmd");
    printResponse(res);
  });

  document.getElementById("refreshLogsBtn").addEventListener("click", refreshLogs);

  document.getElementById("exportCsvBtn").addEventListener("click", async () => {
    const msg = await invoke("export_logs", {
      format: "csv",
      destination: "stronghold_data/threat_export.csv",
    });
    setStatus(msg);
  });

  document.getElementById("exportJsonBtn").addEventListener("click", async () => {
    const msg = await invoke("export_logs", {
      format: "json",
      destination: "stronghold_data/threat_export.json",
    });
    setStatus(msg);
  });

  document.getElementById("saveSettingsBtn").addEventListener("click", saveSettings);
  document.getElementById("reloadSettingsBtn").addEventListener("click", loadConfig);
  document.getElementById("setupFinishBtn").addEventListener("click", finishSetup);

  els.languageSelect.addEventListener("change", () => {
    state.language = els.languageSelect.value;
    applyI18n();
  });

  els.setupLanguageSelect.addEventListener("change", () => {
    state.language = els.setupLanguageSelect.value;
    applyI18n();
  });

  setInterval(refreshLive, 9000);
  setInterval(refreshDashboard, 15000);
}

async function runFullScan() {
  setStatus(t("status_scan_started"));
  const res = await invoke("run_full_scan");
  applyDashboard(res.dashboard);
  renderFindings(res.reports);
  await refreshLive();
  await refreshLogs();
  setStatus(t("status_scan_done"));
}

async function loadConfig() {
  const config = await invoke("get_config");
  state.config = config;
  state.language = config.preferred_language === "en" ? "en" : "de";

  els.languageSelect.value = state.language;
  els.cpuThresholdInput.value = String(Math.round(config.cpu_alert_threshold));
  els.memoryThresholdInput.value = String(Math.round(config.memory_alert_threshold));
  els.dryRunInput.checked = !!config.dry_run_response;
  els.autoScanInput.checked = !!config.auto_scan_on_start;

  els.setupLanguageSelect.value = state.language;
  els.setupCpuInput.value = String(Math.round(config.cpu_alert_threshold));
  els.setupMemoryInput.value = String(Math.round(config.memory_alert_threshold));
  els.setupDryRunInput.checked = !!config.dry_run_response;
  els.setupAutoScanInput.checked = !!config.auto_scan_on_start;

  applyI18n();
  setStatus(t("status_config_loaded"));
}

async function saveSettings() {
  const cpu = Number(els.cpuThresholdInput.value);
  const memory = Number(els.memoryThresholdInput.value);
  if (!isThresholdValid(cpu) || !isThresholdValid(memory)) {
    return setStatus(t("status_invalid_thresholds"));
  }

  const next = {
    ...state.config,
    cpu_alert_threshold: cpu,
    memory_alert_threshold: memory,
    dry_run_response: !!els.dryRunInput.checked,
    auto_scan_on_start: !!els.autoScanInput.checked,
    preferred_language: els.languageSelect.value,
  };

  const msg = await invoke("save_config", { config: next });
  state.config = next;
  state.language = next.preferred_language;
  applyI18n();
  setStatus(msg || t("status_config_saved"));
}

function openSetup() {
  els.setupModal.classList.remove("hidden");
}

async function finishSetup() {
  const cpu = Number(els.setupCpuInput.value);
  const memory = Number(els.setupMemoryInput.value);
  if (!isThresholdValid(cpu) || !isThresholdValid(memory)) {
    return setStatus(t("status_invalid_thresholds"));
  }

  const next = {
    ...state.config,
    preferred_language: els.setupLanguageSelect.value,
    cpu_alert_threshold: cpu,
    memory_alert_threshold: memory,
    dry_run_response: !!els.setupDryRunInput.checked,
    auto_scan_on_start: !!els.setupAutoScanInput.checked,
    first_run_completed: true,
  };

  await invoke("save_config", { config: next });
  state.config = next;
  state.language = next.preferred_language;
  applyI18n();

  els.setupModal.classList.add("hidden");
  await loadConfig();
  if (state.config.auto_scan_on_start) {
    await runFullScan();
  }
}

function isThresholdValid(v) {
  return Number.isFinite(v) && v >= 20 && v <= 95;
}

async function refreshDashboard() {
  const snapshot = await invoke("get_dashboard_snapshot");
  applyDashboard(snapshot);
}

async function refreshLive() {
  const payload = await invoke("get_network_live");
  els.connectionRows.innerHTML = payload.connections
    .slice(0, 80)
    .map((c) => `<tr><td>${c.protocol}</td><td>${escapeHtml(c.local_address)}</td><td>${escapeHtml(c.remote_address)}</td><td>${c.state}</td><td>${c.pid ?? "-"}</td></tr>`)
    .join("");

  state.mapNodes = payload.map_nodes;
  drawMap();
  els.networkConnections.textContent = payload.connections.length;
}

async function refreshLogs() {
  const logs = await invoke("get_logs", { limit: 120 });
  els.logRows.innerHTML = logs
    .map((l) => `<tr><td>${new Date(l.ts).toLocaleString()}</td><td>${escapeHtml(l.module)}</td><td>${badge(l.severity)}</td><td>${escapeHtml(l.event_type)}</td><td>${escapeHtml(l.summary)}</td></tr>`)
    .join("");
}

function applyDashboard(d) {
  els.scoreCircle.textContent = String(d.security_score);
  els.riskStatus.innerHTML = badge(d.risk_status);
  els.activeThreats.textContent = d.active_threats;
  els.networkConnections.textContent = d.network_connections;

  const border = d.risk_status === "green" ? "var(--green)" : d.risk_status === "yellow" ? "var(--yellow)" : "var(--red)";
  els.scoreCircle.style.borderColor = border;
}

function renderFindings(reports) {
  const rows = [];
  reports.forEach((r) => {
    r.findings.forEach((f) => {
      rows.push(`<p><strong>${escapeHtml(f.module)}</strong> ${badge(f.severity)} ${escapeHtml(f.title)}<br>${escapeHtml(f.details)}</p>`);
    });
  });
  els.findingsList.innerHTML = rows.length ? rows.join("") : `<p>${t("findings_none")}</p>`;
}

function badge(level) {
  const upper = String(level).toUpperCase();
  const color = level === "green" || level === "low" ? "var(--green)" : level === "yellow" || level === "medium" ? "var(--yellow)" : "var(--red)";
  return `<span style="color:${color};font-weight:700">${upper}</span>`;
}

function printResponse(res) {
  els.responseOutput.textContent = JSON.stringify(res, null, 2);
  setStatus(res.message ?? t("status_ready"));
}

function drawMap() {
  const canvas = els.mapCanvas;
  const ctx = canvas.getContext("2d");

  ctx.clearRect(0, 0, canvas.width, canvas.height);
  ctx.strokeStyle = "#26416f";
  ctx.lineWidth = 1;

  for (let x = 0; x < canvas.width; x += 64) {
    ctx.beginPath();
    ctx.moveTo(x, 0);
    ctx.lineTo(x, canvas.height);
    ctx.stroke();
  }
  for (let y = 0; y < canvas.height; y += 48) {
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(canvas.width, y);
    ctx.stroke();
  }

  const pulse = (Date.now() / 200) % 8;
  state.mapNodes.slice(0, 100).forEach((node) => {
    const x = ((node.longitude + 180) / 360) * canvas.width;
    const y = ((90 - node.latitude) / 180) * canvas.height;
    const color = node.risk_level === "high" ? "#ff5a67" : node.risk_level === "medium" ? "#ffc04d" : "#3cd991";

    ctx.fillStyle = color;
    ctx.beginPath();
    ctx.arc(x, y, 3 + (pulse / 8) * 2, 0, Math.PI * 2);
    ctx.fill();
  });
}

function setStatus(msg) {
  els.statusBar.textContent = msg;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
