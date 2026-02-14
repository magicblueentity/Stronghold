const invoke = window.__TAURI__?.core?.invoke;

const state = {
  lastReports: [],
  mapNodes: [],
  config: null,
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
  cpuThresholdInput: document.getElementById("cpuThresholdInput"),
  memoryThresholdInput: document.getElementById("memoryThresholdInput"),
  dryRunInput: document.getElementById("dryRunInput"),
};

bindNavigation();
bindActions();
boot();

async function boot() {
  if (!invoke) {
    setStatus("Tauri API nicht gefunden. Starte die App via Tauri.");
    return;
  }

  try {
    const version = await invoke("get_version");
    els.versionBadge.textContent = `v${version.string}`;
    await loadConfig();
    await refreshDashboard();
    await refreshLive();
    await refreshLogs();
  } catch (err) {
    setStatus(`Fehler beim Start: ${err}`);
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
  document.getElementById("scanBtn").addEventListener("click", async () => {
    setStatus("Vollscan gestartet...");
    const res = await invoke("run_full_scan");
    state.lastReports = res.reports;
    applyDashboard(res.dashboard);
    renderFindings(res.reports);
    await refreshLive();
    await refreshLogs();
    setStatus("Vollscan abgeschlossen.");
  });

  document.getElementById("seedBtn").addEventListener("click", async () => {
    const msg = await invoke("seed_sample_logs");
    setStatus(msg);
    await refreshLogs();
  });

  document.getElementById("snapshotBtn").addEventListener("click", async () => {
    const label = `snapshot-${new Date().toISOString()}`;
    const msg = await invoke("create_snapshot_cmd", { label });
    setStatus(msg);
  });

  document.getElementById("isolateBtn").addEventListener("click", async () => {
    const pid = Number(document.getElementById("pidInput").value);
    if (!Number.isFinite(pid) || pid <= 0) {
      setStatus("Bitte gültige PID eingeben.");
      return;
    }
    if (!window.confirm(`Prozess ${pid} wirklich isolieren?`)) return;
    const res = await invoke("isolate_process_cmd", { pid });
    printResponse(res);
  });

  document.getElementById("blockIpBtn").addEventListener("click", async () => {
    const ip = document.getElementById("ipInput").value.trim();
    if (!ip) {
      setStatus("Bitte IP eingeben.");
      return;
    }
    if (!window.confirm(`IP ${ip} temporär blockieren?`)) return;
    const res = await invoke("block_ip_cmd", { ip, minutes: 30 });
    printResponse(res);
  });

  document.getElementById("quarantineBtn").addEventListener("click", async () => {
    const path = document.getElementById("fileInput").value.trim();
    if (!path) {
      setStatus("Bitte Dateipfad eingeben.");
      return;
    }
    if (!window.confirm(`Datei in Quarantäne verschieben?\n${path}`)) return;
    const res = await invoke("quarantine_file_cmd", { path });
    printResponse(res);
  });

  document.getElementById("rollbackBtn").addEventListener("click", async () => {
    if (!window.confirm("Registry-Rollback ausführen?")) return;
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

  setInterval(refreshLive, 9000);
  setInterval(refreshDashboard, 15000);
}

async function refreshDashboard() {
  const snapshot = await invoke("get_dashboard_snapshot");
  applyDashboard(snapshot);
}

async function refreshLive() {
  const payload = await invoke("get_network_live");
  els.connectionRows.innerHTML = payload.connections
    .slice(0, 80)
    .map((c) => `<tr><td>${c.protocol}</td><td>${c.local_address}</td><td>${c.remote_address}</td><td>${c.state}</td><td>${c.pid ?? "-"}</td></tr>`)
    .join("");

  state.mapNodes = payload.map_nodes;
  drawMap();

  els.networkConnections.textContent = payload.connections.length;
}

async function refreshLogs() {
  const logs = await invoke("get_logs", { limit: 120 });
  els.logRows.innerHTML = logs
    .map((l) => `<tr><td>${new Date(l.ts).toLocaleString()}</td><td>${l.module}</td><td>${badge(l.severity)}</td><td>${l.event_type}</td><td>${l.summary}</td></tr>`)
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
      rows.push(`<p><strong>${f.module}</strong> ${badge(f.severity)} ${f.title}<br>${f.details}</p>`);
    });
  });

  els.findingsList.innerHTML = rows.length ? rows.join("") : "<p>Keine Findings im letzten Scan.</p>";
}

function badge(level) {
  const color = level === "green" || level === "low" ? "var(--green)" : level === "yellow" || level === "medium" ? "var(--yellow)" : "var(--red)";
  return `<span style="color:${color};font-weight:700">${level.toUpperCase()}</span>`;
}

function printResponse(res) {
  els.responseOutput.textContent = JSON.stringify(res, null, 2);
  setStatus(res.message ?? "Aktion abgeschlossen.");
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

async function loadConfig() {
  const config = await invoke("get_config");
  state.config = config;
  els.cpuThresholdInput.value = String(Math.round(config.cpu_alert_threshold));
  els.memoryThresholdInput.value = String(Math.round(config.memory_alert_threshold));
  els.dryRunInput.checked = !!config.dry_run_response;
}

async function saveSettings() {
  if (!state.config) {
    setStatus("Konfiguration ist noch nicht geladen.");
    return;
  }

  const cpu = Number(els.cpuThresholdInput.value);
  const memory = Number(els.memoryThresholdInput.value);
  if (!Number.isFinite(cpu) || !Number.isFinite(memory) || cpu < 20 || cpu > 95 || memory < 20 || memory > 95) {
    setStatus("Thresholds müssen zwischen 20 und 95 liegen.");
    return;
  }

  const next = {
    ...state.config,
    cpu_alert_threshold: cpu,
    memory_alert_threshold: memory,
    dry_run_response: !!els.dryRunInput.checked,
  };

  const msg = await invoke("save_config", { config: next });
  state.config = next;
  setStatus(msg);
}
