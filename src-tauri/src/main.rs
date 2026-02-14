mod behavior;
mod config;
mod db;
mod human_risk;
mod models;
mod network;
mod response;
mod scanner;
mod version;

use std::{path::PathBuf, sync::{Mutex, RwLock}};

use chrono::{DateTime, Utc};
use models::{DashboardSnapshot, MapNode, ModuleReport, ThreatLogEntry};
use serde::Serialize;
use tauri::State;

use crate::{
    config::AppConfig,
    db::Database,
    response::{block_ip_temporarily, create_snapshot_payload, isolate_process, quarantine_file, rollback_registry_changes},
};

struct AppState {
    db: Mutex<Database>,
    config: RwLock<AppConfig>,
    last_scan_at: Mutex<Option<DateTime<Utc>>>,
    latest_map: Mutex<Vec<MapNode>>,
}

#[derive(Serialize)]
struct FullScanResult {
    dashboard: DashboardSnapshot,
    reports: Vec<ModuleReport>,
}

#[derive(Serialize)]
struct NetworkPayload {
    connections: Vec<models::NetworkConnection>,
    map_nodes: Vec<MapNode>,
}

#[tauri::command]
fn get_version() -> models::AppVersion {
    version::current_version()
}

#[tauri::command]
fn get_config(state: State<AppState>) -> Result<AppConfig, String> {
    let cfg = state.config.read().map_err(|e| e.to_string())?;
    Ok(cfg.clone())
}

#[tauri::command]
fn run_full_scan(state: State<AppState>, password_samples: Vec<String>) -> Result<FullScanResult, String> {
    let config = state.config.read().map_err(|e| e.to_string())?.clone();

    let integrity = scanner::run_system_integrity_scan(&config);
    let behavioral = behavior::run_behavioral_detection(&config);
    let (network_report, connections, map_nodes) = network::run_network_scan();
    let human = human_risk::run_human_risk_monitor(&config, password_samples);

    let reports = vec![integrity, behavioral, network_report, human];
    let dashboard = build_dashboard(&reports, connections.len());

    {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        persist_reports(&db, &reports)?;
        db.insert_history(&dashboard).map_err(|e| e.to_string())?;
    }

    {
        let mut scan_time = state.last_scan_at.lock().map_err(|e| e.to_string())?;
        *scan_time = Some(Utc::now());
    }

    {
        let mut latest_map = state.latest_map.lock().map_err(|e| e.to_string())?;
        *latest_map = map_nodes;
    }

    Ok(FullScanResult { dashboard, reports })
}

#[tauri::command]
fn get_network_live(state: State<AppState>) -> Result<NetworkPayload, String> {
    let connections = network::list_connections();
    let nodes = {
        let cache = state.latest_map.lock().map_err(|e| e.to_string())?;
        if cache.is_empty() {
            let (_, _, nodes) = network::run_network_scan();
            nodes
        } else {
            cache.clone()
        }
    };

    Ok(NetworkPayload {
        connections,
        map_nodes: nodes,
    })
}

#[tauri::command]
fn get_dashboard_snapshot(state: State<AppState>) -> Result<DashboardSnapshot, String> {
    compute_dashboard_snapshot(&state)
}

fn compute_dashboard_snapshot(state: &State<AppState>) -> Result<DashboardSnapshot, String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    let logs = db.list_logs(250).map_err(|e| e.to_string())?;
    let active_threats = logs.iter().filter(|l| l.severity != "low").count() as u32;
    let latest_score = if logs.is_empty() {
        100
    } else {
        let avg: u32 = logs.iter().map(|l| l.risk_score as u32).sum::<u32>() / logs.len() as u32;
        avg as u8
    };

    let last_scan = state
        .last_scan_at
        .lock()
        .map_err(|e| e.to_string())?
        .clone();
    let network_connections = network::list_connections().len();

    Ok(DashboardSnapshot {
        security_score: latest_score,
        risk_status: status_from_score(latest_score).to_string(),
        active_threats,
        network_connections,
        last_scan_at: last_scan,
    })
}

#[tauri::command]
fn get_logs(state: State<AppState>, limit: usize) -> Result<Vec<ThreatLogEntry>, String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    db.list_logs(limit).map_err(|e| e.to_string())
}

#[tauri::command]
fn export_logs(state: State<AppState>, format: String, destination: String) -> Result<String, String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    let path = PathBuf::from(destination);

    match format.to_lowercase().as_str() {
        "json" => db.export_logs_json(&path).map_err(|e| e.to_string())?,
        "csv" => db.export_logs_csv(&path).map_err(|e| e.to_string())?,
        _ => return Err("Unsupported format. Use 'json' or 'csv'.".to_string()),
    }

    Ok(format!("Logs exported to {}", path.display()))
}

#[tauri::command]
fn isolate_process_cmd(state: State<AppState>, pid: u32) -> Result<models::ResponseActionResult, String> {
    let cfg = state.config.read().map_err(|e| e.to_string())?.clone();
    let result = isolate_process(pid, &cfg);
    log_response_action(&state, &result, "Isolation & Response Engine")?;
    Ok(result)
}

#[tauri::command]
fn quarantine_file_cmd(state: State<AppState>, path: String) -> Result<models::ResponseActionResult, String> {
    let cfg = state.config.read().map_err(|e| e.to_string())?.clone();
    let result = quarantine_file(&path, &cfg);
    log_response_action(&state, &result, "Isolation & Response Engine")?;
    Ok(result)
}

#[tauri::command]
fn rollback_registry_cmd(state: State<AppState>) -> Result<models::ResponseActionResult, String> {
    let cfg = state.config.read().map_err(|e| e.to_string())?.clone();
    let result = rollback_registry_changes(&cfg);
    log_response_action(&state, &result, "Isolation & Response Engine")?;
    Ok(result)
}

#[tauri::command]
fn create_snapshot_cmd(state: State<AppState>, label: String) -> Result<String, String> {
    let dashboard = compute_dashboard_snapshot(&state)?;
    let payload = create_snapshot_payload(&label, dashboard.security_score, dashboard.active_threats);
    let db = state.db.lock().map_err(|e| e.to_string())?;
    db.insert_snapshot(&label, &payload).map_err(|e| e.to_string())?;
    Ok(format!("Snapshot '{}' created", label))
}

#[tauri::command]
fn block_ip_cmd(state: State<AppState>, ip: String, minutes: u32) -> Result<models::ResponseActionResult, String> {
    let cfg = state.config.read().map_err(|e| e.to_string())?.clone();
    let result = block_ip_temporarily(&ip, minutes, &cfg);
    log_response_action(&state, &result, "Network Surveillance Layer")?;
    Ok(result)
}

#[tauri::command]
fn seed_sample_logs(state: State<AppState>) -> Result<String, String> {
    let now = Utc::now();
    let samples = vec![
        ThreatLogEntry {
            id: None,
            ts: now,
            module: "System Integrity Scanner".to_string(),
            severity: "medium".to_string(),
            event_type: "startup_script_detected".to_string(),
            summary: "Unexpected script in startup folder".to_string(),
            details: "File C:\\ProgramData\\...\\Startup\\runme.ps1 flagged".to_string(),
            risk_score: 68,
        },
        ThreatLogEntry {
            id: None,
            ts: now,
            module: "Network Surveillance Layer".to_string(),
            severity: "high".to_string(),
            event_type: "suspicious_port".to_string(),
            summary: "Outbound connection to high-risk port".to_string(),
            details: "Established to 185.41.22.9:4444 by pid 5580".to_string(),
            risk_score: 42,
        },
        ThreatLogEntry {
            id: None,
            ts: now,
            module: "Human Risk Monitor".to_string(),
            severity: "high".to_string(),
            event_type: "weak_password_pattern".to_string(),
            summary: "Weak password sample detected".to_string(),
            details: "Pattern matched banned dictionary token".to_string(),
            risk_score: 51,
        },
    ];

    let db = state.db.lock().map_err(|e| e.to_string())?;
    for s in &samples {
        db.insert_log(s).map_err(|e| e.to_string())?;
    }

    Ok("Sample logs inserted".to_string())
}

fn build_dashboard(reports: &[ModuleReport], network_connections: usize) -> DashboardSnapshot {
    let module_avg = if reports.is_empty() {
        100
    } else {
        reports.iter().map(|r| r.score as u32).sum::<u32>() as f32 / reports.len() as f32
    };

    let active_threats = reports
        .iter()
        .flat_map(|r| &r.findings)
        .filter(|f| f.severity == "high" || f.severity == "critical")
        .count() as u32;

    let score = module_avg.round() as u8;

    DashboardSnapshot {
        security_score: score,
        risk_status: status_from_score(score).to_string(),
        active_threats,
        network_connections,
        last_scan_at: Some(Utc::now()),
    }
}

fn status_from_score(score: u8) -> &'static str {
    match score {
        80..=100 => "green",
        55..=79 => "yellow",
        _ => "red",
    }
}

fn persist_reports(db: &Database, reports: &[ModuleReport]) -> Result<(), String> {
    for report in reports {
        for finding in &report.findings {
            let risk = risk_from_impact(finding.score_impact);
            let entry = ThreatLogEntry {
                id: None,
                ts: Utc::now(),
                module: report.module.clone(),
                severity: finding.severity.clone(),
                event_type: finding.title.to_lowercase().replace(' ', "_"),
                summary: finding.title.clone(),
                details: finding.details.clone(),
                risk_score: risk,
            };
            db.insert_log(&entry).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

fn risk_from_impact(impact: i16) -> u8 {
    let val = 100 - impact.unsigned_abs() as i16 * 3;
    val.clamp(1, 100) as u8
}

fn log_response_action(state: &State<AppState>, result: &models::ResponseActionResult, module: &str) -> Result<(), String> {
    let severity = if result.success { "low" } else { "high" };
    let score = if result.success { 85 } else { 35 };

    let entry = ThreatLogEntry {
        id: None,
        ts: Utc::now(),
        module: module.to_string(),
        severity: severity.to_string(),
        event_type: result.action.clone(),
        summary: result.action.clone(),
        details: result.message.clone(),
        risk_score: score,
    };

    let db = state.db.lock().map_err(|e| e.to_string())?;
    db.insert_log(&entry).map_err(|e| e.to_string())?;
    Ok(())
}

fn main() {
    let app_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let data_dir = app_dir.join("stronghold_data");

    let config = config::AppConfig::load_or_create(&app_dir).expect("Failed to load app config");
    let db = db::Database::new(&data_dir).expect("Failed to open database");

    tauri::Builder::default()
        .manage(AppState {
            db: Mutex::new(db),
            config: RwLock::new(config),
            last_scan_at: Mutex::new(None),
            latest_map: Mutex::new(Vec::new()),
        })
        .invoke_handler(tauri::generate_handler![
            get_version,
            get_config,
            run_full_scan,
            get_network_live,
            get_dashboard_snapshot,
            get_logs,
            export_logs,
            isolate_process_cmd,
            quarantine_file_cmd,
            rollback_registry_cmd,
            create_snapshot_cmd,
            block_ip_cmd,
            seed_sample_logs,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
