use crate::{
    config::AppConfig,
    models::{BehaviorReport, HumanRiskReport, ResponseReport, RiskLevel},
};
use anyhow::{anyhow, Result};
use chrono::Local;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

pub fn isolate_process(pid: u32) -> Result<()> {
    let status = Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/F"])
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(anyhow!("taskkill failed for PID {pid}"))
    }
}

pub fn quarantine_file(file: &str, quarantine_dir: &str) -> Result<String> {
    let source = PathBuf::from(file);
    if !source.exists() {
        return Err(anyhow!("File does not exist: {file}"));
    }
    fs::create_dir_all(quarantine_dir)?;
    let file_name = source
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow!("Invalid file name: {file}"))?;
    let target =
        Path::new(quarantine_dir).join(format!("{}_{}", Local::now().timestamp(), file_name));
    fs::rename(&source, &target)?;
    Ok(target.display().to_string())
}

pub fn create_system_snapshot(snapshot_path: &str) -> Result<String> {
    let process_count = sysinfo::System::new_all().processes().len();
    let net_connections = Command::new("netstat")
        .args(["-ano"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).lines().count())
        .unwrap_or(0);
    let data = json!({
        "created_at": Local::now().to_rfc3339(),
        "note": "Stronghold local system response snapshot",
        "process_count": process_count,
        "connection_line_count": net_connections,
        "registry_reverted": false,
        "offline_capable": true
    });
    fs::write(snapshot_path, serde_json::to_string_pretty(&data)?)?;
    Ok(snapshot_path.to_string())
}

pub fn revert_registry_changes() -> Vec<String> {
    let targets = [
        (
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "SuspiciousRunEntry",
        ),
        (
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
            "UnknownAgent",
        ),
    ];

    let mut reverted = Vec::new();
    for (key, value_name) in targets {
        let status = Command::new("reg")
            .args(["delete", key, "/v", value_name, "/f"])
            .status();
        if let Ok(s) = status {
            if s.success() {
                reverted.push(format!("{key}\\{value_name}"));
            }
        }
    }
    reverted
}

pub fn empty_report() -> ResponseReport {
    ResponseReport {
        isolated_processes: Vec::new(),
        quarantined_files: Vec::new(),
        reverted_registry_entries: Vec::new(),
        snapshot_file: None,
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AutoResponseOutcome {
    pub isolated_pids: Vec<u32>,
    pub quarantined_paths: Vec<String>,
    pub reverted_registry_entries: Vec<String>,
    pub snapshot_file: Option<String>,
    pub action_count: usize,
}

pub fn run_auto_response_cycle(
    config: &AppConfig,
    behavior: &BehaviorReport,
    human_risk: &HumanRiskReport,
    risk_level: RiskLevel,
    seen_pids: &mut HashSet<u32>,
    seen_files: &mut HashSet<String>,
) -> AutoResponseOutcome {
    let mut out = AutoResponseOutcome::default();
    let self_pid = std::process::id();

    for pid in behavior
        .suspicious_processes
        .iter()
        .map(|p| p.pid)
        .take(config.max_auto_isolations_per_cycle)
    {
        if pid == self_pid || seen_pids.contains(&pid) {
            continue;
        }
        if isolate_process(pid).is_ok() {
            seen_pids.insert(pid);
            out.isolated_pids.push(pid);
            out.action_count += 1;
        }
    }

    let mut candidates = Vec::new();
    candidates.extend(behavior.file_anomalies.iter().cloned());
    candidates.extend(human_risk.unsafe_downloads.iter().map(|f| f.path.clone()));

    let mut quarantined = 0usize;
    for file in candidates {
        if quarantined >= config.max_auto_quarantines_per_cycle {
            break;
        }
        if seen_files.contains(&file) {
            continue;
        }
        if let Ok(path) = quarantine_file(&file, &config.quarantine_dir) {
            seen_files.insert(file);
            out.quarantined_paths.push(path);
            quarantined += 1;
            out.action_count += 1;
        }
    }

    if risk_level == RiskLevel::Red {
        let reverted = revert_registry_changes();
        if !reverted.is_empty() {
            out.action_count += 1;
            out.reverted_registry_entries = reverted;
        }

        if let Ok(snapshot) = create_system_snapshot("logs/system_snapshot.json") {
            out.snapshot_file = Some(snapshot);
            out.action_count += 1;
        }
    }

    out
}
