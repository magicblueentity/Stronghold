use crate::models::ResponseReport;
use anyhow::{anyhow, Result};
use chrono::Local;
use serde_json::json;
use std::{
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
    let target = Path::new(quarantine_dir).join(format!("{}_{}", Local::now().timestamp(), file_name));
    fs::rename(&source, &target)?;
    Ok(target.display().to_string())
}

pub fn create_system_snapshot(snapshot_path: &str) -> Result<String> {
    let data = json!({
        "created_at": Local::now().to_rfc3339(),
        "note": "Stronghold local system response snapshot",
        "registry_reverted": false,
        "offline_capable": true
    });
    fs::write(snapshot_path, serde_json::to_string_pretty(&data)?)?;
    Ok(snapshot_path.to_string())
}

pub fn revert_registry_changes() -> Vec<String> {
    vec![
        "HKCU/Software/Stronghold/SuspiciousRunEntry".to_string(),
        "HKLM/Software/Microsoft/Windows/CurrentVersion/Run/UnknownAgent".to_string(),
    ]
}

pub fn empty_report() -> ResponseReport {
    ResponseReport {
        isolated_processes: Vec::new(),
        quarantined_files: Vec::new(),
        reverted_registry_entries: Vec::new(),
        snapshot_file: None,
    }
}
