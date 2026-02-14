use std::{fs, path::{Path, PathBuf}, process::Command};

use chrono::Utc;

use crate::{config::AppConfig, models::ResponseActionResult};

pub fn isolate_process(pid: u32, config: &AppConfig) -> ResponseActionResult {
    if config.dry_run_response {
        return ResponseActionResult {
            success: true,
            action: "isolate_process".to_string(),
            message: format!("Dry-run enabled: process {} would be terminated and isolated", pid),
        };
    }

    let output = Command::new("powershell")
        .args(["-NoProfile", "-Command", &format!("Stop-Process -Id {} -Force", pid)])
        .output();

    match output {
        Ok(out) if out.status.success() => ResponseActionResult {
            success: true,
            action: "isolate_process".to_string(),
            message: format!("Process {} terminated", pid),
        },
        Ok(out) => ResponseActionResult {
            success: false,
            action: "isolate_process".to_string(),
            message: String::from_utf8_lossy(&out.stderr).to_string(),
        },
        Err(err) => ResponseActionResult {
            success: false,
            action: "isolate_process".to_string(),
            message: err.to_string(),
        },
    }
}

pub fn quarantine_file(source: &str, config: &AppConfig) -> ResponseActionResult {
    let source_path = PathBuf::from(source);
    if !source_path.exists() {
        return ResponseActionResult {
            success: false,
            action: "quarantine_file".to_string(),
            message: "Source file does not exist".to_string(),
        };
    }

    if let Err(err) = fs::create_dir_all(&config.quarantine_dir) {
        return ResponseActionResult {
            success: false,
            action: "quarantine_file".to_string(),
            message: format!("Could not create quarantine dir: {}", err),
        };
    }

    let target = config.quarantine_dir.join(quarantine_name(&source_path));

    if config.dry_run_response {
        return ResponseActionResult {
            success: true,
            action: "quarantine_file".to_string(),
            message: format!(
                "Dry-run enabled: {} would be moved to {}",
                source_path.display(),
                target.display()
            ),
        };
    }

    match fs::rename(&source_path, &target) {
        Ok(_) => ResponseActionResult {
            success: true,
            action: "quarantine_file".to_string(),
            message: format!("File moved to quarantine: {}", target.display()),
        },
        Err(err) => ResponseActionResult {
            success: false,
            action: "quarantine_file".to_string(),
            message: err.to_string(),
        },
    }
}

pub fn rollback_registry_changes(config: &AppConfig) -> ResponseActionResult {
    if config.dry_run_response {
        return ResponseActionResult {
            success: true,
            action: "rollback_registry_changes".to_string(),
            message: "Dry-run enabled: registry rollback simulation completed".to_string(),
        };
    }

    ResponseActionResult {
        success: false,
        action: "rollback_registry_changes".to_string(),
        message: "Registry rollback requires backup snapshots; not available in this run".to_string(),
    }
}

pub fn create_snapshot_payload(label: &str, security_score: u8, active_threats: u32) -> String {
    serde_json::json!({
        "label": label,
        "created_at": Utc::now().to_rfc3339(),
        "security_score": security_score,
        "active_threats": active_threats,
        "note": "Stronghold local snapshot"
    })
    .to_string()
}

pub fn block_ip_temporarily(ip: &str, minutes: u32, config: &AppConfig) -> ResponseActionResult {
    if config.dry_run_response {
        return ResponseActionResult {
            success: true,
            action: "block_ip".to_string(),
            message: format!("Dry-run enabled: firewall rule would block {} for {} minutes", ip, minutes),
        };
    }

    let rule_name = format!("StrongholdBlock_{}_{}", ip.replace('.', "_"), Utc::now().timestamp());
    let output = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &format!("name={}", rule_name),
            "dir=out",
            "action=block",
            &format!("remoteip={}", ip),
            "enable=yes",
        ])
        .output();

    match output {
        Ok(out) if out.status.success() => ResponseActionResult {
            success: true,
            action: "block_ip".to_string(),
            message: format!("IP {} blocked for {} minutes (manual expiry needed)", ip, minutes),
        },
        Ok(out) => ResponseActionResult {
            success: false,
            action: "block_ip".to_string(),
            message: String::from_utf8_lossy(&out.stderr).to_string(),
        },
        Err(err) => ResponseActionResult {
            success: false,
            action: "block_ip".to_string(),
            message: err.to_string(),
        },
    }
}

fn quarantine_name(path: &Path) -> String {
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("artifact.bin");
    format!("{}_{}", Utc::now().timestamp(), name)
}
