use std::{
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
    process::Command,
    str::FromStr,
};

use chrono::Utc;

use crate::{config::AppConfig, models::ResponseActionResult};

pub fn isolate_process(pid: u32, config: &AppConfig) -> ResponseActionResult {
    if pid <= 4 {
        return ResponseActionResult {
            success: false,
            action: "isolate_process".to_string(),
            message: "Refusing to terminate system-critical PID <= 4".to_string(),
        };
    }

    if config.dry_run_response {
        return ResponseActionResult {
            success: true,
            action: "isolate_process".to_string(),
            message: format!("Dry-run enabled: process {} would be terminated and isolated", pid),
        };
    }

    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!("Stop-Process -Id {} -Force", pid),
        ])
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

    let source_path = match source_path.canonicalize() {
        Ok(v) => v,
        Err(err) => {
            return ResponseActionResult {
                success: false,
                action: "quarantine_file".to_string(),
                message: format!("Could not resolve source file path: {}", err),
            }
        }
    };

    if !is_path_allowed_for_quarantine(&source_path, &config.allowed_quarantine_roots) {
        return ResponseActionResult {
            success: false,
            action: "quarantine_file".to_string(),
            message: "File is outside allowed quarantine roots (Downloads/Desktop/Temp by default)".to_string(),
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
        message: "Registry rollback requires backup snapshots; not available in this run"
            .to_string(),
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
    let minutes = minutes.clamp(1, 240);
    let parsed = match IpAddr::from_str(ip) {
        Ok(v) => v,
        Err(_) => {
            return ResponseActionResult {
                success: false,
                action: "block_ip".to_string(),
                message: "Invalid IP address".to_string(),
            }
        }
    };

    if !is_blockable_remote_ip(parsed) {
        return ResponseActionResult {
            success: false,
            action: "block_ip".to_string(),
            message: "Refusing to block loopback, multicast, link-local, or private ranges"
                .to_string(),
        };
    }

    if config.dry_run_response {
        return ResponseActionResult {
            success: true,
            action: "block_ip".to_string(),
            message: format!(
                "Dry-run enabled: firewall rule would block {} for {} minutes",
                ip, minutes
            ),
        };
    }

    let rule_name = format!(
        "StrongholdBlock_{}_{}",
        ip.replace('.', "_").replace(':', "_"),
        Utc::now().timestamp()
    );
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
        Ok(out) if out.status.success() => {
            let _ = schedule_rule_removal(&rule_name, minutes);
            ResponseActionResult {
                success: true,
                action: "block_ip".to_string(),
                message: format!(
                    "IP {} blocked for {} minutes (auto-removal scheduled)",
                    ip, minutes
                ),
            }
        }
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

fn schedule_rule_removal(rule_name: &str, minutes: u32) -> anyhow::Result<()> {
    let script = format!(
        "Start-Sleep -Seconds {}; netsh advfirewall firewall delete rule name=\"{}\"",
        minutes * 60,
        rule_name
    );
    Command::new("powershell")
        .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &script])
        .spawn()?;
    Ok(())
}

fn is_path_allowed_for_quarantine(path: &Path, roots: &[PathBuf]) -> bool {
    roots.iter().any(|root| {
        let canonical_root = root.canonicalize().unwrap_or_else(|_| root.clone());
        path.starts_with(canonical_root)
    })
}

fn quarantine_name(path: &Path) -> String {
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("artifact.bin");
    format!("{}_{}", Utc::now().timestamp(), name)
}

fn is_blockable_remote_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_unspecified())
        }
        IpAddr::V6(v6) => !(v6.is_loopback() || v6.is_multicast() || v6.is_unspecified()),
    }
}
