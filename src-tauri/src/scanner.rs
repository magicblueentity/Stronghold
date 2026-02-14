use std::{
    collections::HashSet,
    fs,
    path::PathBuf,
    process::Command,
};

use chrono::Utc;
use sha2::{Digest, Sha256};
use sysinfo::System;

use crate::{config::AppConfig, models::{ModuleFinding, ModuleReport}};

pub fn run_system_integrity_scan(config: &AppConfig) -> ModuleReport {
    let started_at = Utc::now();
    let mut findings = Vec::new();

    let mut sys = System::new_all();
    sys.refresh_all();

    let suspicious: HashSet<String> = config
        .suspicious_processes
        .iter()
        .map(|s| s.to_lowercase())
        .collect();

    for proc in sys.processes().values() {
        let name = proc.name().to_string_lossy().to_lowercase();
        if suspicious.iter().any(|sig| name.contains(sig)) {
            findings.push(ModuleFinding {
                module: "System Integrity Scanner".to_string(),
                severity: "high".to_string(),
                title: "Suspicious process signature".to_string(),
                details: format!("Process '{}' matched suspicious signatures", proc.name().to_string_lossy()),
                score_impact: -15,
            });
        }
    }

    findings.extend(check_critical_files(&config.critical_files));
    findings.extend(check_registry_keys(&config.registry_keys));
    findings.extend(check_startup_items(&config.startup_paths));

    let score = score_from_findings(100, &findings);
    let finished_at = Utc::now();

    ModuleReport {
        module: "System Integrity Scanner".to_string(),
        started_at,
        finished_at,
        score,
        findings,
    }
}

fn check_critical_files(paths: &[PathBuf]) -> Vec<ModuleFinding> {
    let mut findings = Vec::new();

    for path in paths {
        if !path.exists() {
            findings.push(ModuleFinding {
                module: "System Integrity Scanner".to_string(),
                severity: "critical".to_string(),
                title: "Critical system file missing".to_string(),
                details: format!("Expected file not found: {}", path.display()),
                score_impact: -20,
            });
            continue;
        }

        match fs::read(path) {
            Ok(contents) => {
                let mut hasher = Sha256::new();
                hasher.update(contents);
                let digest = format!("{:x}", hasher.finalize());
                if digest.starts_with("0000") {
                    findings.push(ModuleFinding {
                        module: "System Integrity Scanner".to_string(),
                        severity: "medium".to_string(),
                        title: "Unusual hash pattern".to_string(),
                        details: format!(
                            "File {} has an unusual hash prefix (heuristic trigger)",
                            path.display()
                        ),
                        score_impact: -6,
                    });
                }
            }
            Err(err) => {
                findings.push(ModuleFinding {
                    module: "System Integrity Scanner".to_string(),
                    severity: "medium".to_string(),
                    title: "Critical file unreadable".to_string(),
                    details: format!("Could not read {}: {}", path.display(), err),
                    score_impact: -10,
                });
            }
        }
    }

    findings
}

fn check_registry_keys(keys: &[String]) -> Vec<ModuleFinding> {
    let mut findings = Vec::new();

    for key in keys {
        let output = Command::new("reg")
            .args(["query", key])
            .output();

        match output {
            Ok(out) if out.status.success() => {
                let body = String::from_utf8_lossy(&out.stdout);
                if body.to_lowercase().contains("powershell -enc") {
                    findings.push(ModuleFinding {
                        module: "System Integrity Scanner".to_string(),
                        severity: "high".to_string(),
                        title: "Potential obfuscated autorun".to_string(),
                        details: format!("Registry key contains encoded PowerShell command: {}", key),
                        score_impact: -12,
                    });
                }
            }
            Ok(_) => {
                findings.push(ModuleFinding {
                    module: "System Integrity Scanner".to_string(),
                    severity: "low".to_string(),
                    title: "Registry key unavailable".to_string(),
                    details: format!("Could not query registry key {}", key),
                    score_impact: -3,
                });
            }
            Err(err) => {
                findings.push(ModuleFinding {
                    module: "System Integrity Scanner".to_string(),
                    severity: "low".to_string(),
                    title: "Registry scanner error".to_string(),
                    details: format!("Failed to execute reg query for {}: {}", key, err),
                    score_impact: -2,
                });
            }
        }
    }

    findings
}

fn check_startup_items(paths: &[PathBuf]) -> Vec<ModuleFinding> {
    let mut findings = Vec::new();

    for path in paths {
        if !path.exists() {
            continue;
        }

        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                let p = entry.path();
                if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
                    let ext = ext.to_lowercase();
                    if ["ps1", "vbs", "js", "hta"].contains(&ext.as_str()) {
                        findings.push(ModuleFinding {
                            module: "System Integrity Scanner".to_string(),
                            severity: "medium".to_string(),
                            title: "Script in startup path".to_string(),
                            details: format!("Startup script found: {}", p.display()),
                            score_impact: -8,
                        });
                    }
                }
            }
        }
    }

    findings
}

fn score_from_findings(start: i16, findings: &[ModuleFinding]) -> u8 {
    let mut score = start;
    for f in findings {
        score += f.score_impact;
    }
    score.clamp(0, 100) as u8
}
