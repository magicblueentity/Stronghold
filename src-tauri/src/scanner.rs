use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use chrono::Utc;
use sha2::{Digest, Sha256};
use sysinfo::System;

use crate::{
    config::AppConfig,
    models::{ModuleFinding, ModuleReport},
};

pub fn run_system_integrity_scan(config: &AppConfig, data_dir: &Path) -> ModuleReport {
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
                details: format!(
                    "Process '{}' matched suspicious signatures",
                    proc.name().to_string_lossy()
                ),
                score_impact: -15,
            });
        }
    }

    findings.extend(check_critical_files(&config.critical_files, data_dir));
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

fn check_critical_files(paths: &[PathBuf], data_dir: &Path) -> Vec<ModuleFinding> {
    let mut findings = Vec::new();
    let baseline_path = data_dir.join("critical_file_baseline.json");
    let mut baseline = load_baseline(&baseline_path);
    let mut baseline_changed = false;

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

        match hash_file(path) {
            Ok(digest) => {
                let key = path.to_string_lossy().to_string();
                match baseline.get(&key) {
                    Some(known) if known != &digest => {
                        findings.push(ModuleFinding {
                            module: "System Integrity Scanner".to_string(),
                            severity: "high".to_string(),
                            title: "Critical file hash changed".to_string(),
                            details: format!(
                                "Hash changed for {}. Validate patches/signatures.",
                                path.display()
                            ),
                            score_impact: -15,
                        });
                    }
                    None => {
                        baseline.insert(key, digest);
                        baseline_changed = true;
                    }
                    _ => {}
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

    if baseline_changed {
        let _ = save_baseline(&baseline_path, &baseline);
        findings.push(ModuleFinding {
            module: "System Integrity Scanner".to_string(),
            severity: "low".to_string(),
            title: "Integrity baseline initialized".to_string(),
            details: "Critical-file baseline was created for future tamper detection".to_string(),
            score_impact: 0,
        });
    }

    findings
}

fn check_registry_keys(keys: &[String]) -> Vec<ModuleFinding> {
    let mut findings = Vec::new();

    for key in keys {
        let output = Command::new("reg").args(["query", key]).output();

        match output {
            Ok(out) if out.status.success() => {
                let body = String::from_utf8_lossy(&out.stdout).to_lowercase();
                if body.contains("powershell -enc") || body.contains("frombase64string") {
                    findings.push(ModuleFinding {
                        module: "System Integrity Scanner".to_string(),
                        severity: "high".to_string(),
                        title: "Potential obfuscated autorun".to_string(),
                        details: format!("Registry key contains obfuscated launch pattern: {}", key),
                        score_impact: -12,
                    });
                }
                if body.contains("\\appdata\\") && body.contains(".js") {
                    findings.push(ModuleFinding {
                        module: "System Integrity Scanner".to_string(),
                        severity: "medium".to_string(),
                        title: "Unusual script autorun path".to_string(),
                        details: format!("Autorun entry references AppData script path: {}", key),
                        score_impact: -7,
                    });
                }
            }
            Ok(_) => {
                findings.push(ModuleFinding {
                    module: "System Integrity Scanner".to_string(),
                    severity: "low".to_string(),
                    title: "Registry key unavailable".to_string(),
                    details: format!("Could not query registry key {}", key),
                    score_impact: -2,
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
                    if ["ps1", "vbs", "js", "hta", "bat", "cmd"].contains(&ext.as_str()) {
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

fn hash_file(path: &Path) -> anyhow::Result<String> {
    let bytes = fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(format!("{:x}", hasher.finalize()))
}

fn load_baseline(path: &Path) -> HashMap<String, String> {
    if !path.exists() {
        return HashMap::new();
    }
    let raw = match fs::read_to_string(path) {
        Ok(v) => v,
        Err(_) => return HashMap::new(),
    };
    serde_json::from_str::<HashMap<String, String>>(&raw).unwrap_or_default()
}

fn save_baseline(path: &Path, data: &HashMap<String, String>) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_string_pretty(data)?)?;
    Ok(())
}

fn score_from_findings(start: i16, findings: &[ModuleFinding]) -> u8 {
    let mut score = start;
    for f in findings {
        score += f.score_impact;
    }
    score.clamp(0, 100) as u8
}
