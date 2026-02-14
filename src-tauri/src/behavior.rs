use std::{fs, path::PathBuf, time::{Duration, SystemTime}};

use chrono::Utc;
use sysinfo::System;

use crate::{config::AppConfig, models::{ModuleFinding, ModuleReport}};

pub fn run_behavioral_detection(config: &AppConfig) -> ModuleReport {
    let started_at = Utc::now();
    let mut findings = Vec::new();

    let mut sys = System::new_all();
    sys.refresh_all();

    let global_cpu = sys.global_cpu_usage();
    if global_cpu > config.cpu_alert_threshold {
        findings.push(ModuleFinding {
            module: "Behavioral Threat Detection".to_string(),
            severity: "high".to_string(),
            title: "Abnormal CPU load".to_string(),
            details: format!(
                "Global CPU usage {:.2}% exceeds threshold {:.2}%",
                global_cpu, config.cpu_alert_threshold
            ),
            score_impact: -10,
        });
    }

    let total_memory = sys.total_memory() as f32;
    let used_memory = sys.used_memory() as f32;
    if total_memory > 0.0 {
        let mem_percent = (used_memory / total_memory) * 100.0;
        if mem_percent > config.memory_alert_threshold {
            findings.push(ModuleFinding {
                module: "Behavioral Threat Detection".to_string(),
                severity: "medium".to_string(),
                title: "High memory pressure".to_string(),
                details: format!(
                    "Memory usage {:.2}% exceeds threshold {:.2}%",
                    mem_percent, config.memory_alert_threshold
                ),
                score_impact: -7,
            });
        }
    }

    findings.extend(find_top_resource_processes(&sys));
    findings.extend(check_recent_file_modifications(&config.startup_paths));

    let score = score_from_findings(100, &findings);
    let finished_at = Utc::now();

    ModuleReport {
        module: "Behavioral Threat Detection".to_string(),
        started_at,
        finished_at,
        score,
        findings,
    }
}

fn find_top_resource_processes(sys: &System) -> Vec<ModuleFinding> {
    let mut findings = Vec::new();

    for process in sys.processes().values() {
        if process.cpu_usage() > 80.0 {
            findings.push(ModuleFinding {
                module: "Behavioral Threat Detection".to_string(),
                severity: "high".to_string(),
                title: "Process CPU spike".to_string(),
                details: format!(
                    "Process '{}' (pid {:?}) uses {:.2}% CPU",
                    process.name().to_string_lossy(),
                    process.pid(),
                    process.cpu_usage()
                ),
                score_impact: -9,
            });
        }

        let memory_mb = process.memory() as f32 / 1024.0;
        if memory_mb > 900.0 {
            findings.push(ModuleFinding {
                module: "Behavioral Threat Detection".to_string(),
                severity: "medium".to_string(),
                title: "Process memory anomaly".to_string(),
                details: format!(
                    "Process '{}' (pid {:?}) uses {:.2} MB memory",
                    process.name().to_string_lossy(),
                    process.pid(),
                    memory_mb
                ),
                score_impact: -6,
            });
        }
    }

    findings
}

fn check_recent_file_modifications(paths: &[PathBuf]) -> Vec<ModuleFinding> {
    let mut findings = Vec::new();
    let threshold = SystemTime::now() - Duration::from_secs(60 * 60);

    for path in paths {
        if !path.exists() {
            continue;
        }

        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                let p = entry.path();
                if let Ok(meta) = fs::metadata(&p) {
                    if let Ok(modified) = meta.modified() {
                        if modified > threshold {
                            findings.push(ModuleFinding {
                                module: "Behavioral Threat Detection".to_string(),
                                severity: "medium".to_string(),
                                title: "Recent startup area change".to_string(),
                                details: format!("File recently modified in startup path: {}", p.display()),
                                score_impact: -5,
                            });
                        }
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
