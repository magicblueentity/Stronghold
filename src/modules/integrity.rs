use crate::{
    config::AppConfig,
    models::{IntegrityReport, ModuleId, RiskLevel, ThreatItem, ThreatKind},
};
use std::{fs, path::Path, process::Command};
use sysinfo::System;

pub fn run_scan(config: &AppConfig) -> IntegrityReport {
    let mut system = System::new_all();
    system.refresh_all();

    let running_processes = system.processes().len();
    let startup_items =
        count_startup_items(&config.startup_locations) + count_registry_startup_items();
    let missing_critical_files = missing_critical_files(&config.critical_files);

    let mut score: i32 = 100;
    score -= (missing_critical_files.len() as i32) * 15;
    if running_processes > 250 {
        score -= 10;
    }
    if startup_items > 30 {
        score -= 10;
    }
    let score = score.clamp(0, 100) as u8;
    let risk_level = RiskLevel::from_score(score);

    let mut threats = Vec::new();
    if !missing_critical_files.is_empty() {
        threats.push(ThreatItem {
            source: ModuleId::Integrity,
            kind: ThreatKind::MissingCriticalFiles {
                count: missing_critical_files.len(),
            },
            risk: RiskLevel::Red,
        });
    }
    if startup_items > 30 {
        threats.push(ThreatItem {
            source: ModuleId::Integrity,
            kind: ThreatKind::HighStartupItems {
                count: startup_items,
            },
            risk: RiskLevel::Yellow,
        });
    }

    IntegrityReport {
        score,
        risk_level,
        running_processes,
        startup_items,
        missing_critical_files,
        threats,
    }
}

fn count_startup_items(paths: &[String]) -> usize {
    paths
        .iter()
        .map(|p| {
            fs::read_dir(p)
                .ok()
                .map(|rd| rd.filter_map(Result::ok).count())
                .unwrap_or(0)
        })
        .sum()
}

fn count_registry_startup_items() -> usize {
    let keys = [
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    ];

    let mut count = 0;
    for key in keys {
        let output = Command::new("reg").args(["query", key]).output();
        let Ok(output) = output else {
            continue;
        };
        let text = String::from_utf8_lossy(&output.stdout);
        count += text
            .lines()
            .map(str::trim)
            .filter(|line| line.contains("REG_SZ") || line.contains("REG_EXPAND_SZ"))
            .count();
    }
    count
}

fn missing_critical_files(files: &[String]) -> Vec<String> {
    files
        .iter()
        .filter(|f| !Path::new(f.as_str()).exists())
        .cloned()
        .collect()
}
