use crate::{
    config::AppConfig,
    models::{IntegrityReport, RiskLevel, ThreatItem},
};
use std::{fs, path::Path};
use sysinfo::System;

pub fn run_scan(config: &AppConfig) -> IntegrityReport {
    let mut system = System::new_all();
    system.refresh_all();

    let running_processes = system.processes().len();
    let startup_items = count_startup_items(&config.startup_locations);
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
            source: "Integrity".to_string(),
            summary: format!("{} critical files missing", missing_critical_files.len()),
            risk: RiskLevel::Red,
        });
    }
    if startup_items > 30 {
        threats.push(ThreatItem {
            source: "Integrity".to_string(),
            summary: format!("High number of startup items: {startup_items}"),
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

fn missing_critical_files(files: &[String]) -> Vec<String> {
    files
        .iter()
        .filter(|f| !Path::new(f.as_str()).exists())
        .cloned()
        .collect()
}
