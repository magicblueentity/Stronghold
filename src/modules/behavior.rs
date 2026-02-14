use crate::{
    config::AppConfig,
    models::{BehaviorReport, ModuleId, ProcessFinding, RiskLevel, ThreatItem, ThreatKind},
    modules::ai,
};
use std::{fs, path::Path};
use sysinfo::System;

pub fn run_scan(config: &AppConfig) -> BehaviorReport {
    let mut system = System::new_all();
    system.refresh_all();

    let mut suspicious_processes = Vec::new();
    let mut high_memory_processes = Vec::new();

    for (pid, process) in system.processes() {
        let name = process.name().to_string_lossy().to_string();
        let exe = process
            .exe()
            .and_then(|p| p.to_str())
            .map(|s| s.to_string());
        let cpu = process.cpu_usage();
        let memory_mb = process.memory() / (1024 * 1024);

        let finding = ProcessFinding {
            pid: pid.as_u32(),
            name,
            exe,
            cpu_percent: cpu,
            memory_mb,
        };

        if cpu >= config.cpu_alert_percent {
            suspicious_processes.push(finding.clone());
        }
        if memory_mb >= config.memory_alert_mb {
            high_memory_processes.push(finding);
        }
    }

    let file_anomalies = scan_temp_executables();

    let ai_signal = if config.enable_ai_module {
        ai::anomaly_score(
            suspicious_processes.len(),
            high_memory_processes.len(),
            file_anomalies.len(),
        )
        .unwrap_or(0.0)
    } else {
        0.0
    };

    let mut score: i32 = 100;
    score -= (suspicious_processes.len() as i32) * 8;
    score -= (high_memory_processes.len() as i32) * 5;
    score -= (file_anomalies.len() as i32) * 10;
    score -= ai_signal.round() as i32;
    let score = score.clamp(0, 100) as u8;
    let risk_level = RiskLevel::from_score(score);

    let mut threats = Vec::new();
    if !suspicious_processes.is_empty() {
        threats.push(ThreatItem {
            source: ModuleId::Behavior,
            kind: ThreatKind::HighCpuProcesses {
                count: suspicious_processes.len(),
            },
            risk: RiskLevel::Yellow,
        });
    }
    if !file_anomalies.is_empty() {
        threats.push(ThreatItem {
            source: ModuleId::Behavior,
            kind: ThreatKind::TempExecutables {
                count: file_anomalies.len(),
            },
            risk: RiskLevel::Red,
        });
    }

    BehaviorReport {
        score,
        risk_level,
        suspicious_processes,
        high_memory_processes,
        file_anomalies,
        threats,
    }
}

fn scan_temp_executables() -> Vec<String> {
    let mut out = Vec::new();
    let candidates = [
        std::env::temp_dir(),
        Path::new("C:/Windows/Temp").to_path_buf(),
    ];

    for dir in candidates {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten().take(200) {
                let path = entry.path();
                if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
                    if matches!(ext.to_ascii_lowercase().as_str(), "exe" | "bat" | "cmd") {
                        out.push(path.display().to_string());
                    }
                }
            }
        }
    }
    out
}
