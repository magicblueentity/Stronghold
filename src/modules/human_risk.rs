use crate::{
    config::AppConfig,
    models::{HumanRiskReport, RiskLevel, ThreatItem},
};
use std::{fs, path::PathBuf};

pub fn run_scan(config: &AppConfig) -> HumanRiskReport {
    let unsafe_downloads = detect_unsafe_downloads();
    let weak_password_accounts = config.weak_password_accounts.clone();
    let risky_actions = simulate_risky_actions(unsafe_downloads.len(), weak_password_accounts.len());

    let mut score: i32 = 100;
    score -= (unsafe_downloads.len() as i32) * 10;
    score -= (weak_password_accounts.len() as i32) * 12;
    score -= (risky_actions.len() as i32) * 8;
    let score = score.clamp(0, 100) as u8;
    let risk_level = RiskLevel::from_score(score);

    let mut threats = Vec::new();
    if !unsafe_downloads.is_empty() {
        threats.push(ThreatItem {
            source: "HumanRisk".to_string(),
            summary: format!("{} potentially unsafe downloads", unsafe_downloads.len()),
            risk: RiskLevel::Yellow,
        });
    }
    if !weak_password_accounts.is_empty() {
        threats.push(ThreatItem {
            source: "HumanRisk".to_string(),
            summary: format!("{} users flagged for weak password policy", weak_password_accounts.len()),
            risk: RiskLevel::Red,
        });
    }

    HumanRiskReport {
        score,
        risk_level,
        unsafe_downloads,
        weak_password_accounts,
        risky_actions,
        threats,
    }
}

fn detect_unsafe_downloads() -> Vec<String> {
    let mut findings = Vec::new();
    let mut download_dir = std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("C:/Users/Public"));
    download_dir.push("Downloads");

    if let Ok(entries) = fs::read_dir(download_dir) {
        for entry in entries.flatten().take(250) {
            let path = entry.path();
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                let ext = ext.to_ascii_lowercase();
                if matches!(ext.as_str(), "exe" | "msi" | "bat" | "scr" | "ps1") {
                    findings.push(path.display().to_string());
                }
            }
        }
    }
    findings
}

fn simulate_risky_actions(unsafe_downloads: usize, weak_passwords: usize) -> Vec<String> {
    let mut actions = Vec::new();
    if unsafe_downloads > 0 {
        actions.push("Downloaded executable files from user download directory".to_string());
    }
    if weak_passwords > 0 {
        actions.push("Account set includes weak-password flagged users".to_string());
    }
    if unsafe_downloads + weak_passwords > 3 {
        actions.push("Risk profile indicates repeated unsafe behavior".to_string());
    }
    actions
}
