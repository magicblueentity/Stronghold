use crate::{
    config::AppConfig,
    models::{HumanRiskReport, RiskLevel, ThreatItem},
};
use std::{
    fs,
    path::PathBuf,
    process::Command,
    time::{Duration, SystemTime},
};

pub fn run_scan(config: &AppConfig) -> HumanRiskReport {
    let unsafe_downloads = detect_unsafe_downloads();
    let weak_password_accounts = detect_weak_accounts_from_policy(config);
    let risky_actions = detect_risky_actions(&unsafe_downloads, &weak_password_accounts);

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
            summary: format!(
                "{} users flagged for weak password policy",
                weak_password_accounts.len()
            ),
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
    let cutoff = SystemTime::now()
        .checked_sub(Duration::from_secs(60 * 60 * 24 * 30))
        .unwrap_or(SystemTime::UNIX_EPOCH);
    let mut download_dir = std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("C:/Users/Public"));
    download_dir.push("Downloads");

    if let Ok(entries) = fs::read_dir(download_dir) {
        for entry in entries.flatten().take(500) {
            let path = entry.path();
            let metadata = entry.metadata().ok();
            let is_recent = metadata
                .and_then(|m| m.modified().ok())
                .map(|m| m >= cutoff)
                .unwrap_or(false);

            if !is_recent {
                continue;
            }
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

fn detect_weak_accounts_from_policy(config: &AppConfig) -> Vec<String> {
    let output = Command::new("net").arg("user").output();
    let Ok(output) = output else {
        return config.weak_password_accounts.clone();
    };
    let text = String::from_utf8_lossy(&output.stdout).to_ascii_lowercase();
    config
        .weak_password_accounts
        .iter()
        .filter(|u| text.contains(&u.to_ascii_lowercase()))
        .cloned()
        .collect()
}

fn detect_risky_actions(unsafe_downloads: &[String], weak_accounts: &[String]) -> Vec<String> {
    let mut actions = Vec::new();
    if !unsafe_downloads.is_empty() {
        actions.push("Downloaded executable files from user download directory".to_string());
    }
    if !weak_accounts.is_empty() {
        actions.push("Account set includes weak-password flagged users".to_string());
    }

    let admin_output = Command::new("net")
        .args(["localgroup", "Administrators"])
        .output();
    if let Ok(out) = admin_output {
        let admin_text = String::from_utf8_lossy(&out.stdout).to_ascii_lowercase();
        if admin_text.contains("guest") {
            actions.push("Guest account appears in local Administrators group".to_string());
        }
    }

    if unsafe_downloads.len() + weak_accounts.len() >= 4 {
        actions.push("User behavior profile exceeds risk threshold".to_string());
    }
    actions
}
