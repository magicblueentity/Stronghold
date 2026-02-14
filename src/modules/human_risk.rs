use crate::{
    config::AppConfig,
    models::{
        FileFinding, HumanRiskReport, ModuleId, RiskLevel, RiskyAction, ThreatItem, ThreatKind,
    },
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
    let penalty_downloads = ((unsafe_downloads.len() as i32) * 2).min(60);
    let penalty_weak = ((weak_password_accounts.len() as i32) * 15).min(40);
    let penalty_actions = (risky_actions.len() as i32) * 5;
    score -= penalty_downloads + penalty_weak + penalty_actions;
    let score = score.clamp(0, 100) as u8;
    let risk_level = RiskLevel::from_score(score);

    let mut threats = Vec::new();
    if !unsafe_downloads.is_empty() {
        threats.push(ThreatItem {
            source: ModuleId::HumanRisk,
            kind: ThreatKind::UnsafeDownloads {
                count: unsafe_downloads.len(),
            },
            risk: RiskLevel::Yellow,
        });
    }
    if !weak_password_accounts.is_empty() {
        threats.push(ThreatItem {
            source: ModuleId::HumanRisk,
            kind: ThreatKind::WeakPasswordPolicy {
                count: weak_password_accounts.len(),
            },
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

fn detect_unsafe_downloads() -> Vec<FileFinding> {
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
            let modified = metadata.and_then(|m| m.modified().ok());
            let is_recent = modified.map(|m| m >= cutoff).unwrap_or(false);

            if !is_recent {
                continue;
            }
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                let ext = ext.to_ascii_lowercase();
                if matches!(ext.as_str(), "exe" | "msi" | "bat" | "scr" | "ps1") {
                    let modified = modified.map(chrono::DateTime::<chrono::Local>::from);
                    findings.push(FileFinding {
                        path: path.display().to_string(),
                        modified,
                    });
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

fn detect_risky_actions(
    unsafe_downloads: &[FileFinding],
    weak_accounts: &[String],
) -> Vec<RiskyAction> {
    let mut actions = Vec::new();
    if !unsafe_downloads.is_empty() {
        actions.push(RiskyAction::RecentExecutableDownloads {
            count: unsafe_downloads.len(),
        });
    }
    if !weak_accounts.is_empty() {
        actions.push(RiskyAction::WeakPasswordAccountsPresent {
            count: weak_accounts.len(),
        });
    }

    let admin_output = Command::new("net")
        .args(["localgroup", "Administrators"])
        .output();
    if let Ok(out) = admin_output {
        let admin_text = String::from_utf8_lossy(&out.stdout).to_ascii_lowercase();
        if admin_text.contains("guest") {
            actions.push(RiskyAction::GuestInAdministratorsGroup);
        }
    }

    if unsafe_downloads.len() + weak_accounts.len() >= 4 {
        actions.push(RiskyAction::HighRiskProfile);
    }
    actions
}
