use std::{fs, path::PathBuf, time::{Duration, SystemTime}};

use chrono::Utc;

use crate::{config::AppConfig, models::{ModuleFinding, ModuleReport}};

pub fn run_human_risk_monitor(config: &AppConfig, password_samples: Vec<String>) -> ModuleReport {
    let started_at = Utc::now();
    let mut findings = Vec::new();

    findings.extend(scan_downloads_folder());
    findings.extend(check_weak_passwords(config, password_samples));

    let score = score_from_findings(100, &findings);
    let finished_at = Utc::now();

    ModuleReport {
        module: "Human Risk Monitor".to_string(),
        started_at,
        finished_at,
        score,
        findings,
    }
}

fn scan_downloads_folder() -> Vec<ModuleFinding> {
    let mut findings = Vec::new();
    let downloads = dirs::download_dir().unwrap_or_else(|| PathBuf::from("."));

    if !downloads.exists() {
        return findings;
    }

    let threshold = SystemTime::now() - Duration::from_secs(60 * 60 * 24 * 2);

    if let Ok(entries) = fs::read_dir(downloads) {
        for entry in entries.flatten() {
            let path = entry.path();
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();

            if ["exe", "msi", "bat", "cmd", "ps1"].contains(&ext.as_str()) {
                let recently_modified = fs::metadata(&path)
                    .and_then(|m| m.modified())
                    .map(|d| d > threshold)
                    .unwrap_or(false);

                if recently_modified {
                    findings.push(ModuleFinding {
                        module: "Human Risk Monitor".to_string(),
                        severity: "medium".to_string(),
                        title: "Recent executable download".to_string(),
                        details: format!("Downloaded executable/script found: {}", path.display()),
                        score_impact: -8,
                    });
                }
            }
        }
    }

    findings
}

fn check_weak_passwords(config: &AppConfig, samples: Vec<String>) -> Vec<ModuleFinding> {
    let mut findings = Vec::new();

    for sample in samples {
        let lowered = sample.to_lowercase();
        let weak = config
            .weak_password_patterns
            .iter()
            .any(|p| lowered.contains(&p.to_lowercase()));

        if weak || sample.len() < 10 {
            findings.push(ModuleFinding {
                module: "Human Risk Monitor".to_string(),
                severity: "high".to_string(),
                title: "Weak password pattern".to_string(),
                details: format!("Password sample '{}' violates security policy", mask(&sample)),
                score_impact: -14,
            });
        }
    }

    findings
}

fn mask(value: &str) -> String {
    if value.len() < 3 {
        return "***".to_string();
    }
    format!("{}***{}", &value[0..1], &value[value.len() - 1..])
}

fn score_from_findings(start: i16, findings: &[ModuleFinding]) -> u8 {
    let mut score = start;
    for f in findings {
        score += f.score_impact;
    }
    score.clamp(0, 100) as u8
}
