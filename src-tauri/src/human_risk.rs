use std::{
    fs,
    path::PathBuf,
    process::Command,
    time::{Duration, SystemTime},
};

use chrono::Utc;

use crate::models::{ModuleFinding, ModuleReport};

pub fn run_human_risk_monitor() -> ModuleReport {
    let started_at = Utc::now();
    let mut findings = Vec::new();

    findings.extend(scan_downloads_folder());
    findings.extend(check_windows_security_posture());

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
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_lowercase();

            if ["exe", "msi", "bat", "cmd", "ps1", "js"].contains(&ext.as_str()) {
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

fn check_windows_security_posture() -> Vec<ModuleFinding> {
    let mut findings = Vec::new();

    if is_uac_disabled() {
        findings.push(ModuleFinding {
            module: "Human Risk Monitor".to_string(),
            severity: "high".to_string(),
            title: "UAC disabled".to_string(),
            details: "EnableLUA is disabled. Re-enable User Account Control for safer elevation boundaries.".to_string(),
            score_impact: -14,
        });
    }

    if is_smartscreen_off() {
        findings.push(ModuleFinding {
            module: "Human Risk Monitor".to_string(),
            severity: "medium".to_string(),
            title: "SmartScreen appears disabled".to_string(),
            details: "Microsoft SmartScreen protection is off or unavailable for check.".to_string(),
            score_impact: -8,
        });
    }

    if is_defender_realtime_disabled() {
        findings.push(ModuleFinding {
            module: "Human Risk Monitor".to_string(),
            severity: "high".to_string(),
            title: "Real-time AV protection disabled".to_string(),
            details: "Windows Defender real-time protection appears disabled.".to_string(),
            score_impact: -16,
        });
    }

    findings
}

fn is_uac_disabled() -> bool {
    let output = Command::new("reg")
        .args([
            "query",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "/v",
            "EnableLUA",
        ])
        .output();

    let Ok(out) = output else { return false; };
    if !out.status.success() {
        return false;
    }

    let text = String::from_utf8_lossy(&out.stdout).to_lowercase();
    text.contains("0x0")
}

fn is_smartscreen_off() -> bool {
    let output = Command::new("reg")
        .args([
            "query",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
            "/v",
            "SmartScreenEnabled",
        ])
        .output();

    let Ok(out) = output else { return false; };
    if !out.status.success() {
        return false;
    }

    let text = String::from_utf8_lossy(&out.stdout).to_lowercase();
    text.contains("off")
}

fn is_defender_realtime_disabled() -> bool {
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "(Get-MpComputerStatus).RealTimeProtectionEnabled",
        ])
        .output();

    let Ok(out) = output else { return false; };
    if !out.status.success() {
        return false;
    }

    let text = String::from_utf8_lossy(&out.stdout).trim().to_lowercase();
    text == "false"
}

fn score_from_findings(start: i16, findings: &[ModuleFinding]) -> u8 {
    let mut score = start;
    for f in findings {
        score += f.score_impact;
    }
    score.clamp(0, 100) as u8
}
