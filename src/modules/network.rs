use crate::models::{ConnectionEntry, NetworkReport, RiskLevel, ThreatItem};
use regex::Regex;
use std::process::Command;

pub fn run_scan() -> NetworkReport {
    let active_connections = read_connections();
    let dns_anomalies = detect_dns_anomalies(&active_connections);

    let mut score: i32 = 100;
    score -= (dns_anomalies.len() as i32) * 12;
    if active_connections.len() > 200 {
        score -= 10;
    }
    let score = score.clamp(0, 100) as u8;
    let risk_level = RiskLevel::from_score(score);

    let mut threats = Vec::new();
    if !dns_anomalies.is_empty() {
        threats.push(ThreatItem {
            source: "Network".to_string(),
            summary: format!("{} DNS/connection anomalies detected", dns_anomalies.len()),
            risk: RiskLevel::Red,
        });
    }

    NetworkReport {
        score,
        risk_level,
        active_connections,
        dns_anomalies,
        threats,
    }
}

fn read_connections() -> Vec<ConnectionEntry> {
    let output = Command::new("netstat").args(["-ano"]).output();
    let Ok(output) = output else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let re = Regex::new(
        r"^(TCP|UDP)\s+(\S+)\s+(\S+)(?:\s+(\S+))?\s+(\d+)$",
    )
    .expect("valid netstat parser");

    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            let cap = re.captures(line)?;
            let protocol = cap.get(1)?.as_str().to_string();
            let local = cap.get(2)?.as_str().to_string();
            let remote = cap.get(3)?.as_str().to_string();
            let state = cap.get(4).map(|m| m.as_str()).unwrap_or("LISTENING");
            let pid = cap.get(5).and_then(|m| m.as_str().parse::<u32>().ok());
            Some(ConnectionEntry {
                protocol,
                local,
                remote,
                state: state.to_string(),
                pid,
            })
        })
        .collect()
}

fn detect_dns_anomalies(connections: &[ConnectionEntry]) -> Vec<String> {
    let mut anomalies = Vec::new();
    for c in connections {
        let is_dns = c.remote.ends_with(":53") || c.local.ends_with(":53");
        let suspicious_port = c.remote.ends_with(":5355") || c.remote.ends_with(":1900");
        let unknown_remote = c.remote.starts_with("0.0.0.0") || c.remote.starts_with("[::]");

        if is_dns && c.state == "ESTABLISHED" {
            anomalies.push(format!("Unusual established DNS flow: {} -> {}", c.local, c.remote));
        }
        if suspicious_port {
            anomalies.push(format!("Potential discovery abuse port usage: {}", c.remote));
        }
        if unknown_remote && c.state == "ESTABLISHED" {
            anomalies.push(format!("Established connection to unspecified endpoint: {}", c.remote));
        }
    }
    anomalies
}
