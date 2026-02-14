use std::{collections::hash_map::DefaultHasher, hash::{Hash, Hasher}, process::Command};

use chrono::Utc;

use crate::models::{MapNode, ModuleFinding, ModuleReport, NetworkConnection};

pub fn run_network_scan() -> (ModuleReport, Vec<NetworkConnection>, Vec<MapNode>) {
    let started_at = Utc::now();
    let connections = list_connections();
    let mut findings = detect_network_findings(&connections);

    if connections.len() > 400 {
        findings.push(ModuleFinding {
            module: "Network Surveillance Layer".to_string(),
            severity: "medium".to_string(),
            title: "High connection count".to_string(),
            details: format!("{} active connections detected", connections.len()),
            score_impact: -7,
        });
    }

    let score = score_from_findings(100, &findings);
    let finished_at = Utc::now();
    let map_nodes = build_map_nodes(&connections);

    (
        ModuleReport {
            module: "Network Surveillance Layer".to_string(),
            started_at,
            finished_at,
            score,
            findings,
        },
        connections,
        map_nodes,
    )
}

pub fn list_connections() -> Vec<NetworkConnection> {
    let output = Command::new("netstat").args(["-ano"]).output();
    let Ok(output) = output else {
        return Vec::new();
    };

    if !output.status.success() {
        return Vec::new();
    }

    let mut out = Vec::new();
    let text = String::from_utf8_lossy(&output.stdout);

    for line in text.lines().skip(4) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 4 {
            continue;
        }

        let protocol = cols[0].to_string();
        let local = cols[1].to_string();
        let remote = cols[2].to_string();

        if protocol.eq_ignore_ascii_case("udp") {
            let pid = cols.last().and_then(|v| v.parse::<u32>().ok());
            out.push(NetworkConnection {
                protocol,
                local_address: local,
                remote_address: remote,
                state: "LISTENING".to_string(),
                pid,
            });
            continue;
        }

        if cols.len() < 5 {
            continue;
        }

        let state = cols[3].to_string();
        let pid = cols[4].parse::<u32>().ok();

        out.push(NetworkConnection {
            protocol,
            local_address: local,
            remote_address: remote,
            state,
            pid,
        });
    }

    out
}

fn detect_network_findings(connections: &[NetworkConnection]) -> Vec<ModuleFinding> {
    let mut findings = Vec::new();

    for conn in connections {
        let remote = conn.remote_address.to_lowercase();
        if remote.contains(":4444") || remote.contains(":1337") {
            findings.push(ModuleFinding {
                module: "Network Surveillance Layer".to_string(),
                severity: "high".to_string(),
                title: "Suspicious remote port".to_string(),
                details: format!("Connection to sensitive port detected: {}", conn.remote_address),
                score_impact: -10,
            });
        }

        if remote.starts_with("0.0.0.0") || remote.starts_with("*") {
            continue;
        }

        if conn.state.eq_ignore_ascii_case("ESTABLISHED") && remote.contains(":53") {
            findings.push(ModuleFinding {
                module: "Network Surveillance Layer".to_string(),
                severity: "low".to_string(),
                title: "DNS session observed".to_string(),
                details: format!("DNS traffic observed at {}", conn.remote_address),
                score_impact: -1,
            });
        }
    }

    findings
}

fn build_map_nodes(connections: &[NetworkConnection]) -> Vec<MapNode> {
    let mut nodes = Vec::new();

    for conn in connections {
        let ip = extract_ip(&conn.remote_address);
        if ip.is_empty() || ip == "0.0.0.0" || ip == "127.0.0.1" || ip == "*" {
            continue;
        }

        let (lat, lon) = pseudo_geo(&ip);
        let risk = if conn.state.eq_ignore_ascii_case("ESTABLISHED") {
            "medium"
        } else {
            "low"
        };

        nodes.push(MapNode {
            ip,
            latitude: lat,
            longitude: lon,
            risk_level: risk.to_string(),
        });
    }

    nodes.truncate(120);
    nodes
}

fn extract_ip(addr: &str) -> String {
    if addr.starts_with('[') {
        if let Some(end) = addr.find(']') {
            return addr[1..end].to_string();
        }
    }

    let mut parts = addr.split(':').collect::<Vec<_>>();
    if parts.len() > 2 {
        parts.pop();
        return parts.join(":");
    }

    parts.first().copied().unwrap_or_default().to_string()
}

fn pseudo_geo(ip: &str) -> (f32, f32) {
    let mut hasher = DefaultHasher::new();
    ip.hash(&mut hasher);
    let h = hasher.finish();

    let lat = ((h % 18_000) as f32 / 100.0) - 90.0;
    let lon = (((h / 18_000) % 36_000) as f32 / 100.0) - 180.0;
    (lat, lon)
}

fn score_from_findings(start: i16, findings: &[ModuleFinding]) -> u8 {
    let mut score = start;
    for f in findings {
        score += f.score_impact;
    }
    score.clamp(0, 100) as u8
}
