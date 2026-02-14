use crate::{
    config::AppConfig,
    models::{
        BehaviorReport, DashboardSnapshot, HumanRiskReport, IntegrityReport, NetworkReport,
        RiskLevel,
    },
    modules::{behavior, human_risk, integrity, network},
};
use anyhow::Result;
use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullScanReport {
    pub scanned_at: DateTime<Local>,
    pub dashboard: DashboardSnapshot,
    pub integrity: IntegrityReport,
    pub behavior: BehaviorReport,
    pub network: NetworkReport,
    pub human_risk: HumanRiskReport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub scanned_at: DateTime<Local>,
    pub security_score: u8,
    pub risk_level: RiskLevel,
    pub active_threats: usize,
    pub network_connections: usize,
    pub integrity_score: u8,
    pub behavior_score: u8,
    pub network_score: u8,
    pub human_risk_score: u8,
}

pub fn run_full_scan(config: &AppConfig) -> FullScanReport {
    let integrity = integrity::run_scan(config);
    let behavior = behavior::run_scan(config);
    let network = network::run_scan();
    let human_risk = human_risk::run_scan(config);

    let security_score = ((integrity.score as u32
        + behavior.score as u32
        + network.score as u32
        + human_risk.score as u32)
        / 4) as u8;
    let active_threats = integrity.threats.len()
        + behavior.threats.len()
        + network.threats.len()
        + human_risk.threats.len();
    let scanned_at = Local::now();

    let dashboard = DashboardSnapshot {
        security_score,
        risk_level: RiskLevel::from_score(security_score),
        active_threats,
        network_connections: network.active_connections.len(),
        last_scan: scanned_at,
    };

    FullScanReport {
        scanned_at,
        dashboard,
        integrity,
        behavior,
        network,
        human_risk,
    }
}

#[allow(dead_code)]
pub fn append_scan_history(path: &str, report: &FullScanReport) -> Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{}", serde_json::to_string(report)?)?;
    Ok(())
}

pub fn build_summary(report: &FullScanReport) -> ScanSummary {
    ScanSummary {
        scanned_at: report.scanned_at,
        security_score: report.dashboard.security_score,
        risk_level: report.dashboard.risk_level,
        active_threats: report.dashboard.active_threats,
        network_connections: report.dashboard.network_connections,
        integrity_score: report.integrity.score,
        behavior_score: report.behavior.score,
        network_score: report.network.score,
        human_risk_score: report.human_risk.score,
    }
}

pub fn append_scan_summary(path: &str, summary: &ScanSummary) -> Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{}", serde_json::to_string(summary)?)?;
    Ok(())
}
