use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    Green,
    Yellow,
    Red,
}

impl RiskLevel {
    pub fn from_score(score: u8) -> Self {
        match score {
            80..=100 => Self::Green,
            55..=79 => Self::Yellow,
            _ => Self::Red,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Green => "Green",
            Self::Yellow => "Yellow",
            Self::Red => "Red",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatItem {
    pub source: String,
    pub summary: String,
    pub risk: RiskLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardSnapshot {
    pub security_score: u8,
    pub risk_level: RiskLevel,
    pub active_threats: usize,
    pub network_connections: usize,
    pub last_scan: DateTime<Local>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityReport {
    pub score: u8,
    pub risk_level: RiskLevel,
    pub running_processes: usize,
    pub startup_items: usize,
    pub missing_critical_files: Vec<String>,
    pub threats: Vec<ThreatItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorReport {
    pub score: u8,
    pub risk_level: RiskLevel,
    pub suspicious_processes: Vec<String>,
    pub high_memory_processes: Vec<String>,
    pub file_anomalies: Vec<String>,
    pub threats: Vec<ThreatItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionEntry {
    pub protocol: String,
    pub local: String,
    pub remote: String,
    pub state: String,
    pub pid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkReport {
    pub score: u8,
    pub risk_level: RiskLevel,
    pub active_connections: Vec<ConnectionEntry>,
    pub dns_anomalies: Vec<String>,
    pub threats: Vec<ThreatItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HumanRiskReport {
    pub score: u8,
    pub risk_level: RiskLevel,
    pub unsafe_downloads: Vec<String>,
    pub weak_password_accounts: Vec<String>,
    pub risky_actions: Vec<String>,
    pub threats: Vec<ThreatItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseReport {
    pub isolated_processes: Vec<u32>,
    pub quarantined_files: Vec<String>,
    pub reverted_registry_entries: Vec<String>,
    pub snapshot_file: Option<String>,
}
