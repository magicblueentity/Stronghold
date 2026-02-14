use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardSnapshot {
    pub security_score: u8,
    pub risk_status: String,
    pub active_threats: u32,
    pub network_connections: usize,
    pub last_scan_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleFinding {
    pub module: String,
    pub severity: String,
    pub title: String,
    pub details: String,
    pub score_impact: i16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleReport {
    pub module: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub score: u8,
    pub findings: Vec<ModuleFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub protocol: String,
    pub local_address: String,
    pub remote_address: String,
    pub state: String,
    pub pid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapNode {
    pub ip: String,
    pub latitude: f32,
    pub longitude: f32,
    pub risk_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatLogEntry {
    pub id: Option<i64>,
    pub ts: DateTime<Utc>,
    pub module: String,
    pub severity: String,
    pub event_type: String,
    pub summary: String,
    pub details: String,
    pub risk_score: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseActionResult {
    pub success: bool,
    pub action: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppVersion {
    pub major: u16,
    pub minor: u8,
    pub patch: u8,
    pub string: String,
}
