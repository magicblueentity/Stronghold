use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleId {
    Integrity,
    Behavior,
    Network,
    HumanRisk,
    Response,
    Kernel,
}

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
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ThreatKind {
    MissingCriticalFiles { count: usize },
    HighStartupItems { count: usize },
    HighCpuProcesses { count: usize },
    TempExecutables { count: usize },
    DnsOrConnectionAnomalies { count: usize },
    UnsafeDownloads { count: usize },
    WeakPasswordPolicy { count: usize },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatItem {
    pub source: ModuleId,
    pub kind: ThreatKind,
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
pub struct ProcessFinding {
    pub pid: u32,
    pub name: String,
    pub exe: Option<String>,
    pub cpu_percent: f32,
    pub memory_mb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorReport {
    pub score: u8,
    pub risk_level: RiskLevel,
    pub suspicious_processes: Vec<ProcessFinding>,
    pub high_memory_processes: Vec<ProcessFinding>,
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
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NetworkAnomaly {
    UnusualEstablishedDnsFlow { local: String, remote: String },
    DiscoveryPortUsage { remote: String },
    EstablishedToUnspecifiedEndpoint { remote: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkReport {
    pub score: u8,
    pub risk_level: RiskLevel,
    pub active_connections: Vec<ConnectionEntry>,
    pub dns_anomalies: Vec<NetworkAnomaly>,
    pub threats: Vec<ThreatItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileFinding {
    pub path: String,
    pub modified: Option<DateTime<Local>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RiskyAction {
    RecentExecutableDownloads { count: usize },
    WeakPasswordAccountsPresent { count: usize },
    GuestInAdministratorsGroup,
    HighRiskProfile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HumanRiskReport {
    pub score: u8,
    pub risk_level: RiskLevel,
    pub unsafe_downloads: Vec<FileFinding>,
    pub weak_password_accounts: Vec<String>,
    pub risky_actions: Vec<RiskyAction>,
    pub threats: Vec<ThreatItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseReport {
    pub isolated_processes: Vec<u32>,
    pub quarantined_files: Vec<String>,
    pub reverted_registry_entries: Vec<String>,
    pub snapshot_file: Option<String>,
}
