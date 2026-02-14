use std::{fs, path::PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub quarantine_dir: PathBuf,
    pub allowed_quarantine_roots: Vec<PathBuf>,
    pub startup_paths: Vec<PathBuf>,
    pub critical_files: Vec<PathBuf>,
    pub registry_keys: Vec<String>,
    pub cpu_alert_threshold: f32,
    pub memory_alert_threshold: f32,
    pub dry_run_response: bool,
    pub suspicious_processes: Vec<String>,
    pub weak_password_patterns: Vec<String>,
    pub preferred_language: String,
    pub auto_scan_on_start: bool,
    pub first_run_completed: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        let program_data = dirs::data_dir().unwrap_or_else(|| PathBuf::from("."));
        let quarantine_dir = program_data.join("Stronghold").join("quarantine");
        let mut allowed_roots = Vec::new();
        if let Some(downloads) = dirs::download_dir() {
            allowed_roots.push(downloads);
        }
        if let Some(desktop) = dirs::desktop_dir() {
            allowed_roots.push(desktop);
        }
        allowed_roots.push(std::env::temp_dir());

        Self {
            quarantine_dir,
            allowed_quarantine_roots: allowed_roots,
            startup_paths: vec![
                PathBuf::from(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"),
                PathBuf::from(r"C:\Users\Public\Desktop"),
            ],
            critical_files: vec![
                PathBuf::from(r"C:\Windows\System32\kernel32.dll"),
                PathBuf::from(r"C:\Windows\System32\ntdll.dll"),
                PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts"),
            ],
            registry_keys: vec![
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run".to_string(),
                r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run".to_string(),
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon".to_string(),
            ],
            cpu_alert_threshold: 75.0,
            memory_alert_threshold: 70.0,
            dry_run_response: true,
            suspicious_processes: vec![
                "mimikatz".to_string(),
                "psexec".to_string(),
                "netcat".to_string(),
                "powersploit".to_string(),
            ],
            weak_password_patterns: vec![
                "123456".to_string(),
                "password".to_string(),
                "qwerty".to_string(),
                "admin".to_string(),
            ],
            preferred_language: "de".to_string(),
            auto_scan_on_start: false,
            first_run_completed: false,
        }
    }
}

impl AppConfig {
    pub fn load_or_create(base_dir: &PathBuf) -> anyhow::Result<Self> {
        let config_path = base_dir.join("appsettings.json");
        if config_path.exists() {
            let raw = fs::read_to_string(config_path)?;
            let mut parsed = serde_json::from_str::<Self>(&raw)?;
            if parsed.allowed_quarantine_roots.is_empty() {
                parsed.allowed_quarantine_roots = Self::default().allowed_quarantine_roots;
            }
            if parsed.preferred_language.trim().is_empty() {
                parsed.preferred_language = "de".to_string();
            }
            fs::create_dir_all(&parsed.quarantine_dir)?;
            return Ok(parsed);
        }

        let cfg = Self::default();
        fs::create_dir_all(&cfg.quarantine_dir)?;
        fs::write(config_path, serde_json::to_string_pretty(&cfg)?)?;
        Ok(cfg)
    }

    pub fn save(&self, base_dir: &PathBuf) -> anyhow::Result<()> {
        let config_path = base_dir.join("appsettings.json");
        fs::write(config_path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }
}
