use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub default_language: String,
    pub cpu_alert_percent: f32,
    pub memory_alert_mb: u64,
    pub quarantine_dir: String,
    pub critical_files: Vec<String>,
    pub startup_locations: Vec<String>,
    pub weak_password_accounts: Vec<String>,
    pub enable_ai_module: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            default_language: "en".to_string(),
            cpu_alert_percent: 70.0,
            memory_alert_mb: 800,
            quarantine_dir: "logs/quarantine".to_string(),
            critical_files: vec![
                "C:/Windows/System32/drivers/etc/hosts".to_string(),
                "C:/Windows/System32/cmd.exe".to_string(),
                "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe".to_string(),
            ],
            startup_locations: vec![
                "C:/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup".to_string(),
                "C:/Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
                    .to_string(),
            ],
            weak_password_accounts: vec!["guest".to_string(), "test-user".to_string()],
            enable_ai_module: true,
        }
    }
}

impl AppConfig {
    pub fn load_or_create(path: &str) -> Result<Self> {
        if Path::new(path).exists() {
            let content = fs::read_to_string(path)
                .with_context(|| format!("Unable to read config at {path}"))?;
            let parsed: Self =
                serde_json::from_str(&content).context("Invalid JSON in config/config.json")?;
            return Ok(parsed);
        }

        if let Some(parent) = Path::new(path).parent() {
            fs::create_dir_all(parent)?;
        }

        let default = Self::default();
        let json = serde_json::to_string_pretty(&default)?;
        fs::write(path, json).with_context(|| format!("Unable to create config at {path}"))?;
        Ok(default)
    }
}
