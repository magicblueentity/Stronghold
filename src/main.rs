mod app;
mod config;
mod engine;
mod i18n;
mod logger;
mod models;
mod modules;

use anyhow::Result;
use app::StrongholdApp;
use config::AppConfig;
use logger::AppLogger;
use modules::response;
use std::{
    collections::HashSet,
    env,
    fs::{self, OpenOptions},
    io::Write,
    thread,
    time::Duration,
};

fn main() -> Result<()> {
    let config = AppConfig::load_or_create("config/config.json")?;
    let logger = AppLogger::new("logs/stronghold.log")?;
    logger.log("Stronghold boot sequence started")?;

    let args: Vec<String> = env::args().skip(1).collect();
    let scan_once = args.iter().any(|a| a == "--scan-once");
    let daemon = args.iter().any(|a| a == "--daemon");
    let force_auto_response = args.iter().any(|a| a == "--auto-response");

    if scan_once {
        run_scan_once(&config, &logger, force_auto_response)?;
        return Ok(());
    }

    if daemon {
        run_daemon(&config, &logger)?;
        return Ok(());
    }

    let native_options = eframe::NativeOptions::default();
    eframe::run_native(
        "Stronghold",
        native_options,
        Box::new(move |_cc| Ok(Box::new(StrongholdApp::new(config, logger.clone())))),
    )
    .map_err(|e| anyhow::anyhow!("Failed to start Stronghold UI: {e}"))?;

    Ok(())
}

fn run_scan_once(config: &AppConfig, logger: &AppLogger, force_auto_response: bool) -> Result<()> {
    let scan = engine::run_full_scan(config);
    engine::append_scan_summary(&config.scan_summary_path, &engine::build_summary(&scan))?;

    let summary = format!(
        "Headless scan complete | score={} risk={} threats={} connections={}",
        scan.dashboard.security_score,
        scan.dashboard.risk_level.as_str(),
        scan.dashboard.active_threats,
        scan.dashboard.network_connections,
    );
    println!("{summary}");
    logger.log(&summary)?;

    if config.auto_response_enabled || force_auto_response {
        let mut seen_pids = HashSet::new();
        let mut seen_files = HashSet::new();
        let outcome = response::run_auto_response_cycle(
            config,
            &scan.behavior,
            &scan.human_risk,
            scan.dashboard.risk_level,
            &mut seen_pids,
            &mut seen_files,
        );
        if outcome.action_count > 0 {
            append_incident_history(
                &config.incident_history_path,
                &outcome,
                "headless-scan-once",
                scan.dashboard.security_score,
            )?;
            let text = format!("Auto-response executed {} actions", outcome.action_count);
            println!("{text}");
            logger.log(&text)?;
        }
    }

    Ok(())
}

fn run_daemon(config: &AppConfig, logger: &AppLogger) -> Result<()> {
    let interval = config.auto_scan_interval_seconds.max(15);
    println!(
        "Stronghold daemon mode active. Interval={}s. Press Ctrl+C to stop.",
        interval
    );
    logger.log(&format!("Daemon mode started with interval {}s", interval))?;

    let mut seen_pids = HashSet::new();
    let mut seen_files = HashSet::new();

    loop {
        let scan = engine::run_full_scan(config);
        if let Err(e) =
            engine::append_scan_summary(&config.scan_summary_path, &engine::build_summary(&scan))
        {
            let _ = logger.log(&format!("Failed to append scan summary: {e}"));
        }

        let summary = format!(
            "Daemon cycle | score={} risk={} threats={} connections={}",
            scan.dashboard.security_score,
            scan.dashboard.risk_level.as_str(),
            scan.dashboard.active_threats,
            scan.dashboard.network_connections,
        );
        println!("{summary}");
        let _ = logger.log(&summary);

        if config.auto_response_enabled {
            let outcome = response::run_auto_response_cycle(
                config,
                &scan.behavior,
                &scan.human_risk,
                scan.dashboard.risk_level,
                &mut seen_pids,
                &mut seen_files,
            );

            if outcome.action_count > 0 {
                let _ = append_incident_history(
                    &config.incident_history_path,
                    &outcome,
                    "daemon-auto",
                    scan.dashboard.security_score,
                );
                let text = format!(
                    "Daemon auto-response executed {} actions",
                    outcome.action_count
                );
                println!("{text}");
                let _ = logger.log(&text);
            }
        }

        thread::sleep(Duration::from_secs(interval));
    }
}

fn append_incident_history(
    path: &str,
    outcome: &response::AutoResponseOutcome,
    trigger: &str,
    score: u8,
) -> Result<()> {
    if let Some(parent) = std::path::Path::new(path).parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let payload = serde_json::json!({
        "ts": chrono::Local::now().to_rfc3339(),
        "trigger": trigger,
        "security_score": score,
        "actions": outcome.action_count,
        "isolated_pids": outcome.isolated_pids,
        "quarantined_paths": outcome.quarantined_paths,
        "reverted_registry_entries": outcome.reverted_registry_entries,
        "snapshot_file": outcome.snapshot_file,
    });
    writeln!(file, "{}", serde_json::to_string(&payload)?)?;
    Ok(())
}
