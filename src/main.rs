mod app;
mod config;
mod i18n;
mod logger;
mod models;
mod modules;

use anyhow::Result;
use app::StrongholdApp;
use config::AppConfig;
use logger::AppLogger;

fn main() -> Result<()> {
    let config = AppConfig::load_or_create("config/config.json")?;
    let logger = AppLogger::new("logs/stronghold.log")?;
    logger.log("Stronghold boot sequence started")?;

    let native_options = eframe::NativeOptions::default();
    eframe::run_native(
        "Stronghold",
        native_options,
        Box::new(move |_cc| Ok(Box::new(StrongholdApp::new(config, logger.clone())))),
    )
    .map_err(|e| anyhow::anyhow!("Failed to start Stronghold UI: {e}"))?;

    Ok(())
}
