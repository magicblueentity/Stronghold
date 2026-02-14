# Stronghold

Stronghold is a native Rust desktop security workstation for Windows.
It was migrated from a hybrid HTML/JS prototype to a Rust-only application with local/offline operation.

## What is implemented now

- Native desktop GUI (`eframe/egui`) with dark theme.
- Dashboard with security score, active threat count, and network visibility.
- Automated operation engine:
  - Interval-based automatic scans in background loop
  - Optional automated response actions (process isolation + quarantine + snapshot)
  - Live automation feed in the dashboard
- Modular scanners:
  - System Integrity Scanner
  - Behavioral Threat Detection
  - Network Surveillance Layer
  - Human Risk Monitor
  - Isolation & Response Engine
- Kernel integration panel:
  - Checks Windows service state for configured kernel driver service.
  - Can request service start via SCM.
- Settings menu:
  - Edit and persist runtime config to `config/config.json`.
  - EN/DE language support in one `.exe`.
- Optional offline AI hook via Python script (`ml/anomaly_detector.py`).

## Important security boundary

Stronghold includes real host telemetry and real response actions (process kill, file quarantine, registry key cleanup, snapshot export).
Kernel-level **enforcement** still requires a separately developed and signed Windows kernel driver.
This repo now includes the user-mode control path and service integration hooks, but not a production kernel driver.

## Project structure

```text
Stronghold/
  Cargo.toml
  src/
    main.rs
    app.rs
    config.rs
    i18n.rs
    logger.rs
    models.rs
    modules/
      ai.rs
      behavior.rs
      human_risk.rs
      integrity.rs
      kernel.rs
      network.rs
      response.rs
  config/
    config.json
  logs/
    sample.log
  assets/
    icon.svg
    INSTALLER.md
  ml/
    anomaly_detector.py
  scripts/
    build-installer.ps1
```

## Build and run (Windows)

1. Install Rust stable and MSVC toolchain.
2. Run locally:
   - `cargo run`
3. Build release:
   - `cargo build --release`
4. Binary output:
   - `target/release/stronghold.exe`

## Headless operation (real automated scans)

- One-time real scan:
  - `cargo run -- --scan-once`
- One-time scan plus immediate auto-response:
  - `cargo run -- --scan-once --auto-response`
- Continuous daemon mode:
  - `cargo run -- --daemon`

Daemon mode uses local system telemetry on each cycle and appends structured scan history.

## Installer (MSI)

1. Run PowerShell script:
   - `powershell -ExecutionPolicy Bypass -File .\scripts\build-installer.ps1 -Release`
2. Output MSI:
   - `target/wix/*.msi`

Notes:
- Script installs `cargo-wix` automatically.
- WiX Toolset must be available on the build machine.

## Configuration

Main file: `config/config.json`

Core options:
- `default_language`
- `cpu_alert_percent`
- `memory_alert_mb`
- `quarantine_dir`
- `kernel_service_name`
- `scan_history_path`
- `incident_history_path`
- `auto_scan_enabled`
- `auto_scan_interval_seconds`
- `auto_response_enabled`
- `max_auto_isolations_per_cycle`
- `max_auto_quarantines_per_cycle`
- `critical_files`
- `startup_locations`
- `weak_password_accounts`
- `enable_ai_module`

Generated runtime files:
- scan summary JSONL: `logs/scan_summary.jsonl`
- optional full scan history JSONL (debug/forensics): `logs/scan_history.jsonl`
- incident history JSONL: `logs/incidents.jsonl`

## Offline mode

Stronghold is offline-capable by design.
All scanner and response modules run locally without cloud dependency.

## Contributing

1. Create branch.
2. Run `cargo fmt` and `cargo check`.
3. Submit PR with module-level notes and test evidence.

## Version

Current version: `26.1.1`

## License

See `COPYRIGHT.txt`.
