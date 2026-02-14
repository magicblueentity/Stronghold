# Stronghold

Stronghold is a fully native Rust desktop security application for Windows.
This repository has been migrated from a hybrid HTML/JS/Tauri/Electron prototype to a Rust-only desktop architecture using `eframe/egui`.

## Features

- System Integrity Scanner
  - Process inventory
  - Critical file presence checks
  - Startup item inspection
  - Security score generation
- Behavioral Threat Detection
  - Suspicious CPU and RAM usage detection
  - Temp executable anomaly scanning
  - Optional offline AI score hook (`ml/anomaly_detector.py`)
- Network Surveillance Layer
  - Active connection inspection via `netstat -ano`
  - DNS/port anomaly heuristics
  - Interactive network map table in UI
- Human Risk Monitor
  - Unsafe download pattern detection
  - Weak-password account policy flags
  - Risk behavior markers
- Isolation & Response Engine
  - Process isolation (`taskkill`)
  - File quarantine to local quarantine folder
  - Registry rollback marker routine
  - Local system snapshot generation

## UI

- Native desktop UI in Rust (`eframe/egui`)
- Dark-mode professional interface
- Dashboard with:
  - Security score
  - Active threats
  - Network connection visibility
- Color-coded risk levels:
  - Green
  - Yellow
  - Red
- Dual language UI controls (EN/DE) in one executable

## Project Structure

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
      mod.rs
      ai.rs
      integrity.rs
      behavior.rs
      network.rs
      human_risk.rs
      response.rs
  config/
    config.json
  logs/
    sample.log
  assets/
    icon.svg
  ml/
    anomaly_detector.py
  .gitignore
  README.md
  COPYRIGHT.txt
```

## Requirements

- Windows 10/11
- Rust toolchain (stable) via `rustup`
- MSVC build tools (for native compilation)
- Optional: Python 3 for AI hook support

## Build & Run (Windows)

1. Install Rust:
   - `rustup default stable`
2. Build:
   - `cargo build --release`
3. Run (debug):
   - `cargo run`
4. Release binary:
   - `target/release/stronghold.exe`

## Configuration

Main config file: `config/config.json`

Key settings:
- `default_language`: `"en"` or `"de"`
- `cpu_alert_percent`: CPU alert threshold
- `memory_alert_mb`: memory alert threshold in MB
- `quarantine_dir`: local quarantine destination
- `critical_files`: file integrity watch list
- `startup_locations`: startup inspection folders
- `weak_password_accounts`: policy flag list
- `enable_ai_module`: enable/disable optional Python AI scoring

## Offline Capability

Stronghold is fully offline-capable.
All scans and response actions operate locally on the host system.
The optional AI module runs locally through Python and does not require network access.

## Versioning

Current app version: `26.1.1`

Semantic versioning intent:
- MAJOR: breaking architecture changes
- MINOR: new features/modules
- PATCH: bug fixes and hardening

## Contributing

1. Fork repository
2. Create feature branch
3. Run `cargo fmt` and `cargo check`
4. Submit pull request with clear module-level change notes

## License

See `COPYRIGHT.txt`.

## Migration Note

All previous HTML/CSS/JavaScript and hybrid runtime artifacts were removed.
The application is now a single native Rust desktop executable workflow.
