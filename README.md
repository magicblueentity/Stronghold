# Stronghold (v26.1.1)

Desktop-Sicherheitsanwendung fuer Windows mit Rust-Core, Tauri-UI, SQLite und optionalem Python-ML-Modul.

Copyright 2026 by Samuel J. Tirwa.

## Neu

- Rebranding auf **Stronghold**
- Mehrsprachigkeit: Deutsch und Englisch
- First-Run Setup Wizard beim ersten Start
- Persistente Settings in `appsettings.json`
- Auto-Scan beim Start (optional)
- Gehaertete Response-Aktionen (PID/IP/Quarantaene-Validierung)

## Build & Run

1. `npm install`
2. Optional: `Copy-Item .\appsettings.example.json .\appsettings.json`
3. `npm run tauri:dev`
4. `npm run tauri:build`

## Setup beim ersten Start

Der Setup-Dialog konfiguriert:
- Sprache (`de`/`en`)
- CPU-/RAM-Thresholds
- Dry-Run-Modus
- Auto-Scan beim Start

Danach wird `first_run_completed = true` gespeichert.

## Einstellungen

Unter `Settings` in der App:
- Sprache wechseln
- Thresholds anpassen
- Dry-Run aktivieren/deaktivieren
- Auto-Scan beim Start setzen

## Lokale Daten

- Konfiguration: `appsettings.json`
- Datenbank/Export/Baselines: `stronghold_data/`
- Sample Logs: `sample_data/`

## Optionales ML-Modul

```powershell
python .\ml\anomaly_detector.py
```
