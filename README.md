# ANCORATE STRONGHOLD (v26.1.1)

Lokale Desktop-Sicherheitsanwendung fuer Windows mit Rust-Core, Tauri-UI, SQLite-Logging und optionalem Python-Anomalie-Scoring.

## Architektur

- `src-tauri/`: Rust-Core (Scanner, Detection, Response, DB, Tauri Commands)
- `ui/`: Desktop-Frontend (Dashboard, Live Monitor, Threat Center, Logs)
- `stronghold_data/`: lokale SQLite DB + Exporte (wird beim Start erzeugt)
- `sample_data/`: Testdaten fuer Threat-History und Exporte
- `ml/`: optionale Python-Komponente fuer Anomalie-Erkennung

## Module

1. System Integrity Scanner
- Prozess-Heuristiken gegen bekannte Angriffs-Tools
- Pruefung kritischer Dateien
- Registry-Checks (Run/Winlogon)
- Startup-Item-Heuristiken

2. Behavioral Threat Detection
- CPU/RAM-Anomalien (global + pro Prozess)
- Erkennung schneller Veraenderungen in Startup-Pfaden
- Modul-Risiko-Score

3. Network Surveillance Layer
- Live-Connections via `netstat -ano`
- Port- und DNS-Heuristiken
- Interaktive Netzwerk-Map (lokale Pseudo-Geokoordinaten)
- Temporaeres IP-Blocking (Firewall), standardmaessig `dry_run`

4. Human Risk Monitor
- Unsichere Downloads im Download-Ordner
- Schwache Passwortmuster
- Empfehlungen via Findings

5. Isolation & Response Engine
- Prozess-Isolation (Stop-Process)
- Datei-Quarantaene
- Registry-Rollback (Dry-Run/Platzhalter)
- Lokale Snapshots in SQLite

## Sicherheitsprinzipien

- Vollstaendig lokal, keine Cloud-Abhaengigkeit
- Sensible Aktionen standardmaessig im `dry_run_response` Modus
- Persistente und exportierbare Threat-History (JSON/CSV)

## Voraussetzungen

- Windows 10/11
- Rust Toolchain (stable)
- Node.js 20+
- Visual Studio Build Tools fuer Rust/Tauri auf Windows

## Build & Run (Schritt fuer Schritt)

1. Projektabhaengigkeiten installieren:
```powershell
npm install
```

2. Optional: Beispielkonfiguration aktivieren:
```powershell
Copy-Item .\appsettings.example.json .\appsettings.json
```

3. Entwicklungsstart:
```powershell
npm run tauri:dev
```

4. Produktion bauen:
```powershell
npm run tauri:build
```

5. Logs exportieren (in der UI):
- `Threat Logs` -> `Export CSV` oder `Export JSON`
- Zielpfade: `stronghold_data/threat_export.csv` und `stronghold_data/threat_export.json`

## Beispielkonfiguration

Datei: `appsettings.example.json`

Wichtige Parameter:
- `dry_run_response`: true/false
- `cpu_alert_threshold`
- `memory_alert_threshold`
- `suspicious_processes`
- `weak_password_patterns`

## Sample Threat-Logs

- JSON: `sample_data/threat_logs.json`
- CSV: `sample_data/threat_logs.csv`
- In-App Seed: Dashboard -> `Beispiel-Logs laden`

## Optionales ML-Modul

Anomalie-Scoring lokal ausfuehren:
```powershell
python .\ml\anomaly_detector.py
```

Ausgabe:
- Input: `sample_data/telemetry.json` (wird bei Bedarf erzeugt)
- Output: `sample_data/anomaly_scores.json`

## Versionierung

Schema: `Major.Minor.Patch`
- Major = Jahr (z. B. 26)
- Minor = Features/Stabilitaet
- Patch = Bugfixes

Aktuelle Version: `26.1.1`
