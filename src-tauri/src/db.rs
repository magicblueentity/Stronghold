use std::{fs, path::PathBuf};

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};

use crate::models::{DashboardSnapshot, ThreatLogEntry};

pub struct Database {
    conn: Connection,
}

impl Database {
    pub fn new(base_dir: &PathBuf) -> anyhow::Result<Self> {
        fs::create_dir_all(base_dir)?;
        let db_path = base_dir.join("stronghold.db");
        let conn = Connection::open(db_path)?;

        let db = Self { conn };
        db.init_schema()?;
        Ok(db)
    }

    fn init_schema(&self) -> anyhow::Result<()> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS threat_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                module TEXT NOT NULL,
                severity TEXT NOT NULL,
                event_type TEXT NOT NULL,
                summary TEXT NOT NULL,
                details TEXT NOT NULL,
                risk_score INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS threat_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                security_score INTEGER NOT NULL,
                active_threats INTEGER NOT NULL,
                network_connections INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                label TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );
            ",
        )?;

        Ok(())
    }

    pub fn insert_log(&self, entry: &ThreatLogEntry) -> anyhow::Result<()> {
        self.conn.execute(
            "
            INSERT INTO threat_logs (ts, module, severity, event_type, summary, details, risk_score)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ",
            params![
                entry.ts.to_rfc3339(),
                entry.module,
                entry.severity,
                entry.event_type,
                entry.summary,
                entry.details,
                entry.risk_score,
            ],
        )?;

        Ok(())
    }

    pub fn list_logs(&self, limit: usize) -> anyhow::Result<Vec<ThreatLogEntry>> {
        let mut stmt = self.conn.prepare(
            "
            SELECT id, ts, module, severity, event_type, summary, details, risk_score
            FROM threat_logs
            ORDER BY id DESC
            LIMIT ?1
            ",
        )?;

        let rows = stmt.query_map(params![limit as i64], |r| {
            let ts_raw: String = r.get(1)?;
            let ts = DateTime::parse_from_rfc3339(&ts_raw)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());

            Ok(ThreatLogEntry {
                id: r.get(0)?,
                ts,
                module: r.get(2)?,
                severity: r.get(3)?,
                event_type: r.get(4)?,
                summary: r.get(5)?,
                details: r.get(6)?,
                risk_score: r.get(7)?,
            })
        })?;

        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn insert_history(&self, snapshot: &DashboardSnapshot) -> anyhow::Result<()> {
        self.conn.execute(
            "
            INSERT INTO threat_history (ts, security_score, active_threats, network_connections)
            VALUES (?1, ?2, ?3, ?4)
            ",
            params![
                Utc::now().to_rfc3339(),
                snapshot.security_score,
                snapshot.active_threats,
                snapshot.network_connections,
            ],
        )?;

        Ok(())
    }

    pub fn insert_snapshot(&self, label: &str, payload_json: &str) -> anyhow::Result<()> {
        self.conn.execute(
            "
            INSERT INTO snapshots (ts, label, payload_json)
            VALUES (?1, ?2, ?3)
            ",
            params![Utc::now().to_rfc3339(), label, payload_json],
        )?;

        Ok(())
    }

    pub fn export_logs_json(&self, destination: &PathBuf) -> anyhow::Result<()> {
        let logs = self.list_logs(10_000)?;
        fs::write(destination, serde_json::to_string_pretty(&logs)?)?;
        Ok(())
    }

    pub fn export_logs_csv(&self, destination: &PathBuf) -> anyhow::Result<()> {
        let logs = self.list_logs(10_000)?;
        let mut csv = String::from("id,ts,module,severity,event_type,summary,details,risk_score\n");

        for l in logs {
            let line = format!(
                "{},{},{},{},{},{},{},{}\n",
                l.id.unwrap_or_default(),
                escape_csv(&l.ts.to_rfc3339()),
                escape_csv(&l.module),
                escape_csv(&l.severity),
                escape_csv(&l.event_type),
                escape_csv(&l.summary),
                escape_csv(&l.details),
                l.risk_score
            );
            csv.push_str(&line);
        }

        fs::write(destination, csv)?;
        Ok(())
    }
}

fn escape_csv(value: &str) -> String {
    let escaped = value.replace('"', "\"\"");
    format!("\"{}\"", escaped)
}
