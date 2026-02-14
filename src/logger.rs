use anyhow::Result;
use chrono::Local;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    sync::{Arc, Mutex},
};

#[derive(Clone)]
pub struct AppLogger {
    path: Arc<String>,
    lock: Arc<Mutex<()>>,
}

impl AppLogger {
    pub fn new(path: &str) -> Result<Self> {
        if let Some(parent) = Path::new(path).parent() {
            fs::create_dir_all(parent)?;
        }
        Ok(Self {
            path: Arc::new(path.to_string()),
            lock: Arc::new(Mutex::new(())),
        })
    }

    pub fn log(&self, msg: &str) -> Result<()> {
        let _guard = self.lock.lock().expect("logger lock poisoned");
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&*self.path)?;
        writeln!(
            file,
            "[{}] {}",
            Local::now().format("%Y-%m-%d %H:%M:%S"),
            msg
        )?;
        Ok(())
    }
}
