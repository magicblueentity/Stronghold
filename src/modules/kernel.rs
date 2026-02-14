use anyhow::{anyhow, Result};
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelServiceState {
    Running,
    Stopped,
    Missing,
    Unknown,
}

pub fn query_service_state(service_name: &str) -> Result<KernelServiceState> {
    let output = Command::new("sc")
        .args(["query", service_name])
        .output()
        .map_err(|e| anyhow!("Failed to execute sc query: {e}"))?;

    let text = String::from_utf8_lossy(&output.stdout).to_ascii_uppercase();
    if text.contains("FAILED 1060") || text.contains("DOES NOT EXIST") {
        return Ok(KernelServiceState::Missing);
    }
    if text.contains("RUNNING") {
        return Ok(KernelServiceState::Running);
    }
    if text.contains("STOPPED") {
        return Ok(KernelServiceState::Stopped);
    }
    Ok(KernelServiceState::Unknown)
}

pub fn start_service(service_name: &str) -> Result<()> {
    let status = Command::new("sc").args(["start", service_name]).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(anyhow!("Failed to start service: {service_name}"))
    }
}
