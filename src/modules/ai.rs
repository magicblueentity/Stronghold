use std::process::Command;

pub fn anomaly_score(
    suspicious_process_count: usize,
    high_memory_count: usize,
    file_anomaly_count: usize,
) -> Option<f32> {
    let script = "ml/anomaly_detector.py";
    if !std::path::Path::new(script).exists() {
        return None;
    }

    let payload = format!(
        "{} {} {}",
        suspicious_process_count, high_memory_count, file_anomaly_count
    );
    let output = Command::new("python")
        .args([script, &payload])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    text.parse::<f32>().ok()
}
