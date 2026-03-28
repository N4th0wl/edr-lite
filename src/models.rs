use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcEvent {
    pub ts_utc: DateTime<Utc>,
    pub pid: u32,
    pub name: String,
    pub exe_path: Option<String>,
    pub original_filename: Option<String>,
    pub sha256: Option<String>,
    pub flags: Vec<String>,
    pub severity: Severity,
}

#[derive(Debug, Clone)]
pub struct DetectionResult {
    pub flags: Vec<String>,
    pub severity: Severity,
}
