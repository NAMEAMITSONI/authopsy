use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::{Endpoint, Role, Severity, Vulnerability};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub endpoint: Endpoint,
    pub responses: HashMap<Role, ResponseInfo>,
    pub vulnerabilities: Vec<Vulnerability>,
    pub duration_ms: u64,
}

impl ScanResult {
    pub fn new(
        endpoint: Endpoint,
        responses: HashMap<Role, ResponseInfo>,
        duration_ms: u64,
    ) -> Self {
        Self {
            endpoint,
            responses,
            vulnerabilities: Vec::new(),
            duration_ms,
        }
    }

    pub fn with_vulnerabilities(mut self, vulns: Vec<Vulnerability>) -> Self {
        self.vulnerabilities = vulns;
        self
    }

    pub fn max_severity(&self) -> Option<Severity> {
        self.vulnerabilities
            .iter()
            .map(|v| v.severity)
            .max_by_key(|s| s.numeric_value())
    }

    pub fn is_vulnerable(&self) -> bool {
        !self.vulnerabilities.is_empty()
    }

    pub fn get_response(&self, role: Role) -> Option<&ResponseInfo> {
        self.responses.get(&role)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseInfo {
    pub status: u16,
    pub size: usize,
    pub body: Option<serde_json::Value>,
    pub keys: Vec<String>,
    pub headers: HashMap<String, String>,
    pub duration_ms: u64,
    pub error: Option<String>,
}

impl ResponseInfo {
    pub fn new(
        status: u16,
        size: usize,
        body: Option<serde_json::Value>,
        duration_ms: u64,
    ) -> Self {
        let keys = body.as_ref().map(Self::extract_keys).unwrap_or_default();
        Self {
            status,
            size,
            body,
            keys,
            headers: HashMap::new(),
            duration_ms,
            error: None,
        }
    }

    pub fn error(err: String) -> Self {
        Self {
            status: 0,
            size: 0,
            body: None,
            keys: Vec::new(),
            headers: HashMap::new(),
            duration_ms: 0,
            error: Some(err),
        }
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    pub fn is_error(&self) -> bool {
        self.error.is_some()
    }

    fn extract_keys(value: &serde_json::Value) -> Vec<String> {
        let mut keys = Vec::new();
        Self::walk_json(value, String::new(), &mut keys);
        keys
    }

    fn walk_json(value: &serde_json::Value, prefix: String, keys: &mut Vec<String>) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, val) in map {
                    let path = if prefix.is_empty() {
                        key.clone()
                    } else {
                        format!("{}.{}", prefix, key)
                    };
                    keys.push(path.clone());
                    Self::walk_json(val, path, keys);
                }
            }
            serde_json::Value::Array(arr) => {
                if let Some(first) = arr.first() {
                    let array_path = format!("{}[]", prefix);
                    keys.push(array_path.clone());
                    Self::walk_json(first, array_path, keys);
                }
            }
            _ => {}
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total_endpoints: usize,
    pub total_requests: usize,
    pub duration_ms: u64,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
    pub ok_count: usize,
}

impl ScanSummary {
    pub fn from_results(results: &[ScanResult], total_duration_ms: u64) -> Self {
        let mut summary = Self {
            total_endpoints: results.len(),
            total_requests: results.len() * 3,
            duration_ms: total_duration_ms,
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            info_count: 0,
            ok_count: 0,
        };

        for result in results {
            match result.max_severity() {
                Some(Severity::Critical) => summary.critical_count += 1,
                Some(Severity::High) => summary.high_count += 1,
                Some(Severity::Medium) => summary.medium_count += 1,
                Some(Severity::Low) => summary.low_count += 1,
                Some(Severity::Info) => summary.info_count += 1,
                None => summary.ok_count += 1,
            }
        }

        summary
    }
}
