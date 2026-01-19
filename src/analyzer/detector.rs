use std::collections::HashSet;
use regex::Regex;

use crate::models::{Role, ScanResult, Vulnerability, VulnType, Evidence, Severity};
use super::differ::JsonDiffer;
use super::status::StatusAnalyzer;

pub struct VulnerabilityDetector {
    length_threshold: f64,
    differ: JsonDiffer,
    sensitive_patterns: Vec<Regex>,
}

impl VulnerabilityDetector {
    pub fn new(length_threshold: f64, ignore_fields: Vec<String>) -> Self {
        let sensitive_patterns = vec![
            Regex::new(r"(?i)password").unwrap(),
            Regex::new(r"(?i)secret").unwrap(),
            Regex::new(r"(?i)token").unwrap(),
            Regex::new(r"(?i)api[_-]?key").unwrap(),
            Regex::new(r"(?i)private").unwrap(),
            Regex::new(r"(?i)internal").unwrap(),
            Regex::new(r"(?i)admin").unwrap(),
            Regex::new(r"(?i)ssn").unwrap(),
            Regex::new(r"(?i)credit[_-]?card").unwrap(),
            Regex::new(r"(?i)cvv").unwrap(),
            Regex::new(r"(?i)routing[_-]?number").unwrap(),
            Regex::new(r"(?i)account[_-]?number").unwrap(),
        ];

        Self {
            length_threshold,
            differ: JsonDiffer::new(ignore_fields),
            sensitive_patterns,
        }
    }

    pub fn analyze(&self, result: &ScanResult, is_public: bool) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        let admin = match result.get_response(Role::Admin) {
            Some(r) if !r.is_error() => r,
            _ => return vulns,
        };

        let user = match result.get_response(Role::User) {
            Some(r) if !r.is_error() => r,
            _ => return vulns,
        };

        let anon = result.get_response(Role::Anonymous).filter(|r| !r.is_error());

        if !is_public {
            vulns.extend(StatusAnalyzer::analyze(admin, user, anon));
        }

        if StatusAnalyzer::both_success(admin, user) && !is_public {
            vulns.extend(self.analyze_content_length(admin.size, user.size));
            vulns.extend(self.analyze_json_structure(admin, user));
            vulns.extend(self.analyze_timing(admin.duration_ms, user.duration_ms));
        }

        self.consolidate_findings(vulns)
    }

    fn analyze_content_length(&self, admin_len: usize, user_len: usize) -> Vec<Vulnerability> {
        let mut findings = Vec::new();
        let diff_ratio = self.differ.length_diff_ratio(admin_len, user_len);

        if diff_ratio < self.length_threshold && admin_len > 50 {
            findings.push(Vulnerability::high(
                VulnType::BrokenAccessControl,
                "Response sizes nearly identical - likely same data returned",
                Evidence::length_comparison(admin_len, user_len, diff_ratio),
            ));
        }

        findings
    }

    fn analyze_json_structure(
        &self,
        admin: &crate::models::ResponseInfo,
        user: &crate::models::ResponseInfo,
    ) -> Vec<Vulnerability> {
        let mut findings = Vec::new();

        let (admin_body, user_body) = match (&admin.body, &user.body) {
            (Some(a), Some(u)) => (a, u),
            _ => return findings,
        };

        let admin_keys = self.differ.extract_keys(admin_body);
        let user_keys = self.differ.extract_keys(user_body);

        if admin_keys.is_empty() || user_keys.is_empty() {
            return findings;
        }

        if self.differ.keys_match(&admin_keys, &user_keys) && admin_keys.len() > 3 {
            findings.push(Vulnerability::critical(
                VulnType::BrokenAccessControl,
                "Identical JSON structure - User sees all Admin data",
                Evidence::key_comparison(
                    &admin_keys.iter().cloned().collect::<Vec<_>>(),
                    &user_keys.iter().cloned().collect::<Vec<_>>(),
                ),
            ));
        }

        let user_extra = self.differ.extra_keys(&admin_keys, &user_keys);
        if !user_extra.is_empty() {
            findings.push(Vulnerability::critical(
                VulnType::DataLeakage,
                "User response contains keys NOT in Admin response",
                Evidence::extra_keys(&user_extra),
            ));
        }

        let user_sensitive = self.find_sensitive_fields(&user_keys);
        if !user_sensitive.is_empty() {
            findings.push(Vulnerability::medium(
                VulnType::SensitiveDataExposure,
                "Sensitive field names visible in User response",
                Evidence::sensitive_fields(&user_sensitive.iter().collect::<Vec<_>>()),
            ));
        }

        let admin_arrays = self.differ.extract_array_lengths(admin_body);
        let user_arrays = self.differ.extract_array_lengths(user_body);

        for (path, admin_len) in &admin_arrays {
            if let Some(&user_len) = user_arrays.get(path) {
                if user_len > *admin_len {
                    findings.push(Vulnerability::high(
                        VulnType::PaginationBypass,
                        format!("User sees {} items vs Admin's {} at {}", user_len, admin_len, path),
                        Evidence::array_lengths(path, *admin_len, user_len),
                    ));
                }
            }
        }

        findings
    }

    fn analyze_timing(&self, admin_ms: u64, user_ms: u64) -> Vec<Vulnerability> {
        let mut findings = Vec::new();

        let diff = (admin_ms as i64 - user_ms as i64).unsigned_abs();

        if diff > 500 && admin_ms > 100 && user_ms > 100 {
            findings.push(Vulnerability::low(
                VulnType::TimingAttack,
                "Significant response time variance detected between roles",
                Evidence::timing_difference(admin_ms, user_ms),
            ));
        }

        findings
    }

    fn find_sensitive_fields(&self, keys: &HashSet<String>) -> Vec<String> {
        keys.iter()
            .filter(|key| {
                self.sensitive_patterns.iter().any(|pattern| pattern.is_match(key))
            })
            .cloned()
            .collect()
    }

    fn consolidate_findings(&self, vulns: Vec<Vulnerability>) -> Vec<Vulnerability> {
        let mut seen_types: HashSet<(VulnType, Severity)> = HashSet::new();
        let mut consolidated = Vec::new();

        for vuln in vulns {
            let key = (vuln.vuln_type, vuln.severity);
            if !seen_types.contains(&key) {
                seen_types.insert(key);
                consolidated.push(vuln);
            }
        }

        consolidated.sort_by(|a, b| b.severity.numeric_value().cmp(&a.severity.numeric_value()));
        consolidated
    }
}

impl Default for VulnerabilityDetector {
    fn default() -> Self {
        Self::new(0.05, Vec::new())
    }
}
