use std::collections::HashMap;
use std::sync::Arc;

use indicatif::{ProgressBar, ProgressStyle};
use tokio::sync::Semaphore;

use crate::fuzzer::{ParamFuzzer, HeaderFuzzer};
use crate::http::HttpClient;
use crate::models::{Endpoint, RoleConfig, ResponseInfo, Vulnerability, VulnType, Evidence, Severity};

pub struct FuzzResult {
    pub endpoint: String,
    pub fuzz_type: FuzzType,
    pub trigger: String,
    pub baseline_status: u16,
    pub fuzzed_status: u16,
    pub baseline_size: usize,
    pub fuzzed_size: usize,
    pub vulnerability: Option<Vulnerability>,
}

#[derive(Debug, Clone)]
pub enum FuzzType {
    QueryParam,
    Header,
}

impl std::fmt::Display for FuzzType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FuzzType::QueryParam => write!(f, "Query Param"),
            FuzzType::Header => write!(f, "Header"),
        }
    }
}

pub struct FuzzerScanner {
    client: HttpClient,
    user_role: RoleConfig,
    semaphore: Arc<Semaphore>,
    path_params: HashMap<String, String>,
}

impl FuzzerScanner {
    pub fn new(
        base_url: String,
        user_role: RoleConfig,
        concurrency: usize,
        timeout: u64,
        path_params: HashMap<String, String>,
    ) -> Self {
        let client = HttpClient::new(base_url, timeout).expect("Failed to create HTTP client");

        Self {
            client,
            user_role,
            semaphore: Arc::new(Semaphore::new(concurrency)),
            path_params,
        }
    }

    pub async fn fuzz_all(&self, endpoints: Vec<Endpoint>, verbose: bool) -> Vec<FuzzResult> {
        let param_combos = ParamFuzzer::get_all_combinations();
        let header_combos = HeaderFuzzer::get_all_bypass_headers();

        let total_tests = endpoints.len() * (param_combos.len() + header_combos.len());
        let pb = self.create_progress_bar(total_tests, verbose);

        let mut all_results = Vec::new();

        for endpoint in &endpoints {
            let baseline = self.get_baseline(endpoint).await;

            if baseline.status == 403 || baseline.status == 401 {
                let param_results = self.fuzz_query_params(endpoint, &baseline, &param_combos, &pb, true).await;
                all_results.extend(param_results);

                let header_results = self.fuzz_headers(endpoint, &baseline, &header_combos, &pb, true).await;
                all_results.extend(header_results);
            } else if baseline.status == 200 {
                let param_results = self.fuzz_query_params(endpoint, &baseline, &param_combos, &pb, false).await;
                all_results.extend(param_results);

                let header_results = self.fuzz_headers(endpoint, &baseline, &header_combos, &pb, false).await;
                all_results.extend(header_results);
            } else {
                pb.inc((param_combos.len() + header_combos.len()) as u64);
            }
        }

        pb.finish_with_message("Fuzzing complete");
        all_results
    }

    async fn get_baseline(&self, endpoint: &Endpoint) -> ResponseInfo {
        self.client
            .request(endpoint, &self.user_role, &self.path_params, None)
            .await
    }

    async fn fuzz_query_params(
        &self,
        endpoint: &Endpoint,
        baseline: &ResponseInfo,
        combos: &[HashMap<String, String>],
        pb: &ProgressBar,
        check_bypass: bool,
    ) -> Vec<FuzzResult> {
        let mut results = Vec::new();

        for params in combos {
            let _permit = self.semaphore.acquire().await.expect("Semaphore closed");

            let response = self.client
                .request_with_fuzz(
                    endpoint,
                    &self.user_role,
                    &self.path_params,
                    None,
                    Some(params),
                    None,
                )
                .await;

            let vuln = if check_bypass {
                self.detect_bypass(baseline, &response, params)
            } else {
                self.detect_data_leak(baseline, &response, params)
            };

            if let Some(v) = vuln {
                let trigger = params
                    .iter()
                    .map(|(k, v)| format!("{}={}", k, v))
                    .collect::<Vec<_>>()
                    .join("&");

                results.push(FuzzResult {
                    endpoint: endpoint.display_path(),
                    fuzz_type: FuzzType::QueryParam,
                    trigger,
                    baseline_status: baseline.status,
                    fuzzed_status: response.status,
                    baseline_size: baseline.size,
                    fuzzed_size: response.size,
                    vulnerability: Some(v),
                });
            }

            pb.inc(1);
        }

        results
    }

    async fn fuzz_headers(
        &self,
        endpoint: &Endpoint,
        baseline: &ResponseInfo,
        combos: &[HashMap<String, String>],
        pb: &ProgressBar,
        check_bypass: bool,
    ) -> Vec<FuzzResult> {
        let mut results = Vec::new();

        for headers in combos {
            let _permit = self.semaphore.acquire().await.expect("Semaphore closed");

            let response = self.client
                .request_with_fuzz(
                    endpoint,
                    &self.user_role,
                    &self.path_params,
                    None,
                    None,
                    Some(headers),
                )
                .await;

            let vuln = if check_bypass {
                self.detect_bypass(baseline, &response, headers)
            } else {
                self.detect_data_leak(baseline, &response, headers)
            };

            if let Some(v) = vuln {
                let trigger = headers
                    .iter()
                    .map(|(k, v)| format!("{}: {}", k, v))
                    .collect::<Vec<_>>()
                    .join(", ");

                results.push(FuzzResult {
                    endpoint: endpoint.display_path(),
                    fuzz_type: FuzzType::Header,
                    trigger,
                    baseline_status: baseline.status,
                    fuzzed_status: response.status,
                    baseline_size: baseline.size,
                    fuzzed_size: response.size,
                    vulnerability: Some(v),
                });
            }

            pb.inc(1);
        }

        results
    }

    fn detect_bypass(
        &self,
        baseline: &ResponseInfo,
        fuzzed: &ResponseInfo,
        trigger: &HashMap<String, String>,
    ) -> Option<Vulnerability> {
        if baseline.status == 403 || baseline.status == 401 {
            if fuzzed.status == 200 {
                let trigger_str = trigger
                    .iter()
                    .map(|(k, v)| format!("{}={}", k, v))
                    .collect::<Vec<_>>()
                    .join(", ");

                return Some(Vulnerability::new(
                    Severity::Critical,
                    VulnType::BrokenAccessControl,
                    format!("Authorization bypass via: {}", trigger_str),
                    Evidence {
                        evidence_type: crate::models::EvidenceType::StatusMatrix,
                        details: format!(
                            "Baseline: {} -> Fuzzed: {} (size: {} -> {})",
                            baseline.status, fuzzed.status, baseline.size, fuzzed.size
                        ),
                    },
                ));
            }
        }

        None
    }

    fn detect_data_leak(
        &self,
        baseline: &ResponseInfo,
        fuzzed: &ResponseInfo,
        trigger: &HashMap<String, String>,
    ) -> Option<Vulnerability> {
        if baseline.status == 200 && fuzzed.status == 200 {
            let size_increase = fuzzed.size as f64 / baseline.size.max(1) as f64;

            if size_increase > 1.5 && fuzzed.size > baseline.size + 100 {
                let trigger_str = trigger
                    .iter()
                    .map(|(k, v)| format!("{}={}", k, v))
                    .collect::<Vec<_>>()
                    .join(", ");

                return Some(Vulnerability::new(
                    Severity::High,
                    VulnType::DataLeakage,
                    format!("Data leak via query param: {}", trigger_str),
                    Evidence {
                        evidence_type: crate::models::EvidenceType::LengthComparison,
                        details: format!(
                            "Response size increased {:.0}%: {} -> {} bytes",
                            (size_increase - 1.0) * 100.0,
                            baseline.size,
                            fuzzed.size
                        ),
                    },
                ));
            }

            if let (Some(base_body), Some(fuzz_body)) = (&baseline.body, &fuzzed.body) {
                let base_keys = Self::count_json_keys(base_body);
                let fuzz_keys = Self::count_json_keys(fuzz_body);

                if fuzz_keys > base_keys + 3 {
                    let trigger_str = trigger
                        .iter()
                        .map(|(k, v)| format!("{}={}", k, v))
                        .collect::<Vec<_>>()
                        .join(", ");

                    return Some(Vulnerability::new(
                        Severity::High,
                        VulnType::DataLeakage,
                        format!("Extra fields exposed via: {}", trigger_str),
                        Evidence {
                            evidence_type: crate::models::EvidenceType::KeyComparison,
                            details: format!(
                                "JSON keys increased: {} -> {} keys",
                                base_keys, fuzz_keys
                            ),
                        },
                    ));
                }
            }
        }

        None
    }

    fn count_json_keys(value: &serde_json::Value) -> usize {
        match value {
            serde_json::Value::Object(map) => {
                let mut count = map.len();
                for v in map.values() {
                    count += Self::count_json_keys(v);
                }
                count
            }
            serde_json::Value::Array(arr) => {
                arr.first().map(Self::count_json_keys).unwrap_or(0)
            }
            _ => 0,
        }
    }

    fn create_progress_bar(&self, total: usize, verbose: bool) -> ProgressBar {
        let pb = ProgressBar::new(total as u64);

        if verbose {
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} Fuzzing...")
                    .expect("Invalid progress bar template")
                    .progress_chars("#>-"),
            );
        } else {
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len}")
                    .expect("Invalid progress bar template")
                    .progress_chars("#>-"),
            );
        }

        pb
    }
}

pub fn print_fuzz_results(results: &[FuzzResult]) {
    use colored::Colorize;

    if results.is_empty() {
        println!("\n{}", "No bypass vulnerabilities found via fuzzing.".green());
        return;
    }

    println!("\n{}", "Fuzzing Results - Bypass Vulnerabilities Found:".red().bold());
    println!("{}", "=".repeat(80));

    for result in results {
        let severity = result
            .vulnerability
            .as_ref()
            .map(|v| v.severity)
            .unwrap_or(Severity::Info);

        let severity_str = match severity {
            Severity::Critical => "CRITICAL".red().bold(),
            Severity::High => "HIGH".red(),
            Severity::Medium => "MEDIUM".yellow(),
            _ => "LOW".blue(),
        };

        println!(
            "\n[{}] {} - {}",
            severity_str,
            result.endpoint.yellow(),
            result.fuzz_type
        );
        println!("  Trigger: {}", result.trigger.cyan());
        println!(
            "  Status: {} -> {}",
            result.baseline_status.to_string().red(),
            result.fuzzed_status.to_string().green()
        );
        println!(
            "  Size: {} -> {} bytes",
            result.baseline_size, result.fuzzed_size
        );
    }

    println!("\n{}", "=".repeat(80));
    println!(
        "Total bypasses found: {}",
        results.len().to_string().red().bold()
    );
}
