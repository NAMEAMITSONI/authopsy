use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use futures::future::join_all;
use indicatif::{ProgressBar, ProgressStyle};
use tokio::sync::Semaphore;

use crate::analyzer::VulnerabilityDetector;
use crate::http::HttpClient;
use crate::models::{Endpoint, ResponseInfo, Role, RoleConfig, ScanResult};

pub struct Scanner {
    client: HttpClient,
    roles: Vec<RoleConfig>,
    semaphore: Arc<Semaphore>,
    path_params: HashMap<String, String>,
    request_bodies: HashMap<String, serde_json::Value>,
    detector: VulnerabilityDetector,
    public_paths: Vec<String>,
}

impl Scanner {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        base_url: String,
        roles: Vec<RoleConfig>,
        concurrency: usize,
        timeout: u64,
        path_params: HashMap<String, String>,
        request_bodies: HashMap<String, serde_json::Value>,
        ignore_fields: Vec<String>,
        public_paths: Vec<String>,
    ) -> Self {
        let client = HttpClient::new(base_url, timeout).expect("Failed to create HTTP client");
        let detector = VulnerabilityDetector::new(0.05, ignore_fields);

        Self {
            client,
            roles,
            semaphore: Arc::new(Semaphore::new(concurrency)),
            path_params,
            request_bodies,
            detector,
            public_paths,
        }
    }

    pub async fn scan_all(&self, endpoints: Vec<Endpoint>, verbose: bool) -> Vec<ScanResult> {
        let total = endpoints.len();
        let pb = self.create_progress_bar(total, verbose);

        let futures: Vec<_> = endpoints
            .into_iter()
            .map(|ep| self.scan_endpoint(ep, &pb))
            .collect();

        let results = join_all(futures).await;

        pb.finish_with_message("Scan complete");
        results
    }

    async fn scan_endpoint(&self, endpoint: Endpoint, pb: &ProgressBar) -> ScanResult {
        let _permit = self.semaphore.acquire().await.expect("Semaphore closed");
        let start = Instant::now();

        pb.set_message(format!("{} {}", endpoint.method, endpoint.path));

        let mut responses: HashMap<Role, ResponseInfo> = HashMap::new();

        for role_config in &self.roles {
            let body = self.get_request_body(&endpoint);
            let response = self
                .client
                .request(&endpoint, role_config, &self.path_params, body.as_ref())
                .await;
            responses.insert(role_config.role, response);
        }

        let duration_ms = start.elapsed().as_millis() as u64;
        let is_public = self.public_paths.iter().any(|p| endpoint.path.contains(p));
        let mut result = ScanResult::new(endpoint, responses, duration_ms);

        let vulnerabilities = self.detector.analyze(&result, is_public);
        result = result.with_vulnerabilities(vulnerabilities);

        pb.inc(1);
        result
    }

    fn get_request_body(&self, endpoint: &Endpoint) -> Option<serde_json::Value> {
        let key = format!("{} {}", endpoint.method, endpoint.path);
        self.request_bodies
            .get(&key)
            .cloned()
            .or_else(|| endpoint.request_body_example.clone())
    }

    fn create_progress_bar(&self, total: usize, verbose: bool) -> ProgressBar {
        let pb = ProgressBar::new(total as u64);

        if verbose {
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
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
