use anyhow::Result;
use reqwest::{Client, Method, RequestBuilder};
use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::models::{Endpoint, HttpMethod, ResponseInfo, RoleConfig};

pub struct HttpClient {
    client: Client,
    base_url: String,
}

impl HttpClient {
    pub fn new(base_url: String, timeout_secs: u64) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .danger_accept_invalid_certs(false)
            .build()?;

        let base_url = base_url.trim_end_matches('/').to_string();

        Ok(Self { client, base_url })
    }

    pub async fn request(
        &self,
        endpoint: &Endpoint,
        role: &RoleConfig,
        path_params: &HashMap<String, String>,
        body: Option<&serde_json::Value>,
    ) -> ResponseInfo {
        let start = Instant::now();
        let resolved_path = endpoint.resolve_path(path_params);
        let url = format!("{}{}", self.base_url, resolved_path);

        let method = Self::to_reqwest_method(endpoint.method);
        let mut request = self.client.request(method, &url);

        if let Some(token) = &role.token {
            request = request.header(&role.header_name, token);
        }

        request = request.header("Accept", "application/json");
        request = request.header("Content-Type", "application/json");

        if endpoint.method.requires_body() {
            if let Some(b) = body {
                request = request.json(b);
            } else if let Some(ref example) = endpoint.request_body_example {
                request = request.json(example);
            }
        }

        self.execute_request(request, start).await
    }

    pub async fn request_with_fuzz(
        &self,
        endpoint: &Endpoint,
        role: &RoleConfig,
        path_params: &HashMap<String, String>,
        body: Option<&serde_json::Value>,
        query_params: Option<&HashMap<String, String>>,
        extra_headers: Option<&HashMap<String, String>>,
    ) -> ResponseInfo {
        let start = Instant::now();
        let resolved_path = endpoint.resolve_path(path_params);

        let query_string = query_params
            .map(|params| {
                let pairs: Vec<String> = params
                    .iter()
                    .map(|(k, v)| {
                        if v.is_empty() {
                            urlencoding::encode(k).to_string()
                        } else {
                            format!("{}={}", urlencoding::encode(k), urlencoding::encode(v))
                        }
                    })
                    .collect();
                if pairs.is_empty() {
                    String::new()
                } else {
                    format!("?{}", pairs.join("&"))
                }
            })
            .unwrap_or_default();

        let url = format!("{}{}{}", self.base_url, resolved_path, query_string);

        let method = Self::to_reqwest_method(endpoint.method);
        let mut request = self.client.request(method, &url);

        if let Some(token) = &role.token {
            request = request.header(&role.header_name, token);
        }

        request = request.header("Accept", "application/json");
        request = request.header("Content-Type", "application/json");

        if let Some(headers) = extra_headers {
            for (key, value) in headers {
                request = request.header(key, value);
            }
        }

        if endpoint.method.requires_body() {
            if let Some(b) = body {
                request = request.json(b);
            } else if let Some(ref example) = endpoint.request_body_example {
                request = request.json(example);
            }
        }

        self.execute_request(request, start).await
    }

    async fn execute_request(&self, request: RequestBuilder, start: Instant) -> ResponseInfo {
        match request.send().await {
            Ok(response) => {
                let status = response.status().as_u16();
                let headers: HashMap<String, String> = response
                    .headers()
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                    .collect();

                let bytes = response.bytes().await.unwrap_or_default();
                let size = bytes.len();
                let body: Option<serde_json::Value> = serde_json::from_slice(&bytes).ok();
                let duration_ms = start.elapsed().as_millis() as u64;

                let mut info = ResponseInfo::new(status, size, body, duration_ms);
                info.headers = headers;
                info
            }
            Err(e) => {
                let duration_ms = start.elapsed().as_millis() as u64;
                let mut info = ResponseInfo::error(e.to_string());
                info.duration_ms = duration_ms;
                info
            }
        }
    }

    fn to_reqwest_method(method: HttpMethod) -> Method {
        match method {
            HttpMethod::Get => Method::GET,
            HttpMethod::Post => Method::POST,
            HttpMethod::Put => Method::PUT,
            HttpMethod::Patch => Method::PATCH,
            HttpMethod::Delete => Method::DELETE,
            HttpMethod::Head => Method::HEAD,
            HttpMethod::Options => Method::OPTIONS,
        }
    }
}
