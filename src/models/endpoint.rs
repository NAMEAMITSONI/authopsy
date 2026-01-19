use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Head,
    Options,
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Head => "HEAD",
            HttpMethod::Options => "OPTIONS",
        };
        write!(f, "{}", s)
    }
}

impl HttpMethod {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "GET" => Some(HttpMethod::Get),
            "POST" => Some(HttpMethod::Post),
            "PUT" => Some(HttpMethod::Put),
            "PATCH" => Some(HttpMethod::Patch),
            "DELETE" => Some(HttpMethod::Delete),
            "HEAD" => Some(HttpMethod::Head),
            "OPTIONS" => Some(HttpMethod::Options),
            _ => None,
        }
    }

    pub fn requires_body(&self) -> bool {
        matches!(self, HttpMethod::Post | HttpMethod::Put | HttpMethod::Patch)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub path: String,
    pub method: HttpMethod,
    pub path_params: Vec<PathParam>,
    pub request_body_schema: Option<serde_json::Value>,
    pub request_body_example: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathParam {
    pub name: String,
    pub param_type: ParamType,
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ParamType {
    String,
    Integer,
    Uuid,
    Boolean,
}

impl PathParam {
    pub fn default_value(&self) -> String {
        match self.param_type {
            ParamType::String => "test".to_string(),
            ParamType::Integer => "1".to_string(),
            ParamType::Uuid => "00000000-0000-0000-0000-000000000001".to_string(),
            ParamType::Boolean => "true".to_string(),
        }
    }
}

impl Endpoint {
    pub fn new(method: HttpMethod, path: String) -> Self {
        let path_params = Self::extract_path_params(&path);
        Self {
            path,
            method,
            path_params,
            request_body_schema: None,
            request_body_example: None,
        }
    }

    fn extract_path_params(path: &str) -> Vec<PathParam> {
        let mut params = Vec::new();
        for segment in path.split('/') {
            if segment.starts_with('{') && segment.ends_with('}') {
                let name = segment[1..segment.len() - 1].to_string();
                let param_type = Self::infer_param_type(&name);
                params.push(PathParam {
                    name,
                    param_type,
                    required: true,
                });
            }
        }
        params
    }

    fn infer_param_type(name: &str) -> ParamType {
        let lower = name.to_lowercase();
        if lower.contains("uuid") || lower.ends_with("_id") && lower.len() > 10 {
            ParamType::Uuid
        } else if lower.contains("id") || lower.contains("count") || lower.contains("num") {
            ParamType::Integer
        } else if lower.contains("enabled") || lower.contains("active") || lower.contains("flag") {
            ParamType::Boolean
        } else {
            ParamType::String
        }
    }

    pub fn resolve_path(
        &self,
        custom_params: &std::collections::HashMap<String, String>,
    ) -> String {
        let mut resolved = self.path.clone();
        for param in &self.path_params {
            let value = custom_params
                .get(&param.name)
                .cloned()
                .unwrap_or_else(|| param.default_value());
            resolved = resolved.replace(&format!("{{{}}}", param.name), &value);
        }
        resolved
    }

    pub fn display_path(&self) -> String {
        format!("{:6} {}", self.method, self.path)
    }
}
