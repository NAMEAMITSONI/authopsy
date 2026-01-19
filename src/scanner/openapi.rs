use anyhow::{Context, Result};
use serde_json::Value;
use std::fs;

use crate::models::{Endpoint, HttpMethod, ParamType, PathParam};

pub struct OpenApiParser;

impl OpenApiParser {
    pub fn new() -> Self {
        Self
    }

    pub fn parse_file(&self, path: &str) -> Result<Vec<Endpoint>> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read OpenAPI spec: {}", path))?;

        self.parse_content(&content)
    }

    pub fn parse_content(&self, content: &str) -> Result<Vec<Endpoint>> {
        let spec: Value = if content.trim().starts_with('{') {
            serde_json::from_str(content)?
        } else {
            serde_json::from_str(content)
                .with_context(|| "Failed to parse as JSON. YAML support requires conversion.")?
        };

        let version = self.detect_version(&spec);
        match version {
            OpenApiVersion::V3 => self.parse_openapi_v3(&spec),
            OpenApiVersion::V2 => self.parse_swagger_v2(&spec),
            OpenApiVersion::Unknown => anyhow::bail!("Unknown OpenAPI/Swagger version"),
        }
    }

    fn detect_version(&self, spec: &Value) -> OpenApiVersion {
        if spec.get("openapi").is_some() {
            OpenApiVersion::V3
        } else if spec.get("swagger").is_some() {
            OpenApiVersion::V2
        } else {
            OpenApiVersion::Unknown
        }
    }

    fn parse_openapi_v3(&self, spec: &Value) -> Result<Vec<Endpoint>> {
        let paths = spec
            .get("paths")
            .and_then(|p| p.as_object())
            .ok_or_else(|| anyhow::anyhow!("No 'paths' found in OpenAPI spec"))?;

        let mut endpoints = Vec::new();

        for (path, methods) in paths {
            let methods_obj = match methods.as_object() {
                Some(m) => m,
                None => continue,
            };

            for (method_str, operation) in methods_obj {
                if let Some(method) = HttpMethod::parse(method_str) {
                    let mut endpoint = Endpoint::new(method, path.clone());

                    if let Some(params) = operation.get("parameters").and_then(|p| p.as_array()) {
                        endpoint.path_params = self.parse_parameters_v3(params, path);
                    }

                    if let Some(request_body) = operation.get("requestBody") {
                        endpoint.request_body_example =
                            self.extract_request_body_example_v3(request_body);
                        endpoint.request_body_schema =
                            self.extract_request_body_schema_v3(request_body);
                    }

                    endpoints.push(endpoint);
                }
            }
        }

        Ok(endpoints)
    }

    fn parse_swagger_v2(&self, spec: &Value) -> Result<Vec<Endpoint>> {
        let paths = spec
            .get("paths")
            .and_then(|p| p.as_object())
            .ok_or_else(|| anyhow::anyhow!("No 'paths' found in Swagger spec"))?;

        let mut endpoints = Vec::new();

        for (path, methods) in paths {
            let methods_obj = match methods.as_object() {
                Some(m) => m,
                None => continue,
            };

            for (method_str, operation) in methods_obj {
                if let Some(method) = HttpMethod::parse(method_str) {
                    let mut endpoint = Endpoint::new(method, path.clone());

                    if let Some(params) = operation.get("parameters").and_then(|p| p.as_array()) {
                        endpoint.path_params = self.parse_parameters_v2(params, path);
                        endpoint.request_body_example = self.extract_body_param_example_v2(params);
                    }

                    endpoints.push(endpoint);
                }
            }
        }

        Ok(endpoints)
    }

    fn parse_parameters_v3(&self, params: &[Value], path: &str) -> Vec<PathParam> {
        let mut path_params = Vec::new();

        for param in params {
            let location = param.get("in").and_then(|v| v.as_str()).unwrap_or("");
            if location != "path" {
                continue;
            }

            let name = match param.get("name").and_then(|v| v.as_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };

            if !path.contains(&format!("{{{}}}", name)) {
                continue;
            }

            let param_type = self.infer_param_type_from_schema(param.get("schema"));
            let required = param
                .get("required")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);

            path_params.push(PathParam {
                name,
                param_type,
                required,
            });
        }

        path_params
    }

    fn parse_parameters_v2(&self, params: &[Value], path: &str) -> Vec<PathParam> {
        let mut path_params = Vec::new();

        for param in params {
            let location = param.get("in").and_then(|v| v.as_str()).unwrap_or("");
            if location != "path" {
                continue;
            }

            let name = match param.get("name").and_then(|v| v.as_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };

            if !path.contains(&format!("{{{}}}", name)) {
                continue;
            }

            let param_type = self.infer_param_type_v2(param);
            let required = param
                .get("required")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);

            path_params.push(PathParam {
                name,
                param_type,
                required,
            });
        }

        path_params
    }

    fn infer_param_type_from_schema(&self, schema: Option<&Value>) -> ParamType {
        let schema = match schema {
            Some(s) => s,
            None => return ParamType::String,
        };

        let type_str = schema.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let format_str = schema.get("format").and_then(|v| v.as_str()).unwrap_or("");

        match (type_str, format_str) {
            ("integer", _) | ("number", _) => ParamType::Integer,
            ("string", "uuid") => ParamType::Uuid,
            ("boolean", _) => ParamType::Boolean,
            _ => ParamType::String,
        }
    }

    fn infer_param_type_v2(&self, param: &Value) -> ParamType {
        let type_str = param.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let format_str = param.get("format").and_then(|v| v.as_str()).unwrap_or("");

        match (type_str, format_str) {
            ("integer", _) | ("number", _) => ParamType::Integer,
            ("string", "uuid") => ParamType::Uuid,
            ("boolean", _) => ParamType::Boolean,
            _ => ParamType::String,
        }
    }

    fn extract_request_body_example_v3(&self, request_body: &Value) -> Option<Value> {
        let content = request_body.get("content")?;
        let json_content = content.get("application/json")?;

        if let Some(example) = json_content.get("example") {
            return Some(example.clone());
        }

        if let Some(examples) = json_content.get("examples").and_then(|e| e.as_object()) {
            if let Some((_, first_example)) = examples.iter().next() {
                if let Some(value) = first_example.get("value") {
                    return Some(value.clone());
                }
            }
        }

        None
    }

    fn extract_request_body_schema_v3(&self, request_body: &Value) -> Option<Value> {
        let content = request_body.get("content")?;
        let json_content = content.get("application/json")?;
        json_content.get("schema").cloned()
    }

    fn extract_body_param_example_v2(&self, params: &[Value]) -> Option<Value> {
        for param in params {
            let location = param.get("in").and_then(|v| v.as_str()).unwrap_or("");
            if location == "body" {
                if let Some(schema) = param.get("schema") {
                    if let Some(example) = schema.get("example") {
                        return Some(example.clone());
                    }
                }
            }
        }
        None
    }
}

impl Default for OpenApiParser {
    fn default() -> Self {
        Self::new()
    }
}

enum OpenApiVersion {
    V3,
    V2,
    Unknown,
}
