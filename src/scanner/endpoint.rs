use anyhow::{Result, bail};

use crate::models::{Endpoint, HttpMethod};

pub struct EndpointParser;

impl EndpointParser {
    pub fn parse(input: &str) -> Result<Vec<Endpoint>> {
        let mut endpoints = Vec::new();

        for part in input.split(',') {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                continue;
            }

            let endpoint = Self::parse_single(trimmed)?;
            endpoints.push(endpoint);
        }

        if endpoints.is_empty() {
            bail!("No valid endpoints found in input");
        }

        Ok(endpoints)
    }

    fn parse_single(input: &str) -> Result<Endpoint> {
        let parts: Vec<&str> = input.split_whitespace().collect();

        if parts.len() != 2 {
            bail!(
                "Invalid endpoint format: '{}'. Expected 'METHOD /path'",
                input
            );
        }

        let method = HttpMethod::parse(parts[0]).ok_or_else(|| {
            anyhow::anyhow!("Invalid HTTP method: '{}'. Supported: GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS", parts[0])
        })?;

        let path = parts[1].to_string();

        if !path.starts_with('/') {
            bail!("Path must start with '/': '{}'", path);
        }

        Ok(Endpoint::new(method, path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_single_endpoint() {
        let endpoints = EndpointParser::parse("GET /api/users").unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].method, HttpMethod::Get);
        assert_eq!(endpoints[0].path, "/api/users");
    }

    #[test]
    fn test_parse_multiple_endpoints() {
        let input = "GET /api/users, POST /api/users, DELETE /api/users/{id}";
        let endpoints = EndpointParser::parse(input).unwrap();
        assert_eq!(endpoints.len(), 3);
    }

    #[test]
    fn test_parse_with_path_params() {
        let endpoints = EndpointParser::parse("GET /api/users/{userId}").unwrap();
        assert_eq!(endpoints[0].path_params.len(), 1);
        assert_eq!(endpoints[0].path_params[0].name, "userId");
    }

    #[test]
    fn test_invalid_method() {
        let result = EndpointParser::parse("INVALID /api/users");
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_path() {
        let result = EndpointParser::parse("GET");
        assert!(result.is_err());
    }
}
