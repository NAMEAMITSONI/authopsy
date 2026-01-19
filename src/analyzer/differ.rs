use serde_json::Value;
use std::collections::{HashMap, HashSet};

pub struct JsonDiffer {
    ignore_patterns: Vec<String>,
}

impl JsonDiffer {
    pub fn new(ignore_patterns: Vec<String>) -> Self {
        Self { ignore_patterns }
    }

    pub fn extract_keys(&self, value: &Value) -> HashSet<String> {
        let mut keys = HashSet::new();
        self.walk_json(value, String::new(), &mut keys);
        self.filter_ignored(keys)
    }

    pub fn extract_array_lengths(&self, value: &Value) -> HashMap<String, usize> {
        let mut lengths = HashMap::new();
        self.walk_arrays(value, String::new(), &mut lengths);
        lengths
    }

    pub fn keys_match(&self, keys1: &HashSet<String>, keys2: &HashSet<String>) -> bool {
        keys1 == keys2
    }

    pub fn extra_keys<'a>(
        &self,
        base: &'a HashSet<String>,
        compare: &'a HashSet<String>,
    ) -> Vec<&'a String> {
        compare.difference(base).collect()
    }

    pub fn length_diff_ratio(&self, len1: usize, len2: usize) -> f64 {
        if len1 == 0 && len2 == 0 {
            return 0.0;
        }
        let max_len = len1.max(len2) as f64;
        let diff = (len1 as i64 - len2 as i64).unsigned_abs() as f64;
        diff / max_len
    }

    fn walk_json(&self, value: &Value, prefix: String, keys: &mut HashSet<String>) {
        match value {
            Value::Object(map) => {
                for (key, val) in map {
                    let path = if prefix.is_empty() {
                        key.clone()
                    } else {
                        format!("{}.{}", prefix, key)
                    };
                    keys.insert(path.clone());
                    self.walk_json(val, path, keys);
                }
            }
            Value::Array(arr) => {
                if !prefix.is_empty() {
                    let array_path = format!("{}[]", prefix);
                    keys.insert(array_path.clone());
                    if let Some(first) = arr.first() {
                        self.walk_json(first, array_path, keys);
                    }
                }
            }
            _ => {}
        }
    }

    fn walk_arrays(&self, value: &Value, prefix: String, lengths: &mut HashMap<String, usize>) {
        match value {
            Value::Object(map) => {
                for (key, val) in map {
                    let path = if prefix.is_empty() {
                        key.clone()
                    } else {
                        format!("{}.{}", prefix, key)
                    };
                    self.walk_arrays(val, path, lengths);
                }
            }
            Value::Array(arr) => {
                if !prefix.is_empty() {
                    lengths.insert(prefix.clone(), arr.len());
                }
                if let Some(first) = arr.first() {
                    let array_path = format!("{}[]", prefix);
                    self.walk_arrays(first, array_path, lengths);
                }
            }
            _ => {}
        }
    }

    fn filter_ignored(&self, keys: HashSet<String>) -> HashSet<String> {
        if self.ignore_patterns.is_empty() {
            return keys;
        }

        keys.into_iter()
            .filter(|key| {
                !self
                    .ignore_patterns
                    .iter()
                    .any(|pattern| key.contains(pattern) || key.ends_with(pattern))
            })
            .collect()
    }
}

impl Default for JsonDiffer {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_extract_keys_simple() {
        let differ = JsonDiffer::default();
        let value = json!({
            "id": 1,
            "name": "test"
        });

        let keys = differ.extract_keys(&value);
        assert!(keys.contains("id"));
        assert!(keys.contains("name"));
    }

    #[test]
    fn test_extract_keys_nested() {
        let differ = JsonDiffer::default();
        let value = json!({
            "user": {
                "id": 1,
                "profile": {
                    "email": "test@example.com"
                }
            }
        });

        let keys = differ.extract_keys(&value);
        assert!(keys.contains("user"));
        assert!(keys.contains("user.id"));
        assert!(keys.contains("user.profile"));
        assert!(keys.contains("user.profile.email"));
    }

    #[test]
    fn test_extract_keys_array() {
        let differ = JsonDiffer::default();
        let value = json!({
            "items": [
                {"id": 1, "name": "item1"},
                {"id": 2, "name": "item2"}
            ]
        });

        let keys = differ.extract_keys(&value);
        assert!(keys.contains("items"));
        assert!(keys.contains("items[]"));
        assert!(keys.contains("items[].id"));
        assert!(keys.contains("items[].name"));
    }

    #[test]
    fn test_length_diff_ratio() {
        let differ = JsonDiffer::default();
        assert_eq!(differ.length_diff_ratio(100, 100), 0.0);
        assert_eq!(differ.length_diff_ratio(100, 95), 0.05);
        assert_eq!(differ.length_diff_ratio(100, 50), 0.5);
    }

    #[test]
    fn test_filter_ignored() {
        let differ = JsonDiffer::new(vec!["timestamp".to_string(), "updatedAt".to_string()]);
        let value = json!({
            "id": 1,
            "timestamp": 12345,
            "data": {
                "updatedAt": "2024-01-01"
            }
        });

        let keys = differ.extract_keys(&value);
        assert!(keys.contains("id"));
        assert!(!keys.contains("timestamp"));
        assert!(keys.contains("data"));
        assert!(!keys.contains("data.updatedAt"));
    }
}
