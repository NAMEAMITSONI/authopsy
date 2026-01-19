use std::collections::HashMap;

pub struct ParamFuzzer;

impl ParamFuzzer {
    const BYPASS_PARAMS: &'static [(&'static str, &'static str)] = &[
        ("include_details", "true"),
        ("show_all", "true"),
        ("all", "true"),
        ("admin", "true"),
        ("debug", "true"),
        ("test", "true"),
        ("internal", "true"),
        ("full", "true"),
        ("verbose", "true"),
        ("expand", "true"),
        ("include_private", "true"),
        ("include_sensitive", "true"),
        ("include_deleted", "true"),
        ("show_hidden", "true"),
        ("bypass", "true"),
        ("override", "true"),
        ("force", "true"),
        ("raw", "true"),
        ("detailed", "true"),
        ("extended", "true"),
    ];

    const SEARCH_PARAMS: &'static [(&'static str, &'static str)] = &[
        ("q", ""),
        ("query", ""),
        ("search", ""),
        ("filter", ""),
        ("keyword", ""),
        ("term", ""),
    ];

    const PAGINATION_BYPASS: &'static [(&'static str, &'static str)] = &[
        ("limit", "10000"),
        ("page_size", "10000"),
        ("per_page", "10000"),
        ("count", "10000"),
        ("size", "10000"),
        ("offset", "0"),
        ("skip", "0"),
    ];

    pub fn get_bypass_combinations() -> Vec<HashMap<String, String>> {
        let mut combinations = Vec::new();

        for (key, value) in Self::BYPASS_PARAMS {
            let mut params = HashMap::new();
            params.insert(key.to_string(), value.to_string());
            combinations.push(params);
        }

        combinations
    }

    pub fn get_search_combinations() -> Vec<HashMap<String, String>> {
        let mut combinations = Vec::new();

        for (key, value) in Self::SEARCH_PARAMS {
            let mut params = HashMap::new();
            params.insert(key.to_string(), value.to_string());
            combinations.push(params);
        }

        combinations
    }

    pub fn get_pagination_combinations() -> Vec<HashMap<String, String>> {
        let mut combinations = Vec::new();

        for (key, value) in Self::PAGINATION_BYPASS {
            let mut params = HashMap::new();
            params.insert(key.to_string(), value.to_string());
            combinations.push(params);
        }

        combinations
    }

    pub fn get_all_combinations() -> Vec<HashMap<String, String>> {
        let mut all = Vec::new();
        all.extend(Self::get_bypass_combinations());
        all.extend(Self::get_search_combinations());
        all.extend(Self::get_pagination_combinations());
        all
    }
}
