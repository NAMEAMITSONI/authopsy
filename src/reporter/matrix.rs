use crate::models::{Role, ScanResult, Severity};

pub struct AccessControlMatrix {
    entries: Vec<MatrixEntry>,
}

pub struct MatrixEntry {
    pub endpoint: String,
    pub admin_status: String,
    pub user_status: String,
    pub anon_status: String,
    pub severity: Option<Severity>,
    pub is_vulnerable: bool,
}

impl AccessControlMatrix {
    pub fn from_results(results: &[ScanResult]) -> Self {
        let entries = results
            .iter()
            .map(|r| {
                let admin_status = r
                    .get_response(Role::Admin)
                    .map(|resp| Self::format_status(resp.status, resp.is_error()))
                    .unwrap_or_else(|| "-".to_string());

                let user_status = r
                    .get_response(Role::User)
                    .map(|resp| {
                        let status = Self::format_status(resp.status, resp.is_error());
                        if r.is_vulnerable() && resp.is_success() {
                            format!("{} ⚠", status)
                        } else {
                            status
                        }
                    })
                    .unwrap_or_else(|| "-".to_string());

                let anon_status = r
                    .get_response(Role::Anonymous)
                    .map(|resp| {
                        let status = Self::format_status(resp.status, resp.is_error());
                        if r.is_vulnerable() && resp.is_success() && r.max_severity() == Some(Severity::High) {
                            format!("{} ⚠", status)
                        } else {
                            status
                        }
                    })
                    .unwrap_or_else(|| "-".to_string());

                MatrixEntry {
                    endpoint: r.endpoint.display_path(),
                    admin_status,
                    user_status,
                    anon_status,
                    severity: r.max_severity(),
                    is_vulnerable: r.is_vulnerable(),
                }
            })
            .collect();

        Self { entries }
    }

    fn format_status(status: u16, is_error: bool) -> String {
        if is_error {
            "ERR".to_string()
        } else {
            status.to_string()
        }
    }

    pub fn entries(&self) -> &[MatrixEntry] {
        &self.entries
    }
}
