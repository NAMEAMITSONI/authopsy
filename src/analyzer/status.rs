use crate::models::{ResponseInfo, Vulnerability, VulnType, Evidence};

pub struct StatusAnalyzer;

impl StatusAnalyzer {
    pub fn analyze(
        admin: &ResponseInfo,
        user: &ResponseInfo,
        anon: Option<&ResponseInfo>,
    ) -> Vec<Vulnerability> {
        let mut findings = Vec::new();

        let anon_status = anon.map(|r| r.status).unwrap_or(0);

        match (admin.status, user.status, anon_status) {
            (200, 200, 401 | 403) => {
                findings.push(Vulnerability::critical(
                    VulnType::VerticalPrivilegeEscalation,
                    "User can access Admin-only resource with 200 OK",
                    Evidence::status_matrix(admin.status, user.status, anon_status),
                ));
            }

            (200, 200, 200) => {
                findings.push(Vulnerability::high(
                    VulnType::MissingAuthentication,
                    "Endpoint accessible without any authentication",
                    Evidence::status_matrix(admin.status, user.status, anon_status),
                ));
            }

            (401 | 403, 200, _) => {
                findings.push(Vulnerability::critical(
                    VulnType::RoleConfusion,
                    "Lower privilege role has MORE access than higher privilege role",
                    Evidence::status_matrix(admin.status, user.status, anon_status),
                ));
            }

            (200, 401 | 403, 200) => {
                findings.push(Vulnerability::critical(
                    VulnType::MissingAuthentication,
                    "Anonymous user can access while authenticated User cannot",
                    Evidence::status_matrix(admin.status, user.status, anon_status),
                ));
            }

            (200, 200, 0) if anon.is_none() => {}

            (200, 403 | 401, 401 | 403) => {}

            (200, 403 | 401, 0) => {}

            _ => {}
        }

        findings
    }

    pub fn both_success(admin: &ResponseInfo, user: &ResponseInfo) -> bool {
        admin.is_success() && user.is_success()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_response(status: u16) -> ResponseInfo {
        ResponseInfo::new(status, 100, None, 50)
    }

    #[test]
    fn test_vertical_privilege_escalation() {
        let admin = mock_response(200);
        let user = mock_response(200);
        let anon = mock_response(403);

        let findings = StatusAnalyzer::analyze(&admin, &user, Some(&anon));
        assert!(!findings.is_empty());
        assert_eq!(findings[0].vuln_type, VulnType::VerticalPrivilegeEscalation);
    }

    #[test]
    fn test_missing_auth() {
        let admin = mock_response(200);
        let user = mock_response(200);
        let anon = mock_response(200);

        let findings = StatusAnalyzer::analyze(&admin, &user, Some(&anon));
        assert!(!findings.is_empty());
        assert_eq!(findings[0].vuln_type, VulnType::MissingAuthentication);
    }

    #[test]
    fn test_proper_enforcement() {
        let admin = mock_response(200);
        let user = mock_response(403);
        let anon = mock_response(401);

        let findings = StatusAnalyzer::analyze(&admin, &user, Some(&anon));
        assert!(findings.is_empty());
    }

    #[test]
    fn test_role_confusion() {
        let admin = mock_response(403);
        let user = mock_response(200);
        let anon = mock_response(401);

        let findings = StatusAnalyzer::analyze(&admin, &user, Some(&anon));
        assert!(!findings.is_empty());
        assert_eq!(findings[0].vuln_type, VulnType::RoleConfusion);
    }
}
