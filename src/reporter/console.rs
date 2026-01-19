use colored::Colorize;
use tabled::{Table, Tabled, settings::{Style, Modify, object::Rows, Alignment}};

use crate::models::{ScanResult, Severity, ScanSummary};
use super::matrix::AccessControlMatrix;

pub struct ConsoleReporter;

#[derive(Tabled)]
struct TableRow {
    #[tabled(rename = "Endpoint")]
    endpoint: String,
    #[tabled(rename = "Admin")]
    admin: String,
    #[tabled(rename = "User")]
    user: String,
    #[tabled(rename = "Anon")]
    anon: String,
    #[tabled(rename = "Status")]
    status: String,
}

impl ConsoleReporter {
    pub fn new() -> Self {
        Self
    }

    pub fn print_matrix(&self, results: &[ScanResult]) {
        let matrix = AccessControlMatrix::from_results(results);

        let rows: Vec<TableRow> = matrix
            .entries()
            .iter()
            .map(|entry| {
                let status = match entry.severity {
                    Some(Severity::Critical) => "CRITICAL".red().bold().to_string(),
                    Some(Severity::High) => "HIGH".red().to_string(),
                    Some(Severity::Medium) => "MEDIUM".yellow().to_string(),
                    Some(Severity::Low) => "LOW".blue().to_string(),
                    Some(Severity::Info) => "INFO".cyan().to_string(),
                    None => "OK".green().to_string(),
                };

                TableRow {
                    endpoint: entry.endpoint.clone(),
                    admin: entry.admin_status.clone(),
                    user: if entry.is_vulnerable && entry.user_status.contains("200") {
                        entry.user_status.yellow().to_string()
                    } else {
                        entry.user_status.clone()
                    },
                    anon: entry.anon_status.clone(),
                    status,
                }
            })
            .collect();

        let table = Table::new(rows)
            .with(Style::rounded())
            .with(Modify::new(Rows::first()).with(Alignment::center()))
            .to_string();

        println!("\n{}", table);
    }

    pub fn print_summary(&self, results: &[ScanResult]) {
        let duration: u64 = results.iter().map(|r| r.duration_ms).max().unwrap_or(0);
        let summary = ScanSummary::from_results(results, duration);

        println!("\n{}", "Summary".bold().underline());
        println!(
            "{} endpoints scanned in {:.2}s",
            summary.total_endpoints,
            summary.duration_ms as f64 / 1000.0
        );

        if summary.critical_count > 0 {
            println!("  {}: {}", "CRITICAL".red().bold(), summary.critical_count);
        }
        if summary.high_count > 0 {
            println!("  {}: {}", "HIGH".red(), summary.high_count);
        }
        if summary.medium_count > 0 {
            println!("  {}: {}", "MEDIUM".yellow(), summary.medium_count);
        }
        if summary.low_count > 0 {
            println!("  {}: {}", "LOW".blue(), summary.low_count);
        }
        if summary.info_count > 0 {
            println!("  {}: {}", "INFO".cyan(), summary.info_count);
        }
        println!("  {}: {}", "OK".green(), summary.ok_count);
        println!();
    }

    pub fn print_details(&self, results: &[ScanResult]) {
        let vulnerable: Vec<_> = results.iter().filter(|r| r.is_vulnerable()).collect();

        if vulnerable.is_empty() {
            return;
        }

        println!("\n{}", "Findings".bold().underline());

        for result in vulnerable {
            let severity = result.max_severity().unwrap_or(Severity::Info);
            let severity_str = match severity {
                Severity::Critical => "CRITICAL".red().bold().to_string(),
                Severity::High => "HIGH".red().to_string(),
                Severity::Medium => "MEDIUM".yellow().to_string(),
                Severity::Low => "LOW".blue().to_string(),
                Severity::Info => "INFO".cyan().to_string(),
            };

            println!(
                "\n[{}] {}",
                severity_str,
                result.endpoint.display_path().white().bold()
            );

            for vuln in &result.vulnerabilities {
                println!("  → {}: {}", vuln.vuln_type.to_string().yellow(), vuln.description);

                let recommendation = Self::get_recommendation(&vuln.vuln_type);
                if !recommendation.is_empty() {
                    println!("    {}: {}", "Fix".cyan(), recommendation);
                }
            }
        }
    }

    fn get_recommendation(vuln_type: &crate::models::VulnType) -> &'static str {
        use crate::models::VulnType;
        match vuln_type {
            VulnType::BrokenAccessControl => "Add role-based authorization check before returning data",
            VulnType::VerticalPrivilegeEscalation => "Verify user role matches required permission level",
            VulnType::HorizontalPrivilegeEscalation => "Check resource ownership before granting access",
            VulnType::DataLeakage => "Filter response fields based on user permissions",
            VulnType::SensitiveDataExposure => "Remove or mask sensitive fields for non-admin users",
            VulnType::MissingAuthentication => "Require authentication token for this endpoint",
            VulnType::InconsistentAuth => "Standardize authentication requirements across endpoints",
            VulnType::RoleConfusion => "Review and fix role hierarchy in authorization logic",
            VulnType::PaginationBypass => "Enforce pagination limits server-side regardless of request",
            VulnType::TimingAttack => "Use constant-time comparison for sensitive operations",
            VulnType::InfoDisclosure => "Return generic error messages to prevent information leakage",
        }
    }
}

impl Default for ConsoleReporter {
    fn default() -> Self {
        Self::new()
    }
}
