use anyhow::{Result, Context};
use std::fs;
use tera::{Tera, Context as TeraContext};
use chrono::Utc;

use crate::models::{ScanResult, ScanSummary, Severity};

pub struct JsonExporter;

impl JsonExporter {
    pub fn export(results: &[ScanResult], path: &str) -> Result<()> {
        let output = ExportData {
            scan_time: Utc::now().to_rfc3339(),
            results: results.to_vec(),
            summary: ScanSummary::from_results(results, 0),
        };

        let json = serde_json::to_string_pretty(&output)?;
        fs::write(path, json).with_context(|| format!("Failed to write to {}", path))?;
        Ok(())
    }

    pub fn load(path: &str) -> Result<Vec<ScanResult>> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read {}", path))?;

        let data: ExportData = serde_json::from_str(&content)?;
        Ok(data.results)
    }
}

pub struct HtmlExporter;

impl HtmlExporter {
    pub fn export(results: &[ScanResult], path: &str) -> Result<()> {
        let template = Self::get_template();
        let mut tera = Tera::default();
        tera.add_raw_template("report", &template)?;

        let summary = ScanSummary::from_results(results, 0);

        let mut context = TeraContext::new();
        context.insert("scan_time", &Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string());
        context.insert("total_endpoints", &summary.total_endpoints);
        context.insert("critical_count", &summary.critical_count);
        context.insert("high_count", &summary.high_count);
        context.insert("medium_count", &summary.medium_count);
        context.insert("low_count", &summary.low_count);
        context.insert("ok_count", &summary.ok_count);

        let rows: Vec<HtmlRow> = results
            .iter()
            .map(|r| {
                let severity = r.max_severity();
                HtmlRow {
                    endpoint: r.endpoint.display_path(),
                    admin_status: r.responses.get(&crate::models::Role::Admin)
                        .map(|resp| resp.status.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                    user_status: r.responses.get(&crate::models::Role::User)
                        .map(|resp| resp.status.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                    anon_status: r.responses.get(&crate::models::Role::Anonymous)
                        .map(|resp| resp.status.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                    severity: severity.map(|s| s.to_string()).unwrap_or_else(|| "OK".to_string()),
                    severity_class: Self::severity_class(severity),
                    vulnerabilities: r.vulnerabilities.iter().map(|v| VulnRow {
                        vuln_type: v.vuln_type.to_string(),
                        description: v.description.clone(),
                        evidence: v.evidence.details.clone(),
                    }).collect(),
                }
            })
            .collect();

        context.insert("rows", &rows);

        let html = tera.render("report", &context)?;
        fs::write(path, html).with_context(|| format!("Failed to write to {}", path))?;
        Ok(())
    }

    fn severity_class(severity: Option<Severity>) -> String {
        match severity {
            Some(Severity::Critical) => "critical",
            Some(Severity::High) => "high",
            Some(Severity::Medium) => "medium",
            Some(Severity::Low) => "low",
            Some(Severity::Info) => "info",
            None => "ok",
        }.to_string()
    }

    fn get_template() -> String {
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authopsy Scan Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; }
        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
        h1 { color: #58a6ff; margin-bottom: 0.5rem; }
        .subtitle { color: #8b949e; margin-bottom: 2rem; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
        .stat { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 1rem; text-align: center; }
        .stat-value { font-size: 2rem; font-weight: bold; }
        .stat-label { color: #8b949e; font-size: 0.875rem; }
        .critical .stat-value { color: #f85149; }
        .high .stat-value { color: #f85149; }
        .medium .stat-value { color: #d29922; }
        .low .stat-value { color: #58a6ff; }
        .ok .stat-value { color: #3fb950; }
        table { width: 100%; border-collapse: collapse; background: #161b22; border: 1px solid #30363d; border-radius: 6px; overflow: hidden; }
        th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid #30363d; }
        th { background: #21262d; color: #c9d1d9; font-weight: 600; }
        tr:hover { background: #21262d; }
        .severity { padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
        .severity.critical { background: #f8514933; color: #f85149; }
        .severity.high { background: #f8514933; color: #f85149; }
        .severity.medium { background: #d2992233; color: #d29922; }
        .severity.low { background: #58a6ff33; color: #58a6ff; }
        .severity.info { background: #8b949e33; color: #8b949e; }
        .severity.ok { background: #3fb95033; color: #3fb950; }
        .vuln-details { font-size: 0.875rem; color: #8b949e; margin-top: 0.5rem; }
        .vuln-type { color: #f0883e; font-weight: 500; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Authopsy Scan Report</h1>
        <p class="subtitle">Generated: {{ scan_time }}</p>

        <div class="summary">
            <div class="stat">
                <div class="stat-value">{{ total_endpoints }}</div>
                <div class="stat-label">Endpoints</div>
            </div>
            <div class="stat critical">
                <div class="stat-value">{{ critical_count }}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat high">
                <div class="stat-value">{{ high_count }}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat medium">
                <div class="stat-value">{{ medium_count }}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat low">
                <div class="stat-value">{{ low_count }}</div>
                <div class="stat-label">Low</div>
            </div>
            <div class="stat ok">
                <div class="stat-value">{{ ok_count }}</div>
                <div class="stat-label">OK</div>
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>Endpoint</th>
                    <th>Admin</th>
                    <th>User</th>
                    <th>Anon</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {% for row in rows %}
                <tr>
                    <td>
                        {{ row.endpoint }}
                        {% if row.vulnerabilities %}
                        <div class="vuln-details">
                            {% for vuln in row.vulnerabilities %}
                            <div><span class="vuln-type">{{ vuln.vuln_type }}:</span> {{ vuln.description }}</div>
                            {% endfor %}
                        </div>
                        {% endif %}
                    </td>
                    <td>{{ row.admin_status }}</td>
                    <td>{{ row.user_status }}</td>
                    <td>{{ row.anon_status }}</td>
                    <td><span class="severity {{ row.severity_class }}">{{ row.severity }}</span></td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</body>
</html>"#.to_string()
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ExportData {
    scan_time: String,
    results: Vec<ScanResult>,
    summary: ScanSummary,
}

#[derive(serde::Serialize)]
struct HtmlRow {
    endpoint: String,
    admin_status: String,
    user_status: String,
    anon_status: String,
    severity: String,
    severity_class: String,
    vulnerabilities: Vec<VulnRow>,
}

#[derive(serde::Serialize)]
struct VulnRow {
    vuln_type: String,
    description: String,
    evidence: String,
}
