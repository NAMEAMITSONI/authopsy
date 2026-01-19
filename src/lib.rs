pub mod analyzer;
pub mod cli;
pub mod fuzzer;
pub mod http;
pub mod models;
pub mod reporter;
pub mod scanner;

pub use analyzer::VulnerabilityDetector;
pub use fuzzer::{HeaderFuzzer, ParamFuzzer};
pub use models::{
    Endpoint, HttpMethod, Role, RoleConfig, ScanResult, Severity, VulnType, Vulnerability,
};
pub use reporter::{ConsoleReporter, HtmlExporter, JsonExporter};
pub use scanner::{FuzzerScanner, Scanner};
