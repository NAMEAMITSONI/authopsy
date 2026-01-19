use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "authopsy")]
#[command(version, about = "High-performance RBAC vulnerability scanner")]
#[command(propagate_version = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    Scan {
        #[arg(short, long)]
        url: String,

        #[arg(short, long)]
        spec: Option<String>,

        #[arg(short, long)]
        endpoints: Option<String>,

        #[arg(long)]
        admin: String,

        #[arg(long)]
        user: String,

        #[arg(long, default_value = "true")]
        anon: bool,

        #[arg(long, default_value = "Authorization")]
        header: String,

        #[arg(short, long, default_value = "50")]
        concurrency: usize,

        #[arg(short, long, default_value = "10")]
        timeout: u64,

        #[arg(short, long)]
        output: Option<String>,

        #[arg(long)]
        ignore: Option<String>,

        #[arg(short, long)]
        verbose: bool,

        #[arg(short, long)]
        params: Option<String>,

        #[arg(short, long)]
        bodies: Option<String>,

        #[arg(long)]
        skip_paths: Option<String>,

        #[arg(long)]
        public_paths: Option<String>,
    },

    Report {
        #[arg(short, long)]
        input: String,

        #[arg(short, long, default_value = "html")]
        format: String,

        #[arg(short, long)]
        output: Option<String>,
    },

    Parse {
        #[arg(short, long)]
        spec: String,
    },

    Fuzz {
        #[arg(short, long)]
        url: String,

        #[arg(short, long)]
        spec: Option<String>,

        #[arg(short, long)]
        endpoints: Option<String>,

        #[arg(long)]
        user: String,

        #[arg(long, default_value = "Authorization")]
        header: String,

        #[arg(short, long, default_value = "20")]
        concurrency: usize,

        #[arg(short, long, default_value = "10")]
        timeout: u64,

        #[arg(short, long)]
        params: Option<String>,

        #[arg(short, long)]
        verbose: bool,
    },
}
