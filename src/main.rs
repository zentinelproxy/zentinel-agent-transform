//! Zentinel Transform Agent CLI entry point.
//!
//! Request/Response transformation agent for Zentinel proxy using v2 protocol.

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};
use zentinel_agent_protocol::v2::{GrpcAgentServerV2, UdsAgentServerV2};
use zentinel_agent_transform::{TransformAgent, TransformConfig};

#[derive(Parser, Debug)]
#[command(name = "zentinel-transform-agent")]
#[command(
    author,
    version,
    about = "Request/Response transformation agent for Zentinel"
)]
struct Args {
    /// Configuration file path (YAML or JSON)
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Template directory path. Overrides `settings.template_dir` from the
    /// configuration file (default `/etc/zentinel/templates`).
    #[arg(long)]
    template_dir: Option<PathBuf>,

    /// Unix socket to listen on (agent protocol v2 over UDS). Used unless
    /// `--grpc-address` is given.
    #[arg(
        short,
        long,
        default_value = "/tmp/zentinel-transform.sock",
        env = "TRANSFORM_SOCKET"
    )]
    socket: PathBuf,

    /// gRPC address to listen on (e.g. "127.0.0.1:50051"). When given, the
    /// agent serves agent protocol v2 over gRPC instead of the Unix socket.
    #[arg(long, env = "TRANSFORM_GRPC_ADDRESS")]
    grpc_address: Option<String>,

    /// Output logs as JSON
    #[arg(long)]
    json_logs: bool,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Print example configuration and exit.
    #[arg(long)]
    example_config: bool,

    /// Validate configuration and exit.
    #[arg(long)]
    validate: bool,
}

fn print_example_config() {
    let example = r#"# Transform Agent Configuration Example
version: "1"

settings:
  # Maximum body size to buffer for transformation (bytes)
  max_body_size: 10485760  # 10MB
  # Template directory path
  template_dir: "/etc/zentinel/templates"
  # Enable template caching
  cache_templates: true
  # Enable debug headers (X-Transform-Rule, X-Transform-Time)
  debug_headers: false
  # Default timeout for transformations (ms)
  timeout_ms: 100

rules:
  # API v1 to v2 rewrite example
  - name: "api-v1-rewrite"
    description: "Rewrite API v1 paths to v2"
    enabled: true
    priority: 100
    match:
      path:
        pattern: "^/api/v1/(.*)$"
        type: regex
    request:
      url:
        rewrite: "/api/v2/${1}"
        preserve_query: true

  # Add CORS headers example
  - name: "add-cors-headers"
    description: "Add CORS headers to responses"
    enabled: true
    priority: 50
    match:
      path:
        pattern: "^/api/.*"
        type: regex
    response:
      headers:
        set:
          - name: "Access-Control-Allow-Origin"
            value: "*"
          - name: "Access-Control-Allow-Methods"
            value: "GET, POST, PUT, DELETE, OPTIONS"
"#;
    println!("{}", example);
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&args.log_level));

    if args.json_logs {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().json())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer())
            .init();
    }

    // Print example config if requested
    if args.example_config {
        print_example_config();
        return Ok(());
    }

    // Load configuration
    let mut config = if let Some(config_path) = &args.config {
        let content = std::fs::read_to_string(config_path)
            .with_context(|| format!("Failed to read config file: {}", config_path.display()))?;
        if config_path
            .extension()
            .is_some_and(|e| e == "yaml" || e == "yml")
        {
            serde_yaml::from_str(&content)?
        } else {
            serde_json::from_str(&content)?
        }
    } else {
        TransformConfig::default()
    };

    // Override template directory from CLI
    if let Some(dir) = &args.template_dir {
        config.settings.template_dir = dir.to_string_lossy().to_string();
    }

    // Validate only if requested
    if args.validate {
        // Create agent to validate configuration
        let _agent = TransformAgent::new(config)?;
        info!("Configuration is valid");
        return Ok(());
    }

    // Create agent
    let agent = TransformAgent::new(config)?;

    info!("Transform agent initialized");

    if let Some(grpc_addr) = args.grpc_address {
        let addr = grpc_addr
            .parse()
            .context("Invalid gRPC address format (expected host:port)")?;
        info!(
            config = ?args.config,
            grpc_address = %grpc_addr,
            "Listening on gRPC (agent protocol v2)"
        );
        GrpcAgentServerV2::new("transform", Box::new(agent))
            .run(addr)
            .await
            .context("Failed to run Transform Agent gRPC server")?;
    } else {
        info!(
            config = ?args.config,
            socket = %args.socket.display(),
            "Listening on Unix socket (agent protocol v2)"
        );
        UdsAgentServerV2::new("transform", args.socket, Box::new(agent))
            .run()
            .await
            .context("Failed to run Transform Agent UDS server")?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_names_the_binary() {
        let err = Args::try_parse_from(["x", "--version"]).unwrap_err();
        assert_eq!(
            err.to_string().trim(),
            format!("zentinel-transform-agent {}", env!("CARGO_PKG_VERSION"))
        );
    }

    #[test]
    fn defaults_to_the_unix_socket() {
        let args = Args::try_parse_from(["x"]).unwrap();
        assert!(args.grpc_address.is_none());
        assert_eq!(args.socket, PathBuf::from("/tmp/zentinel-transform.sock"));
        assert!(args.template_dir.is_none());
    }
}
