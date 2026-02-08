//! udp-fanout: Lightweight high-performance UDP fanout proxy.
//!
//! Replicates incoming UDP datagrams to multiple downstream receivers using
//! three forwarding paths:
//!   - tc_ebpf:   kernel-only forwarding via TC eBPF + bpf_redirect_neigh (fastest)
//!   - af_xdp:    zero-copy receive via AF_XDP + userspace sendto (MetalLB compatible)
//!   - userspace: pure userspace with recvmmsg/sendmmsg batching (portable fallback)
//!
//! Designed for market data distribution, telemetry replication, and similar
//! high-throughput UDP forwarding workloads.

mod af_xdp;
mod config;
mod ebpf_manager;
mod health;
mod kubernetes;
mod metrics;
mod userspace;
mod xdp_manager;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::signal;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use af_xdp::AfXdpForwarder;
use config::{Config, ForwardingMode};
use ebpf_manager::EbpfManager;
use metrics::MetricsState;
use userspace::UserspaceForwarder;
use xdp_manager::XdpManager;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "udp-fanout",
    about = "Lightweight high-performance UDP fanout proxy with eBPF kernel bypass",
    version
)]
struct Cli {
    /// Path to the YAML configuration file.
    #[arg(short, long, default_value = "config.yaml")]
    config: PathBuf,

    /// Log level (trace, debug, info, warn, error).
    #[arg(short, long, default_value = "info")]
    log_level: String,

    /// Path to the compiled TC eBPF program ELF binary.
    /// Required when using tc_ebpf mode.
    #[arg(long, default_value = "udp-fanout-ebpf")]
    ebpf_program: PathBuf,

    /// Path to the compiled XDP eBPF program ELF binary.
    /// Required when using af_xdp mode.
    #[arg(long, default_value = "udp-fanout-ebpf-xdp")]
    xdp_program: PathBuf,
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing/logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&cli.log_level)),
        )
        .with_target(false)
        .with_timer(tracing_subscriber::fmt::time::uptime())
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        config = %cli.config.display(),
        "starting udp-fanout"
    );

    // Load and validate config
    let config = Config::load(&cli.config).context("loading configuration")?;
    info!(listeners = config.listeners.len(), "configuration loaded");

    // Separate listeners by mode
    let ebpf_listeners: Vec<&_> = config
        .listeners
        .iter()
        .filter(|l| l.mode == ForwardingMode::TcEbpf)
        .collect();

    let afxdp_listeners: Vec<&_> = config
        .listeners
        .iter()
        .filter(|l| l.mode == ForwardingMode::AfXdp)
        .collect();

    let userspace_listeners: Vec<&_> = config
        .listeners
        .iter()
        .filter(|l| l.mode == ForwardingMode::Userspace)
        .collect();

    info!(
        tc_ebpf = ebpf_listeners.len(),
        af_xdp = afxdp_listeners.len(),
        userspace = userspace_listeners.len(),
        "configured listeners by mode"
    );

    // --- Initialize TC eBPF manager ---
    let ebpf_manager: Arc<Mutex<Option<EbpfManager>>> = Arc::new(Mutex::new(None));
    let mut tc_k8s_tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    if !ebpf_listeners.is_empty() {
        let ebpf_bytes = std::fs::read(&cli.ebpf_program).with_context(|| {
            format!(
                "reading TC eBPF program from {}. Build it with: cargo xtask build-ebpf",
                cli.ebpf_program.display()
            )
        })?;

        let mut mgr = EbpfManager::load(&ebpf_bytes).context("loading TC eBPF program")?;

        mgr.setup_listeners(&ebpf_listeners)
            .context("setting up TC eBPF listeners")?;

        *ebpf_manager.lock().await = Some(mgr);

        info!(
            listeners = ebpf_listeners.len(),
            "TC eBPF fast path initialized"
        );

        // Spawn Kubernetes EndpointSlice watchers for tc_ebpf listeners that use discovery.
        for (listener_id, listener) in ebpf_listeners.iter().enumerate() {
            if let Some(k8s_cfg) = listener.kubernetes.clone() {
                tc_k8s_tasks.push(kubernetes::spawn_endpointslice_watcher_tc_ebpf(
                    listener.name.clone(),
                    k8s_cfg,
                    listener_id as u32,
                    ebpf_manager.clone(),
                ));
            }
        }
    }

    // --- Initialize AF_XDP ---
    let mut afxdp_forwarders: Vec<AfXdpForwarder> = Vec::new();
    let mut afxdp_stats_vec: Vec<(String, Arc<af_xdp::AfXdpStats>)> = Vec::new();
    let mut xdp_mgr: Option<XdpManager> = None;

    if !afxdp_listeners.is_empty() {
        let xdp_bytes = std::fs::read(&cli.xdp_program).with_context(|| {
            format!(
                "reading XDP eBPF program from {}. Build it with: cargo xtask build-ebpf-xdp",
                cli.xdp_program.display()
            )
        })?;

        let mut mgr = XdpManager::load(&xdp_bytes).context("loading XDP eBPF program")?;

        mgr.setup_listeners(&afxdp_listeners)
            .context("setting up XDP listeners")?;

        let ifindex = mgr
            .attached_ifindex()
            .context("getting attached interface index")?;

        // Start AF_XDP forwarders
        for (i, listener) in afxdp_listeners.iter().enumerate() {
            let queue_id = i as u32; // Each listener binds to a different RX queue

            let forwarder = AfXdpForwarder::start(listener, ifindex, queue_id)
                .with_context(|| {
                    format!("starting AF_XDP forwarder for '{}'", listener.name)
                })?;

            // Register the AF_XDP socket fd in the XSKMAP
            mgr.register_xsk_socket(queue_id, forwarder.xsk_fd)
                .with_context(|| {
                    format!(
                        "registering XSK socket for '{}' (queue {})",
                        listener.name, queue_id
                    )
                })?;

            afxdp_stats_vec.push((listener.name.clone(), forwarder.stats.clone()));
            afxdp_forwarders.push(forwarder);
        }

        info!(
            listeners = afxdp_listeners.len(),
            "AF_XDP path initialized"
        );

        xdp_mgr = Some(mgr);
    }

    // --- Start userspace forwarders ---
    let mut userspace_forwarders: Vec<UserspaceForwarder> = Vec::new();
    let mut userspace_stats_vec: Vec<(String, Arc<userspace::UserspaceStats>)> = Vec::new();

    for listener in &userspace_listeners {
        let forwarder = UserspaceForwarder::start(listener)
            .with_context(|| format!("starting userspace forwarder for '{}'", listener.name))?;

        userspace_stats_vec.push((listener.name.clone(), forwarder.stats.clone()));
        userspace_forwarders.push(forwarder);
    }

    // --- Start health checker ---
    let health_handle = if config.health.enabled {
        let all_listeners: Vec<&_> = config.listeners.iter().collect();
        Some(health::spawn_health_checker(
            &config.health,
            &all_listeners,
            ebpf_manager.clone(),
        ))
    } else {
        None
    };

    // --- Start metrics server ---
    let metrics_handle = if config.metrics.enabled {
        let state = MetricsState {
            ebpf_manager: ebpf_manager.clone(),
            userspace_stats: Arc::new(userspace_stats_vec),
            afxdp_stats: Arc::new(afxdp_stats_vec),
            num_ebpf_listeners: ebpf_listeners.len() as u32,
            ebpf_listener_names: Arc::new(
                ebpf_listeners.iter().map(|l| l.name.clone()).collect(),
            ),
        };

        let metrics_config = config.metrics;
        Some(tokio::spawn(async move {
            if let Err(e) = metrics::serve_metrics(&metrics_config, state).await {
                error!(error = %e, "metrics server error");
            }
        }))
    } else {
        None
    };

    // --- Wait for shutdown signal ---
    info!("udp-fanout is running. Press Ctrl+C to stop.");

    shutdown_signal().await;

    info!("shutdown signal received, cleaning up...");

    // --- Graceful shutdown ---

    // Stop health checker
    if let Some(handle) = health_handle {
        handle.abort();
    }

    // Stop metrics server
    if let Some(handle) = metrics_handle {
        handle.abort();
    }

    // Stop userspace forwarders
    for forwarder in userspace_forwarders {
        forwarder.shutdown();
    }

    // Stop AF_XDP forwarders
    for forwarder in afxdp_forwarders {
        forwarder.shutdown();
    }

    // Stop tc_ebpf k8s watchers
    for handle in tc_k8s_tasks {
        handle.abort();
    }

    // Detach XDP program
    if let Some(mgr) = xdp_mgr {
        if let Err(e) = mgr.detach() {
            warn!(error = %e, "error detaching XDP program");
        }
    }

    // Detach TC eBPF programs
    if let Some(mgr) = ebpf_manager.lock().await.take() {
        if let Err(e) = mgr.detach() {
            warn!(error = %e, "error detaching TC eBPF programs");
        }
    }

    info!("udp-fanout stopped");
    Ok(())
}

// ---------------------------------------------------------------------------
// Signal Handling
// ---------------------------------------------------------------------------

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => info!("received Ctrl+C"),
        _ = terminate => info!("received SIGTERM"),
    }
}
