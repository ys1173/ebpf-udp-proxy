//! Prometheus metrics endpoint.
//!
//! Exposes packet counters and health status in Prometheus exposition format
//! via a lightweight HTTP server. Reads stats from eBPF per-CPU maps and
//! userspace atomic counters.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{extract::State, response::IntoResponse, routing::get, Router};
use tokio::sync::Mutex;
use tracing::info;

use crate::config::MetricsConfig;
use crate::ebpf_manager::EbpfManager;
use crate::userspace::UserspaceStats;

// ---------------------------------------------------------------------------
// Metrics State
// ---------------------------------------------------------------------------

/// Shared state for the metrics endpoint.
#[derive(Clone)]
pub struct MetricsState {
    /// eBPF manager for reading per-CPU stats maps.
    pub ebpf_manager: Arc<Mutex<Option<EbpfManager>>>,
    /// Userspace forwarding stats (one per listener in userspace mode).
    pub userspace_stats: Arc<Vec<(String, Arc<UserspaceStats>)>>,
    /// Number of eBPF-mode listeners (for iterating stats maps).
    pub num_ebpf_listeners: u32,
    /// Listener names for eBPF-mode listeners (indexed by listener_id).
    pub ebpf_listener_names: Arc<Vec<String>>,
}

// ---------------------------------------------------------------------------
// HTTP Server
// ---------------------------------------------------------------------------

/// Start the Prometheus metrics HTTP server.
pub async fn serve_metrics(config: &MetricsConfig, state: MetricsState) -> Result<()> {
    let app = Router::new()
        .route(&config.path, get(metrics_handler))
        .route("/healthz", get(|| async { "ok" }))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(config.bind)
        .await
        .with_context(|| format!("binding metrics server to {}", config.bind))?;

    info!(bind = %config.bind, path = %config.path, "metrics server started");

    axum::serve(listener, app)
        .await
        .context("metrics server error")?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Metrics Handler
// ---------------------------------------------------------------------------

async fn metrics_handler(State(state): State<MetricsState>) -> impl IntoResponse {
    let mut output = String::with_capacity(4096);

    // --- Header comments ---
    output.push_str("# HELP udp_fanout_packets_received_total Total UDP packets received\n");
    output.push_str("# TYPE udp_fanout_packets_received_total counter\n");
    output.push_str("# HELP udp_fanout_packets_forwarded_total Total UDP packets forwarded\n");
    output.push_str("# TYPE udp_fanout_packets_forwarded_total counter\n");
    output.push_str("# HELP udp_fanout_packets_dropped_total Total UDP packets dropped\n");
    output.push_str("# TYPE udp_fanout_packets_dropped_total counter\n");
    output.push_str(
        "# HELP udp_fanout_packets_no_healthy_total Total UDP packets dropped due to no ready downstreams\n",
    );
    output.push_str("# TYPE udp_fanout_packets_no_healthy_total counter\n");
    output.push_str("# HELP udp_fanout_bytes_received_total Total bytes received\n");
    output.push_str("# TYPE udp_fanout_bytes_received_total counter\n");
    output.push_str("# HELP udp_fanout_bytes_forwarded_total Total bytes forwarded\n");
    output.push_str("# TYPE udp_fanout_bytes_forwarded_total counter\n");

    // --- eBPF-mode listener stats ---
    if let Some(ref mgr) = *state.ebpf_manager.lock().await {
        for listener_id in 0..state.num_ebpf_listeners {
            let name = state
                .ebpf_listener_names
                .get(listener_id as usize)
                .map(|s| s.as_str())
                .unwrap_or("unknown");

            match mgr.read_stats(listener_id) {
                Ok(stats) => {
                    write_metric(
                        &mut output,
                        "udp_fanout_packets_received_total",
                        name,
                        "tc_ebpf",
                        stats.pkts_received,
                    );
                    write_metric(
                        &mut output,
                        "udp_fanout_packets_forwarded_total",
                        name,
                        "tc_ebpf",
                        stats.pkts_forwarded,
                    );
                    write_metric(
                        &mut output,
                        "udp_fanout_packets_dropped_total",
                        name,
                        "tc_ebpf",
                        stats.pkts_dropped,
                    );
                    write_metric(
                        &mut output,
                        "udp_fanout_bytes_received_total",
                        name,
                        "tc_ebpf",
                        stats.bytes_received,
                    );
                    write_metric(
                        &mut output,
                        "udp_fanout_bytes_forwarded_total",
                        name,
                        "tc_ebpf",
                        stats.bytes_forwarded,
                    );
                }
                Err(e) => {
                    output.push_str(&format!(
                        "# ERROR reading eBPF stats for listener {}: {}\n",
                        name, e
                    ));
                }
            }
        }
    }

    // --- Userspace-mode listener stats ---
    for (name, stats) in state.userspace_stats.iter() {
        use std::sync::atomic::Ordering::Relaxed;
        write_metric(
            &mut output,
            "udp_fanout_packets_received_total",
            name,
            "userspace",
            stats.pkts_received.load(Relaxed),
        );
        write_metric(
            &mut output,
            "udp_fanout_packets_forwarded_total",
            name,
            "userspace",
            stats.pkts_forwarded.load(Relaxed),
        );
        write_metric(
            &mut output,
            "udp_fanout_packets_dropped_total",
            name,
            "userspace",
            stats.pkts_dropped.load(Relaxed),
        );
        write_metric(
            &mut output,
            "udp_fanout_packets_no_healthy_total",
            name,
            "userspace",
            stats.pkts_no_healthy.load(Relaxed),
        );
        write_metric(
            &mut output,
            "udp_fanout_bytes_received_total",
            name,
            "userspace",
            stats.bytes_received.load(Relaxed),
        );
        write_metric(
            &mut output,
            "udp_fanout_bytes_forwarded_total",
            name,
            "userspace",
            stats.bytes_forwarded.load(Relaxed),
        );
    }

    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        output,
    )
}

fn write_metric(output: &mut String, metric: &str, listener: &str, mode: &str, value: u64) {
    output.push_str(&format!(
        "{}{{listener=\"{}\",mode=\"{}\"}} {}\n",
        metric, listener, mode, value
    ));
}
