//! Downstream health checking.
//!
//! Periodically probes downstream receivers and disables/enables them in the
//! eBPF maps based on reachability. Supports ICMP ping and UDP echo probes.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use crate::config::{HealthConfig, HealthProtocol, ListenerConfig};
use crate::ebpf_manager::EbpfManager;

// ---------------------------------------------------------------------------
// Public Interface
// ---------------------------------------------------------------------------

/// Tracks health state for all downstream receivers.
#[derive(Debug, Clone, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Unhealthy { consecutive_failures: u32 },
    Unknown,
}

/// Entry for a monitored downstream.
struct MonitoredDownstream {
    listener_id: u32,
    downstream_idx: u32,
    name: String,
    address: SocketAddr,
    status: HealthStatus,
}

/// Run the health checker loop as a tokio task.
///
/// Returns a JoinHandle that can be aborted on shutdown.
pub fn spawn_health_checker(
    config: &HealthConfig,
    listeners: &[&ListenerConfig],
    ebpf_manager: Arc<Mutex<Option<EbpfManager>>>,
) -> tokio::task::JoinHandle<()> {
    let interval = config.interval();
    let timeout = config.timeout();
    let protocol = config.protocol.clone();

    // Build list of all downstreams to monitor
    let mut targets: Vec<MonitoredDownstream> = Vec::new();
    for (listener_id, listener) in listeners.iter().enumerate() {
        for (ds_idx, ds) in listener.downstream.iter().enumerate() {
            targets.push(MonitoredDownstream {
                listener_id: listener_id as u32,
                downstream_idx: ds_idx as u32,
                name: ds.name.clone(),
                address: ds.address,
                status: HealthStatus::Unknown,
            });
        }
    }

    let total = targets.len();
    info!(
        targets = total,
        interval = ?interval,
        timeout = ?timeout,
        protocol = ?protocol,
        "starting health checker"
    );

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);

        loop {
            ticker.tick().await;

            for target in targets.iter_mut() {
                let healthy = match protocol {
                    HealthProtocol::Icmp => check_icmp(target.address, timeout).await,
                    HealthProtocol::UdpEcho => check_udp_echo(target.address, timeout).await,
                };

                let prev_status = target.status.clone();

                match healthy {
                    Ok(true) => {
                        if target.status != HealthStatus::Healthy {
                            info!(
                                downstream = %target.name,
                                address = %target.address,
                                "downstream is healthy"
                            );
                            target.status = HealthStatus::Healthy;

                            // Re-enable in eBPF map
                            if let Some(ref mut mgr) =
                                *ebpf_manager.lock().await
                            {
                                if let Err(e) = mgr.set_downstream_active(
                                    target.listener_id,
                                    target.downstream_idx,
                                    true,
                                ) {
                                    error!(
                                        error = %e,
                                        "failed to re-enable downstream in eBPF map"
                                    );
                                }
                            }
                        }
                    }
                    Ok(false) | Err(_) => {
                        let failures = match &target.status {
                            HealthStatus::Unhealthy {
                                consecutive_failures,
                            } => consecutive_failures + 1,
                            _ => 1,
                        };

                        target.status = HealthStatus::Unhealthy {
                            consecutive_failures: failures,
                        };

                        // Disable after 3 consecutive failures
                        if failures == 3 {
                            warn!(
                                downstream = %target.name,
                                address = %target.address,
                                failures,
                                "downstream marked unhealthy, disabling"
                            );

                            if let Some(ref mut mgr) =
                                *ebpf_manager.lock().await
                            {
                                if let Err(e) = mgr.set_downstream_active(
                                    target.listener_id,
                                    target.downstream_idx,
                                    false,
                                ) {
                                    error!(
                                        error = %e,
                                        "failed to disable downstream in eBPF map"
                                    );
                                }
                            }
                        } else if failures > 3 {
                            debug!(
                                downstream = %target.name,
                                failures,
                                "downstream still unhealthy"
                            );
                        }
                    }
                }
            }
        }
    })
}

// ---------------------------------------------------------------------------
// Probe Implementations
// ---------------------------------------------------------------------------

/// ICMP ping probe. Returns true if the host is reachable.
async fn check_icmp(addr: SocketAddr, timeout: Duration) -> Result<bool> {
    // Use tokio::process to run a quick ping
    // This avoids needing raw socket privileges for ICMP in userspace
    let ip = addr.ip().to_string();

    let output = tokio::process::Command::new("ping")
        .args(["-c", "1", "-W", &timeout.as_secs().max(1).to_string(), &ip])
        .output()
        .await
        .context("running ping")?;

    Ok(output.status.success())
}

/// UDP echo probe. Sends a small payload and waits for a response.
async fn check_udp_echo(addr: SocketAddr, timeout: Duration) -> Result<bool> {
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
        .await
        .context("binding probe socket")?;

    let probe_data = b"udp-fanout-health-probe";

    socket
        .send_to(probe_data, addr)
        .await
        .context("sending probe")?;

    let mut buf = [0u8; 64];

    match tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await {
        Ok(Ok((len, _from))) => Ok(len > 0),
        Ok(Err(e)) => {
            debug!(error = %e, "UDP echo probe recv error");
            Ok(false)
        }
        Err(_) => {
            debug!(address = %addr, "UDP echo probe timeout");
            Ok(false)
        }
    }
}
