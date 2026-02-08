//! eBPF program lifecycle manager.
//!
//! Loads the compiled TC eBPF program, attaches it to the network interface,
//! and populates eBPF maps from the YAML configuration. Handles cleanup on
//! shutdown (detach programs, remove qdiscs).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use aya::maps::{Array, HashMap, PerCpuArray, PerCpuValues};
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::Ebpf;
use tracing::{debug, error, info, warn};

use crate::config::ListenerConfig;
use udp_fanout_common::*;

// ---------------------------------------------------------------------------
// Public Interface
// ---------------------------------------------------------------------------

/// Aggregated stats read from eBPF per-CPU counters.
#[derive(Debug, Default, Clone)]
pub struct EbpfAggregatedStats {
    pub pkts_received: u64,
    pub pkts_forwarded: u64,
    pub pkts_dropped: u64,
    pub bytes_received: u64,
    pub bytes_forwarded: u64,
}

/// Manages the lifecycle of eBPF programs and maps for TC-mode listeners.
pub struct EbpfManager {
    bpf: Ebpf,
    attached_interfaces: Vec<String>,
    num_listeners: u32,
}

impl EbpfManager {
    /// Load the eBPF program from the embedded binary.
    ///
    /// The `ebpf_bytes` argument is the compiled eBPF ELF binary, typically
    /// included via `include_bytes_aligned!` or loaded from a file path.
    pub fn load(ebpf_bytes: &[u8]) -> Result<Self> {
        let mut bpf = Ebpf::load(ebpf_bytes).context("loading eBPF program")?;

        // Initialize aya-log if available (for eBPF-side info!() calls)
        if let Err(e) = aya_log::EbpfLogger::init(&mut bpf) {
            warn!("eBPF logging not available: {}", e);
        }

        Ok(Self {
            bpf,
            attached_interfaces: Vec::new(),
            num_listeners: 0,
        })
    }

    /// Configure maps and attach the TC program for a set of listeners.
    ///
    /// Call this once after loading, passing all tc_ebpf-mode listeners.
    pub fn setup_listeners(&mut self, listeners: &[&ListenerConfig]) -> Result<()> {
        if listeners.is_empty() {
            return Ok(());
        }

        // Populate maps
        for (listener_id, listener) in listeners.iter().enumerate() {
            let listener_id = listener_id as u32;
            self.populate_listener_maps(listener_id, listener)
                .with_context(|| {
                    format!("populating maps for listener '{}'", listener.name)
                })?;
        }
        self.num_listeners = listeners.len() as u32;

        // Attach TC program to each unique interface
        let mut attached = std::collections::HashSet::new();
        for listener in listeners {
            let iface = listener
                .interface
                .as_deref()
                .expect("interface required for tc_ebpf mode");

            if attached.insert(iface.to_string()) {
                self.attach_tc(iface)
                    .with_context(|| format!("attaching TC to {}", iface))?;
            }
        }

        Ok(())
    }

    /// Read aggregated stats for a listener (summed across all CPUs).
    pub fn read_stats(&self, listener_id: u32) -> Result<EbpfAggregatedStats> {
        let stats_map: PerCpuArray<_, StatsEntry> = self
            .bpf
            .map("STATS")
            .context("STATS map not found")?
            .try_into()
            .context("STATS map type mismatch")?;

        let per_cpu = stats_map
            .get(&listener_id, 0)
            .context("reading STATS entry")?;

        let mut agg = EbpfAggregatedStats::default();
        for entry in per_cpu.iter() {
            agg.pkts_received += entry.pkts_received;
            agg.pkts_forwarded += entry.pkts_forwarded;
            agg.pkts_dropped += entry.pkts_dropped;
            agg.bytes_received += entry.bytes_received;
            agg.bytes_forwarded += entry.bytes_forwarded;
        }

        Ok(agg)
    }

    /// Update a downstream entry's active status in the eBPF map.
    ///
    /// Used by health checker to disable/enable downstreams dynamically.
    pub fn set_downstream_active(
        &mut self,
        listener_id: u32,
        downstream_idx: u32,
        active: bool,
    ) -> Result<()> {
        let mut ds_map: Array<_, DownstreamEntry> = self
            .bpf
            .map_mut("DOWNSTREAM_ADDRS")
            .context("DOWNSTREAM_ADDRS map not found")?
            .try_into()
            .context("DOWNSTREAM_ADDRS map type mismatch")?;

        let map_idx = listener_id * MAX_DOWNSTREAM + downstream_idx;
        let mut entry = ds_map
            .get(&map_idx, 0)
            .context("reading downstream entry")?;

        entry.active = if active { 1 } else { 0 };
        ds_map
            .set(map_idx, entry, 0)
            .context("updating downstream entry")?;

        debug!(
            listener_id,
            downstream_idx,
            active,
            "updated downstream active status"
        );

        Ok(())
    }

    /// Detach all TC programs and clean up. Called on shutdown.
    pub fn detach(mut self) -> Result<()> {
        info!("detaching eBPF programs");

        for iface in &self.attached_interfaces {
            if let Err(e) = self.remove_tc_qdisc(iface) {
                warn!(interface = %iface, error = %e, "failed to remove TC qdisc");
            }
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Private: Map Population
    // -----------------------------------------------------------------------

    fn populate_listener_maps(
        &mut self,
        listener_id: u32,
        listener: &ListenerConfig,
    ) -> Result<()> {
        let port = listener.bind.port();
        let iface = listener
            .interface
            .as_deref()
            .expect("interface required for tc_ebpf mode");

        let ifindex = interface_index(iface)?;

        // --- LISTENER_CONFIG: port → listener_id + ifindex ---
        let mut listener_map: HashMap<_, ListenerKey, ListenerValue> = self
            .bpf
            .map_mut("LISTENER_CONFIG")
            .context("LISTENER_CONFIG map not found")?
            .try_into()
            .context("LISTENER_CONFIG map type mismatch")?;

        let key = ListenerKey {
            port: port.to_be(), // Store in network byte order for direct comparison in eBPF
            _pad: 0,
        };
        let value = ListenerValue {
            listener_id,
            ifindex,
        };
        listener_map
            .insert(key, value, 0)
            .context("inserting listener config")?;

        info!(
            listener = %listener.name,
            id = listener_id,
            port = port,
            ifindex = ifindex,
            "registered listener in eBPF map"
        );

        // --- DOWNSTREAM_ADDRS: flat array entries ---
        let mut ds_map: Array<_, DownstreamEntry> = self
            .bpf
            .map_mut("DOWNSTREAM_ADDRS")
            .context("DOWNSTREAM_ADDRS map not found")?
            .try_into()
            .context("DOWNSTREAM_ADDRS map type mismatch")?;

        for (i, ds) in listener.downstream.iter().enumerate() {
            let ip = match ds.address.ip() {
                std::net::IpAddr::V4(v4) => v4,
                _ => bail!("only IPv4 downstreams supported in tc_ebpf mode"),
            };
            let port = ds.address.port();

            let entry = DownstreamEntry {
                dst_ip: u32::from(ip).to_be(), // Network byte order
                dst_port: port.to_be(),         // Network byte order
                active: 1,
                _pad: 0,
            };

            let map_idx = listener_id * MAX_DOWNSTREAM + i as u32;
            ds_map
                .set(map_idx, entry, 0)
                .context("inserting downstream entry")?;

            info!(
                listener = %listener.name,
                downstream = %ds.name,
                address = %ds.address,
                "registered downstream in eBPF map"
            );
        }

        // --- DOWNSTREAM_COUNT ---
        let mut count_map: Array<_, DownstreamCount> = self
            .bpf
            .map_mut("DOWNSTREAM_COUNT")
            .context("DOWNSTREAM_COUNT map not found")?
            .try_into()
            .context("DOWNSTREAM_COUNT map type mismatch")?;

        count_map
            .set(
                listener_id,
                DownstreamCount {
                    count: listener.downstream.len() as u32,
                },
                0,
            )
            .context("inserting downstream count")?;

        Ok(())
    }

    /// Replace the downstream table for a listener with a contiguous list.
    ///
    /// This is intended for Kubernetes EndpointSlice discovery: userspace
    /// maintains the "ready endpoints" set and writes it to the eBPF maps.
    pub fn replace_downstreams(&mut self, listener_id: u32, endpoints: &[SocketAddr]) -> Result<()> {
        if endpoints.len() > MAX_DOWNSTREAM as usize {
            bail!(
                "too many endpoints for listener {}: {} > MAX_DOWNSTREAM ({})",
                listener_id,
                endpoints.len(),
                MAX_DOWNSTREAM
            );
        }

        let mut ds_map: Array<_, DownstreamEntry> = self
            .bpf
            .map_mut("DOWNSTREAM_ADDRS")
            .context("DOWNSTREAM_ADDRS map not found")?
            .try_into()
            .context("DOWNSTREAM_ADDRS map type mismatch")?;

        // Clear all entries first (mark inactive).
        let base = listener_id * MAX_DOWNSTREAM;
        for i in 0..MAX_DOWNSTREAM {
            let idx = base + i;
            let entry = DownstreamEntry {
                dst_ip: 0,
                dst_port: 0,
                active: 0,
                _pad: 0,
            };
            ds_map.set(idx, entry, 0).ok();
        }

        // Write active endpoints contiguously.
        for (i, addr) in endpoints.iter().enumerate() {
            let ip = match addr.ip() {
                std::net::IpAddr::V4(v4) => v4,
                _ => bail!("only IPv4 endpoints supported in tc_ebpf mode"),
            };
            let port = addr.port();
            let entry = DownstreamEntry {
                dst_ip: u32::from(ip).to_be(),
                dst_port: port.to_be(),
                active: 1,
                _pad: 0,
            };
            let idx = base + i as u32;
            ds_map
                .set(idx, entry, 0)
                .with_context(|| format!("updating downstream entry idx={}", idx))?;
        }

        let mut count_map: Array<_, DownstreamCount> = self
            .bpf
            .map_mut("DOWNSTREAM_COUNT")
            .context("DOWNSTREAM_COUNT map not found")?
            .try_into()
            .context("DOWNSTREAM_COUNT map type mismatch")?;

        count_map
            .set(
                listener_id,
                DownstreamCount {
                    count: endpoints.len() as u32,
                },
                0,
            )
            .context("updating downstream count")?;

        info!(
            listener_id,
            endpoints = endpoints.len(),
            "updated tc_ebpf downstream set"
        );

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Private: TC Attachment
    // -----------------------------------------------------------------------

    fn attach_tc(&mut self, iface: &str) -> Result<()> {
        // Add clsact qdisc (required for TC eBPF attachment)
        // This is idempotent — if already exists, it's fine.
        if let Err(e) = tc::qdisc_add_clsact(iface) {
            // EEXIST is fine
            let msg = format!("{}", e);
            if !msg.contains("exist") {
                return Err(e).context("adding clsact qdisc");
            }
        }

        // Load and attach the classifier program to TC ingress
        let program: &mut SchedClassifier = self
            .bpf
            .program_mut("udp_fanout")
            .context("eBPF program 'udp_fanout' not found")?
            .try_into()
            .context("program type mismatch (expected SchedClassifier)")?;

        program.load().context("loading TC program")?;

        program
            .attach(iface, TcAttachType::Ingress)
            .context("attaching to TC ingress")?;

        info!(interface = iface, "attached TC eBPF program to ingress");
        self.attached_interfaces.push(iface.to_string());

        Ok(())
    }

    fn remove_tc_qdisc(&self, iface: &str) -> Result<()> {
        // Best-effort removal of the clsact qdisc
        // This will also detach all TC programs on this interface
        tc::qdisc_detach_program(iface, TcAttachType::Ingress, "udp_fanout")
            .context("detaching TC program")?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Get the interface index for a network interface name.
fn interface_index(iface: &str) -> Result<u32> {
    let idx = nix::net::if_::if_nametoindex(iface)
        .with_context(|| format!("interface '{}' not found", iface))?;
    Ok(idx)
}
