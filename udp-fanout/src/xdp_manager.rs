//! XDP program lifecycle manager for AF_XDP mode.
//!
//! Loads the XDP eBPF program, attaches it to the network interface,
//! populates the XSKMAP and port filter maps, and handles cleanup.
//!
//! This is separate from `ebpf_manager.rs` (which manages TC programs)
//! because XDP and TC are fundamentally different attachment points.

use std::os::fd::RawFd;

use anyhow::{Context, Result};
use aya::maps::{HashMap, XskMap};
use aya::programs::{Xdp, XdpFlags};
use aya::Ebpf;
use tracing::{debug, info, warn};

use crate::config::ListenerConfig;

// ---------------------------------------------------------------------------
// Public Interface
// ---------------------------------------------------------------------------

/// Manages the lifecycle of XDP programs and maps for AF_XDP-mode listeners.
pub struct XdpManager {
    bpf: Ebpf,
    attached_interface: Option<String>,
}

impl XdpManager {
    /// Load the XDP eBPF program from the ELF binary.
    pub fn load(ebpf_bytes: &[u8]) -> Result<Self> {
        let mut bpf = Ebpf::load(ebpf_bytes).context("loading XDP eBPF program")?;

        // Initialize aya-log if available
        if let Err(e) = aya_log::EbpfLogger::init(&mut bpf) {
            warn!("XDP eBPF logging not available: {}", e);
        }

        Ok(Self {
            bpf,
            attached_interface: None,
        })
    }

    /// Attach the XDP program to a network interface.
    ///
    /// Tries native (driver) mode first, falls back to SKB (generic) mode.
    pub fn attach(&mut self, iface: &str) -> Result<()> {
        let program: &mut Xdp = self
            .bpf
            .program_mut("xdp_redirect_afxdp")
            .context("XDP program 'xdp_redirect_afxdp' not found")?
            .try_into()
            .context("program type mismatch (expected Xdp)")?;

        program.load().context("loading XDP program")?;

        // Try native mode first (best performance), fall back to SKB mode
        match program.attach(iface, XdpFlags::default()) {
            Ok(_link_id) => {
                info!(interface = iface, mode = "native", "attached XDP program");
            }
            Err(native_err) => {
                warn!(
                    interface = iface,
                    error = %native_err,
                    "native XDP attach failed, trying SKB mode"
                );
                program
                    .attach(iface, XdpFlags::SKB_MODE)
                    .with_context(|| {
                        format!(
                            "attaching XDP to {} (both native and SKB failed; native error: {})",
                            iface, native_err
                        )
                    })?;
                info!(interface = iface, mode = "skb", "attached XDP program");
            }
        }

        self.attached_interface = Some(iface.to_string());
        Ok(())
    }

    /// Register a port in the XDP port filter map.
    ///
    /// Packets with this UDP destination port will be redirected to AF_XDP.
    /// All other traffic passes through to the kernel (XDP_PASS).
    pub fn register_port(&mut self, port: u16) -> Result<()> {
        let mut port_map: HashMap<_, u16, u8> = self
            .bpf
            .map_mut("XDP_PORTS")
            .context("XDP_PORTS map not found")?
            .try_into()
            .context("XDP_PORTS map type mismatch")?;

        // Store port in network byte order for direct comparison in eBPF
        let port_be = port.to_be();
        port_map
            .insert(port_be, 1u8, 0)
            .context("inserting port into XDP_PORTS")?;

        info!(port, "registered port in XDP filter");
        Ok(())
    }

    /// Register an AF_XDP socket fd in the XSKMAP.
    ///
    /// The XDP program will redirect matching packets to this socket.
    /// `queue_id` is the RX queue index.
    pub fn register_xsk_socket(&mut self, queue_id: u32, xsk_fd: RawFd) -> Result<()> {
        let mut xsk_map: XskMap<_> = self
            .bpf
            .map_mut("XSKMAP")
            .context("XSKMAP map not found")?
            .try_into()
            .context("XSKMAP map type mismatch")?;

        xsk_map
            .set(queue_id, xsk_fd, 0)
            .context("registering AF_XDP socket in XSKMAP")?;

        info!(queue_id, xsk_fd, "registered AF_XDP socket in XSKMAP");
        Ok(())
    }

    /// Set up AF_XDP listeners: register ports and attach XDP program.
    ///
    /// Call this after loading, passing all af_xdp-mode listeners.
    /// The AF_XDP sockets are registered separately via `register_xsk_socket()`
    /// after the forwarders are started (since we need the socket fds).
    pub fn setup_listeners(&mut self, listeners: &[&ListenerConfig]) -> Result<()> {
        if listeners.is_empty() {
            return Ok(());
        }

        // Register all ports
        for listener in listeners {
            let port = listener.bind.port();
            self.register_port(port)
                .with_context(|| format!("registering port for listener '{}'", listener.name))?;
        }

        // Attach to the interface (all AF_XDP listeners must use the same interface)
        let iface = listeners[0]
            .interface
            .as_deref()
            .expect("interface required for af_xdp mode");

        // Validate all listeners use the same interface
        for listener in &listeners[1..] {
            let li = listener
                .interface
                .as_deref()
                .expect("interface required for af_xdp mode");
            if li != iface {
                anyhow::bail!(
                    "all af_xdp listeners must use the same interface; '{}' uses '{}' but '{}' uses '{}'",
                    listeners[0].name,
                    iface,
                    listener.name,
                    li
                );
            }
        }

        self.attach(iface)
            .with_context(|| format!("attaching XDP to {}", iface))?;

        Ok(())
    }

    /// Get the interface index for the attached interface.
    pub fn attached_ifindex(&self) -> Result<u32> {
        let iface = self
            .attached_interface
            .as_deref()
            .context("no interface attached")?;
        interface_index(iface)
    }

    /// Detach the XDP program and clean up.
    pub fn detach(self) -> Result<()> {
        if let Some(ref iface) = self.attached_interface {
            info!(interface = %iface, "detaching XDP program");
            // aya handles detachment when the Ebpf/Xdp objects are dropped,
            // but we log it explicitly.
        }
        // The Ebpf object is dropped here, which detaches the program.
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
