//! Shared types between the udp-fanout userspace daemon and eBPF programs.
//!
//! This crate is `no_std` compatible so it can be used in eBPF programs.
//! All types must be `repr(C)` for stable ABI across eBPF and userspace.

#![no_std]

/// Maximum number of downstream receivers per listener.
/// This is a compile-time bound for eBPF array sizing.
pub const MAX_DOWNSTREAM: u32 = 64;

/// Maximum number of listeners (bound ports).
pub const MAX_LISTENERS: u32 = 16;


// ---------------------------------------------------------------------------
// eBPF Map Key/Value Types
// ---------------------------------------------------------------------------

/// Key for the listener config map: UDP port number.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ListenerKey {
    /// UDP destination port to intercept (network byte order in eBPF, host order in userspace).
    pub port: u16,
    pub _pad: u16,
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ListenerKey {}

/// Value for the listener config map: listener index + metadata.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ListenerValue {
    /// Index into the downstream arrays (0..MAX_LISTENERS-1).
    pub listener_id: u32,
    /// Network interface index for egress redirect.
    pub ifindex: u32,
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ListenerValue {}

/// A single downstream receiver entry.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DownstreamEntry {
    /// Destination IPv4 address (network byte order).
    pub dst_ip: u32,
    /// Destination UDP port (network byte order).
    pub dst_port: u16,
    /// Whether this entry is active.
    pub active: u8,
    pub _pad: u8,
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for DownstreamEntry {}

/// Number of active downstream receivers for a listener.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DownstreamCount {
    pub count: u32,
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for DownstreamCount {}

/// Per-CPU statistics counters for a listener.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct StatsEntry {
    /// Total packets received on this listener.
    pub pkts_received: u64,
    /// Total packets successfully forwarded (sum across all downstreams).
    pub pkts_forwarded: u64,
    /// Total packets dropped (clone/redirect failures).
    pub pkts_dropped: u64,
    /// Total bytes received.
    pub bytes_received: u64,
    /// Total bytes forwarded.
    pub bytes_forwarded: u64,
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for StatsEntry {}

// ---------------------------------------------------------------------------
// eBPF Map Names (must match between eBPF program and userspace loader)
// ---------------------------------------------------------------------------

/// Map name: HashMap<ListenerKey, ListenerValue> — port-to-listener mapping.
pub const MAP_LISTENER_CONFIG: &str = "LISTENER_CONFIG";

/// Map name: Array of DownstreamEntry — flat array indexed by
/// (listener_id * MAX_DOWNSTREAM + downstream_index).
pub const MAP_DOWNSTREAM_ADDRS: &str = "DOWNSTREAM_ADDRS";

/// Map name: Array<DownstreamCount> — indexed by listener_id.
pub const MAP_DOWNSTREAM_COUNT: &str = "DOWNSTREAM_COUNT";

/// Map name: PerCpuArray<StatsEntry> — indexed by listener_id.
pub const MAP_STATS: &str = "STATS";

/// Map name: PerCpuArray<u32> — per-listener round-robin counters (indexed by listener_id).
pub const MAP_RR_COUNTERS: &str = "RR_COUNTERS";

/// Map name: XskMap — AF_XDP socket map (indexed by RX queue).
pub const MAP_XSKMAP: &str = "XSKMAP";

/// Map name: HashMap<u16, u8> — XDP port filter (port in network byte order → present).
pub const MAP_XDP_PORTS: &str = "XDP_PORTS";

/// Maximum AF_XDP sockets (one per RX queue).
pub const MAX_XSK_SOCKETS: u32 = 64;

// ---------------------------------------------------------------------------
// Protocol Constants
// ---------------------------------------------------------------------------

/// Ethernet header size.
pub const ETH_HLEN: usize = 14;

/// Minimum IPv4 header size (no options).
pub const IP_HLEN: usize = 20;

/// UDP header size.
pub const UDP_HLEN: usize = 8;

/// Minimum total header size: Eth + IPv4 + UDP.
pub const MIN_HEADER_LEN: usize = ETH_HLEN + IP_HLEN + UDP_HLEN;

/// EtherType for IPv4.
pub const ETH_P_IP: u16 = 0x0800;

/// IP protocol number for UDP.
pub const IPPROTO_UDP: u8 = 17;
