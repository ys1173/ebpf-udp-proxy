//! XDP eBPF program for AF_XDP-based UDP forwarding.
//!
//! Attached to XDP hook on the network interface. Classifies incoming packets:
//! - UDP packets matching configured ports → redirect to AF_XDP socket via XSKMAP
//! - Everything else (ARP, TCP, non-matching UDP) → XDP_PASS to kernel stack
//!
//! This is the key to MetalLB L2 compatibility: ARP packets pass through
//! untouched, so MetalLB can respond to ARP requests for virtual IPs.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, XskMap},
    programs::XdpContext,
};
use udp_fanout_common::*;

// ---------------------------------------------------------------------------
// eBPF Maps
// ---------------------------------------------------------------------------

/// AF_XDP socket map. Userspace registers AF_XDP socket fds here.
/// Index = RX queue index. The XDP program redirects matching packets
/// to the socket registered for the queue the packet arrived on.
#[map]
static XSKMAP: XskMap = XskMap::with_max_entries(64, 0);

/// Port filter map. If a UDP destination port (network byte order) is
/// present as a key, the packet should be redirected to AF_XDP.
/// Value is unused (just a presence check).
#[map]
static XDP_PORTS: HashMap<u16, u8> = HashMap::with_max_entries(MAX_LISTENERS, 0);

// ---------------------------------------------------------------------------
// XDP Entry Point
// ---------------------------------------------------------------------------

/// XDP hook: classify packets and redirect matching UDP to AF_XDP socket.
///
/// Returns:
/// - `XDP_REDIRECT`: packet redirected to AF_XDP socket (matched port)
/// - `XDP_PASS`: packet passes to normal kernel stack (no match)
#[xdp]
pub fn xdp_redirect_afxdp(ctx: XdpContext) -> u32 {
    match try_redirect(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

/// Inner redirect logic with error handling.
fn try_redirect(ctx: &XdpContext) -> Result<u32, ()> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    // Need at least Ethernet header (14 bytes)
    if data + ETH_HLEN > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    // --- Parse Ethernet header ---
    // EtherType is at offset 12, 2 bytes
    let ether_type = u16::from_be(unsafe { (data as *const u8).add(12).cast::<u16>().read_unaligned() });
    if ether_type != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }

    // --- Parse IPv4 header ---
    // Need at least Eth + minimum IP header
    if data + ETH_HLEN + IP_HLEN > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip_start = data + ETH_HLEN;
    let ver_ihl: u8 = unsafe { *(ip_start as *const u8) };
    let protocol: u8 = unsafe { *(ip_start as *const u8).add(9) };

    if protocol != IPPROTO_UDP {
        return Ok(xdp_action::XDP_PASS);
    }

    let ihl = (ver_ihl & 0x0F) as usize;
    let ip_hdr_len = ihl * 4;
    if ip_hdr_len < IP_HLEN {
        return Ok(xdp_action::XDP_PASS);
    }

    // --- Parse UDP header ---
    let udp_start = data + ETH_HLEN + ip_hdr_len;
    // Need at least UDP header (8 bytes)
    if udp_start + UDP_HLEN > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    // UDP destination port at offset 2 (network byte order)
    let udp_dst_port: u16 = unsafe { (udp_start as *const u8).add(2).cast::<u16>().read_unaligned() };

    // --- Lookup port in filter map ---
    // Port is stored in network byte order for direct comparison
    if unsafe { XDP_PORTS.get(&udp_dst_port) }.is_none() {
        return Ok(xdp_action::XDP_PASS);
    }

    // --- Redirect to AF_XDP socket ---
    // Use queue index 0 for single-queue AF_XDP setup.
    // In multi-queue setups, this could be derived from packet hash or RSS.
    match XSKMAP.redirect(0, 0) {
        Ok(action) => Ok(action),
        Err(_) => Ok(xdp_action::XDP_PASS),
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
