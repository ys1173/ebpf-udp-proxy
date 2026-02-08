//! Core fanout logic: parse headers, match port, clone + redirect to downstreams.
//!
//! All packet reads use ctx.load() (bpf_skb_load_bytes) instead of direct
//! packet pointer access. This avoids eBPF verifier issues with variable-offset
//! packet pointers while keeping the code simple and correct.

use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_REDIRECT, TC_ACT_SHOT, BPF_FIB_LOOKUP_SKIP_NEIGH},
    helpers::{bpf_fib_lookup, bpf_redirect_neigh},
    programs::TcContext,
};
use udp_fanout_common::*;

use crate::{DOWNSTREAM_ADDRS, DOWNSTREAM_COUNT, LISTENER_CONFIG, RR_COUNTERS, STATS};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const ETH_P_IP_BE: u16 = (ETH_P_IP >> 8) | (ETH_P_IP << 8); // 0x0008 in LE

// ---------------------------------------------------------------------------
// Main Fanout Logic
// ---------------------------------------------------------------------------

/// Attempt to parse and fanout the packet. Returns TC action code.
pub fn try_fanout(ctx: &mut TcContext) -> Result<i32, ()> {
    // Packet length for stats (computed from skb pointers).
    let pkt_len = (ctx.data_end() - ctx.data()) as u64;

    // --- Parse Ethernet header ---
    let ether_type: u16 = ctx.load(12).map_err(|_| ())?;
    if ether_type != ETH_P_IP_BE {
        return Ok(TC_ACT_OK as i32);
    }

    // --- Parse IPv4 header ---
    let ver_ihl: u8 = ctx.load(ETH_HLEN).map_err(|_| ())?;
    let protocol: u8 = ctx.load(ETH_HLEN + 9).map_err(|_| ())?;
    if protocol != IPPROTO_UDP {
        return Ok(TC_ACT_OK as i32);
    }

    let ihl = (ver_ihl & 0x0F) as usize;
    let ip_hdr_len = ihl * 4;
    if ip_hdr_len < IP_HLEN {
        return Ok(TC_ACT_OK as i32);
    }

    // --- Read all header fields upfront ---
    let ip_tos: u8 = ctx.load(ETH_HLEN + 1).map_err(|_| ())?;
    let ip_tot_len: u16 = ctx.load(ETH_HLEN + 2).map_err(|_| ())?;
    let ip_check: u16 = ctx.load(ETH_HLEN + 10).map_err(|_| ())?;
    let ip_src_addr: u32 = ctx.load(ETH_HLEN + 12).map_err(|_| ())?;
    let ip_dst_addr: u32 = ctx.load(ETH_HLEN + 16).map_err(|_| ())?;

    // UDP fields at variable offset (this is why we use ctx.load)
    let udp_off = ETH_HLEN + ip_hdr_len;
    let udp_src_port: u16 = ctx.load(udp_off).map_err(|_| ())?;
    let udp_dst_port: u16 = ctx.load(udp_off + 2).map_err(|_| ())?;

    // --- Lookup listener by destination port ---
    let key = ListenerKey {
        port: udp_dst_port,
        _pad: 0,
    };
    let listener = match unsafe { LISTENER_CONFIG.get(&key) } {
        Some(v) => v,
        None => return Ok(TC_ACT_OK as i32),
    };

    let listener_id = listener.listener_id;
    let ifindex = listener.ifindex;

    // --- Get downstream count ---
    let ds_count = match DOWNSTREAM_COUNT.get(listener_id) {
        Some(c) => c.count,
        None => return Ok(TC_ACT_OK as i32),
    };

    if ds_count == 0 {
        if let Some(stats) = STATS.get_ptr_mut(listener_id) {
            unsafe { (*stats).pkts_dropped += 1 };
        }
        return Ok(TC_ACT_SHOT as i32);
    }

    // --- Update stats: received ---
    if let Some(stats) = STATS.get_ptr_mut(listener_id) {
        unsafe {
            (*stats).pkts_received += 1;
            (*stats).bytes_received += pkt_len;
        }
    }

    // --- Select one downstream (round-robin) ---
    let base_idx = listener_id * MAX_DOWNSTREAM;

    let mut rr: u32 = 0;
    if let Some(ptr) = RR_COUNTERS.get_ptr_mut(listener_id) {
        unsafe {
            rr = *ptr;
            *ptr = rr.wrapping_add(1);
        }
    }

    let start = rr % ds_count;
    let mut chosen: Option<DownstreamEntry> = None;
    let mut j: u32 = 0;
    while j < MAX_DOWNSTREAM && j < ds_count {
        let i = (start + j) % ds_count;
        let idx = base_idx + i;
        if let Some(ds) = DOWNSTREAM_ADDRS.get(idx) {
            if ds.active != 0 {
                chosen = Some(*ds);
                break;
            }
        }
        j += 1;
    }

    let ds = match chosen {
        Some(d) => d,
        None => {
            if let Some(stats) = STATS.get_ptr_mut(listener_id) {
                unsafe { (*stats).pkts_dropped += 1 };
            }
            return Ok(TC_ACT_SHOT as i32);
        }
    };

    // --- Rewrite L3/L4 headers ---

    // Rewrite IPv4 destination address
    // Values are already in network byte order (from map), use to_ne_bytes()
    // to get the raw memory representation (which IS the network byte order).
    ctx.store(ETH_HLEN + 16, &ds.dst_ip.to_ne_bytes(), 0)
        .map_err(|_| ())?;

    // Incremental IP checksum update for changed dst_addr
    let new_check = incremental_csum_update(ip_check, ip_dst_addr, ds.dst_ip);
    ctx.store(ETH_HLEN + 10, &new_check.to_ne_bytes(), 0)
        .map_err(|_| ())?;

    // Rewrite UDP destination port
    ctx.store(udp_off + 2, &ds.dst_port.to_ne_bytes(), 0)
        .map_err(|_| ())?;

    // Zero out UDP checksum (optional for IPv4 per RFC 768)
    ctx.store(udp_off + 6, &0u16.to_ne_bytes(), 0)
        .map_err(|_| ())?;

    // --- FIB lookup to resolve output ifindex (skip neighbor check) ---
    let mut fib: aya_ebpf::bindings::bpf_fib_lookup = unsafe { core::mem::zeroed() };
    fib.family = 2; // AF_INET
    fib.l4_protocol = IPPROTO_UDP;
    fib.sport = udp_src_port;
    fib.dport = ds.dst_port;
    fib.__bindgen_anon_1 = aya_ebpf::bindings::bpf_fib_lookup__bindgen_ty_1 {
        tot_len: u16::from_be(ip_tot_len),
    };
    fib.ifindex = ifindex;
    fib.__bindgen_anon_2 = aya_ebpf::bindings::bpf_fib_lookup__bindgen_ty_2 {
        tos: ip_tos,
    };
    fib.__bindgen_anon_3 = aya_ebpf::bindings::bpf_fib_lookup__bindgen_ty_3 {
        ipv4_src: ip_src_addr,
    };
    fib.__bindgen_anon_4 = aya_ebpf::bindings::bpf_fib_lookup__bindgen_ty_4 {
        ipv4_dst: ds.dst_ip,
    };

    let rc = unsafe {
        bpf_fib_lookup(
            ctx.skb.skb as *mut _,
            &mut fib as *mut _,
            core::mem::size_of::<aya_ebpf::bindings::bpf_fib_lookup>() as i32,
            BPF_FIB_LOOKUP_SKIP_NEIGH as u32,
        )
    };

    if rc != 0 {
        if let Some(stats) = STATS.get_ptr_mut(listener_id) {
            unsafe { (*stats).pkts_dropped += 1 };
        }
        return Ok(TC_ACT_SHOT as i32);
    }

    // Use bpf_redirect_neigh: handles L2 rewrite + neighbor resolution automatically.
    // No manual MAC rewriting needed — the kernel resolves ARP on demand.
    let ret = unsafe { bpf_redirect_neigh(fib.ifindex, core::ptr::null_mut(), 0, 0) };

    if let Some(stats) = STATS.get_ptr_mut(listener_id) {
        if ret == TC_ACT_REDIRECT as i64 {
            unsafe {
                (*stats).pkts_forwarded += 1;
                (*stats).bytes_forwarded += pkt_len;
            }
        } else {
            unsafe { (*stats).pkts_dropped += 1 };
        }
    }

    Ok(ret as i32)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Incremental checksum update when changing a 32-bit field (RFC 1624).
#[inline(always)]
fn incremental_csum_update(old_check: u16, old_val: u32, new_val: u32) -> u16 {
    // HC' = ~(~HC + ~m + m')
    let hc = !old_check as u32;
    let old_hi = !((old_val >> 16) as u16) as u32;
    let old_lo = !(old_val as u16) as u32;
    let new_hi = (new_val >> 16) as u32;
    let new_lo = (new_val & 0xFFFF) as u32;

    let mut sum = hc + old_hi + old_lo + new_hi + new_lo;

    // Fold carries
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}
