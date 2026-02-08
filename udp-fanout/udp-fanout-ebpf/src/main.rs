//! TC eBPF program for high-performance UDP fanout.
//!
//! Attached to TC ingress on the configured network interface. Intercepts UDP
//! packets matching configured ports, clones them to each downstream receiver
//! with rewritten L2/L3/L4 headers, and drops the original.
//!
//! This is the fast path — packets never reach userspace.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_OK,
    macros::{classifier, map},
    maps::{Array, HashMap, PerCpuArray},
    programs::TcContext,
};

use udp_fanout_common::*;

mod fanout;

// ---------------------------------------------------------------------------
// eBPF Maps
// ---------------------------------------------------------------------------

/// Port → listener mapping. Userspace populates this from YAML config.
#[map]
static LISTENER_CONFIG: HashMap<ListenerKey, ListenerValue> =
    HashMap::with_max_entries(MAX_LISTENERS, 0);

/// Flat array of downstream entries. Index = listener_id * MAX_DOWNSTREAM + i.
/// Total entries = MAX_LISTENERS * MAX_DOWNSTREAM.
#[map]
static DOWNSTREAM_ADDRS: Array<DownstreamEntry> =
    Array::with_max_entries(MAX_LISTENERS * MAX_DOWNSTREAM, 0);

/// Number of active downstreams per listener. Index = listener_id.
#[map]
static DOWNSTREAM_COUNT: Array<DownstreamCount> =
    Array::with_max_entries(MAX_LISTENERS, 0);

/// Per-CPU stats counters. Index = listener_id. Lock-free via per-CPU.
#[map]
static STATS: PerCpuArray<StatsEntry> = PerCpuArray::with_max_entries(MAX_LISTENERS, 0);

/// Per-CPU round-robin counters. Index = listener_id.
#[map]
static RR_COUNTERS: PerCpuArray<u32> = PerCpuArray::with_max_entries(MAX_LISTENERS, 0);

// ---------------------------------------------------------------------------
// TC Classifier Entry Point
// ---------------------------------------------------------------------------

/// TC ingress classifier. Attached to the qdisc on the configured interface.
///
/// Returns:
/// - `TC_ACT_SHOT`: packet was intercepted and cloned to downstreams (drop original)
/// - `TC_ACT_OK`: packet not matched, pass through normal stack
#[classifier]
pub fn udp_fanout(mut ctx: TcContext) -> i32 {
    match fanout::try_fanout(&mut ctx) {
        Ok(action) => action,
        Err(_) => TC_ACT_OK as i32,
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
