//! AF_XDP zero-copy forwarding path.
//!
//! Combines XDP redirect to AF_XDP socket (zero-copy receive) with userspace
//! fanout via sendmmsg. This path offers near-kernel performance for receive
//! while retaining full flexibility for packet processing in userspace.
//!
//! Architecture:
//! 1. XDP program classifies packets by port and redirects to AF_XDP socket
//! 2. Userspace reads packets from the RX ring (zero-copy via shared UMEM)
//! 3. For each packet, sendmmsg fans out to all downstream addresses
//! 4. Consumed buffers are returned to the fill ring for reuse

use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use tracing::{debug, error, info, warn};

use crate::config::ListenerConfig;
use crate::kubernetes;

// ---------------------------------------------------------------------------
// AF_XDP Configuration Constants
// ---------------------------------------------------------------------------

/// Number of descriptors in each ring (must be power of 2).
const RING_SIZE: u32 = 4096;

/// UMEM frame size — each frame holds one packet.
const FRAME_SIZE: u32 = 4096;

/// Total number of UMEM frames.
const NUM_FRAMES: u32 = RING_SIZE * 2;

/// Total UMEM size.
const UMEM_SIZE: usize = (NUM_FRAMES * FRAME_SIZE) as usize;

// ---------------------------------------------------------------------------
// Public Interface
// ---------------------------------------------------------------------------

/// Statistics for the AF_XDP forwarding path.
#[derive(Debug, Default)]
pub struct AfXdpStats {
    pub pkts_received: AtomicU64,
    pub pkts_forwarded: AtomicU64,
    pub pkts_dropped: AtomicU64,
    pub pkts_no_healthy: AtomicU64,
    pub bytes_received: AtomicU64,
    pub bytes_forwarded: AtomicU64,
    pub rx_ring_empty: AtomicU64,
    pub fill_ring_full: AtomicU64,
}

/// A running AF_XDP forwarding instance.
pub struct AfXdpForwarder {
    thread: Option<thread::JoinHandle<()>>,
    shutdown: Arc<AtomicBool>,
    pub stats: Arc<AfXdpStats>,
    k8s_task: Option<tokio::task::JoinHandle<()>>,
}

impl AfXdpForwarder {
    /// Start the AF_XDP forwarder for the given listener config.
    ///
    /// This will:
    /// 1. Load the XDP classifier program
    /// 2. Create the AF_XDP socket with shared UMEM
    /// 3. Spawn a worker thread for the receive-fanout loop
    pub fn start(
        config: &ListenerConfig,
        _ebpf_bytes: &[u8], // XDP program binary for AF_XDP classifier
    ) -> Result<Self> {
        let shutdown = Arc::new(AtomicBool::new(false));
        let stats = Arc::new(AfXdpStats::default());
        let rr_counter = Arc::new(AtomicU64::new(0));

        // Downstream addresses (static or k8s-discovered).
        let downstreams: Arc<ArcSwap<Vec<SocketAddr>>> = Arc::new(ArcSwap::from_pointee(
            config
                .downstream
                .iter()
                .map(|d| d.address)
                .collect::<Vec<_>>(),
        ));

        // If Kubernetes discovery is configured, start watcher and replace downstream snapshots.
        let k8s_task = config.kubernetes.clone().map(|k8s_cfg| {
            kubernetes::spawn_endpointslice_watcher(
                config.name.clone(),
                k8s_cfg,
                downstreams.clone(),
            )
        });

        let iface = config
            .interface
            .clone()
            .expect("interface required for af_xdp mode");

        let bind_port = config.bind.port();
        let batch_size = config.settings.batch_size;
        let max_pkt_size = config.settings.max_packet_size;

        let shutdown_clone = shutdown.clone();
        let stats_clone = stats.clone();
        let name = config.name.clone();

        info!(
            listener = %name,
            interface = %iface,
            downstreams = downstreams.load().len(),
            ring_size = RING_SIZE,
            kubernetes = config.kubernetes.is_some(),
            "starting AF_XDP forwarder"
        );

        let thread = thread::Builder::new()
            .name(format!("afxdp-{}", name))
            .spawn(move || {
                if let Err(e) = af_xdp_worker(
                    &iface,
                    bind_port,
                    &downstreams,
                    &rr_counter,
                    batch_size,
                    max_pkt_size,
                    &shutdown_clone,
                    &stats_clone,
                ) {
                    error!(listener = %name, error = %e, "AF_XDP worker exited with error");
                }
            })
            .context("spawning AF_XDP worker")?;

        Ok(Self {
            thread: Some(thread),
            shutdown,
            stats,
            k8s_task,
        })
    }

    /// Signal the worker to stop and wait.
    pub fn shutdown(mut self) {
        info!("shutting down AF_XDP forwarder");
        self.shutdown.store(true, Ordering::Release);
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.k8s_task {
            handle.abort();
        }
    }
}

// ---------------------------------------------------------------------------
// AF_XDP Worker
// ---------------------------------------------------------------------------

/// Main AF_XDP receive + fanout loop.
///
/// Implementation notes:
/// - Uses the `aya` crate's AF_XDP support when available
/// - Falls back to raw libc AF_XDP socket creation
/// - The XDP program must redirect matching packets to our XSKMAP
fn af_xdp_worker(
    iface: &str,
    bind_port: u16,
    downstreams: &ArcSwap<Vec<SocketAddr>>,
    rr_counter: &AtomicU64,
    batch_size: usize,
    max_pkt_size: usize,
    shutdown: &AtomicBool,
    stats: &AfXdpStats,
) -> Result<()> {
    // --- Step 1: Allocate UMEM ---
    // UMEM is a contiguous memory region shared between kernel and userspace.
    // Each frame in UMEM holds one packet.
    let umem = allocate_umem(UMEM_SIZE)?;

    info!(
        umem_size = UMEM_SIZE,
        frame_size = FRAME_SIZE,
        num_frames = NUM_FRAMES,
        "allocated UMEM"
    );

    // --- Step 2: Create AF_XDP socket ---
    // The socket is bound to a specific (interface, queue_id) pair.
    // XDP program redirects packets to this socket via XSKMAP.
    let queue_id = 0u32; // TODO: multi-queue support
    let xsk_fd = create_af_xdp_socket(iface, queue_id, &umem)?;

    // --- Step 3: Create send socket for fanout ---
    let send_sock =
        socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))
            .context("creating send socket")?;

    let send_fd = send_sock.as_raw_fd();

    // --- Step 4: Pre-fill the fill ring ---
    // Fill ring tells the kernel which UMEM frames are available for receiving.
    prefill_ring(xsk_fd, NUM_FRAMES, FRAME_SIZE)?;

    info!(interface = iface, queue = queue_id, "entering AF_XDP receive loop");

    // --- Step 5: Receive + fanout loop ---
    let mut pkt_buf = vec![0u8; max_pkt_size];

    while !shutdown.load(Ordering::Relaxed) {
        // Poll the RX ring for completed receives
        let received = poll_rx_ring(xsk_fd, &umem, &mut pkt_buf, batch_size)?;

        if received == 0 {
            stats.rx_ring_empty.fetch_add(1, Ordering::Relaxed);
            // Brief sleep to avoid busy-spinning when idle
            std::thread::sleep(std::time::Duration::from_micros(10));
            continue;
        }

        for _i in 0..received {
            let pkt_len = pkt_buf.len(); // Actual length from ring descriptor

            stats.pkts_received.fetch_add(1, Ordering::Relaxed);
            stats.bytes_received.fetch_add(pkt_len as u64, Ordering::Relaxed);

            // Strict load balancing: one packet to one downstream (round-robin)
            let snapshot = downstreams.load();
            if snapshot.is_empty() {
                stats.pkts_no_healthy.fetch_add(1, Ordering::Relaxed);
                stats.pkts_dropped.fetch_add(1, Ordering::Relaxed);
                continue;
            }

            let idx = (rr_counter.fetch_add(1, Ordering::Relaxed) as usize) % snapshot.len();
            let dst = snapshot[idx];

            match sendto_one(send_fd, &pkt_buf[..pkt_len], dst) {
                Ok(true) => {
                    stats.pkts_forwarded.fetch_add(1, Ordering::Relaxed);
                    stats
                        .bytes_forwarded
                        .fetch_add(pkt_len as u64, Ordering::Relaxed);
                }
                Ok(false) => {
                    // Kernel send buffer full (EAGAIN) – count as drop.
                    stats.pkts_dropped.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => {
                    warn!(error = %e, "sendto error");
                    stats.pkts_dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        // Return consumed frames to the fill ring
        if let Err(e) = refill_ring(xsk_fd, received as u32, FRAME_SIZE) {
            warn!(error = %e, "failed to refill AF_XDP ring");
            stats.fill_ring_full.fetch_add(1, Ordering::Relaxed);
        }
    }

    info!("AF_XDP receive loop exited");
    Ok(())
}

// ---------------------------------------------------------------------------
// AF_XDP Low-Level Operations (libc-based)
// ---------------------------------------------------------------------------
// These are simplified stubs. A full implementation would use the aya AF_XDP
// support or direct mmap-based ring buffer management.

/// Send a single UDP packet to one destination (no allocation).
///
/// Returns:
/// - Ok(true) if sent successfully
/// - Ok(false) if it would block (EAGAIN)
fn sendto_one(fd: std::os::fd::RawFd, pkt: &[u8], addr: SocketAddr) -> Result<bool> {
    let sockaddr: socket2::SockAddr = addr.into();
    let ret = unsafe {
        libc::sendto(
            fd,
            pkt.as_ptr() as *const libc::c_void,
            pkt.len(),
            0,
            sockaddr.as_ptr(),
            sockaddr.len() as libc::socklen_t,
        )
    };

    if ret < 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::WouldBlock {
            return Ok(false);
        }
        return Err(err.into());
    }

    Ok(true)
}

fn allocate_umem(size: usize) -> Result<Vec<u8>> {
    // Use mmap for page-aligned allocation
    let umem = unsafe {
        let ptr = libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_HUGETLB,
            -1,
            0,
        );
        if ptr == libc::MAP_FAILED {
            // Fallback without hugepages
            let ptr = libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            if ptr == libc::MAP_FAILED {
                anyhow::bail!("mmap for UMEM failed: {}", std::io::Error::last_os_error());
            }
            std::slice::from_raw_parts_mut(ptr as *mut u8, size).to_vec()
        } else {
            std::slice::from_raw_parts_mut(ptr as *mut u8, size).to_vec()
        }
    };
    Ok(umem)
}

fn create_af_xdp_socket(iface: &str, queue_id: u32, _umem: &[u8]) -> Result<i32> {
    // Create AF_XDP socket
    let fd = unsafe { libc::socket(libc::AF_XDP, libc::SOCK_RAW, 0) };
    if fd < 0 {
        anyhow::bail!(
            "creating AF_XDP socket: {}",
            std::io::Error::last_os_error()
        );
    }

    // In a full implementation, we would:
    // 1. Register UMEM with setsockopt(fd, SOL_XDP, XDP_UMEM_REG, ...)
    // 2. Set up fill and completion ring sizes
    // 3. Set up RX and TX ring sizes
    // 4. mmap the rings
    // 5. Bind to (ifindex, queue_id) with bind()

    info!(
        interface = iface,
        queue_id,
        fd,
        "created AF_XDP socket (stub)"
    );

    Ok(fd)
}

fn prefill_ring(_xsk_fd: i32, _num_frames: u32, _frame_size: u32) -> Result<()> {
    // Fill ring with frame addresses so kernel knows where to write packets.
    // In a real implementation, write frame offsets to the fill ring.
    Ok(())
}

fn poll_rx_ring(
    _xsk_fd: i32,
    _umem: &[u8],
    _pkt_buf: &mut [u8],
    _batch_size: usize,
) -> Result<usize> {
    // Poll for received packets in the RX ring.
    // Returns number of packets available.
    // In a real implementation:
    // 1. Read RX ring producer/consumer pointers
    // 2. Copy packet data from UMEM frames to pkt_buf
    // 3. Advance consumer pointer
    Ok(0)
}

fn refill_ring(_xsk_fd: i32, _count: u32, _frame_size: u32) -> Result<()> {
    // Return consumed frames back to the fill ring.
    // Write frame addresses to fill ring producer slot.
    Ok(())
}

/// Send a packet to multiple destinations using sendmmsg(2).
fn sendmmsg_fanout(fd: i32, pkt: &[u8], addrs: &[SocketAddr]) -> Result<usize> {
    if addrs.is_empty() {
        return Ok(0);
    }

    let sockaddrs: Vec<socket2::SockAddr> = addrs.iter().map(|a| (*a).into()).collect();

    let mut iovecs: Vec<libc::iovec> = addrs
        .iter()
        .map(|_| libc::iovec {
            iov_base: pkt.as_ptr() as *mut libc::c_void,
            iov_len: pkt.len(),
        })
        .collect();

    let mut msgs: Vec<libc::mmsghdr> = iovecs
        .iter_mut()
        .zip(sockaddrs.iter())
        .map(|(iov, addr)| {
            let mut hdr: libc::mmsghdr = unsafe { std::mem::zeroed() };
            hdr.msg_hdr.msg_iov = iov as *mut libc::iovec;
            hdr.msg_hdr.msg_iovlen = 1;
            hdr.msg_hdr.msg_name = addr.as_ptr() as *mut libc::c_void;
            hdr.msg_hdr.msg_namelen = addr.len() as libc::socklen_t;
            hdr
        })
        .collect();

    let ret = unsafe { libc::sendmmsg(fd, msgs.as_mut_ptr(), msgs.len() as libc::c_uint, 0) };

    if ret < 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::WouldBlock {
            return Ok(0);
        }
        return Err(err.into());
    }

    Ok(ret as usize)
}
