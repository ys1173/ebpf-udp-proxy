//! Pure userspace UDP fanout forwarding path.
//!
//! Uses recvmmsg/sendmmsg for batched I/O and per-CPU worker threads for
//! scalability. This is the portable fallback when eBPF is not available.

use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use tracing::{debug, error, info, warn};

use crate::config::ListenerConfig;
use crate::kubernetes;

// ---------------------------------------------------------------------------
// Public Interface
// ---------------------------------------------------------------------------

/// Statistics for a userspace forwarding worker.
#[derive(Debug, Default)]
pub struct UserspaceStats {
    pub pkts_received: AtomicU64,
    pub pkts_forwarded: AtomicU64,
    pub pkts_dropped: AtomicU64,
    pub pkts_no_healthy: AtomicU64,
    pub bytes_received: AtomicU64,
    pub bytes_forwarded: AtomicU64,
}

/// A running userspace forwarding instance for one listener.
pub struct UserspaceForwarder {
    threads: Vec<thread::JoinHandle<()>>,
    shutdown: Arc<AtomicBool>,
    pub stats: Arc<UserspaceStats>,
    k8s_task: Option<tokio::task::JoinHandle<()>>,
}

impl UserspaceForwarder {
    /// Start the userspace forwarder for the given listener config.
    pub fn start(config: &ListenerConfig) -> Result<Self> {
        let shutdown = Arc::new(AtomicBool::new(false));
        let stats = Arc::new(UserspaceStats::default());
        let rr_counter = Arc::new(AtomicU64::new(0));

        let bind_addr = config.bind;
        let max_pkt_size = config.settings.max_packet_size;
        let batch_size = config.settings.batch_size;
        let recv_buf_size = config.settings.recv_buf_size;

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

        // Determine worker count
        let num_workers = if config.settings.workers > 0 {
            config.settings.workers
        } else {
            num_cpus()
        };

        info!(
            listener = %config.name,
            bind = %bind_addr,
            downstreams = downstreams.load().len(),
            workers = num_workers,
            batch_size = batch_size,
            kubernetes = config.kubernetes.is_some(),
            "starting userspace forwarder"
        );

        let mut threads = Vec::with_capacity(num_workers);

        for worker_id in 0..num_workers {
            let shutdown = shutdown.clone();
            let stats = stats.clone();
            let downstreams = downstreams.clone();
            let rr_counter = rr_counter.clone();
            let name = config.name.clone();
            let pin_cpus = config.settings.pin_cpus;

            let handle = thread::Builder::new()
                .name(format!("uf-{}-{}", name, worker_id))
                .spawn(move || {
                    // Pin to CPU core if requested
                    if pin_cpus {
                        if let Some(core_id) = (core_affinity::CoreId { id: worker_id }).into() {
                            core_affinity::set_for_current(core_id);
                            debug!(worker = worker_id, core = worker_id, "pinned to CPU core");
                        }
                    }

                    if let Err(e) = worker_loop(
                        worker_id,
                        bind_addr,
                        &downstreams,
                        &rr_counter,
                        max_pkt_size,
                        batch_size,
                        recv_buf_size,
                        &shutdown,
                        &stats,
                    ) {
                        error!(worker = worker_id, error = %e, "worker exited with error");
                    }
                })
                .with_context(|| format!("spawning worker {}", worker_id))?;

            threads.push(handle);
        }

        Ok(Self {
            threads,
            shutdown,
            stats,
            k8s_task,
        })
    }

    /// Signal all workers to stop and wait for them to finish.
    pub fn shutdown(self) {
        info!("shutting down userspace forwarder");
        self.shutdown.store(true, Ordering::Release);
        for handle in self.threads {
            let _ = handle.join();
        }
        if let Some(handle) = self.k8s_task {
            handle.abort();
        }
    }
}

// ---------------------------------------------------------------------------
// Worker Loop
// ---------------------------------------------------------------------------

fn worker_loop(
    worker_id: usize,
    bind_addr: SocketAddr,
    downstreams: &ArcSwap<Vec<SocketAddr>>,
    rr_counter: &AtomicU64,
    max_pkt_size: usize,
    batch_size: usize,
    recv_buf_size: usize,
    shutdown: &AtomicBool,
    stats: &UserspaceStats,
) -> Result<()> {
    // Create and configure the receive socket
    let recv_sock = create_recv_socket(bind_addr, recv_buf_size)
        .with_context(|| format!("worker {}: creating recv socket", worker_id))?;

    let recv_fd = recv_sock.as_raw_fd();

    // Create send socket (unbound, for sendmmsg)
    let send_sock = create_send_socket(bind_addr)
        .with_context(|| format!("worker {}: creating send socket", worker_id))?;

    let send_fd = send_sock.as_raw_fd();

    // Pre-allocate receive buffers
    let mut recv_bufs: Vec<Vec<u8>> = (0..batch_size)
        .map(|_| vec![0u8; max_pkt_size])
        .collect();

    info!(worker = worker_id, "entering receive loop");

    let mut last_heartbeat = Instant::now();

    while !shutdown.load(Ordering::Relaxed) {
        if last_heartbeat.elapsed() >= Duration::from_secs(5) {
            let ds = downstreams.load().len();
            debug!(
                worker = worker_id,
                downstreams = ds,
                pkts_received = stats.pkts_received.load(Ordering::Relaxed),
                pkts_forwarded = stats.pkts_forwarded.load(Ordering::Relaxed),
                pkts_dropped = stats.pkts_dropped.load(Ordering::Relaxed),
                pkts_no_healthy = stats.pkts_no_healthy.load(Ordering::Relaxed),
                "userspace worker heartbeat"
            );
            last_heartbeat = Instant::now();
        }

        // --- Batch receive with recvmmsg ---
        // Ensure the buffers are full-sized for the next receive (recvmmsg truncates them).
        for buf in recv_bufs.iter_mut() {
            if buf.len() != max_pkt_size {
                buf.resize(max_pkt_size, 0);
            }
        }

        let received = recvmmsg(recv_fd, &mut recv_bufs, batch_size)?;

        if received == 0 {
            continue;
        }

        // --- Strict load balancing: one packet to one downstream (round-robin) ---
        for pkt_idx in 0..received {
            let pkt = &recv_bufs[pkt_idx];
            let pkt_len = pkt.len(); // actual length set by recvmmsg via truncate()

            stats.pkts_received.fetch_add(1, Ordering::Relaxed);
            stats.bytes_received.fetch_add(pkt_len as u64, Ordering::Relaxed);

            let snapshot = downstreams.load();
            if snapshot.is_empty() {
                stats.pkts_no_healthy.fetch_add(1, Ordering::Relaxed);
                stats.pkts_dropped.fetch_add(1, Ordering::Relaxed);
                continue;
            }

            let idx = (rr_counter.fetch_add(1, Ordering::Relaxed) as usize) % snapshot.len();
            let dst = snapshot[idx];

            match sendto_one(send_fd, pkt, dst) {
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
                    warn!(worker = worker_id, error = %e, "sendto error");
                    stats.pkts_dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    info!(worker = worker_id, "receive loop exited");
    Ok(())
}

// ---------------------------------------------------------------------------
// Socket Creation
// ---------------------------------------------------------------------------

fn create_recv_socket(
    bind_addr: SocketAddr,
    recv_buf_size: usize,
) -> Result<socket2::Socket> {
    let domain = if bind_addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };

    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))
        .context("creating UDP socket")?;

    // SO_REUSEPORT for multi-worker binding
    socket.set_reuse_port(true).context("SO_REUSEPORT")?;
    socket.set_reuse_address(true).context("SO_REUSEADDR")?;

    // Set receive buffer size
    if recv_buf_size > 0 {
        socket
            .set_recv_buffer_size(recv_buf_size)
            .context("SO_RCVBUF")?;
    }

    // Non-blocking for poll-based receive with timeout
    socket.set_nonblocking(false)?;
    // Set a read timeout so we can check shutdown flag periodically
    socket.set_read_timeout(Some(std::time::Duration::from_millis(100)))?;

    let addr: socket2::SockAddr = bind_addr.into();
    socket.bind(&addr).with_context(|| format!("bind {}", bind_addr))?;

    Ok(socket)
}

fn create_send_socket(bind_addr: SocketAddr) -> Result<socket2::Socket> {
    let domain = if bind_addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };

    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))
        .context("creating send socket")?;

    Ok(socket)
}

// ---------------------------------------------------------------------------
// Batched I/O: recvmmsg / sendmmsg
// ---------------------------------------------------------------------------

/// Receive a batch of UDP datagrams using recvmmsg(2).
///
/// Returns the number of datagrams received (0 on timeout).
fn recvmmsg(fd: RawFd, bufs: &mut [Vec<u8>], max_msgs: usize) -> Result<usize> {
    let count = max_msgs.min(bufs.len());

    // Build iovec and mmsghdr arrays
    let mut iovecs: Vec<libc::iovec> = bufs[..count]
        .iter_mut()
        .map(|buf| libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        })
        .collect();

    let mut msgs: Vec<libc::mmsghdr> = iovecs
        .iter_mut()
        .map(|iov| {
            let mut hdr: libc::mmsghdr = unsafe { std::mem::zeroed() };
            hdr.msg_hdr.msg_iov = iov as *mut libc::iovec;
            hdr.msg_hdr.msg_iovlen = 1;
            hdr
        })
        .collect();

    let ret = unsafe {
        libc::recvmmsg(
            fd,
            msgs.as_mut_ptr(),
            count as libc::c_uint,
            libc::MSG_WAITFORONE, // Block for first message, then drain non-blocking
            std::ptr::null_mut(), // No timeout (using socket read timeout instead)
        )
    };

    if ret < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::WouldBlock || err.kind() == io::ErrorKind::TimedOut {
            return Ok(0);
        }
        return Err(err.into());
    }

    // Truncate buffers to actual received lengths
    for i in 0..ret as usize {
        let actual_len = msgs[i].msg_len as usize;
        bufs[i].truncate(actual_len);
        // Resize back to max for next receive
        // (we'll do this at the start of next iteration)
    }

    Ok(ret as usize)
}

/// Send a single packet to multiple destinations using sendmmsg(2).
///
/// Returns the number of messages successfully sent.
fn sendmmsg_fanout(fd: RawFd, pkt: &[u8], addrs: &[SocketAddr]) -> Result<usize> {
    if addrs.is_empty() {
        return Ok(0);
    }

    // Build sockaddr storage for each destination
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

    let ret = unsafe {
        libc::sendmmsg(
            fd,
            msgs.as_mut_ptr(),
            msgs.len() as libc::c_uint,
            0, // No flags
        )
    };

    if ret < 0 {
        let err = io::Error::last_os_error();
        // EAGAIN is not fatal — just means kernel buffers are full
        if err.kind() == io::ErrorKind::WouldBlock {
            return Ok(0);
        }
        return Err(err.into());
    }

    Ok(ret as usize)
}

/// Send a single UDP packet to one destination (no allocation).
///
/// Returns:
/// - Ok(true) if sent successfully
/// - Ok(false) if it would block (EAGAIN)
fn sendto_one(fd: RawFd, pkt: &[u8], addr: SocketAddr) -> Result<bool> {
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
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::WouldBlock {
            return Ok(false);
        }
        return Err(err.into());
    }

    Ok(true)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}
