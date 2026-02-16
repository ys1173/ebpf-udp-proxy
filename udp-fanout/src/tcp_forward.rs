//! TCP forward mode: UDP receive → TCP forward with persistent connections.
//!
//! Receives UDP datagrams via recvmmsg batched I/O and forwards each packet
//! over persistent TCP connections to downstream receivers (e.g., Vector pods).
//! Each worker thread owns its own TCP connection pool — zero lock contention
//! in the hot path.

use std::io::{self, BufWriter, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use tracing::{debug, error, info, warn};

use crate::config::{ListenerConfig, TcpFramingMode};
use crate::kubernetes;

// ---------------------------------------------------------------------------
// Public Interface
// ---------------------------------------------------------------------------

/// Statistics for TCP forward mode.
#[derive(Debug, Default)]
pub struct TcpForwardStats {
    pub pkts_received: AtomicU64,
    pub pkts_forwarded: AtomicU64,
    pub pkts_dropped: AtomicU64,
    pub pkts_no_downstream: AtomicU64,
    pub bytes_received: AtomicU64,
    pub bytes_forwarded: AtomicU64,
    pub connections_active: AtomicU64,
    pub connection_errors: AtomicU64,
    pub write_errors: AtomicU64,
}

/// A running TCP forward instance for one listener.
pub struct TcpForwarder {
    threads: Vec<thread::JoinHandle<()>>,
    shutdown: Arc<AtomicBool>,
    pub stats: Arc<TcpForwardStats>,
    k8s_task: Option<tokio::task::JoinHandle<()>>,
}

impl TcpForwarder {
    /// Start the TCP forwarder for the given listener config.
    pub fn start(config: &ListenerConfig) -> Result<Self> {
        let shutdown = Arc::new(AtomicBool::new(false));
        let stats = Arc::new(TcpForwardStats::default());
        let rr_counter = Arc::new(AtomicU64::new(0));

        let bind_addr = config.bind;
        let max_pkt_size = config.settings.max_packet_size;
        let batch_size = config.settings.batch_size;
        let recv_buf_size = config.settings.recv_buf_size;
        let tcp_framing = config.settings.tcp_framing.clone();
        let tcp_send_buf_size = config.settings.tcp_send_buf_size;
        let tcp_connect_timeout = Duration::from_millis(config.settings.tcp_connect_timeout_ms);
        let tcp_nodelay = config.settings.tcp_nodelay;

        // Downstream addresses (static or k8s-discovered).
        let downstreams: Arc<ArcSwap<Vec<SocketAddr>>> = Arc::new(ArcSwap::from_pointee(
            config
                .downstream
                .iter()
                .map(|d| d.address)
                .collect::<Vec<_>>(),
        ));

        // If Kubernetes discovery is configured, start watcher.
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
            framing = ?tcp_framing,
            tcp_nodelay = tcp_nodelay,
            tcp_send_buf_size = tcp_send_buf_size,
            kubernetes = config.kubernetes.is_some(),
            "starting tcp_forward forwarder"
        );

        let mut threads = Vec::with_capacity(num_workers);

        for worker_id in 0..num_workers {
            let shutdown = shutdown.clone();
            let stats = stats.clone();
            let downstreams = downstreams.clone();
            let rr_counter = rr_counter.clone();
            let name = config.name.clone();
            let pin_cpus = config.settings.pin_cpus;
            let tcp_framing = tcp_framing.clone();

            let handle = thread::Builder::new()
                .name(format!("tf-{}-{}", name, worker_id))
                .spawn(move || {
                    // Pin to CPU core if requested
                    if pin_cpus {
                        if let Some(core_id) =
                            (core_affinity::CoreId { id: worker_id }).into()
                        {
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
                        &tcp_framing,
                        tcp_send_buf_size,
                        tcp_connect_timeout,
                        tcp_nodelay,
                        &shutdown,
                        &stats,
                    ) {
                        error!(worker = worker_id, error = %e, "tcp_forward worker exited with error");
                    }
                })
                .with_context(|| format!("spawning tcp_forward worker {}", worker_id))?;

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
        info!("shutting down tcp_forward forwarder");
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
// TCP Connection Pool (per-worker, no locks)
// ---------------------------------------------------------------------------

/// A single TCP connection with buffered writes.
struct TcpConnection {
    writer: BufWriter<TcpStream>,
    addr: SocketAddr,
}

impl TcpConnection {
    fn new(stream: TcpStream, addr: SocketAddr, buf_size: usize) -> Self {
        Self {
            writer: BufWriter::with_capacity(buf_size, stream),
            addr,
        }
    }
}

/// Per-worker TCP connection pool. Owns connections — no Arc/Mutex needed.
struct TcpConnectionPool {
    /// One slot per downstream. None = disconnected (will lazy-reconnect).
    connections: Vec<Option<TcpConnection>>,
    /// Current downstream addresses (to detect changes).
    addrs: Vec<SocketAddr>,
    /// Per-connection backoff state: next allowed reconnect time.
    backoff: Vec<Instant>,
    /// Per-connection backoff duration (doubles on failure, caps at MAX_BACKOFF).
    backoff_dur: Vec<Duration>,
    /// Config.
    send_buf_size: usize,
    connect_timeout: Duration,
    nodelay: bool,
}

const MIN_BACKOFF: Duration = Duration::from_millis(100);
const MAX_BACKOFF: Duration = Duration::from_secs(2);

impl TcpConnectionPool {
    fn new(
        addrs: &[SocketAddr],
        send_buf_size: usize,
        connect_timeout: Duration,
        nodelay: bool,
    ) -> Self {
        let n = addrs.len();
        let now = Instant::now();
        Self {
            connections: vec![None; n],
            addrs: addrs.to_vec(),
            backoff: vec![now; n],
            backoff_dur: vec![MIN_BACKOFF; n],
            send_buf_size,
            connect_timeout,
            nodelay,
        }
    }

    /// Reconcile the pool with a new set of downstream addresses.
    /// Keeps existing connections for addresses that haven't changed.
    fn reconcile(&mut self, new_addrs: &[SocketAddr]) {
        if self.addrs == *new_addrs {
            return;
        }

        let mut new_connections: Vec<Option<TcpConnection>> = vec![None; new_addrs.len()];
        let now = Instant::now();
        let mut new_backoff = vec![now; new_addrs.len()];
        let mut new_backoff_dur = vec![MIN_BACKOFF; new_addrs.len()];

        // Migrate existing connections for addresses that still exist.
        for (new_idx, new_addr) in new_addrs.iter().enumerate() {
            if let Some(old_idx) = self.addrs.iter().position(|a| a == new_addr) {
                new_connections[new_idx] = self.connections[old_idx].take();
                new_backoff[new_idx] = self.backoff[old_idx];
                new_backoff_dur[new_idx] = self.backoff_dur[old_idx];
            }
        }

        self.connections = new_connections;
        self.addrs = new_addrs.to_vec();
        self.backoff = new_backoff;
        self.backoff_dur = new_backoff_dur;
    }

    /// Get or lazily connect to downstream at `idx`. Returns None if connection
    /// failed or is in backoff.
    fn get_or_connect(
        &mut self,
        idx: usize,
        stats: &TcpForwardStats,
    ) -> Option<&mut BufWriter<TcpStream>> {
        if self.connections[idx].is_some() {
            return self.connections[idx]
                .as_mut()
                .map(|c| &mut c.writer);
        }

        // Check backoff
        let now = Instant::now();
        if now < self.backoff[idx] {
            return None;
        }

        let addr = self.addrs[idx];
        match TcpStream::connect_timeout(&addr, self.connect_timeout) {
            Ok(stream) => {
                if let Err(e) = stream.set_nodelay(self.nodelay) {
                    warn!(addr = %addr, error = %e, "failed to set TCP_NODELAY");
                }
                // Set non-blocking to false for blocking writes with BufWriter
                if let Err(e) = stream.set_nonblocking(false) {
                    warn!(addr = %addr, error = %e, "failed to set blocking mode");
                }
                // Set write timeout to avoid blocking forever
                if let Err(e) = stream.set_write_timeout(Some(Duration::from_millis(500))) {
                    warn!(addr = %addr, error = %e, "failed to set write timeout");
                }

                debug!(addr = %addr, "TCP connection established");
                stats.connections_active.fetch_add(1, Ordering::Relaxed);
                // Reset backoff on success
                self.backoff_dur[idx] = MIN_BACKOFF;
                self.connections[idx] = Some(TcpConnection::new(stream, addr, self.send_buf_size));
                self.connections[idx]
                    .as_mut()
                    .map(|c| &mut c.writer)
            }
            Err(e) => {
                debug!(addr = %addr, error = %e, "TCP connect failed, backing off");
                stats.connection_errors.fetch_add(1, Ordering::Relaxed);
                // Exponential backoff
                self.backoff[idx] = now + self.backoff_dur[idx];
                self.backoff_dur[idx] =
                    (self.backoff_dur[idx] * 2).min(MAX_BACKOFF);
                None
            }
        }
    }

    /// Mark connection at `idx` as failed (will reconnect on next use).
    fn mark_failed(&mut self, idx: usize, stats: &TcpForwardStats) {
        if self.connections[idx].take().is_some() {
            stats.connections_active.fetch_sub(1, Ordering::Relaxed);
        }
        let now = Instant::now();
        self.backoff[idx] = now + self.backoff_dur[idx];
        self.backoff_dur[idx] = (self.backoff_dur[idx] * 2).min(MAX_BACKOFF);
    }

    /// Flush all active connections after a batch.
    fn flush_all(&mut self, stats: &TcpForwardStats) {
        for idx in 0..self.connections.len() {
            if let Some(ref mut conn) = self.connections[idx] {
                if let Err(e) = conn.writer.flush() {
                    debug!(addr = %conn.addr, error = %e, "TCP flush failed");
                    stats.write_errors.fetch_add(1, Ordering::Relaxed);
                    // Drop connection — will reconnect next time
                    self.connections[idx] = None;
                    stats.connections_active.fetch_sub(1, Ordering::Relaxed);
                    let now = Instant::now();
                    self.backoff[idx] = now + self.backoff_dur[idx];
                    self.backoff_dur[idx] =
                        (self.backoff_dur[idx] * 2).min(MAX_BACKOFF);
                }
            }
        }
    }

    fn len(&self) -> usize {
        self.addrs.len()
    }
}

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

/// Frame a UDP payload for TCP transport. Writes into `frame_buf` and returns
/// the slice to write to TCP.
///
/// Uses a reusable buffer to avoid allocation in the hot path.
fn frame_message<'a>(
    payload: &[u8],
    framing: &TcpFramingMode,
    frame_buf: &'a mut Vec<u8>,
) -> &'a [u8] {
    frame_buf.clear();
    match framing {
        TcpFramingMode::Newline => {
            // payload + '\n'
            frame_buf.reserve(payload.len() + 1);
            frame_buf.extend_from_slice(payload);
            frame_buf.push(b'\n');
        }
        TcpFramingMode::OctetCounting => {
            // RFC 6587: "<length> <message>"
            // e.g. "128 <syslog message of 128 bytes>"
            let prefix = format!("{} ", payload.len());
            frame_buf.reserve(prefix.len() + payload.len());
            frame_buf.extend_from_slice(prefix.as_bytes());
            frame_buf.extend_from_slice(payload);
        }
        TcpFramingMode::LengthPrefix => {
            // 4-byte big-endian length + payload
            frame_buf.reserve(4 + payload.len());
            frame_buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            frame_buf.extend_from_slice(payload);
        }
    }
    frame_buf.as_slice()
}

// ---------------------------------------------------------------------------
// Local Stats (batch-flush to reduce atomic contention)
// ---------------------------------------------------------------------------

struct LocalStats {
    pkts_received: u64,
    pkts_forwarded: u64,
    pkts_dropped: u64,
    pkts_no_downstream: u64,
    bytes_received: u64,
    bytes_forwarded: u64,
    write_errors: u64,
}

impl LocalStats {
    fn new() -> Self {
        Self {
            pkts_received: 0,
            pkts_forwarded: 0,
            pkts_dropped: 0,
            pkts_no_downstream: 0,
            bytes_received: 0,
            bytes_forwarded: 0,
            write_errors: 0,
        }
    }

    fn flush(&mut self, stats: &TcpForwardStats) {
        if self.pkts_received > 0 {
            stats
                .pkts_received
                .fetch_add(self.pkts_received, Ordering::Relaxed);
            self.pkts_received = 0;
        }
        if self.pkts_forwarded > 0 {
            stats
                .pkts_forwarded
                .fetch_add(self.pkts_forwarded, Ordering::Relaxed);
            self.pkts_forwarded = 0;
        }
        if self.pkts_dropped > 0 {
            stats
                .pkts_dropped
                .fetch_add(self.pkts_dropped, Ordering::Relaxed);
            self.pkts_dropped = 0;
        }
        if self.pkts_no_downstream > 0 {
            stats
                .pkts_no_downstream
                .fetch_add(self.pkts_no_downstream, Ordering::Relaxed);
            self.pkts_no_downstream = 0;
        }
        if self.bytes_received > 0 {
            stats
                .bytes_received
                .fetch_add(self.bytes_received, Ordering::Relaxed);
            self.bytes_received = 0;
        }
        if self.bytes_forwarded > 0 {
            stats
                .bytes_forwarded
                .fetch_add(self.bytes_forwarded, Ordering::Relaxed);
            self.bytes_forwarded = 0;
        }
        if self.write_errors > 0 {
            stats
                .write_errors
                .fetch_add(self.write_errors, Ordering::Relaxed);
            self.write_errors = 0;
        }
    }
}

// ---------------------------------------------------------------------------
// Worker Loop
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn worker_loop(
    worker_id: usize,
    bind_addr: SocketAddr,
    downstreams: &ArcSwap<Vec<SocketAddr>>,
    rr_counter: &AtomicU64,
    max_pkt_size: usize,
    batch_size: usize,
    recv_buf_size: usize,
    tcp_framing: &TcpFramingMode,
    tcp_send_buf_size: usize,
    tcp_connect_timeout: Duration,
    tcp_nodelay: bool,
    shutdown: &AtomicBool,
    stats: &TcpForwardStats,
) -> Result<()> {
    // Create and configure the receive socket (same as userspace.rs)
    let recv_sock = create_recv_socket(bind_addr, recv_buf_size)
        .with_context(|| format!("worker {}: creating recv socket", worker_id))?;

    let recv_fd = recv_sock.as_raw_fd();

    // Pre-allocate receive buffers
    let mut recv_bufs: Vec<Vec<u8>> = (0..batch_size)
        .map(|_| vec![0u8; max_pkt_size])
        .collect();

    // Pre-allocate frame buffer (reused per packet)
    let mut frame_buf: Vec<u8> = Vec::with_capacity(max_pkt_size + 32);

    // Initialize TCP connection pool
    let initial_ds = downstreams.load();
    let mut pool = TcpConnectionPool::new(
        &initial_ds,
        tcp_send_buf_size,
        tcp_connect_timeout,
        tcp_nodelay,
    );

    // Track downstream version for change detection
    let mut cached_ds_ptr = initial_ds.as_ptr();

    let mut local = LocalStats::new();
    let mut last_heartbeat = Instant::now();

    info!(worker = worker_id, "tcp_forward: entering receive loop");

    while !shutdown.load(Ordering::Relaxed) {
        // Heartbeat logging
        if last_heartbeat.elapsed() >= Duration::from_secs(5) {
            debug!(
                worker = worker_id,
                downstreams = pool.len(),
                pkts_received = stats.pkts_received.load(Ordering::Relaxed),
                pkts_forwarded = stats.pkts_forwarded.load(Ordering::Relaxed),
                pkts_dropped = stats.pkts_dropped.load(Ordering::Relaxed),
                connections_active = stats.connections_active.load(Ordering::Relaxed),
                "tcp_forward worker heartbeat"
            );
            last_heartbeat = Instant::now();
        }

        // Check for downstream changes (once per batch, not per packet)
        let ds_snapshot = downstreams.load();
        let new_ptr = ds_snapshot.as_ptr();
        if new_ptr != cached_ds_ptr {
            pool.reconcile(&ds_snapshot);
            cached_ds_ptr = new_ptr;
            debug!(
                worker = worker_id,
                downstreams = ds_snapshot.len(),
                "downstream list updated"
            );
        }

        // Ensure buffers are full-sized for next receive
        for buf in recv_bufs.iter_mut() {
            if buf.len() != max_pkt_size {
                buf.resize(max_pkt_size, 0);
            }
        }

        // --- Batch receive with recvmmsg ---
        let received = recvmmsg(recv_fd, &mut recv_bufs, batch_size)?;

        if received == 0 {
            continue;
        }

        // --- Round-robin: one packet → one downstream via TCP ---
        for pkt_idx in 0..received {
            let pkt = &recv_bufs[pkt_idx];
            let pkt_len = pkt.len();

            local.pkts_received += 1;
            local.bytes_received += pkt_len as u64;

            if pool.len() == 0 {
                local.pkts_no_downstream += 1;
                local.pkts_dropped += 1;
                continue;
            }

            // Round-robin select
            let idx = (rr_counter.fetch_add(1, Ordering::Relaxed) as usize) % pool.len();

            // Frame the message
            let framed = frame_message(pkt, tcp_framing, &mut frame_buf);
            let framed_len = framed.len();

            // Get or establish TCP connection
            if let Some(writer) = pool.get_or_connect(idx, stats) {
                match writer.write_all(framed) {
                    Ok(()) => {
                        local.pkts_forwarded += 1;
                        local.bytes_forwarded += framed_len as u64;
                    }
                    Err(e) => {
                        debug!(worker = worker_id, error = %e, "TCP write failed");
                        local.write_errors += 1;
                        local.pkts_dropped += 1;
                        pool.mark_failed(idx, stats);
                    }
                }
            } else {
                // Connection unavailable (in backoff or failed)
                local.pkts_dropped += 1;
            }
        }

        // Flush all TCP connections after each batch
        pool.flush_all(stats);

        // Flush local stats to shared atomics
        local.flush(stats);
    }

    info!(worker = worker_id, "tcp_forward: receive loop exited");
    Ok(())
}

// ---------------------------------------------------------------------------
// Socket Creation (same as userspace.rs)
// ---------------------------------------------------------------------------

fn create_recv_socket(bind_addr: SocketAddr, recv_buf_size: usize) -> Result<socket2::Socket> {
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

    if recv_buf_size > 0 {
        socket
            .set_recv_buffer_size(recv_buf_size)
            .context("SO_RCVBUF")?;
    }

    socket.set_nonblocking(false)?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;

    let addr: socket2::SockAddr = bind_addr.into();
    socket
        .bind(&addr)
        .with_context(|| format!("bind {}", bind_addr))?;

    Ok(socket)
}

// ---------------------------------------------------------------------------
// Batched Receive: recvmmsg
// ---------------------------------------------------------------------------

/// Receive a batch of UDP datagrams using recvmmsg(2).
fn recvmmsg(fd: RawFd, bufs: &mut [Vec<u8>], max_msgs: usize) -> Result<usize> {
    let count = max_msgs.min(bufs.len());

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
            libc::MSG_WAITFORONE,
            std::ptr::null_mut(),
        )
    };

    if ret < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::WouldBlock || err.kind() == io::ErrorKind::TimedOut {
            return Ok(0);
        }
        return Err(err.into());
    }

    for i in 0..ret as usize {
        let actual_len = msgs[i].msg_len as usize;
        bufs[i].truncate(actual_len);
    }

    Ok(ret as usize)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_newline() {
        let mut buf = Vec::new();
        let framed = frame_message(b"hello world", &TcpFramingMode::Newline, &mut buf);
        assert_eq!(framed, b"hello world\n");
    }

    #[test]
    fn test_frame_octet_counting() {
        let mut buf = Vec::new();
        let framed = frame_message(b"hello", &TcpFramingMode::OctetCounting, &mut buf);
        assert_eq!(framed, b"5 hello");
    }

    #[test]
    fn test_frame_length_prefix() {
        let mut buf = Vec::new();
        let payload = b"test";
        let framed = frame_message(payload, &TcpFramingMode::LengthPrefix, &mut buf);
        assert_eq!(&framed[..4], &[0, 0, 0, 4]); // 4 bytes big-endian
        assert_eq!(&framed[4..], b"test");
    }

    #[test]
    fn test_frame_empty_payload() {
        let mut buf = Vec::new();
        let framed = frame_message(b"", &TcpFramingMode::Newline, &mut buf);
        assert_eq!(framed, b"\n");

        let framed = frame_message(b"", &TcpFramingMode::OctetCounting, &mut buf);
        assert_eq!(framed, b"0 ");

        let framed = frame_message(b"", &TcpFramingMode::LengthPrefix, &mut buf);
        assert_eq!(&framed[..4], &[0, 0, 0, 0]);
        assert_eq!(framed.len(), 4);
    }
}
