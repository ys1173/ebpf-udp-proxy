//! AF_XDP high-performance forwarding path.
//!
//! Combines XDP redirect to AF_XDP socket (zero-copy receive) with userspace
//! round-robin forwarding via sendmmsg. This path offers near-kernel performance
//! for receive while retaining full flexibility for packet processing in userspace.
//!
//! Architecture:
//! 1. XDP program classifies packets by port and redirects to AF_XDP socket
//! 2. Userspace reads complete L2 frames from the RX ring (shared UMEM)
//! 3. Parses Eth/IP/UDP headers, extracts UDP payload
//! 4. Forwards payload via sendmmsg to one downstream per packet (round-robin)
//! 5. Consumed buffers are returned to the fill ring for reuse
//!
//! Performance optimizations:
//! - Zero-copy receive (XDP_ZEROCOPY with XDP_COPY fallback)
//! - Batched sends via sendmmsg (single syscall for entire batch)
//! - Busy-spinning on RX ring (no poll() syscall in hot path)
//! - Per-batch ArcSwap load (amortized downstream snapshot)
//! - Pre-cached sockaddrs (no per-packet allocation)
//! - Local stats counters flushed per batch (reduced atomic contention)
//! - CPU pinning and SO_BUSY_POLL for cache locality and low latency
//!
//! MetalLB compatibility:
//! The XDP program passes all non-matching traffic (ARP, TCP, other UDP)
//! through XDP_PASS to the kernel, so MetalLB L2 mode works normally.

use std::net::SocketAddr;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;

use anyhow::{bail, Context, Result};
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

/// Total number of UMEM frames. We use 2x ring size to ensure
/// the fill ring can always be refilled while RX ring has entries.
const NUM_FRAMES: u32 = RING_SIZE * 2;

/// Total UMEM size in bytes.
const UMEM_SIZE: usize = (NUM_FRAMES * FRAME_SIZE) as usize;

/// Maximum packets to process per batch. Larger batches amortize
/// syscall overhead (one sendmmsg per batch instead of N sendto).
const MAX_BATCH_SIZE: u32 = 256;

/// Number of busy-spin iterations before falling back to poll().
/// Tuned so the spin takes roughly 10-50µs on modern CPUs.
const BUSY_SPIN_ITERS: u32 = 1000;

/// Send socket buffer size (4 MB). Large enough to absorb send bursts.
const SEND_BUF_SIZE: usize = 4 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Linux AF_XDP Constants (from <linux/if_xdp.h>)
// ---------------------------------------------------------------------------

const SOL_XDP: i32 = 283;
const XDP_MMAP_OFFSETS: i32 = 1;
const XDP_RX_RING: i32 = 2;
const XDP_UMEM_REG: i32 = 3;
const XDP_UMEM_FILL_RING: i32 = 4;
const XDP_UMEM_COMPLETION_RING: i32 = 5;
const XDP_STATISTICS: i32 = 7;

// mmap page offsets for each ring
const XDP_PGOFF_RX_RING: i64 = 0;
const XDP_PGOFF_TX_RING: i64 = 0x80000000;
const XDP_UMEM_PGOFF_FILL_RING: i64 = 0x100000000;
const XDP_UMEM_PGOFF_COMPLETION_RING: i64 = 0x180000000;

// Bind flags
const XDP_COPY: u16 = 1 << 1;
const XDP_ZEROCOPY: u16 = 1 << 2;

// Busy poll socket options (from <linux/socket.h>)
const SO_BUSY_POLL: i32 = 46;
const SO_PREFER_BUSY_POLL: i32 = 69;
const SO_BUSY_POLL_BUDGET: i32 = 70;

// ---------------------------------------------------------------------------
// AF_XDP Kernel Structs (repr(C) for FFI)
// ---------------------------------------------------------------------------

#[repr(C)]
struct XdpUmemReg {
    addr: u64,
    len: u64,
    chunk_size: u32,
    headroom: u32,
    flags: u32,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct XdpRingOffset {
    producer: u64,
    consumer: u64,
    desc: u64,
    flags: u64,
}

#[repr(C)]
#[derive(Debug, Default)]
struct XdpMmapOffsets {
    rx: XdpRingOffset,
    tx: XdpRingOffset,
    fr: XdpRingOffset, // fill ring
    cr: XdpRingOffset, // completion ring
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct XdpDesc {
    addr: u64,
    len: u32,
    options: u32,
}

#[repr(C)]
struct SockaddrXdp {
    sxdp_family: u16,
    sxdp_flags: u16,
    sxdp_ifindex: u32,
    sxdp_queue_id: u32,
    sxdp_shared_umem_fd: u32,
}

// ---------------------------------------------------------------------------
// Ring Buffer Abstraction
// ---------------------------------------------------------------------------

/// Manages a mmap'd ring buffer (producer/consumer pattern).
struct RingBuffer {
    /// Pointer to producer index (u32, atomic).
    producer: *mut u32,
    /// Pointer to consumer index (u32, atomic).
    consumer: *mut u32,
    /// Pointer to flags (u32).
    _flags: *mut u32,
    /// Pointer to the descriptor array.
    ring: *mut u8,
    /// Mask for wrapping indices (ring_size - 1).
    mask: u32,
    /// Cached producer value (for consumer-side optimization).
    cached_prod: u32,
    /// Cached consumer value (for producer-side optimization).
    cached_cons: u32,
    /// mmap base pointer (for cleanup).
    mmap_ptr: *mut u8,
    /// mmap size (for cleanup).
    mmap_len: usize,
}

unsafe impl Send for RingBuffer {}

impl RingBuffer {
    /// Read the producer index (acquire ordering for consumer reads).
    #[inline(always)]
    fn load_producer(&self) -> u32 {
        unsafe { core::ptr::read_volatile(self.producer) }
    }

    /// Read the consumer index (acquire ordering for producer reads).
    #[inline(always)]
    fn load_consumer(&self) -> u32 {
        unsafe { core::ptr::read_volatile(self.consumer) }
    }

    /// Write the producer index (release ordering).
    #[inline(always)]
    fn store_producer(&self, val: u32) {
        unsafe {
            core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
            core::ptr::write_volatile(self.producer, val);
        }
    }

    /// Write the consumer index (release ordering).
    #[inline(always)]
    fn store_consumer(&self, val: u32) {
        unsafe {
            core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
            core::ptr::write_volatile(self.consumer, val);
        }
    }
}

impl Drop for RingBuffer {
    fn drop(&mut self) {
        if !self.mmap_ptr.is_null() && self.mmap_len > 0 {
            unsafe {
                libc::munmap(self.mmap_ptr as *mut libc::c_void, self.mmap_len);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// AF_XDP Socket State
// ---------------------------------------------------------------------------

/// Complete AF_XDP socket with UMEM and ring buffers.
struct XskSocket {
    fd: RawFd,
    umem_ptr: *mut u8,
    umem_len: usize,
    fill_ring: RingBuffer,
    rx_ring: RingBuffer,
    ring_size: u32,
}

unsafe impl Send for XskSocket {}

impl XskSocket {
    /// Create and configure an AF_XDP socket.
    fn create(ifindex: u32, queue_id: u32) -> Result<Self> {
        // --- Create AF_XDP socket ---
        let fd = unsafe { libc::socket(libc::AF_XDP, libc::SOCK_RAW, 0) };
        if fd < 0 {
            bail!(
                "creating AF_XDP socket: {}",
                std::io::Error::last_os_error()
            );
        }

        info!(fd, "created AF_XDP socket");

        // --- Enable busy polling on the AF_XDP socket ---
        // SO_PREFER_BUSY_POLL tells the kernel to prefer busy-polling over IRQ
        // SO_BUSY_POLL sets the busy-poll timeout in microseconds
        // SO_BUSY_POLL_BUDGET sets max packets to process per busy-poll cycle
        Self::try_set_busy_poll(fd);

        // --- Allocate UMEM ---
        let umem_ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                UMEM_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_POPULATE,
                -1,
                0,
            )
        };
        if umem_ptr == libc::MAP_FAILED {
            unsafe { libc::close(fd) };
            bail!("mmap UMEM: {}", std::io::Error::last_os_error());
        }

        info!(
            umem_size = UMEM_SIZE,
            frame_size = FRAME_SIZE,
            num_frames = NUM_FRAMES,
            "allocated UMEM"
        );

        // --- Register UMEM ---
        let umem_reg = XdpUmemReg {
            addr: umem_ptr as u64,
            len: UMEM_SIZE as u64,
            chunk_size: FRAME_SIZE,
            headroom: 0,
            flags: 0,
        };

        let ret = unsafe {
            libc::setsockopt(
                fd,
                SOL_XDP,
                XDP_UMEM_REG,
                &umem_reg as *const _ as *const libc::c_void,
                std::mem::size_of::<XdpUmemReg>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            Self::cleanup_early(fd, umem_ptr as *mut u8);
            bail!("XDP_UMEM_REG: {}", std::io::Error::last_os_error());
        }

        // --- Set ring sizes ---
        let ring_size = RING_SIZE;
        for (opt, name) in [
            (XDP_UMEM_FILL_RING, "FILL"),
            (XDP_UMEM_COMPLETION_RING, "COMPLETION"),
            (XDP_RX_RING, "RX"),
        ] {
            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    SOL_XDP,
                    opt,
                    &ring_size as *const _ as *const libc::c_void,
                    std::mem::size_of::<u32>() as libc::socklen_t,
                )
            };
            if ret < 0 {
                Self::cleanup_early(fd, umem_ptr as *mut u8);
                bail!(
                    "setting {} ring size: {}",
                    name,
                    std::io::Error::last_os_error()
                );
            }
        }

        // --- Get mmap offsets ---
        let mut offsets = XdpMmapOffsets::default();
        let mut optlen = std::mem::size_of::<XdpMmapOffsets>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                fd,
                SOL_XDP,
                XDP_MMAP_OFFSETS,
                &mut offsets as *mut _ as *mut libc::c_void,
                &mut optlen,
            )
        };
        if ret < 0 {
            Self::cleanup_early(fd, umem_ptr as *mut u8);
            bail!("XDP_MMAP_OFFSETS: {}", std::io::Error::last_os_error());
        }

        debug!(?offsets, "got XDP mmap offsets");

        // --- mmap fill ring ---
        let fill_ring_mmap_len =
            offsets.fr.desc as usize + ring_size as usize * std::mem::size_of::<u64>();
        let fill_ring_ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                fill_ring_mmap_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                fd,
                XDP_UMEM_PGOFF_FILL_RING,
            )
        };
        if fill_ring_ptr == libc::MAP_FAILED {
            Self::cleanup_early(fd, umem_ptr as *mut u8);
            bail!("mmap fill ring: {}", std::io::Error::last_os_error());
        }

        let fill_ring = RingBuffer {
            producer: unsafe { fill_ring_ptr.byte_add(offsets.fr.producer as usize) as *mut u32 },
            consumer: unsafe { fill_ring_ptr.byte_add(offsets.fr.consumer as usize) as *mut u32 },
            _flags: unsafe {
                fill_ring_ptr.byte_add(offsets.fr.flags as usize) as *mut u32
            },
            ring: unsafe { fill_ring_ptr.byte_add(offsets.fr.desc as usize) as *mut u8 },
            mask: ring_size - 1,
            cached_prod: 0,
            cached_cons: 0,
            mmap_ptr: fill_ring_ptr as *mut u8,
            mmap_len: fill_ring_mmap_len,
        };

        // --- mmap RX ring ---
        let rx_ring_mmap_len =
            offsets.rx.desc as usize + ring_size as usize * std::mem::size_of::<XdpDesc>();
        let rx_ring_ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                rx_ring_mmap_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                fd,
                XDP_PGOFF_RX_RING,
            )
        };
        if rx_ring_ptr == libc::MAP_FAILED {
            // fill_ring will be cleaned up when dropped
            Self::cleanup_early(fd, umem_ptr as *mut u8);
            bail!("mmap RX ring: {}", std::io::Error::last_os_error());
        }

        let rx_ring = RingBuffer {
            producer: unsafe { rx_ring_ptr.byte_add(offsets.rx.producer as usize) as *mut u32 },
            consumer: unsafe { rx_ring_ptr.byte_add(offsets.rx.consumer as usize) as *mut u32 },
            _flags: unsafe {
                rx_ring_ptr.byte_add(offsets.rx.flags as usize) as *mut u32
            },
            ring: unsafe { rx_ring_ptr.byte_add(offsets.rx.desc as usize) as *mut u8 },
            mask: ring_size - 1,
            cached_prod: 0,
            cached_cons: 0,
            mmap_ptr: rx_ring_ptr as *mut u8,
            mmap_len: rx_ring_mmap_len,
        };

        // --- Bind to interface + queue ---
        // Try zero-copy first for best performance, then copy mode for compatibility
        let bind_mode = Self::bind_socket(fd, ifindex, queue_id)?;

        info!(
            ifindex,
            queue_id,
            ring_size,
            mode = bind_mode,
            "AF_XDP socket bound"
        );

        Ok(Self {
            fd,
            umem_ptr: umem_ptr as *mut u8,
            umem_len: UMEM_SIZE,
            fill_ring,
            rx_ring,
            ring_size,
        })
    }

    /// Try to bind with zero-copy, then copy mode, then default.
    fn bind_socket(fd: RawFd, ifindex: u32, queue_id: u32) -> Result<&'static str> {
        // Try zero-copy first (best performance — NIC DMA's directly into UMEM)
        let sxdp_zc = SockaddrXdp {
            sxdp_family: libc::AF_XDP as u16,
            sxdp_flags: XDP_ZEROCOPY,
            sxdp_ifindex: ifindex,
            sxdp_queue_id: queue_id,
            sxdp_shared_umem_fd: 0,
        };

        let ret = unsafe {
            libc::bind(
                fd,
                &sxdp_zc as *const _ as *const libc::sockaddr,
                std::mem::size_of::<SockaddrXdp>() as libc::socklen_t,
            )
        };
        if ret == 0 {
            return Ok("zero-copy");
        }
        let zc_err = std::io::Error::last_os_error();
        warn!(
            error = %zc_err,
            "XDP_ZEROCOPY bind failed, trying XDP_COPY mode"
        );

        // Fall back to copy mode
        let sxdp_copy = SockaddrXdp {
            sxdp_flags: XDP_COPY,
            ..sxdp_zc
        };

        let ret = unsafe {
            libc::bind(
                fd,
                &sxdp_copy as *const _ as *const libc::sockaddr,
                std::mem::size_of::<SockaddrXdp>() as libc::socklen_t,
            )
        };
        if ret == 0 {
            return Ok("copy");
        }
        let copy_err = std::io::Error::last_os_error();
        warn!(
            error = %copy_err,
            "XDP_COPY bind failed, trying default mode"
        );

        // Final fallback — no flags
        let sxdp_default = SockaddrXdp {
            sxdp_flags: 0,
            ..sxdp_zc
        };

        let ret = unsafe {
            libc::bind(
                fd,
                &sxdp_default as *const _ as *const libc::sockaddr,
                std::mem::size_of::<SockaddrXdp>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            bail!(
                "bind AF_XDP socket to ifindex={} queue={}: zero-copy: {}, copy: {}, default: {}",
                ifindex,
                queue_id,
                zc_err,
                copy_err,
                std::io::Error::last_os_error()
            );
        }

        Ok("default")
    }

    /// Try to enable busy polling on the AF_XDP socket.
    /// This is best-effort — fails silently on older kernels.
    fn try_set_busy_poll(fd: RawFd) {
        // Enable busy poll preference
        let enable: i32 = 1;
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                SO_PREFER_BUSY_POLL,
                &enable as *const _ as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            debug!(
                "SO_PREFER_BUSY_POLL not supported: {}",
                std::io::Error::last_os_error()
            );
            return;
        }

        // Set busy poll timeout (microseconds)
        let timeout_us: i32 = 20; // 20µs busy poll
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                SO_BUSY_POLL,
                &timeout_us as *const _ as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            debug!(
                "SO_BUSY_POLL not supported: {}",
                std::io::Error::last_os_error()
            );
            return;
        }

        // Set busy poll budget (max packets per poll)
        let budget: i32 = 256;
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                SO_BUSY_POLL_BUDGET,
                &budget as *const _ as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            debug!(
                "SO_BUSY_POLL_BUDGET not supported: {}",
                std::io::Error::last_os_error()
            );
        }

        info!("AF_XDP busy polling enabled (timeout={}µs, budget={})", timeout_us, budget);
    }

    /// Pre-fill the fill ring with UMEM frame addresses.
    /// This tells the kernel which frames are available for receiving packets.
    fn prefill(&mut self) -> Result<()> {
        let ring_size = self.ring_size;

        for i in 0..ring_size {
            let frame_addr = (i as u64) * (FRAME_SIZE as u64);
            unsafe {
                let slot = self
                    .fill_ring
                    .ring
                    .add((i & self.fill_ring.mask) as usize * std::mem::size_of::<u64>())
                    as *mut u64;
                *slot = frame_addr;
            }
        }

        // Update producer to indicate all frames are available
        self.fill_ring.store_producer(ring_size);
        self.fill_ring.cached_prod = ring_size;

        info!(frames = ring_size, "pre-filled fill ring");
        Ok(())
    }

    /// Poll the RX ring for received packets.
    ///
    /// Returns descriptors (addr, len) of received packets in the UMEM.
    /// Caller must process packets and then call `refill()` to return frames.
    #[inline(always)]
    fn poll_rx(&mut self, batch: &mut Vec<(u64, u32)>) -> usize {
        batch.clear();

        let prod = self.rx_ring.load_producer();
        let cons = self.rx_ring.load_consumer();
        let available = prod.wrapping_sub(cons);

        if available == 0 {
            return 0;
        }

        // Ensure memory ordering — acquire fence before reading descriptors
        unsafe {
            core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
        }

        let to_read = available.min(MAX_BATCH_SIZE);

        for i in 0..to_read {
            let idx = (cons.wrapping_add(i) & self.rx_ring.mask) as usize;
            let desc = unsafe {
                let ptr = self
                    .rx_ring
                    .ring
                    .add(idx * std::mem::size_of::<XdpDesc>()) as *const XdpDesc;
                *ptr
            };
            batch.push((desc.addr, desc.len));
        }

        // Advance consumer
        self.rx_ring
            .store_consumer(cons.wrapping_add(to_read));

        to_read as usize
    }

    /// Return consumed frame addresses to the fill ring.
    #[inline(always)]
    fn refill(&mut self, addrs: &[u64]) -> Result<()> {
        if addrs.is_empty() {
            return Ok(());
        }

        let prod = self.fill_ring.cached_prod;
        let cons = self.fill_ring.load_consumer();
        let free_slots = self.ring_size.wrapping_sub(prod.wrapping_sub(cons));

        if (addrs.len() as u32) > free_slots {
            bail!(
                "fill ring full: need {} slots, have {}",
                addrs.len(),
                free_slots
            );
        }

        for (i, &addr) in addrs.iter().enumerate() {
            let idx =
                (prod.wrapping_add(i as u32) & self.fill_ring.mask) as usize;
            unsafe {
                let slot = self
                    .fill_ring
                    .ring
                    .add(idx * std::mem::size_of::<u64>())
                    as *mut u64;
                *slot = addr;
            }
        }

        // Memory barrier before updating producer
        let new_prod = prod.wrapping_add(addrs.len() as u32);
        self.fill_ring.store_producer(new_prod);
        self.fill_ring.cached_prod = new_prod;

        Ok(())
    }

    /// Get the raw file descriptor (for poll/select and XSKMAP registration).
    fn raw_fd(&self) -> RawFd {
        self.fd
    }

    /// Read a packet's data from the UMEM.
    ///
    /// Returns a slice into the mmap'd UMEM memory (zero-copy read).
    #[inline(always)]
    fn packet_data(&self, addr: u64, len: u32) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(self.umem_ptr.add(addr as usize), len as usize)
        }
    }

    fn cleanup_early(fd: RawFd, umem_ptr: *mut u8) {
        unsafe {
            libc::close(fd);
            if !umem_ptr.is_null() {
                libc::munmap(umem_ptr as *mut libc::c_void, UMEM_SIZE);
            }
        }
    }
}

impl Drop for XskSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
            if !self.umem_ptr.is_null() {
                libc::munmap(self.umem_ptr as *mut libc::c_void, self.umem_len);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Packet Parsing
// ---------------------------------------------------------------------------

/// Parse L2/L3/L4 headers from a raw frame and extract UDP payload.
///
/// Returns (payload_offset, payload_len) into the frame data,
/// or None if the frame is not a valid IPv4/UDP packet.
#[inline(always)]
fn parse_udp_payload(frame: &[u8]) -> Option<(usize, usize)> {
    // Minimum: Eth(14) + IP(20) + UDP(8) = 42
    if frame.len() < 42 {
        return None;
    }

    // Check EtherType (offset 12, big-endian)
    let ether_type = u16::from_be_bytes([frame[12], frame[13]]);
    if ether_type != 0x0800 {
        return None;
    }

    // Parse IP header
    let ip_start = 14;
    let ver_ihl = frame[ip_start];
    let ihl = (ver_ihl & 0x0F) as usize;
    let ip_hdr_len = ihl * 4;
    if ip_hdr_len < 20 {
        return None;
    }

    let protocol = frame[ip_start + 9];
    if protocol != 17 {
        // Not UDP
        return None;
    }

    // UDP header
    let udp_start = ip_start + ip_hdr_len;
    if frame.len() < udp_start + 8 {
        return None;
    }

    let udp_len =
        u16::from_be_bytes([frame[udp_start + 4], frame[udp_start + 5]]) as usize;

    // UDP payload
    let payload_start = udp_start + 8;
    let payload_len = if udp_len >= 8 {
        udp_len - 8
    } else {
        return None;
    };

    // Bounds check
    if payload_start + payload_len > frame.len() {
        // Truncated — use what we have
        let available = frame.len().saturating_sub(payload_start);
        if available == 0 {
            return None;
        }
        return Some((payload_start, available));
    }

    Some((payload_start, payload_len))
}

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
    pub parse_errors: AtomicU64,
}

/// A running AF_XDP forwarding instance.
pub struct AfXdpForwarder {
    thread: Option<thread::JoinHandle<()>>,
    shutdown: Arc<AtomicBool>,
    pub stats: Arc<AfXdpStats>,
    k8s_task: Option<tokio::task::JoinHandle<()>>,
    /// The AF_XDP socket fd, needed for XSKMAP registration.
    pub xsk_fd: RawFd,
}

impl AfXdpForwarder {
    /// Start the AF_XDP forwarder for the given listener config.
    ///
    /// The `ifindex` is the network interface index (resolved by XDP manager).
    /// The `queue_id` is the RX queue to bind to.
    ///
    /// Returns the forwarder (with xsk_fd for XSKMAP registration).
    pub fn start(
        config: &ListenerConfig,
        ifindex: u32,
        queue_id: u32,
    ) -> Result<Self> {
        let shutdown = Arc::new(AtomicBool::new(false));
        let stats = Arc::new(AfXdpStats::default());
        let rr_counter = Arc::new(AtomicU64::new(0));

        // Create AF_XDP socket
        let mut xsk = XskSocket::create(ifindex, queue_id)
            .context("creating AF_XDP socket")?;

        // Pre-fill the fill ring
        xsk.prefill().context("pre-filling fill ring")?;

        let xsk_fd = xsk.raw_fd();

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

        let shutdown_clone = shutdown.clone();
        let stats_clone = stats.clone();
        let name = config.name.clone();
        let pin_cpus = config.settings.pin_cpus;

        info!(
            listener = %name,
            ifindex,
            queue_id,
            xsk_fd,
            downstreams = downstreams.load().len(),
            ring_size = RING_SIZE,
            batch_size = MAX_BATCH_SIZE,
            kubernetes = config.kubernetes.is_some(),
            pin_cpus,
            "starting AF_XDP forwarder"
        );

        let thread = thread::Builder::new()
            .name(format!("afxdp-{}-q{}", name, queue_id))
            .spawn(move || {
                // Pin to CPU core matching queue_id for NUMA locality
                if pin_cpus {
                    if let Some(core_id) = (core_affinity::CoreId { id: queue_id as usize }).into() {
                        core_affinity::set_for_current(core_id);
                        info!(
                            listener = %name,
                            queue_id,
                            core = queue_id,
                            "AF_XDP worker pinned to CPU core"
                        );
                    }
                }

                if let Err(e) = af_xdp_worker(
                    xsk,
                    &downstreams,
                    &rr_counter,
                    &shutdown_clone,
                    &stats_clone,
                    &name,
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
            xsk_fd,
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
// Local Stats — batch-flush to avoid atomic contention per packet
// ---------------------------------------------------------------------------

/// Thread-local stats counters, flushed to shared atomics once per batch.
struct LocalStats {
    pkts_received: u64,
    pkts_forwarded: u64,
    pkts_dropped: u64,
    pkts_no_healthy: u64,
    bytes_received: u64,
    bytes_forwarded: u64,
    parse_errors: u64,
}

impl LocalStats {
    fn new() -> Self {
        Self {
            pkts_received: 0,
            pkts_forwarded: 0,
            pkts_dropped: 0,
            pkts_no_healthy: 0,
            bytes_received: 0,
            bytes_forwarded: 0,
            parse_errors: 0,
        }
    }

    /// Flush local counters to shared atomics and reset.
    #[inline]
    fn flush(&mut self, stats: &AfXdpStats) {
        if self.pkts_received > 0 {
            stats.pkts_received.fetch_add(self.pkts_received, Ordering::Relaxed);
            self.pkts_received = 0;
        }
        if self.pkts_forwarded > 0 {
            stats.pkts_forwarded.fetch_add(self.pkts_forwarded, Ordering::Relaxed);
            self.pkts_forwarded = 0;
        }
        if self.pkts_dropped > 0 {
            stats.pkts_dropped.fetch_add(self.pkts_dropped, Ordering::Relaxed);
            self.pkts_dropped = 0;
        }
        if self.pkts_no_healthy > 0 {
            stats.pkts_no_healthy.fetch_add(self.pkts_no_healthy, Ordering::Relaxed);
            self.pkts_no_healthy = 0;
        }
        if self.bytes_received > 0 {
            stats.bytes_received.fetch_add(self.bytes_received, Ordering::Relaxed);
            self.bytes_received = 0;
        }
        if self.bytes_forwarded > 0 {
            stats.bytes_forwarded.fetch_add(self.bytes_forwarded, Ordering::Relaxed);
            self.bytes_forwarded = 0;
        }
        if self.parse_errors > 0 {
            stats.parse_errors.fetch_add(self.parse_errors, Ordering::Relaxed);
            self.parse_errors = 0;
        }
    }
}

// ---------------------------------------------------------------------------
// AF_XDP Worker
// ---------------------------------------------------------------------------

/// Main AF_XDP receive + forward loop.
///
/// Hot path optimizations:
/// - Busy-spins on RX ring producer pointer (no poll() syscall)
/// - Batches sends into a single sendmmsg() syscall
/// - Loads downstream snapshot once per batch (not per packet)
/// - Uses local stats counters flushed per batch
/// - Pre-caches sockaddr for each downstream
fn af_xdp_worker(
    mut xsk: XskSocket,
    downstreams: &ArcSwap<Vec<SocketAddr>>,
    rr_counter: &AtomicU64,
    shutdown: &AtomicBool,
    stats: &AfXdpStats,
    name: &str,
) -> Result<()> {
    // Create send socket for downstream forwarding
    let send_sock = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .context("creating send socket")?;

    // Set non-blocking for sendto/sendmmsg
    send_sock.set_nonblocking(true)?;

    // Enlarge send buffer to absorb bursts
    if let Err(e) = send_sock.set_send_buffer_size(SEND_BUF_SIZE) {
        warn!(error = %e, "failed to set SO_SNDBUF (continuing with default)");
    } else {
        info!(send_buf_size = SEND_BUF_SIZE, "send socket buffer configured");
    }

    let send_fd = send_sock.as_raw_fd();

    // Set up poll fd for the AF_XDP socket (fallback when idle)
    let mut pollfd = libc::pollfd {
        fd: xsk.raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };

    info!(listener = %name, "entering AF_XDP receive loop");

    let mut rx_batch: Vec<(u64, u32)> = Vec::with_capacity(MAX_BATCH_SIZE as usize);
    let mut refill_addrs: Vec<u64> = Vec::with_capacity(MAX_BATCH_SIZE as usize);
    let mut local_stats = LocalStats::new();

    // Pre-allocated sendmmsg buffers
    let mut send_iovecs: Vec<libc::iovec> = Vec::with_capacity(MAX_BATCH_SIZE as usize);
    let mut send_msgs: Vec<libc::mmsghdr> = Vec::with_capacity(MAX_BATCH_SIZE as usize);

    // Cached downstream sockaddrs: (SocketAddr, socket2::SockAddr)
    // Rebuilt only when the downstream snapshot changes (detected via data pointer).
    let mut cached_ds: Vec<(SocketAddr, socket2::SockAddr)> = Vec::new();
    let mut cached_ds_data_ptr: *const SocketAddr = std::ptr::null();
    let mut cached_ds_len: usize = 0;

    while !shutdown.load(Ordering::Relaxed) {
        // --- Busy-spin on RX ring before falling back to poll() ---
        let mut received = 0;
        for _ in 0..BUSY_SPIN_ITERS {
            received = xsk.poll_rx(&mut rx_batch);
            if received > 0 {
                break;
            }
            // Pause hint — reduces power consumption and pipeline stalls
            core::hint::spin_loop();
        }

        if received == 0 {
            // Nothing after busy-spin — fall back to poll() with short timeout
            // This avoids burning 100% CPU when there's no traffic.
            pollfd.revents = 0;
            let poll_ret = unsafe { libc::poll(&mut pollfd, 1, 10) };
            if poll_ret < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err.into());
            }
            if poll_ret == 0 {
                // Timeout — check shutdown and retry
                continue;
            }

            // poll() says data ready — read it
            received = xsk.poll_rx(&mut rx_batch);
            if received == 0 {
                stats.rx_ring_empty.fetch_add(1, Ordering::Relaxed);
                continue;
            }
        }

        // --- Load downstream snapshot once per batch ---
        let ds_guard = downstreams.load();
        let ds_snapshot: &Vec<SocketAddr> = &*ds_guard;

        if ds_snapshot.is_empty() {
            // No healthy downstreams — drop entire batch
            local_stats.pkts_received += received as u64;
            local_stats.pkts_no_healthy += received as u64;
            local_stats.pkts_dropped += received as u64;
            for &(addr, len) in &rx_batch {
                local_stats.bytes_received += len as u64;
                refill_addrs.push(addr);
            }
            // Refill and flush
            if !refill_addrs.is_empty() {
                if let Err(e) = xsk.refill(&refill_addrs) {
                    warn!(error = %e, "failed to refill AF_XDP ring");
                    stats.fill_ring_full.fetch_add(1, Ordering::Relaxed);
                }
                refill_addrs.clear();
            }
            local_stats.flush(stats);
            continue;
        }

        // --- Update cached sockaddrs if downstream snapshot changed ---
        // Compare the Vec's underlying data pointer (stable for the same allocation).
        let ds_new_data_ptr = ds_snapshot.as_ptr();
        let ds_new_len = ds_snapshot.len();
        if ds_new_data_ptr != cached_ds_data_ptr || ds_new_len != cached_ds_len {
            cached_ds.clear();
            for addr in ds_snapshot.iter() {
                cached_ds.push((*addr, (*addr).into()));
            }
            cached_ds_data_ptr = ds_new_data_ptr;
            cached_ds_len = ds_new_len;
        }

        // --- Parse batch and prepare sendmmsg ---
        send_iovecs.clear();
        send_msgs.clear();
        refill_addrs.clear();

        // Track which parsed packets are ready to send
        // We need to keep payload slices alive (they reference UMEM), so we
        // collect (offset, len, dst_idx) tuples first.
        struct SendEntry {
            /// Index into rx_batch for UMEM refill tracking
            payload_ptr: *const u8,
            payload_len: usize,
            ds_idx: usize,
        }

        let mut send_entries: Vec<SendEntry> = Vec::with_capacity(received);

        let ds_len = cached_ds.len();

        for &(addr, len) in &rx_batch {
            let frame = xsk.packet_data(addr, len);

            local_stats.pkts_received += 1;
            local_stats.bytes_received += len as u64;

            // Parse headers and extract UDP payload
            let (payload_offset, payload_len) = match parse_udp_payload(frame) {
                Some(p) => p,
                None => {
                    local_stats.parse_errors += 1;
                    local_stats.pkts_dropped += 1;
                    refill_addrs.push(addr);
                    continue;
                }
            };

            let payload = &frame[payload_offset..payload_offset + payload_len];

            // Round-robin to one downstream
            let idx = (rr_counter.fetch_add(1, Ordering::Relaxed) as usize) % ds_len;

            send_entries.push(SendEntry {
                payload_ptr: payload.as_ptr(),
                payload_len,
                ds_idx: idx,
            });

            // Don't refill yet — payload references UMEM memory
        }

        // --- Build sendmmsg batch ---
        // SAFETY: payload_ptr points into UMEM which stays mapped for lifetime of xsk
        for entry in &send_entries {
            send_iovecs.push(libc::iovec {
                iov_base: entry.payload_ptr as *mut libc::c_void,
                iov_len: entry.payload_len,
            });
        }

        // Build mmsghdr array referencing iovecs and cached sockaddrs
        for (i, entry) in send_entries.iter().enumerate() {
            let sockaddr = &cached_ds[entry.ds_idx].1;
            let mut hdr: libc::mmsghdr = unsafe { std::mem::zeroed() };
            hdr.msg_hdr.msg_iov = &mut send_iovecs[i] as *mut libc::iovec;
            hdr.msg_hdr.msg_iovlen = 1;
            hdr.msg_hdr.msg_name = sockaddr.as_ptr() as *mut libc::c_void;
            hdr.msg_hdr.msg_namelen = sockaddr.len() as libc::socklen_t;
            send_msgs.push(hdr);
        }

        // --- Fire the batch with a single sendmmsg() syscall ---
        if !send_msgs.is_empty() {
            let sent = unsafe {
                libc::sendmmsg(
                    send_fd,
                    send_msgs.as_mut_ptr(),
                    send_msgs.len() as libc::c_uint,
                    libc::MSG_DONTWAIT as libc::c_int,
                )
            };

            if sent < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() != std::io::ErrorKind::WouldBlock {
                    warn!(error = %err, "AF_XDP sendmmsg error");
                }
                // All packets in this batch are dropped
                local_stats.pkts_dropped += send_entries.len() as u64;
            } else {
                let sent = sent as usize;
                // Count sent packets
                for i in 0..sent {
                    local_stats.pkts_forwarded += 1;
                    local_stats.bytes_forwarded += send_entries[i].payload_len as u64;
                }
                // Count unsent (partial send)
                if sent < send_entries.len() {
                    local_stats.pkts_dropped += (send_entries.len() - sent) as u64;
                }
            }
        }

        // --- Now refill ALL frames (including ones we sent from) ---
        for &(addr, _) in &rx_batch {
            refill_addrs.push(addr);
        }

        if !refill_addrs.is_empty() {
            if let Err(e) = xsk.refill(&refill_addrs) {
                warn!(error = %e, "failed to refill AF_XDP ring");
                stats.fill_ring_full.fetch_add(1, Ordering::Relaxed);
            }
            refill_addrs.clear();
        }

        // --- Flush local stats to shared atomics ---
        local_stats.flush(stats);
    }

    info!(listener = %name, "AF_XDP receive loop exited");
    Ok(())
}
