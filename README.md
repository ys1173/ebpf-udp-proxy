# ebpf-udp-proxy

High-performance UDP load-balancing proxy with eBPF kernel bypass for Kubernetes.

Receives UDP datagrams on one or more listeners and forwards each packet to exactly one downstream receiver using round-robin selection. Three forwarding paths cover different deployment scenarios — from line-rate kernel-only forwarding to MetalLB-compatible AF_XDP to portable userspace fallback.

## Forwarding Modes

### TC eBPF (`tc_ebpf`)

Kernel-only forwarding via TC ingress hook. The eBPF program rewrites L3/L4 headers, performs a FIB lookup for routing, and calls `bpf_redirect_neigh()` to send the packet directly to the downstream pod's veth interface. The packet never enters userspace on the proxy node.

Best for: bare-metal or cloud deployments where the proxy runs on the host network without MetalLB.

### AF_XDP (`af_xdp`)

XDP program on the physical NIC redirects matching UDP packets to an AF_XDP socket via XSKMAP. Userspace reads complete L2 frames from shared UMEM ring buffers (zero-copy receive), parses headers, extracts the UDP payload, and forwards via `sendto` to one downstream. All non-matching traffic (ARP, TCP, other UDP) passes through `XDP_PASS` to the kernel stack untouched.

Best for: Kubernetes with MetalLB L2 mode. Because ARP passes through normally, MetalLB can claim virtual IPs without conflict. No dummy interface workaround needed.

### Userspace (`userspace`)

Pure userspace path using `recvmmsg`/`sendmmsg` batched I/O with SO_REUSEPORT multi-worker threads and optional CPU pinning. No eBPF, no root required beyond binding the listen port.

Best for: development, testing, or environments where eBPF is unavailable.

## Features

- **Round-robin load balancing**: One packet → one downstream, cycling through available receivers. Per-CPU counters (eBPF) or atomics (userspace/AF_XDP) for lock-free distribution
- **Kubernetes EndpointSlice discovery**: Automatic downstream discovery from Service selectors — no manual IP configuration
- **Health monitoring**: Active ICMP ping or UDP echo probes with automatic disable after 3 consecutive failures
- **Prometheus metrics**: Per-listener packet/byte counters with mode labels, plus AF_XDP-specific ring buffer metrics
- **No buffering, no backpressure**: Fire-and-forget forwarding. If the send buffer is full (EAGAIN), the packet is dropped and counted
- **YAML configuration**: Simple config with per-listener mode selection, K8s discovery, and tuning knobs

## Architecture

```
                    ┌─────────────────────────────────────────────┐
                    │              Forwarding Modes                │
                    ├─────────────┬──────────────┬────────────────┤
                    │  TC eBPF    │   AF_XDP     │   Userspace    │
                    │             │              │                │
  Incoming UDP ───► │ TC ingress  │ XDP hook     │ recvmmsg()     │
                    │ FIB lookup  │ XSKMAP redir │ on UDP socket  │
                    │ redirect_   │ UMEM rx ring │                │
                    │ neigh()     │ parse + strip│                │
                    │             │ headers      │                │
  Outgoing UDP ◄── │ direct to   │ sendto()     │ sendto()       │
                    │ pod veth    │ round-robin  │ round-robin    │
                    └─────────────┴──────────────┴────────────────┘
                                        │
                            ┌───────────┼───────────┐
                         pod-1       pod-2       pod-3
                       receiver    receiver    receiver
```

## Quick Start

### Prerequisites

- Rust stable (1.75+) + nightly (for eBPF programs)
- `bpf-linker`: `cargo install bpf-linker`
- System packages: `clang`, `llvm`, `libelf-dev`
- Linux kernel 5.10+ (for `bpf_redirect_neigh` in TC mode)
- Linux kernel 4.18+ (for AF_XDP mode)
- Kubernetes 1.19+ (for EndpointSlice discovery)

### Build

```bash
# Build everything: TC eBPF + XDP eBPF + userspace daemon
cargo xtask build --release

# Outputs:
#   target/release/udp-fanout       # userspace daemon
#   target/udp-fanout-ebpf          # TC eBPF program (BPF ELF)
#   target/udp-fanout-ebpf-xdp     # XDP eBPF program (BPF ELF)

# Build individual components
cargo xtask build-ebpf --release       # TC eBPF only
cargo xtask build-ebpf-xdp --release   # XDP eBPF only
```

### Run Locally (Userspace Mode)

```bash
./target/release/udp-fanout --config config.example.yaml

# Send test traffic
echo "test" | nc -u localhost 5514
```

### Run with TC eBPF (Requires Root)

```bash
sudo ./target/release/udp-fanout \
  --config config.yaml \
  --ebpf-program target/udp-fanout-ebpf
```

### Run with AF_XDP (Requires Root)

```bash
sudo ./target/release/udp-fanout \
  --config config.yaml \
  --xdp-program target/udp-fanout-ebpf-xdp
```

## Configuration

### Userspace Mode

```yaml
listeners:
  - name: syslog
    bind: "0.0.0.0:5514"
    mode: userspace
    downstream:
      - name: sink-1
        address: "10.0.0.1:5514"
      - name: sink-2
        address: "10.0.0.2:5514"
```

### TC eBPF with Kubernetes Discovery

```yaml
listeners:
  - name: syslog
    bind: "0.0.0.0:5514"
    interface: eth0
    mode: tc_ebpf
    kubernetes:
      namespace: logging
      service: vector-receivers
      port: 5514

health:
  enabled: true
  interval_secs: 5
  timeout_secs: 2
  protocol: icmp

metrics:
  enabled: true
  bind: "0.0.0.0:9090"
```

### AF_XDP with MetalLB

```yaml
listeners:
  - name: market-data
    bind: "0.0.0.0:9000"
    interface: eth0
    mode: af_xdp
    kubernetes:
      namespace: trading
      service: udp-receivers
      port: 9000

health:
  enabled: true
  protocol: udp_echo

metrics:
  enabled: true
  bind: "0.0.0.0:9090"
```

See [config.example.yaml](config.example.yaml) for all options including batch size, worker count, recv buffer size, and max packet size.

## Kubernetes Deployment

```bash
# Apply RBAC for EndpointSlice read access
kubectl apply -f k8s/rbac.yaml

# Deploy as DaemonSet
kubectl apply -f k8s/daemonset.yaml

# For MetalLB deployments (AF_XDP mode)
kubectl apply -f k8s/service-metallb.yaml
kubectl apply -f k8s/daemonset.yaml  # with mode: af_xdp in configmap
```

The DaemonSet requires `hostNetwork: true` and capabilities `CAP_NET_ADMIN`, `CAP_BPF`, `CAP_SYS_RESOURCE` for eBPF/XDP attachment.

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for the full deployment guide and [docs/METALLB_DEPLOYMENT.md](docs/METALLB_DEPLOYMENT.md) for MetalLB-specific details.

## Monitoring

Prometheus metrics on `:9090/metrics`:

```
udp_fanout_packets_received_total{listener="syslog",mode="tc_ebpf"} 1584302
udp_fanout_packets_forwarded_total{listener="syslog",mode="tc_ebpf"} 1584298
udp_fanout_packets_dropped_total{listener="syslog",mode="tc_ebpf"} 4
udp_fanout_bytes_received_total{listener="syslog",mode="tc_ebpf"} 792151000
udp_fanout_bytes_forwarded_total{listener="syslog",mode="tc_ebpf"} 792149000

# AF_XDP-specific
udp_fanout_afxdp_rx_ring_empty_total{listener="market-data",mode="af_xdp"} 12
udp_fanout_afxdp_fill_ring_full_total{listener="market-data",mode="af_xdp"} 0
udp_fanout_afxdp_parse_errors_total{listener="market-data",mode="af_xdp"} 0
```

## Docker Build

```bash
# Multi-stage build (eBPF nightly + userspace stable + runtime)
docker build -t ebpf-udp-proxy:latest .
```

## Project Structure

```
├── udp-fanout/                  # Userspace daemon
│   └── src/
│       ├── main.rs              # CLI, lifecycle, mode dispatch
│       ├── config.rs            # YAML config parsing and validation
│       ├── af_xdp.rs            # AF_XDP socket, UMEM, ring buffers, forwarding
│       ├── xdp_manager.rs       # XDP program loading and XSKMAP management
│       ├── ebpf_manager.rs      # TC eBPF program loading and map management
│       ├── userspace.rs         # recvmmsg/sendmmsg multi-worker forwarding
│       ├── kubernetes.rs        # EndpointSlice watcher for downstream discovery
│       ├── health.rs            # ICMP/UDP health probes
│       └── metrics.rs           # Prometheus metrics endpoint
├── udp-fanout-ebpf/             # TC eBPF program (bpfel-unknown-none target)
│   └── src/
│       ├── main.rs              # TC classifier entry, maps
│       └── fanout.rs            # Round-robin, FIB lookup, bpf_redirect_neigh
├── udp-fanout-ebpf-xdp/        # XDP eBPF program (bpfel-unknown-none target)
│   └── src/
│       └── main.rs              # XDP hook, XSKMAP redirect, port filter
├── udp-fanout-common/           # Shared no_std types (eBPF + userspace)
│   └── src/
│       └── lib.rs               # Map types, constants, protocol defs
├── xtask/                       # Build helper (cargo xtask)
├── k8s/                         # Kubernetes manifests
├── docs/                        # Deployment and architecture docs
└── Dockerfile                   # Multi-stage container build
```

## Performance Tuning

### AF_XDP Mode Performance Characteristics

AF_XDP mode achieves **~30,000 packets/sec per core** at maximum CPU utilization. Performance scales linearly with the number of cores when properly configured with RSS (Receive Side Scaling).

**Tested Performance (AWS t3.medium, 2 cores, native XDP)**:
- 30k pkt/sec: 1 core @ ~100% CPU
- 60k pkt/sec: 2 cores @ ~100% CPU (requires RSS and multi-source traffic)
- 120k+ pkt/sec: 4+ cores (requires larger instance)

### Native XDP Requirements (AWS ENA Driver)

For **native XDP mode** (driver-level packet interception), the AWS ENA driver requires:

1. **MTU ≤ 3498 bytes** (jumbo frames not supported with XDP)
   ```bash
   sudo ip link set ens5 mtu 3498
   ```

2. **Queue count ≤ 50% of max queues**
   ```bash
   # Check max queues
   ethtool -l ens5

   # If max=2, set to 1 for native XDP
   sudo ethtool -L ens5 combined 1

   # If max=4+, set to 2 for dual-core processing
   sudo ethtool -L ens5 combined 2
   ```

3. **Minimum instance size**: t3.medium or larger
   - For **multi-core** (2+ queues with XDP): Requires 4+ max queues
   - Recommended: **c5n.large** or **c6i.large** (4 queues → 2 XDP queues)

**Startup logs verify native XDP**:
```
INFO attached XDP program interface="ens5" mode="native"  ✓ Good
WARN native XDP attach failed, trying SKB mode            ✗ Falls back to slower mode
```

### Multi-Core Scaling

The proxy automatically detects available RX queues and spawns one AF_XDP forwarder per queue. Each forwarder runs on a separate core.

**Current config** (1 listener → N cores):
```yaml
listeners:
  - name: "vector-af-xdp"
    mode: af_xdp
    bind: "172.31.25.200:514"
    interface: "ens5"
```

With 2 queues available, this automatically creates:
- `vector-af-xdp-q0` on queue 0
- `vector-af-xdp-q1` on queue 1

**Startup logs**:
```
INFO detected available RX queues on interface num_queues=2
INFO AF_XDP path initialized listeners=1 forwarders=2 queues_per_listener=2
```

### RSS (Receive Side Scaling) Configuration

Multi-core performance requires **RSS** to distribute packets across queues. RSS hashes incoming packets based on the 5-tuple (src IP, src port, dst IP, dst port, protocol).

**Key insight**: Traffic from a **single source IP** will hash to the **same queue**, utilizing only one core. To activate all cores:
- Send from **multiple source IPs** (e.g., multiple log generators)
- Use different **source ports** in your application
- Distribute traffic from multiple hosts

**Check RSS distribution**:
```bash
# View RSS hash configuration
ethtool -x ens5

# Monitor per-queue packet counts
ethtool -S ens5 | grep "queue.*packets"

# Check per-queue interrupts
cat /proc/interrupts | grep ens5
```

**Verify multi-core utilization**:
```bash
# Show per-thread CPU usage
top -H -p $(pgrep udp-fanout)

# Should see multiple "afxdp-" threads with ~100% CPU each
```

### Locked Memory Limits

AF_XDP requires elevated locked memory limits for UMEM (shared packet buffers):
```bash
ulimit -l unlimited
sudo ./target/release/udp-fanout --config config.yaml
```

Or set system-wide in `/etc/security/limits.conf`:
```
* soft memlock unlimited
* hard memlock unlimited
```

### Performance Optimization Checklist

**For maximum throughput**:
- ✅ Use **native XDP mode** (not SKB)
- ✅ Configure MTU ≤ 3498 and queues ≤ 50% of max
- ✅ Use instance with **4+ queues** for multi-core (c5n.large+)
- ✅ Send traffic from **multiple sources** to activate RSS
- ✅ Enable `--release` build for optimized binaries
- ✅ Pin process to NUMA node if on multi-socket system
- ✅ Consider disabling IRQ balance for dedicated cores

**Monitor performance**:
```bash
# Real-time packet rate (per queue)
watch -n1 'ethtool -S ens5 | grep queue.*packets'

# CPU per thread
top -H -p $(pgrep udp-fanout)

# Prometheus metrics
curl localhost:9090/metrics | grep udp_fanout
```

### Exposing to External Traffic

To receive logs from outside AWS:

1. **Configure iptables DNAT** to forward public IP traffic to MetalLB VIP:
   ```bash
   PUBLIC_IP=172.31.25.67  # Instance private IP
   VIP=172.31.25.200       # MetalLB VIP
   PORT=514

   sudo iptables -t nat -A PREROUTING -d $PUBLIC_IP -p udp --dport $PORT \
     -j DNAT --to-destination $VIP:$PORT
   sudo iptables -t nat -A POSTROUTING -d $VIP -p udp --dport $PORT \
     -j MASQUERADE
   ```

2. **Configure AWS Security Group** to allow inbound UDP on port 514 from your source IPs

3. **Send logs to instance public IP**:
   ```bash
   echo "test log" | nc -u <EC2_PUBLIC_IP> 514
   ```

### Troubleshooting Performance

**Problem**: Only one core utilized
- **Cause**: All traffic from single source IP hashes to one queue
- **Solution**: Send from multiple source IPs or accept single-core performance

**Problem**: Native XDP fails to attach
- **Cause**: MTU > 3498 or queue count > 50% of max
- **Solution**: Reduce MTU and queue count as documented above

**Problem**: SKB mode instead of native
- **Check**: `dmesg | grep xdp` for error messages
- **Check**: Queue and MTU settings with `ethtool`

**Problem**: Lower than expected throughput
- **Check**: CPU usage with `top -H` - should be near 100% per thread
- **Check**: RSS distribution with `ethtool -S ens5`
- **Check**: No packet drops in metrics (`udp_fanout_packets_dropped_total`)

## Limitations

- UDP only — TCP is not supported (use kube-proxy or a general-purpose L4 proxy for TCP)
- Round-robin only — no weighted, least-connections, or hash-based balancing
- Host network required — needs direct NIC access for TC/XDP attachment
- Stateless — no connection tracking, no session affinity
- AF_XDP currently uses copy mode — zero-copy mode can be enabled for NICs with driver support

## License

Apache License 2.0 — see [LICENSE](LICENSE)

## Credits

Built with [Aya](https://aya-rs.dev/) (Rust eBPF), [Tokio](https://tokio.rs/) (async runtime), and [kube-rs](https://kube.rs/) (Kubernetes client). Inspired by Envoy's UDP proxy architecture and Cilium's eBPF service load balancing.
