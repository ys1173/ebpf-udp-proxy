# udp-fanout — Build, Deploy & Test Guide

**Lightweight High-Performance UDP Fanout Proxy with eBPF Kernel Bypass**  
Version 0.1.0

---

## 1. Overview

udp-fanout is a lightweight, single-purpose UDP proxy that load-balances incoming UDP datagrams to downstream receivers. It offers two forwarding paths, selected per-listener via configuration:

| Mode      | How It Works | Performance   | Requires Root |
|-----------|--------------|---------------|----------------|
| **tc_ebpf** | TC eBPF program selects one downstream per packet (round-robin), resolves next hop via `bpf_fib_lookup()`, and redirects in-kernel. | ~2-4 Mpps | Yes (CAP_BPF, CAP_NET_ADMIN) |
| **userspace** | Pure userspace with recvmmsg/sendmmsg batching. Portable fallback. | ~500K-1M pps | No |

**Note:** All modes are fire-and-forget: no buffering, no backpressure, no retries. If a send fails, the packet is dropped and a counter incremented.

---

## 2. Prerequisites

### 2.1 System Requirements

- Linux x86_64 (kernel 4.18+ for TC eBPF `bpf_fib_lookup`)
- 2+ CPU cores recommended for userspace mode workers
- Root or CAP_BPF + CAP_NET_ADMIN capabilities for eBPF modes

### 2.2 Build Dependencies

| Dependency      | Install Command | Required For |
|-----------------|-----------------|--------------|
| Rust (stable)   | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` | All builds |
| Rust (nightly)  | `rustup toolchain install nightly --component rust-src` | eBPF program |
| BPF target      | `rustup target add bpfel-unknown-none --toolchain nightly` | eBPF program |
| bpf-linker      | `cargo +nightly install bpf-linker` | eBPF program |
| libelf-dev      | `sudo apt-get install libelf-dev pkg-config` | eBPF program |
| linux-headers   | `sudo apt-get install linux-headers-$(uname -r)` | eBPF program |

---

## 3. Building

### 3.1 Quick Build (Both eBPF + Userspace)

From the project root directory:

```bash
cargo xtask build --release
```

This compiles the eBPF program (nightly, BPF target) and the userspace daemon (stable, release mode). Output binaries:

- `target/release/udp-fanout` (daemon binary)
- `target/udp-fanout-ebpf` (eBPF ELF binary)

### 3.2 Build eBPF Only

```bash
cargo xtask build-ebpf --release
```

### 3.3 Build Userspace Only

If you only need the userspace fallback (no root required):

```bash
cargo build --release -p udp-fanout
```

### 3.4 Manual eBPF Build

If xtask has issues, you can build the eBPF program directly:

```bash
cd udp-fanout-ebpf
cargo +nightly build --target=bpfel-unknown-none -Z build-std=core --release
cp target/bpfel-unknown-none/release/udp-fanout-ebpf ../target/udp-fanout-ebpf
```

---

## 4. Configuration

Copy the example config and edit it for your environment:

```bash
cp config.example.yaml config.yaml
```

### 4.1 Listener Configuration

| Field                 | Description | Required |
|-----------------------|-------------|----------|
| name                  | Human-readable listener name (used in metrics labels) | Yes |
| bind                  | Listen address:port (e.g. 0.0.0.0:9000) | Yes |
| interface             | NIC name for eBPF attachment (e.g. eth0) | tc_ebpf |
| mode                  | tc_ebpf \| userspace | No (default: userspace) |
| kubernetes.namespace  | Namespace to watch EndpointSlices in (defaults to pod namespace in-cluster, else `default`) | No |
| kubernetes.service    | Service name (EndpointSlices selected via label `kubernetes.io/service-name`) | Option A only |
| kubernetes.port       | UDP port to send to on each ready endpoint | Option A only |
| downstream[].name     | Downstream receiver name | Static downstreams only |
| downstream[].address  | Destination ip:port | Static downstreams only |
| downstream[].mac      | Legacy field (optional). TC mode uses FIB lookup for next-hop MACs. | No |

### 4.2 Notes on TC eBPF mode in Kubernetes

When using Option A (EndpointSlice discovery), the TC eBPF fast path does **not** require pod MAC
addresses. It uses a kernel FIB lookup (`bpf_fib_lookup`) to resolve the next-hop MAC and output
interface for each selected endpoint IP.

### 4.3 Tuning Settings

| Setting         | Default   | Description |
|-----------------|-----------|-------------|
| max_packet_size | 9000      | Maximum UDP datagram size (use 1500 for standard MTU, 9000 for jumbo) |
| batch_size      | 32        | recvmmsg/sendmmsg batch size (userspace mode) |
| workers         | 0 (auto)  | Worker thread count for userspace mode (0 = number of CPUs) |
| pin_cpus        | true      | Pin worker threads to CPU cores for cache locality |
| recv_buf_size   | 0 (system) | SO_RCVBUF socket buffer size. Try 16777216 (16MB) for high throughput |

---

## 5. Running

### 5.1 Userspace Mode (No Root)

```bash
./target/release/udp-fanout --config config.yaml
```

### 5.2 eBPF Mode (Requires Root)

```bash
sudo ./target/release/udp-fanout \
  --config config.yaml \
  --ebpf-program target/udp-fanout-ebpf
```

### 5.3 CLI Options

| Flag              | Default        | Description |
|-------------------|----------------|-------------|
| --config, -c      | config.yaml    | Path to YAML configuration file |
| --log-level, -l   | info           | Log level: trace, debug, info, warn, error |
| --ebpf-program    | udp-fanout-ebpf | Path to compiled eBPF ELF binary |

### 5.4 Logging (Recommended for first test run)

The daemon uses `tracing`. On first test runs, use `debug` so you can quickly tell which stage failed (config parsing, eBPF attach, Kubernetes discovery, etc.) without enabling per-packet logs.

Set log level via CLI:

```bash
./target/release/udp-fanout --config config.yaml --log-level debug
```

Or override via environment (takes precedence over `--log-level`):

```bash
RUST_LOG=debug ./target/release/udp-fanout --config config.yaml
```

High-signal log lines to look for:

- **Startup / config**
  - `starting udp-fanout`
  - `configuration loaded`
  - `configured listeners by mode`
- **Userspace dataplane**
  - `starting userspace forwarder`
  - `entering receive loop` (per worker)
  - `userspace worker heartbeat` (every ~5s at `debug`; shows downstream count + packet counters)
- **Kubernetes EndpointSlice discovery (Option A)**
  - `starting EndpointSlice watch`
  - `k8s discovery: 0 ready endpoints` (warn; common cause of "no forwarding")
  - `tc_ebpf k8s membership updated` (info; membership changed and will be applied to maps)
- **TC eBPF dataplane**
  - `registered listener in eBPF map`
  - `eBPF fast path initialized`
  - `updated tc_ebpf downstream set` (info; eBPF maps updated with discovered endpoints)
- **Metrics**
  - `metrics server error` (if bind fails, port already in use, etc.)

### 5.5 Graceful Shutdown

Send SIGTERM or Ctrl+C. The daemon will detach eBPF programs, stop worker threads, and exit cleanly.

---

## 6. Testing

### 6.1 Quick Smoke Test (Userspace)

This test verifies basic load balancing without root. It starts 3 UDP sinks, runs the proxy, sends packets, and checks packets are distributed across sinks (each packet delivered to exactly one downstream).

**Write a test config:**

```bash
cat > /tmp/test-config.yaml << 'EOF'
listeners:
  - name: test-fanout
    bind: "127.0.0.1:19000"
    mode: userspace
    downstream:
      - name: sink-1
        address: "127.0.0.1:19001"
      - name: sink-2
        address: "127.0.0.1:19002"
      - name: sink-3
        address: "127.0.0.1:19003"
    settings:
      workers: 1
metrics:
  enabled: true
  bind: "127.0.0.1:19090"
  path: /metrics
EOF
```

**Start 3 UDP sink listeners** (in separate terminals or background):

Terminal 1:

```bash
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('127.0.0.1', 19001))
s.settimeout(10)
for i in range(10):
    data, _ = s.recvfrom(4096)
    print(f'sink:19001 #{i+1}: {data.decode()}')
"
```

Repeat for ports 19002 and 19003.

**Start the proxy:**

```bash
./target/release/udp-fanout --config /tmp/test-config.yaml --log-level debug
```

**Send test packets:**

```bash
for i in $(seq 1 10); do
  echo "test-packet-$i" | nc -u -w0 127.0.0.1 19000
done
```

**Verify:** Across all sinks combined, you should see exactly 10 packets (distribution will be roughly round-robin). Check metrics:

```bash
curl -s http://127.0.0.1:19090/metrics
```

**Note:** Expected metrics: packets_received = 10, packets_forwarded = 10 (one forward per packet).

### 6.2 eBPF Mode Test (Requires Root)

For TC eBPF testing you need root access and a kernel that supports `bpf_fib_lookup` (Linux 4.18+). Use network namespaces for a self-contained test:

**Create test namespaces with veth pairs:**

```bash
sudo ip netns add ns-src
sudo ip netns add ns-dst1
sudo ip link add veth-src type veth peer name veth-proxy-src
sudo ip link add veth-dst1 type veth peer name veth-proxy-dst1
sudo ip link set veth-src netns ns-src
sudo ip link set veth-dst1 netns ns-dst1
# Assign IPs and bring up interfaces...
```

Run with sudo:

```bash
sudo ./target/release/udp-fanout --config config.yaml --ebpf-program target/udp-fanout-ebpf
```

**Verify TC attachment:**

```bash
sudo tc filter show dev eth0 ingress
```

You should see the udp_fanout classifier listed.

---

## 7. Monitoring

When metrics are enabled, the daemon exposes a Prometheus-compatible endpoint.

### 7.1 Available Metrics

| Metric | Labels | Description |
|--------|--------|-------------|
| udp_fanout_packets_received_total | listener, mode | Total packets received per listener |
| udp_fanout_packets_forwarded_total | listener, mode | Total packets forwarded (one per successfully forwarded packet) |
| udp_fanout_packets_dropped_total | listener, mode | Total packets dropped (send failures) |
| udp_fanout_packets_no_healthy_total | listener, mode | Total packets dropped due to no ready downstreams (userspace) |
| udp_fanout_bytes_received_total | listener, mode | Total bytes received |
| udp_fanout_bytes_forwarded_total | listener, mode | Total bytes forwarded |

### 7.2 Health Endpoint

```bash
curl http://localhost:9090/healthz
```

Returns "ok" if the daemon is running.

---

## 8. Kubernetes Deployment

### 8.1 Build Container Image

```bash
docker build -t udp-fanout:latest .
```

### 8.2 Deploy

```bash
kubectl apply -f k8s/rbac.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/daemonset.yaml
```

### 8.3 Key K8s Notes

- The DaemonSet uses `hostNetwork: true` for direct NIC access (required for TC eBPF attachment).
- Security capabilities required: BPF, NET_ADMIN, SYS_ADMIN, PERFMON.
- The ConfigMap at `k8s/configmap.yaml` contains the proxy config. Edit downstream addresses for your environment.
- Prometheus annotations are set for auto-scraping on port 9090.

---

## 9. Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| "Permission denied" on startup | eBPF modes need root/capabilities | Run with sudo or add CAP_BPF + CAP_NET_ADMIN |
| "interface not found" | Wrong interface name in config | Check with: `ip link show` |
| eBPF build fails: "bpf-linker not found" | Missing eBPF build toolchain | `cargo +nightly install bpf-linker` |
| Packets not reaching downstreams (tc_ebpf) | Routing/neighbor resolution failing for destination IP | Check node routing (`ip route`) and neighbor table (`ip neigh`); ensure kernel 4.18+ |
| Packets not reaching downstreams (userspace) | Firewall blocking UDP | Check: `sudo iptables -L -n` |
| High packet drops in metrics | Socket buffer too small or downstream too slow | Increase recv_buf_size in config (try 16MB) |
| "LISTENER_CONFIG map not found" | eBPF binary mismatch or not built | Rebuild: `cargo xtask build-ebpf --release` |

---

## 10. Project Structure

| Directory | Description |
|-----------|-------------|
| udp-fanout/ | Userspace daemon: main binary, config parsing, forwarding paths, metrics, health |
| udp-fanout-ebpf/ | TC eBPF program: packet parsing, header rewriting, `bpf_fib_lookup` next-hop resolution, `bpf_redirect` |
| udp-fanout-common/ | Shared types between eBPF and userspace (map keys, stats structs, constants) |
| xtask/ | Build helper: compiles eBPF with correct target, then userspace daemon |
| k8s/ | Kubernetes manifests: DaemonSet + ConfigMap |
