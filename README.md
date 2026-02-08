# udp-fanout

High-performance UDP packet fanout proxy with eBPF fast path for Kubernetes.

Receives UDP datagrams on one or more listeners and forwards each packet to exactly one downstream receiver using round-robin load balancing — all in kernel space with TC eBPF for line-rate performance.

## Features

- **Kernel-space forwarding**: TC eBPF fast path with `bpf_redirect_neigh()` — zero userspace copies, line-rate throughput
- **Kubernetes-native**: Automatic endpoint discovery via EndpointSlice watch — no manual configuration
- **Round-robin load balancing**: Per-CPU counters for lock-free packet distribution
- **Health monitoring**: Active ICMP/UDP probes to detect failed receivers in ~5-7 seconds (vs k8s default ~40-60s)
- **Userspace fallback**: Pure userspace mode with `recvmmsg`/`sendmmsg` batching for portability
- **Zero configuration**: Discovers downstream IPs automatically from Kubernetes Service selectors

## Use Cases

- **Log aggregation**: Distribute syslog/GELF/fluent-bit traffic across Vector/Logstash/Loki instances
- **Telemetry replication**: Fan out StatsD/OpenTelemetry metrics to multiple collectors
- **Market data distribution**: Low-latency fanout for UDP multicast streams (finance/trading)
- **DNS load balancing**: Distribute DNS queries across resolver pools

## Architecture

```
External sender → Host NIC (TC ingress eBPF)
                        ↓ bpf_redirect_neigh
                  Pod veth interfaces
                        ↓ round-robin
            ┌───────────┼───────────┐
         pod-1       pod-2       pod-3
      receiver    receiver    receiver
```

**How it works:**
1. Incoming UDP packets hit the host NIC with TC eBPF program attached to ingress
2. eBPF program matches destination port → looks up downstream pod IP from map
3. Rewrites L3/L4 headers (dst IP/port), performs FIB lookup for routing
4. `bpf_redirect_neigh()` redirects packet to pod veth, kernel resolves neighbor/MAC automatically
5. Zero copies, zero context switches — packet never enters userspace on the proxy node

## Performance

- **Throughput**: Line-rate forwarding (tested at 10Gbps+)
- **Latency**: Sub-microsecond kernel forwarding (vs ~100µs userspace proxy overhead)
- **CPU overhead**: <5% on modern CPUs at 1M pps
- **Scalability**: Handles 1000+ downstream endpoints per listener

## Quick Start

### Prerequisites

- Kubernetes 1.19+ (EndpointSlice API)
- Linux kernel 5.10+ (for `bpf_redirect_neigh`)
- Host network mode (DaemonSet with `hostNetwork: true`)

### Deploy on Kubernetes

```bash
# 1. Apply RBAC for EndpointSlice read access
kubectl apply -f k8s/rbac.yaml

# 2. Deploy udp-fanout as DaemonSet
kubectl apply -f k8s/daemonset.yaml

# 3. Deploy downstream receivers (example: Vector)
kubectl apply -f k8s/example-receivers.yaml

# 4. Verify eBPF program attached
kubectl -n udp-fanout logs daemonset/udp-fanout | grep "attached TC eBPF"
```

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for detailed Kubernetes deployment guide.

**For MetalLB LoadBalancer integration**: See [docs/METALLB_DEPLOYMENT.md](docs/METALLB_DEPLOYMENT.md) for deploying with MetalLB L2 VIP using a dummy interface approach.

### Local Testing (Userspace Mode)

```bash
# Build
cargo xtask build --release

# Run in userspace mode (no eBPF, no root required)
./target/release/udp-fanout --config config.example.yaml

# Send test traffic
echo "test" | nc -u localhost 5514
```

## Configuration

Minimal example (Kubernetes service discovery):

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

See [config.example.yaml](config.example.yaml) for full options including static downstream configuration.

## Building

### Requirements

- Rust stable (1.75+) + nightly (for eBPF)
- `bpf-linker` for eBPF program linking
- System packages: `clang`, `llvm`, `libelf-dev`

### Build Commands

```bash
# Install bpf-linker
cargo install bpf-linker

# Build both eBPF and userspace
cargo xtask build --release

# Outputs:
#   target/release/udp-fanout          # userspace daemon
#   target/udp-fanout-ebpf             # eBPF program (BPF ELF)
```

### Docker Build

```bash
# Multi-stage build (builds eBPF + userspace)
docker build -t udp-fanout:latest .

# Or use pre-built binaries (faster)
docker build -t udp-fanout:latest -f Dockerfile.runtime .
```
## Documentation

- **[Deployment Guide](docs/DEPLOYMENT.md)**: Kubernetes deployment, troubleshooting, production best practices
- **[MetalLB Deployment](docs/METALLB_DEPLOYMENT.md)**: Deploy with MetalLB L2 LoadBalancer and VIP redundancy
- **[Architecture](docs/ARCHITECTURE.md)**: Deep dive into eBPF packet flow, round-robin algorithm, FIB lookup
- **[Configuration Reference](docs/CONFIGURATION.md)**: All config options explained
- **[Development Guide](docs/DEVELOPMENT.md)**: Building, testing, contributing

## Monitoring

Prometheus metrics exposed on `:9090/metrics`:

```
udp_fanout_packets_received_total{listener="syslog"}
udp_fanout_packets_forwarded_total{listener="syslog"}
udp_fanout_packets_dropped_total{listener="syslog"}
udp_fanout_downstream_active{listener="syslog"}
udp_fanout_downstream_health{listener="syslog",endpoint="10.42.0.5:5514"}
```

## Comparison

Comparison for UDP proxy forwarding workloads:

| Feature | udp-fanout (TC eBPF) | NGINX | Envoy | HAProxy |
|---------|----------------------|-------|-------|---------|
| **Throughput** | Very High | Medium | Medium-High | Low-Medium |
| **Latency** | Very Low | Medium | Medium | Low |
| **CPU overhead** | Very Low | Medium-High | Low-Medium | Medium-High |
| **Data plane** | Kernel (eBPF) | Userspace | Userspace | Userspace |
| **Load balancing** | Round-robin | Round-robin, hash | Consistent hash, ring hash | Round-robin, least-conn, hash |
| **Stateful** | No (stateless) | Yes (per-connection) | Yes (per-connection) | Yes (per-connection) |
| **K8s integration** | Native (EndpointSlice) | Manual config | Service mesh (xDS) | Manual config |
| **Health checks** | Active (ICMP/UDP) | Passive | Active (HTTP/gRPC) | Active (TCP/HTTP) |
| **Config complexity** | Low (YAML) | Medium (nginx.conf) | High (xDS/Envoy API) | Medium (HAProxy cfg) |
| **Observability** | Prometheus | Logs, Prometheus | Rich (traces, stats) | Logs, Prometheus |
| **Best for** | High-throughput fanout | General L4/L7 proxy | Service mesh | L4/L7 load balancing |

**Why eBPF is faster for UDP fanout:**
- Zero userspace copies — packet stays in kernel from NIC to pod veth
- No context switches — eBPF runs in softirq context at packet arrival
- Stateless forwarding — no connection tracking overhead (UDP is connectionless)
- Direct redirect — `bpf_redirect_neigh()` bypasses full network stack traversal

## Limitations

- **UDP only**: TCP not supported (use kernel's built-in load balancing for TCP)
- **Round-robin only**: No weighted/least-connections (eBPF complexity constraints)
- **Host network required**: Needs direct NIC access for TC attach
- **Single packet per connection**: No connection tracking (stateless forwarding)

## License

Apache License 2.0 - see [LICENSE](LICENSE)

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Credits

Built with:
- [Aya](https://aya-rs.dev/) - Rust eBPF library
- [Tokio](https://tokio.rs/) - Async runtime
- [kube-rs](https://kube.rs/) - Kubernetes client

Inspired by Cilium's eBPF-based service load balancing.
