# Quick Start Guide - AF-XDP Mode

## Prerequisites

1. **Build the proxy**:
   ```bash
   cargo xtask build --release
   ```

2. **Configure network for native XDP** (AWS ENA):
   ```bash
   # Set MTU (required for XDP)
   sudo ip link set ens5 mtu 3498

   # Set queue count (≤50% of max for native XDP)
   # For 2-core instance with 2 max queues:
   sudo ethtool -L ens5 combined 1

   # For 4+ core instance with 4+ max queues:
   sudo ethtool -L ens5 combined 2
   ```

## Run the Proxy

```bash
cd /home/ubuntu/ebpf-udp-proxy
sudo bash -c 'ulimit -l unlimited && ./target/release/udp-fanout --config config.yaml'
```

**Verify native XDP mode**:
```
✓ INFO attached XDP program interface="ens5" mode="native"
✗ WARN native XDP attach failed, trying SKB mode  # ← Fix MTU/queues
```

## Send Test Traffic

From external host:
```bash
echo "test log" | nc -u <EC2_PUBLIC_IP> 514
```

From local host:
```bash
echo "test log" | nc -u 172.31.25.200 514
```

## Monitor Performance

**Check CPU usage**:
```bash
top -H -p $(pgrep udp-fanout)
```

**Check packet delivery**:
```bash
# Vector pod logs
kubectl logs -l app=vector --tail=5

# Prometheus metrics
curl localhost:9090/metrics | grep udp_fanout
```

**Check RSS distribution** (multi-core):
```bash
ethtool -S ens5 | grep "queue.*packets"
```

## Expected Performance

- **Single core**: ~30,000 packets/sec @ 100% CPU
- **Dual core**: ~60,000 packets/sec @ 100% CPU (requires multi-source traffic)
- **Memory**: ~60 MB per forwarder (stable)
- **Latency**: <100μs (driver-level processing)

## Troubleshooting

**Problem**: Native XDP fails
```bash
# Check current settings
ip link show ens5 | grep mtu
ethtool -l ens5

# Fix
sudo ip link set ens5 mtu 3498
sudo ethtool -L ens5 combined 1
```

**Problem**: No packets arriving from external sources
```bash
# Check iptables rules
sudo iptables -t nat -L PREROUTING -n | grep 514

# Add if missing
sudo iptables -t nat -A PREROUTING -d 172.31.25.67 -p udp --dport 514 \
  -j DNAT --to-destination 172.31.25.200:514
```

**Problem**: Only one core utilized (multi-queue setup)
- This is normal for single-source traffic
- RSS distributes based on source IP
- Send from multiple sources to activate all cores

## Configuration File

Edit `/home/ubuntu/ebpf-udp-proxy/config.yaml`:
```yaml
listeners:
  - name: "vector-af-xdp"
    interface: "ens5"          # Network interface
    mode: af_xdp               # Use AF-XDP mode
    bind: "172.31.25.200:514"  # MetalLB VIP
    downstream:
      - name: "vector-1"
        address: "10.42.0.21:5514"
      - name: "vector-2"
        address: "10.42.0.22:5514"
      - name: "vector-3"
        address: "10.42.0.27:5514"
log_level: "info"
```

## Stop the Proxy

Press `Ctrl+C` in the terminal, or:
```bash
sudo pkill -INT udp-fanout
```

## For Production

1. Make network settings persistent:
   ```bash
   # Add to /etc/network/interfaces or systemd-networkd
   ```

2. Run as systemd service:
   ```bash
   sudo systemctl enable udp-fanout
   sudo systemctl start udp-fanout
   ```

3. Monitor with Prometheus/Grafana

4. Set up log rotation and alerting

See `README.md` for full documentation.
