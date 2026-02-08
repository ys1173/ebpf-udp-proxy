# MetalLB Deployment Guide

Deploy udp-fanout with MetalLB LoadBalancer for VIP redundancy.

## Architecture

```
External client
    ↓
MetalLB VIP (L2 announcement) — e.g., 192.168.1.100:5514
    ↓
Node (where VIP is announced)
    ↓
iptables PREROUTING (kube-proxy DNAT) → 10.255.0.1:5514
    ↓
dummy0 interface (10.255.0.1)
    ↓
TC eBPF ingress (udp-fanout)
    ↓
Rewrite dst IP/port + bpf_redirect_neigh
    ↓
cni0 → Pod veth interfaces
    ↓
Receiver pods (round-robin)
```

## Why dummy0 Interface?

**Problem**: If we attach TC eBPF directly to the physical NIC (eth0), it runs BEFORE kube-proxy's iptables DNAT, causing conflicts.

**Solution**:
1. kube-proxy DNATs traffic from MetalLB VIP → dummy0 interface IP
2. Packet re-enters network stack on dummy0
3. TC eBPF on dummy0 intercepts and load-balances to pods

This gives you:
- ✅ MetalLB L2 VIP for failover
- ✅ kube-proxy handles initial routing
- ✅ Your eBPF does the actual load balancing
- ✅ Clean separation of concerns

## Prerequisites

- MetalLB installed and configured (L2 mode)
- IP pool configured in MetalLB
- Kubernetes 1.19+
- Kernel 5.10+

## Deployment Steps

### 1. Deploy RBAC

```bash
kubectl apply -f k8s/rbac.yaml
```

### 2. Deploy udp-fanout with dummy interface

```bash
# Apply ConfigMap (update namespace/service for your receivers)
kubectl apply -f k8s/configmap-metallb.yaml

# Apply DaemonSet (includes init container to create dummy0)
kubectl apply -f k8s/daemonset-metallb.yaml
```

### 3. Verify dummy interface created

```bash
kubectl exec -n udp-fanout daemonset/udp-fanout -- ip addr show dummy0
```

Expected output:
```
dummy0: <BROADCAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN
    inet 10.255.0.1/32 scope global dummy0
```

### 4. Deploy MetalLB Service

**Option A: Automatic endpoint (simpler, works for single-node or L2 mode)**

```bash
kubectl apply -f k8s/service-metallb.yaml
```

**Option B: Manual endpoints per node (multi-node clusters)**

Edit `k8s/service-metallb.yaml` and list all node IPs in the Endpoints section:

```yaml
subsets:
  - addresses:
      - ip: 10.255.0.1  # Node 1
      - ip: 10.255.0.1  # Node 2 (same dummy IP on all nodes)
      - ip: 10.255.0.1  # Node 3
    ports:
      - port: 5514
```

**Why this works**: Even though the IP is the same (10.255.0.1), kube-proxy creates iptables rules on each node. When MetalLB sends traffic to a specific node, that node's kube-proxy routes it to its local dummy0.

### 5. Deploy receiver pods

```bash
kubectl apply -f k8s/example-receivers.yaml
```

### 6. Verify end-to-end

```bash
# Check MetalLB assigned external IP
kubectl -n udp-fanout get svc udp-fanout-lb
# Example output:
# NAME             TYPE           EXTERNAL-IP      PORT(S)
# udp-fanout-lb    LoadBalancer   192.168.1.100    5514:xxxxx/UDP

# Check udp-fanout logs
kubectl -n udp-fanout logs daemonset/udp-fanout | grep "attached TC eBPF"
# Expected: INFO attached TC eBPF program to ingress interface="dummy0"

# Check endpoint discovery
kubectl -n udp-fanout logs daemonset/udp-fanout | grep "endpoints="
# Expected: INFO updated tc_ebpf downstream set listener_id=0 endpoints=3

# Send test traffic from external machine
echo "test" | nc -u 192.168.1.100 5514

# Check receiver logs
kubectl -n udp-fanout logs -l app=udp-receiver --tail=10
# Expected: Collected events. events=XXX
```

## Troubleshooting

### dummy0 not created

```bash
# Check init container logs
kubectl -n udp-fanout logs daemonset/udp-fanout -c setup-dummy-interface
```

If failed, the init container needs `privileged: true` or specific capabilities.

### TC eBPF not attaching to dummy0

```bash
# Check if dummy0 exists
kubectl exec -n udp-fanout daemonset/udp-fanout -- ip link show dummy0

# Check if clsact qdisc is attached
kubectl exec -n udp-fanout daemonset/udp-fanout -- tc qdisc show dev dummy0
# Expected: qdisc clsact ffff: parent ffff:fff1

# Check TC filter
kubectl exec -n udp-fanout daemonset/udp-fanout -- tc filter show dev dummy0 ingress
# Expected: filter protocol all ... bpf ... name udp_fanout
```

### Traffic not reaching pods

**Check 1: MetalLB VIP announced**
```bash
kubectl -n metallb-system logs -l component=speaker
```

**Check 2: kube-proxy DNAT rules**
```bash
# On the node where MetalLB announced the VIP
sudo iptables -t nat -L KUBE-SERVICES -n -v | grep udp-fanout
```

Should show DNAT rule: `192.168.1.100:5514 → 10.255.0.1:5514`

**Check 3: Packet flow with tcpdump**
```bash
# On MetalLB node, check packets arrive on physical NIC
kubectl exec -n udp-fanout daemonset/udp-fanout -- \
  tcpdump -i eth0 udp port 5514 -n -c 5

# Check packets on dummy0 after DNAT
kubectl exec -n udp-fanout daemonset/udp-fanout -- \
  tcpdump -i dummy0 udp port 5514 -n -c 5

# Check redirected packets on cni0
kubectl exec -n udp-fanout daemonset/udp-fanout -- \
  tcpdump -i cni0 udp port 5514 -n -c 5
```

**Check 4: eBPF stats**
```bash
# Get program ID
kubectl exec -n udp-fanout daemonset/udp-fanout -- \
  tc filter show dev dummy0 ingress | grep -oP 'id \K\d+'

# Dump stats map (replace PROG_ID with actual ID)
kubectl exec -n udp-fanout daemonset/udp-fanout -- \
  bpftool prog show id <PROG_ID>

kubectl exec -n udp-fanout daemonset/udp-fanout -- \
  bpftool map dump name STATS
```

Look for `pkts_forwarded` vs `pkts_dropped`.

### Performance issues

**Double network stack traversal** adds ~10-20µs latency vs direct hostNetwork deployment.

If unacceptable:
- Consider using hostNetwork deployment instead (see `k8s/daemonset.yaml`)
- Or use MetalLB with `externalTrafficPolicy: Local` (requires different setup)

## Comparison: dummy0 vs hostNetwork

| Feature | dummy0 + MetalLB | hostNetwork Direct |
|---------|------------------|-------------------|
| MetalLB VIP | ✅ Yes | ❌ No (bind to node IP) |
| Failover | ✅ MetalLB handles | ⚠️ DNS round-robin |
| Latency | ~10-20µs overhead | Best (no overhead) |
| Complexity | Medium | Low |
| Ops familiarity | ✅ Standard k8s Service | ⚠️ Non-standard |

## Production Recommendations

1. **Monitor latency**: Add metrics for packet processing time
2. **Test failover**: Kill MetalLB speaker pod and verify VIP migrates
3. **Document dummy IP**: Make 10.255.0.1 a reserved/documented IP in your network
4. **Automate endpoints**: Consider using a controller to manage Endpoints dynamically
5. **Health checks**: Keep `health.enabled: true` for fast failure detection

## Next Steps

- Scale receiver pods and verify round-robin distribution
- Test with production traffic volumes
- Set up Prometheus alerts on `udp_fanout_packets_dropped_total`
