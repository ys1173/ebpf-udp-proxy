# Kubernetes Deployment Guide

Complete guide for deploying udp-fanout in production Kubernetes environments.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Deploy](#quick-deploy)
- [Configuration](#configuration)
- [Production Checklist](#production-checklist)
- [Troubleshooting](#troubleshooting)
- [Examples](#examples)

## Prerequisites

### Cluster Requirements

- **Kubernetes version**: 1.19+ (EndpointSlice API stable)
- **Kernel version**: 5.10+ (for `bpf_redirect_neigh` support)
- **CNI**: Any (Flannel, Calico, Cilium, etc.)
- **Nodes**: DaemonSet runs on all nodes by default

Check kernel version on nodes:
```bash
kubectl get nodes -o wide
# Or SSH to a node and run:
uname -r  # should be >= 5.10
```

### Required Permissions

The udp-fanout DaemonSet needs:
- `hostNetwork: true` - Direct NIC access for TC eBPF attach
- Capabilities: `BPF`, `NET_ADMIN`, `SYS_ADMIN`, `PERFMON`
- RBAC: Read access to EndpointSlices in target namespaces

## Quick Deploy

### Step 1: Build and Push Container Image

**Option A: Use pre-built image** (if available from registry):
```bash
# Pull from your registry
kubectl set image daemonset/udp-fanout udp-fanout=yourregistry/udp-fanout:latest -n udp-fanout
```

**Option B: Build locally and import** (for testing):
```bash
# Build the image
cd udp-fanout
docker build -t udp-fanout:latest .

# For k3s/k3d - import directly
docker save udp-fanout:latest | sudo k3s ctr images import -

# For kind - load into cluster
kind load docker-image udp-fanout:latest

# For minikube - use minikube's docker
eval $(minikube docker-env)
docker build -t udp-fanout:latest .
```

**Option C: Build and push to registry**:
```bash
docker build -t yourregistry/udp-fanout:v0.1.0 .
docker push yourregistry/udp-fanout:v0.1.0
```

### Step 2: Deploy RBAC

```bash
kubectl apply -f k8s/rbac.yaml
```

This creates:
- Namespace: `udp-fanout`
- ServiceAccount: `udp-fanout`
- Role: Read access to EndpointSlices
- RoleBinding: Grants ServiceAccount the Role

### Step 3: Configure

Edit `k8s/daemonset.yaml` and adjust the ConfigMap:

```yaml
listeners:
  - name: syslog
    bind: "0.0.0.0:5514"           # Listener port on host
    interface: eth0                 # Host NIC (check with `ip link`)
    mode: tc_ebpf
    kubernetes:
      namespace: logging            # Where your receivers are deployed
      service: vector-aggregators   # Service name (headless recommended)
      port: 5514                    # Receiver port
```

**Important**: Check your host interface name:
```bash
kubectl exec -n udp-fanout daemonset/udp-fanout -- ip link show
# Common names: eth0, ens3, eno1, enp0s3
```

### Step 4: Deploy DaemonSet

```bash
kubectl apply -f k8s/daemonset.yaml
```

### Step 5: Verify

```bash
# Check pods running
kubectl -n udp-fanout get pods -o wide

# Verify eBPF program attached
kubectl -n udp-fanout logs daemonset/udp-fanout | grep "attached TC eBPF"
# Expected: "INFO attached TC eBPF program to ingress interface="eth0""

# Check endpoint discovery
kubectl -n udp-fanout logs daemonset/udp-fanout | grep "endpoints="
# Expected: "INFO updated tc_ebpf downstream set listener_id=0 endpoints=3"

# Verify from host (if accessible)
sudo tc filter show dev eth0 ingress
# Should show: filter protocol all pref 49152 bpf ... name udp_fanout
```

## Configuration

### Listener Modes

**tc_ebpf** (recommended for production):
```yaml
listeners:
  - name: my-listener
    bind: "0.0.0.0:9000"
    interface: eth0
    mode: tc_ebpf
    kubernetes:
      namespace: my-namespace
      service: my-receivers
      port: 9000
```

**userspace** (fallback for older kernels):
```yaml
listeners:
  - name: my-listener
    bind: "0.0.0.0:9000"
    mode: userspace
    kubernetes:
      namespace: my-namespace
      service: my-receivers
      port: 9000
    settings:
      batch_size: 64
      workers: 4
      pin_cpus: true
```

### Health Checks

**Recommended for production** — detect pod failures in ~5-7 seconds (vs k8s default ~40-60s):

```yaml
health:
  enabled: true
  interval_secs: 5      # Probe every 5 seconds
  timeout_secs: 2       # Mark unhealthy after 2s no response
  protocol: icmp        # or udp_echo (requires app support)
```

**Without health checks**: Relies purely on Kubernetes endpoint removal, which can take 40-60 seconds for node failures.

### Metrics

```yaml
metrics:
  enabled: true
  bind: "0.0.0.0:9090"
  path: /metrics
```

Exposed metrics:
- `udp_fanout_packets_received_total`
- `udp_fanout_packets_forwarded_total`
- `udp_fanout_packets_dropped_total`
- `udp_fanout_downstream_active`
- `udp_fanout_downstream_health`

### Static Downstreams (No Kubernetes Discovery)

For bare-metal or testing:

```yaml
listeners:
  - name: my-listener
    bind: "0.0.0.0:9000"
    interface: eth0
    mode: tc_ebpf
    downstream:
      - name: receiver-1
        address: "10.0.1.10:9000"
      - name: receiver-2
        address: "10.0.1.11:9000"
      - name: receiver-3
        address: "10.0.1.12:9000"
```

## Production Checklist

### Performance Tuning

1. **Pin to CPUs** (userspace mode only):
   ```yaml
   settings:
     pin_cpus: true
     workers: 4  # Match physical cores
   ```

2. **Increase socket buffers** (userspace mode):
   ```yaml
   settings:
     recv_buf_size: 16777216  # 16MB
   ```

3. **Node affinity** (if you have dedicated ingress nodes):
   ```yaml
   nodeSelector:
     node-role.kubernetes.io/ingress: "true"
   ```

### Security

1. **Non-privileged with capabilities** (already configured in manifests):
   ```yaml
   securityContext:
     privileged: false
     capabilities:
       add: [BPF, NET_ADMIN, SYS_ADMIN, PERFMON]
       drop: [ALL]
     readOnlyRootFilesystem: true
   ```

2. **NetworkPolicy** (restrict access if needed):
   ```yaml
   apiVersion: networking.k8s.io/v1
   kind: NetworkPolicy
   metadata:
     name: udp-fanout-policy
   spec:
     podSelector:
       matchLabels:
         app.kubernetes.io/name: udp-fanout
     policyTypes:
       - Ingress
     ingress:
       - from:
           - podSelector: {}
         ports:
           - protocol: UDP
             port: 5514
   ```

### High Availability

1. **DaemonSet scheduling**:
   - Default: Runs on all nodes
   - Selective: Use `nodeSelector` or `affinity` to run only on specific nodes

2. **Update strategy**:
   ```yaml
   updateStrategy:
     type: RollingUpdate
     rollingUpdate:
       maxUnavailable: 1  # Only one node at a time during updates
   ```

3. **Resource limits**:
   ```yaml
   resources:
     requests:
       cpu: "100m"
       memory: "64Mi"
     limits:
       cpu: "2"          # Allow bursts for packet processing
       memory: "256Mi"
   ```

### Monitoring

1. **Prometheus scraping** (annotations already in manifests):
   ```yaml
   annotations:
     prometheus.io/scrape: "true"
     prometheus.io/port: "9090"
     prometheus.io/path: "/metrics"
   ```

2. **Alerting rules**:
   ```yaml
   - alert: UdpFanoutHighDropRate
     expr: rate(udp_fanout_packets_dropped_total[5m]) > 0.01
     annotations:
       summary: "udp-fanout dropping packets"
   ```

3. **Logs** (structured JSON recommended for production):
   ```bash
   kubectl -n udp-fanout logs -f daemonset/udp-fanout --tail=100
   ```

## Troubleshooting

### Pods not receiving traffic

**Check 1: eBPF program attached**
```bash
kubectl -n udp-fanout logs daemonset/udp-fanout | grep "attached TC eBPF"
```
If missing → check capabilities and host network mode.

**Check 2: Endpoints discovered**
```bash
kubectl -n udp-fanout logs daemonset/udp-fanout | grep "endpoints="
```
If `endpoints=0` → check RBAC, Service selector, namespace config.

**Check 3: Verify TC filter on host**
```bash
kubectl exec -n udp-fanout daemonset/udp-fanout -- tc filter show dev eth0 ingress
```
Should show `bpf ... name udp_fanout`.

**Check 4: Test with tcpdump**
```bash
# On host NIC
kubectl exec -n udp-fanout daemonset/udp-fanout -- tcpdump -i eth0 udp port 5514 -n -c 5

# On pod veth (should see redirected packets)
kubectl exec -n logging vector-0 -- tcpdump -i eth0 udp port 5514 -n -c 5
```

### High packet drops

**Check 1: eBPF stats**
```bash
kubectl exec -n udp-fanout daemonset/udp-fanout -- \
  bpftool map dump name STATS
```
Look at `pkts_dropped` vs `pkts_forwarded` ratio.

**Check 2: Downstream unhealthy**
```bash
kubectl -n udp-fanout logs daemonset/udp-fanout | grep "health.*failed"
```

**Check 3: FIB lookup failures** (rare after `bpf_redirect_neigh` fix)
```bash
kubectl -n udp-fanout logs daemonset/udp-fanout | grep "FIB"
```

### Performance issues

**Check 1: CPU saturation**
```bash
kubectl top pods -n udp-fanout
```
If >80% → increase CPU limits or reduce packet rate.

**Check 2: Kernel version**
```bash
kubectl exec -n udp-fanout daemonset/udp-fanout -- uname -r
```
If <5.10 → falls back to manual L2 rewrite (slower).

**Check 3: Interface MTU**
```bash
kubectl exec -n udp-fanout daemonset/udp-fanout -- ip link show eth0
```
Ensure MTU matches expected packet sizes.

### Common Errors

**"failed to attach TC program: permission denied"**
- Missing capabilities → check `securityContext` in DaemonSet
- SELinux/AppArmor blocking → may need `privileged: true` temporarily

**"interface not found: eth0"**
- Wrong interface name → check with `ip link` and update config
- Container doesn't have access → ensure `hostNetwork: true`

**"EndpointSlice not found"**
- Wrong namespace in config → verify receiver namespace
- Service doesn't exist → create a headless Service for receivers
- Missing RBAC → verify Role has `endpointslices` read permission

## Examples

### Example: Vector Log Aggregation

Deploy Vector receivers:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vector-aggregators
  namespace: logging
spec:
  replicas: 3
  selector:
    matchLabels:
      app: vector
  template:
    metadata:
      labels:
        app: vector
    spec:
      containers:
        - name: vector
          image: timberio/vector:latest-alpine
          volumeMounts:
            - name: config
              mountPath: /etc/vector
          ports:
            - containerPort: 5514
              protocol: UDP
      volumes:
        - name: config
          configMap:
            name: vector-config
---
apiVersion: v1
kind: Service
metadata:
  name: vector-aggregators
  namespace: logging
spec:
  clusterIP: None  # Headless service
  selector:
    app: vector
  ports:
    - port: 5514
      protocol: UDP
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: vector-config
  namespace: logging
data:
  vector.yaml: |
    sources:
      syslog:
        type: socket
        address: "0.0.0.0:5514"
        mode: udp
    sinks:
      loki:
        type: loki
        inputs: [syslog]
        endpoint: http://loki:3100
```

Then configure udp-fanout:

```yaml
listeners:
  - name: syslog
    bind: "0.0.0.0:5514"
    interface: eth0
    mode: tc_ebpf
    kubernetes:
      namespace: logging
      service: vector-aggregators
      port: 5514

health:
  enabled: true
  interval_secs: 5
  timeout_secs: 2
  protocol: icmp
```

### Example: Multi-Tenant with Multiple Listeners

```yaml
listeners:
  # Tenant A - syslog
  - name: tenant-a-syslog
    bind: "0.0.0.0:5514"
    interface: eth0
    mode: tc_ebpf
    kubernetes:
      namespace: tenant-a
      service: log-receivers
      port: 5514

  # Tenant B - metrics
  - name: tenant-b-metrics
    bind: "0.0.0.0:9125"
    interface: eth0
    mode: tc_ebpf
    kubernetes:
      namespace: tenant-b
      service: statsd-receivers
      port: 9125

  # Tenant C - custom UDP app
  - name: tenant-c-app
    bind: "0.0.0.0:8888"
    interface: eth0
    mode: tc_ebpf
    kubernetes:
      namespace: tenant-c
      service: app-receivers
      port: 8888
```

## Next Steps

- [Architecture Deep Dive](ARCHITECTURE.md)
- [Configuration Reference](CONFIGURATION.md)
- [Development Guide](DEVELOPMENT.md)
