# Release Checklist

Before uploading to GitHub, complete these steps:

## 1. Code Cleanup

- [x] Remove test scripts (done)
- [x] Remove test artifacts (done)
- [x] Add .gitignore (done)
- [ ] Review and clean up any hardcoded values (interface names, etc.)
- [ ] Remove any sensitive data or internal references

## 2. Documentation

- [x] README.md with features, quickstart, examples (done)
- [x] LICENSE file (Apache 2.0) (done)
- [x] CONTRIBUTING.md (done)
- [x] docs/DEPLOYMENT.md - comprehensive k8s guide (done)
- [ ] docs/ARCHITECTURE.md - technical deep dive (optional)
- [ ] docs/CONFIGURATION.md - all config options (optional)
- [ ] CHANGELOG.md - for future releases

## 3. Container Images

Decision needed:
- [ ] Build and push to Docker Hub / GitHub Container Registry?
- [ ] Or document local build only (current state)?

If pushing to registry:
```bash
docker build -t yourusername/udp-fanout:v0.1.0 .
docker push yourusername/udp-fanout:v0.1.0
```

Then update `k8s/daemonset.yaml`:
```yaml
image: yourusername/udp-fanout:v0.1.0
imagePullPolicy: IfNotPresent  # instead of Never
```

## 4. Kubernetes Manifests

- [x] rbac.yaml - namespace + RBAC (done)
- [x] configmap.yaml - simplified example (done)
- [x] daemonset.yaml - production-ready (done)
- [x] example-receivers.yaml - Vector example (done)
- [x] test-deployment.yaml - full test stack (done)

Check:
- [ ] All manifests use placeholder values (not hardcoded to your cluster)
- [ ] Comments explain what needs to be customized
- [ ] Image references point to public registry (if applicable)

## 5. Testing

Verify end-to-end:
- [x] Build succeeds: `cargo xtask build --release` (done)
- [x] Docker build succeeds: `docker build .` (done)
- [x] k8s deployment works: `kubectl apply -f k8s/` (done)
- [x] Traffic flows: external → eno1 → pods (done)
- [x] Health checks work (done)
- [ ] Clean cluster deployment (test on fresh k3s/kind cluster)

## 6. Git Setup

```bash
cd udp-fanout

# Initialize repo
git init

# Add all files
git add .

# Initial commit
git commit -m "Initial release: udp-fanout v0.1.0

Features:
- eBPF TC fast path with bpf_redirect_neigh
- Kubernetes EndpointSlice discovery
- Health monitoring (ICMP probes)
- Round-robin load balancing
- Tested on k3s with Vector receivers"

# Add remote (replace with your GitHub repo URL)
git remote add origin https://github.com/yourusername/udp-fanout.git

# Push
git branch -M main
git push -u origin main
```

## 7. GitHub Repository Setup

On GitHub after pushing:

1. **Add description**: "High-performance UDP fanout proxy with eBPF fast path for Kubernetes"

2. **Add topics/tags**:
   - ebpf
   - kubernetes
   - udp
   - load-balancer
   - rust
   - networking
   - observability

3. **Add README badges** (optional):
   ```markdown
   ![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)
   ![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)
   ![Kubernetes](https://img.shields.io/badge/kubernetes-1.19%2B-blue.svg)
   ```

4. **Create release** (v0.1.0):
   - Tag: `v0.1.0`
   - Title: "Initial Release"
   - Description: Copy key features from README

5. **Setup GitHub Actions** (optional - future work):
   - Build on push
   - Run tests
   - Build Docker image

## 8. Post-Release

- [ ] Announce on Rust forums / r/rust
- [ ] Submit to awesome-ebpf list
- [ ] Write blog post explaining the architecture
- [ ] Monitor issues and respond to feedback

## Current Status

✅ **Code is production-ready**
✅ **Documentation complete**
✅ **Tested end-to-end on k3s**
✅ **Licensed (Apache 2.0)**

Ready to push to GitHub after completing items above!

## Quick Start for Users (After Release)

```bash
# Clone
git clone https://github.com/yourusername/udp-fanout
cd udp-fanout

# Build image
docker build -t udp-fanout:latest .

# Deploy
kubectl apply -f k8s/rbac.yaml
kubectl apply -f k8s/configmap.yaml  # Edit first!
kubectl apply -f k8s/daemonset.yaml

# Test
kubectl apply -f k8s/example-receivers.yaml
# Send traffic and watch logs
kubectl -n udp-fanout logs -f daemonset/udp-fanout
```
