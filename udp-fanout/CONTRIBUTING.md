# Contributing to udp-fanout

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## Code of Conduct

Be respectful, inclusive, and professional. We welcome contributions from everyone.

## How to Contribute

### Reporting Bugs

Open an issue with:
- Clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Environment details (kernel version, k8s version, CNI)
- Relevant logs

### Suggesting Features

Open an issue with:
- Use case description
- Proposed solution
- Alternatives considered
- Impact on existing functionality

### Pull Requests

1. **Fork and clone**:
   ```bash
   git clone https://github.com/yourusername/udp-fanout
   cd udp-fanout
   ```

2. **Create a branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make changes**:
   - Follow Rust style guidelines (`cargo fmt`)
   - Add tests for new functionality
   - Update documentation if needed

4. **Test**:
   ```bash
   cargo test
   cargo xtask build --release
   # Test in Kubernetes if applicable
   ```

5. **Commit**:
   ```bash
   git commit -m "feat: add your feature"
   ```
   Follow [Conventional Commits](https://www.conventionalcommits.org/)

6. **Push and open PR**:
   ```bash
   git push origin feature/your-feature-name
   ```
   Open PR with clear description and link to related issues.

## Development Setup

### Prerequisites

- Rust stable (1.75+) + nightly
- bpf-linker: `cargo install bpf-linker`
- System packages: `clang`, `llvm`, `libelf-dev`
- Kubernetes cluster for testing (k3s, kind, minikube)

### Build

```bash
# Build eBPF + userspace
cargo xtask build --release

# Run tests
cargo test

# Format code
cargo fmt --all

# Lint
cargo clippy --all-targets
```

### Testing

**Unit tests**:
```bash
cargo test -p udp-fanout
cargo test -p udp-fanout-common
```

**eBPF tests** (requires root):
```bash
sudo -E cargo xtask build
sudo -E cargo test -p udp-fanout-ebpf
```

**Integration tests in Kubernetes**:
```bash
# Build and load into cluster
docker build -t udp-fanout:dev .
kind load docker-image udp-fanout:dev

# Deploy
kubectl apply -f k8s/rbac.yaml
kubectl apply -f k8s/daemonset.yaml
kubectl apply -f k8s/example-receivers.yaml

# Test
kubectl -n udp-fanout logs -f daemonset/udp-fanout
```

## Project Structure

```
udp-fanout/
├── udp-fanout/          # Userspace daemon (Rust)
│   └── src/
│       ├── main.rs      # CLI + main loop
│       ├── ebpf_manager.rs  # eBPF map management
│       ├── kubernetes.rs    # EndpointSlice watcher
│       ├── health.rs    # Health probes
│       └── userspace.rs # Userspace fallback mode
├── udp-fanout-ebpf/     # eBPF program (Rust)
│   └── src/
│       ├── main.rs      # Entry point, map definitions
│       └── fanout.rs    # Packet processing logic
├── udp-fanout-common/   # Shared types (Rust)
│   └── src/lib.rs       # Data structures, constants
├── xtask/               # Build automation
├── k8s/                 # Kubernetes manifests
└── docs/                # Documentation
```

## eBPF Development

**Important**: eBPF verifier is strict. Follow these patterns:

1. **Bounds checking**: Always use `ctx.load()` for packet access
2. **Loop unrolling**: Keep loops simple, verifier doesn't like complex control flow
3. **Map access**: Check return values, handle `None` cases
4. **Packet modification**: Use `ctx.store()` with correct offsets

**Debugging eBPF**:
```bash
# Verbose verifier output
sudo bpftool prog load udp-fanout-ebpf --debug

# Check loaded program
sudo bpftool prog show | grep udp_fanout

# Dump maps
sudo bpftool map dump name STATS
```

## Documentation

Update docs when adding:
- New config options → `config.example.yaml` + `docs/CONFIGURATION.md`
- New features → `README.md` + relevant doc in `docs/`
- Breaking changes → `CHANGELOG.md` (when created)

## License

By contributing, you agree that your contributions will be licensed under Apache License 2.0.

## Questions?

Open a discussion or reach out via issues!
