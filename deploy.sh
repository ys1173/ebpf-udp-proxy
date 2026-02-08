#!/usr/bin/env bash
#
# deploy.sh — Deploy, build, and optionally test udp-fanout on a remote Linux machine.
#
# Usage:
#   ./deploy.sh                    # Deploy + build
#   ./deploy.sh --test             # Deploy + build + run smoke test
#
# Prerequisites:
#   - SSH access configured: `ssh homevideosvr` must work from your terminal
#   - Remote machine: Linux x86_64 with kernel 4.18+ (tc_ebpf uses bpf_fib_lookup)
#

set -euo pipefail

REMOTE_HOST="homevideosvr"
REMOTE_DIR="/home/home/temp/ebpf_udp_proxy"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RUN_TEST=false

for arg in "$@"; do
    case "$arg" in
        --test) RUN_TEST=true ;;
        --host=*) REMOTE_HOST="${arg#--host=}" ;;
        *) echo "Unknown arg: $arg"; exit 1 ;;
    esac
done

echo "==> Deploying udp-fanout to ${REMOTE_HOST}:${REMOTE_DIR}"

# Step 1: Ensure remote directory exists
ssh "${REMOTE_HOST}" "mkdir -p ${REMOTE_DIR}"

# Step 2: Sync project files (exclude build artifacts and envoy source)
rsync -avz --delete \
    --exclude 'target/' \
    --exclude '.git/' \
    --exclude 'envoy-main/' \
    "${SCRIPT_DIR}/" \
    "${REMOTE_HOST}:${REMOTE_DIR}/"

echo "==> Files synced"

# Step 3: Install Rust toolchain if not present, then build
ssh "${REMOTE_HOST}" bash -s <<'REMOTE_BUILD'
set -euo pipefail
cd /home/home/temp/ebpf_udp_proxy

echo "==> Checking build dependencies..."

# Install Rust if not present
if ! command -v rustc &>/dev/null; then
    echo "==> Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi
source "$HOME/.cargo/env" 2>/dev/null || true

echo "    rustc: $(rustc --version)"
echo "    cargo: $(cargo --version)"

# Install nightly toolchain + BPF target for eBPF compilation
echo "==> Setting up eBPF toolchain..."
rustup toolchain install nightly --component rust-src 2>/dev/null || true
rustup target add bpfel-unknown-none --toolchain nightly 2>/dev/null || true

# Install bpf-linker if not present
if ! command -v bpf-linker &>/dev/null; then
    echo "==> Installing bpf-linker (this may take a few minutes)..."
    cargo +nightly install bpf-linker
fi

# Install system deps for eBPF (best-effort)
if command -v apt-get &>/dev/null; then
    echo "==> Checking system packages..."
    sudo apt-get update -qq 2>/dev/null || true
    sudo apt-get install -y -qq libelf-dev pkg-config linux-headers-$(uname -r) 2>/dev/null || true
elif command -v dnf &>/dev/null; then
    sudo dnf install -y elfutils-libelf-devel pkgconfig kernel-headers 2>/dev/null || true
fi

# Step 3a: Build eBPF program
echo "==> Building eBPF program..."
cd udp-fanout-ebpf
cargo +nightly build \
    --target=bpfel-unknown-none \
    -Z build-std=core \
    --release 2>&1

# Copy eBPF binary to workspace target
cd ..
mkdir -p target
cp udp-fanout-ebpf/target/bpfel-unknown-none/release/udp-fanout-ebpf target/udp-fanout-ebpf 2>/dev/null || true
echo "    eBPF binary: target/udp-fanout-ebpf"

# Step 3b: Build userspace daemon
echo "==> Building userspace daemon..."
cargo build --release -p udp-fanout 2>&1

echo "    daemon binary: target/release/udp-fanout"
echo ""
echo "==> Build complete!"
ls -lh target/release/udp-fanout target/udp-fanout-ebpf 2>/dev/null

REMOTE_BUILD

echo "==> Build finished on remote"

# Step 4: Run smoke test if requested
if [ "$RUN_TEST" = true ]; then
    echo ""
    echo "==> Running smoke test..."
    ssh "${REMOTE_HOST}" bash -s <<'REMOTE_TEST'
set -euo pipefail
cd /home/home/temp/ebpf_udp_proxy
source "$HOME/.cargo/env" 2>/dev/null || true

# Write a minimal test config (userspace mode — no root needed)
cat > /tmp/udp-fanout-test.yaml <<'YAML'
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
      max_packet_size: 1500
      batch_size: 32
      workers: 1

metrics:
  enabled: true
  bind: "127.0.0.1:19090"
  path: /metrics
YAML

echo "--- Test config written to /tmp/udp-fanout-test.yaml"

# Start 3 UDP listener sinks in background
for port in 19001 19002 19003; do
    python3 -c "
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('127.0.0.1', $port))
s.settimeout(5)
count = 0
try:
    while count < 10:
        data, addr = s.recvfrom(4096)
        count += 1
        print(f'sink:$port received #{count}: {data.decode()}', flush=True)
except socket.timeout:
    pass
print(f'sink:$port total received: {count}', flush=True)
" &
    echo "--- Started UDP sink on port $port (PID $!)"
done

# Give sinks time to bind
sleep 0.5

# Start the proxy in background
./target/release/udp-fanout \
    --config /tmp/udp-fanout-test.yaml \
    --log-level debug &
PROXY_PID=$!
echo "--- Started udp-fanout (PID $PROXY_PID)"

# Give proxy time to start
sleep 1

# Send 10 test packets
echo "--- Sending 10 test packets to 127.0.0.1:19000..."
for i in $(seq 1 10); do
    echo "test-packet-$i" | python3 -c "
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
msg = sys.stdin.read().strip().encode()
s.sendto(msg, ('127.0.0.1', 19000))
"
done

echo "--- Packets sent. Waiting for sinks to receive..."
sleep 3

# Check metrics
echo ""
echo "--- Metrics:"
curl -s http://127.0.0.1:19090/metrics 2>/dev/null || echo "(metrics endpoint not reachable)"

# Cleanup
echo ""
echo "--- Cleaning up..."
kill $PROXY_PID 2>/dev/null || true
wait 2>/dev/null || true
echo "==> Smoke test complete"

REMOTE_TEST
fi

echo ""
echo "==> Done! Binary is at ${REMOTE_HOST}:${REMOTE_DIR}/target/release/udp-fanout"
echo ""
echo "To run manually:"
echo "  ssh ${REMOTE_HOST}"
echo "  cd ${REMOTE_DIR}"
echo "  sudo ./target/release/udp-fanout --config config.example.yaml --ebpf-program target/udp-fanout-ebpf"
echo ""
echo "To test eBPF mode (requires root):"
echo "  sudo ./target/release/udp-fanout --config config.example.yaml --ebpf-program target/udp-fanout-ebpf"
