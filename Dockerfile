# Multi-stage build for udp-fanout
#
# Stage 1: Build eBPF program (needs nightly + bpf-linker)
# Stage 2: Build userspace daemon
# Stage 3: Minimal runtime image

# ---------------------------------------------------------------------------
# Stage 1: eBPF Build
# ---------------------------------------------------------------------------
FROM rust:1.82-bookworm AS ebpf-builder

# Install BPF toolchain dependencies
RUN apt-get update && apt-get install -y \
    llvm-17 \
    clang-17 \
    libelf-dev \
    linux-headers-generic \
    && rm -rf /var/lib/apt/lists/*

# Install nightly toolchain and bpf-linker
RUN rustup toolchain install nightly --component rust-src \
    && rustup target add bpfel-unknown-none --toolchain nightly \
    && cargo +nightly install bpf-linker

WORKDIR /build
COPY . .

# Build eBPF program
RUN cd udp-fanout-ebpf && \
    cargo +nightly build \
        --target=bpfel-unknown-none \
        -Z build-std=core \
        --release

# ---------------------------------------------------------------------------
# Stage 2: Userspace Build
# ---------------------------------------------------------------------------
FROM rust:1.82-bookworm AS userspace-builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    libelf-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .

# Copy eBPF binary from stage 1
COPY --from=ebpf-builder \
    /build/udp-fanout-ebpf/target/bpfel-unknown-none/release/udp-fanout-ebpf \
    /build/target/udp-fanout-ebpf

# Build userspace daemon in release mode
RUN cargo build --release -p udp-fanout

# ---------------------------------------------------------------------------
# Stage 3: Minimal Runtime
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# Install minimal runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libelf1 \
    iputils-ping \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user (will still need CAP_BPF, CAP_NET_ADMIN via K8s)
RUN useradd -r -s /bin/false udp-fanout

WORKDIR /opt/udp-fanout

# Copy binaries
COPY --from=userspace-builder /build/target/release/udp-fanout /opt/udp-fanout/udp-fanout
COPY --from=userspace-builder /build/target/udp-fanout-ebpf /opt/udp-fanout/udp-fanout-ebpf

# Copy example config
COPY config.example.yaml /opt/udp-fanout/config.example.yaml

# Metrics port
EXPOSE 9090/tcp

ENTRYPOINT ["/opt/udp-fanout/udp-fanout"]
CMD ["--config", "/etc/udp-fanout/config.yaml", "--ebpf-program", "/opt/udp-fanout/udp-fanout-ebpf"]
