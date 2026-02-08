//! YAML configuration parsing and validation.
//!
//! Defines the configuration model for udp-fanout and validates it at load time.

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Top-Level Config
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct Config {
    pub listeners: Vec<ListenerConfig>,
    #[serde(default)]
    pub health: HealthConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
}

// ---------------------------------------------------------------------------
// Listener Config
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ListenerConfig {
    /// Human-readable name for this listener.
    pub name: String,

    /// Bind address (ip:port). The port determines which UDP traffic to intercept.
    pub bind: SocketAddr,

    /// Network interface name for eBPF attachment (e.g., "eth0").
    /// Required for tc_ebpf and af_xdp modes.
    #[serde(default)]
    pub interface: Option<String>,

    /// Forwarding mode.
    #[serde(default)]
    pub mode: ForwardingMode,

    /// Kubernetes EndpointSlice-based discovery (k8s-native).
    ///
    /// When set, downstream endpoints are discovered dynamically from the Kubernetes API.
    /// This is supported for userspace (and af_xdp) modes. It is **not** supported for tc_ebpf
    /// because that mode requires L2 (MAC) rewrite info for each downstream.
    #[serde(default)]
    pub kubernetes: Option<KubernetesDiscoveryConfig>,

    /// Downstream receivers.
    ///
    /// - With `kubernetes` discovery: this can be omitted/empty.
    /// - Without discovery: at least one downstream is required.
    #[serde(default)]
    pub downstream: Vec<DownstreamConfig>,

    /// Per-listener tuning settings.
    #[serde(default)]
    pub settings: ListenerSettings,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ForwardingMode {
    /// TC eBPF fast path — kernel-only forwarding via bpf_clone_redirect.
    TcEbpf,
    /// AF_XDP zero-copy receive with userspace fanout.
    AfXdp,
    /// Pure userspace with recvmmsg/sendmmsg.
    #[default]
    Userspace,
}

#[derive(Debug, Deserialize)]
pub struct DownstreamConfig {
    /// Human-readable name.
    pub name: String,

    /// Destination address (ip:port).
    pub address: SocketAddr,

    /// Destination MAC address (required for tc_ebpf mode).
    /// Format: "aa:bb:cc:dd:ee:ff"
    #[serde(default)]
    pub mac: Option<String>,
}

// ---------------------------------------------------------------------------
// Kubernetes Discovery Config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct KubernetesDiscoveryConfig {
    /// Namespace containing the Service / EndpointSlices.
    ///
    /// If omitted, defaults to "default".
    #[serde(default)]
    pub namespace: Option<String>,

    /// Kubernetes Service name. EndpointSlices are selected via label:
    /// `kubernetes.io/service-name=<service>`.
    pub service: String,

    /// UDP port to send to on each ready endpoint.
    pub port: u16,
}

#[derive(Debug, Deserialize)]
pub struct ListenerSettings {
    /// Maximum UDP datagram size.
    #[serde(default = "default_max_packet_size")]
    pub max_packet_size: usize,

    /// Maximum downstream receivers (eBPF array bound).
    #[serde(default = "default_max_downstream")]
    pub max_downstream: u32,

    /// Batch size for recvmmsg/sendmmsg (af_xdp and userspace modes).
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,

    /// Number of worker threads (userspace mode). 0 = auto-detect.
    #[serde(default)]
    pub workers: usize,

    /// Pin worker threads to CPU cores.
    #[serde(default = "default_true")]
    pub pin_cpus: bool,

    /// Socket receive buffer size. 0 = system default.
    #[serde(default)]
    pub recv_buf_size: usize,
}

impl Default for ListenerSettings {
    fn default() -> Self {
        Self {
            max_packet_size: default_max_packet_size(),
            max_downstream: default_max_downstream(),
            batch_size: default_batch_size(),
            workers: 0,
            pin_cpus: true,
            recv_buf_size: 0,
        }
    }
}

fn default_max_packet_size() -> usize {
    9000 // Jumbo frame support
}
fn default_max_downstream() -> u32 {
    64
}
fn default_batch_size() -> usize {
    32
}
fn default_true() -> bool {
    true
}

// ---------------------------------------------------------------------------
// Health Check Config
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct HealthConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_health_interval")]
    pub interval_secs: u64,

    #[serde(default = "default_health_timeout")]
    pub timeout_secs: u64,

    #[serde(default)]
    pub protocol: HealthProtocol,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: default_health_interval(),
            timeout_secs: default_health_timeout(),
            protocol: HealthProtocol::default(),
        }
    }
}

impl HealthConfig {
    pub fn interval(&self) -> Duration {
        Duration::from_secs(self.interval_secs)
    }
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs)
    }
}

fn default_health_interval() -> u64 {
    5
}
fn default_health_timeout() -> u64 {
    2
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum HealthProtocol {
    #[default]
    Icmp,
    UdpEcho,
}

// ---------------------------------------------------------------------------
// Metrics Config
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct MetricsConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_metrics_bind")]
    pub bind: SocketAddr,

    #[serde(default = "default_metrics_path")]
    pub path: String,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: default_metrics_bind(),
            path: default_metrics_path(),
        }
    }
}

fn default_metrics_bind() -> SocketAddr {
    "0.0.0.0:9090".parse().unwrap()
}
fn default_metrics_path() -> String {
    "/metrics".to_string()
}

// ---------------------------------------------------------------------------
// Loading & Validation
// ---------------------------------------------------------------------------

impl Config {
    /// Load config from a YAML file path.
    pub fn load(path: &Path) -> Result<Self> {
        let contents =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;

        let config: Config =
            serde_yaml::from_str(&contents).with_context(|| "parsing YAML config")?;

        config.validate()?;
        Ok(config)
    }

    /// Validate configuration consistency.
    fn validate(&self) -> Result<()> {
        if self.listeners.is_empty() {
            bail!("at least one listener is required");
        }

        for (i, listener) in self.listeners.iter().enumerate() {
            let ctx = format!("listener[{}] '{}'", i, listener.name);

            if listener.kubernetes.is_none() && listener.downstream.is_empty() {
                bail!("{}: at least one downstream is required", ctx);
            }

            if listener.downstream.len() > listener.settings.max_downstream as usize {
                bail!(
                    "{}: {} downstreams exceeds max_downstream ({})",
                    ctx,
                    listener.downstream.len(),
                    listener.settings.max_downstream
                );
            }

            // eBPF modes require interface
            if matches!(
                listener.mode,
                ForwardingMode::TcEbpf | ForwardingMode::AfXdp
            ) {
                if listener.interface.is_none() {
                    bail!("{}: 'interface' is required for {:?} mode", ctx, listener.mode);
                }
            }

            // MAC validation (optional/back-compat).
            // tc_ebpf no longer requires static MACs because it uses FIB lookup for next-hop.
            for (j, ds) in listener.downstream.iter().enumerate() {
                if let Some(ref mac) = ds.mac {
                    parse_mac(mac)
                        .with_context(|| format!("{}: downstream[{}] invalid MAC", ctx, j))?;
                }
            }

            // Validate k8s discovery config (if present)
            if let Some(k8s) = &listener.kubernetes {
                if k8s.service.trim().is_empty() {
                    bail!("{}: kubernetes.service must not be empty", ctx);
                }
                if k8s.port == 0 {
                    bail!("{}: kubernetes.port must be 1..65535, got 0", ctx);
                }
            }

            // Validate packet size
            if listener.settings.max_packet_size == 0
                || listener.settings.max_packet_size > 65535
            {
                bail!(
                    "{}: max_packet_size must be 1..65535, got {}",
                    ctx,
                    listener.settings.max_packet_size
                );
            }
        }

        Ok(())
    }
}

/// Parse a MAC address string "aa:bb:cc:dd:ee:ff" into 6 bytes.
pub fn parse_mac(s: &str) -> Result<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        bail!("MAC address must have 6 octets, got '{}'", s);
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16)
            .with_context(|| format!("invalid MAC octet '{}' in '{}'", part, s))?;
    }
    Ok(mac)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mac() {
        let mac = parse_mac("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_parse_mac_invalid() {
        assert!(parse_mac("aa:bb:cc").is_err());
        assert!(parse_mac("gg:bb:cc:dd:ee:ff").is_err());
    }

    #[test]
    fn test_minimal_config() {
        let yaml = r#"
listeners:
  - name: test
    bind: "0.0.0.0:9000"
    mode: userspace
    downstream:
      - name: sink
        address: "10.0.0.1:9000"
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        config.validate().unwrap();
        assert_eq!(config.listeners.len(), 1);
        assert_eq!(config.listeners[0].downstream.len(), 1);
    }

    #[test]
    fn test_tc_ebpf_requires_mac() {
        let yaml = r#"
listeners:
  - name: test
    bind: "0.0.0.0:9000"
    interface: eth0
    mode: tc_ebpf
    downstream:
      - name: sink
        address: "10.0.0.1:9000"
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn test_k8s_discovery_allows_empty_downstreams() {
        let yaml = r#"
listeners:
  - name: test
    bind: "0.0.0.0:9000"
    mode: userspace
    kubernetes:
      namespace: default
      service: udp-receivers
      port: 9000
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        config.validate().unwrap();
        assert_eq!(config.listeners.len(), 1);
        assert!(config.listeners[0].downstream.is_empty());
        assert!(config.listeners[0].kubernetes.is_some());
    }
}
