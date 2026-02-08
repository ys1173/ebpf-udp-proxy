//! Kubernetes EndpointSlice discovery.
//!
//! This is the k8s-native equivalent of Envoy EDS membership: we watch EndpointSlice objects
//! for a Service and maintain a live set of "ready" endpoints. The dataplane can then do
//! per-packet load balancing over the ready set (e.g., round-robin).

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use futures::{StreamExt, TryStreamExt};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use kube::api::ListParams;
use kube::runtime::watcher::{watcher, Config as WatcherConfig, Event};
use kube::{Api, Client, ResourceExt};
use tracing::{debug, info, warn};

use crate::config::KubernetesDiscoveryConfig;
use crate::ebpf_manager::EbpfManager;

/// Spawn a background task that watches EndpointSlices and updates `downstreams`.
///
/// `downstreams` is always replaced with a new snapshot (Arc<Vec<SocketAddr>>) containing only
/// endpoints that are considered ready.
pub fn spawn_endpointslice_watcher(
    listener_name: String,
    cfg: KubernetesDiscoveryConfig,
    downstreams: Arc<ArcSwap<Vec<SocketAddr>>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = endpointslice_watch_loop(listener_name, cfg, downstreams).await {
            warn!(error = %e, "kubernetes discovery task exited");
        }
    })
}

/// Spawn a background task that watches EndpointSlices and pushes ready endpoints into tc_ebpf maps.
///
/// This is the "Option A for tc_ebpf": Kubernetes is the membership source (like EDS),
/// and the TC dataplane forwards to endpoints in the eBPF maps.
pub fn spawn_endpointslice_watcher_tc_ebpf(
    listener_name: String,
    cfg: KubernetesDiscoveryConfig,
    listener_id: u32,
    ebpf_manager: Arc<tokio::sync::Mutex<Option<EbpfManager>>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) =
            endpointslice_watch_loop_tc_ebpf(listener_name, cfg, listener_id, ebpf_manager).await
        {
            warn!(error = %e, "kubernetes tc_ebpf discovery task exited");
        }
    })
}

async fn endpointslice_watch_loop(
    listener_name: String,
    cfg: KubernetesDiscoveryConfig,
    downstreams: Arc<ArcSwap<Vec<SocketAddr>>>,
) -> Result<()> {
    let namespace = match cfg.namespace.clone() {
        Some(ns) => ns,
        None => read_incluster_namespace().unwrap_or_else(|| "default".to_string()),
    };

    let client = Client::try_default()
        .await
        .context("creating Kubernetes client (in-cluster or kubeconfig)")?;

    let api: Api<EndpointSlice> = Api::namespaced(client, &namespace);
    let selector = format!("kubernetes.io/service-name={}", cfg.service);

    // Use label selector at the watch layer for efficiency.
    let lp = ListParams::default().labels(&selector);
    let wc = WatcherConfig {
        label_selector: Some(selector),
        ..Default::default()
    };

    info!(
        listener = %listener_name,
        namespace = %namespace,
        service = %cfg.service,
        port = cfg.port,
        "starting EndpointSlice watch"
    );

    // Track per-slice endpoints so we can handle delete events correctly.
    let mut slice_to_ips: HashMap<String, Vec<IpAddr>> = HashMap::new();
    let mut last_count: usize = usize::MAX;

    // Initial list to populate state quickly.
    let initial = api
        .list(&lp)
        .await
        .context("listing EndpointSlices")?
        .items;
    for es in initial {
        let name = es.name_any();
        slice_to_ips.insert(name, ready_ips_from_slice(&es));
    }
    last_count = publish_snapshot(&listener_name, cfg.port, &slice_to_ips, &downstreams);

    // Watch loop: reconnect on errors.
    loop {
        let mut w = watcher(api.clone(), wc.clone()).boxed();

        while let Some(ev) = w.try_next().await? {
            match ev {
                Event::Applied(es) => {
                    let name = es.name_any();
                    slice_to_ips.insert(name, ready_ips_from_slice(&es));
                    last_count =
                        publish_snapshot(&listener_name, cfg.port, &slice_to_ips, &downstreams);
                }
                Event::Deleted(es) => {
                    let name = es.name_any();
                    slice_to_ips.remove(&name);
                    last_count =
                        publish_snapshot(&listener_name, cfg.port, &slice_to_ips, &downstreams);
                }
                Event::Restarted(ess) => {
                    slice_to_ips.clear();
                    for es in ess {
                        let name = es.name_any();
                        slice_to_ips.insert(name, ready_ips_from_slice(&es));
                    }
                    last_count =
                        publish_snapshot(&listener_name, cfg.port, &slice_to_ips, &downstreams);
                }
            }
        }

        // If the watcher stream ends, back off briefly and retry.
        warn!(
            listener = %listener_name,
            "EndpointSlice watch stream ended; retrying"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

async fn endpointslice_watch_loop_tc_ebpf(
    listener_name: String,
    cfg: KubernetesDiscoveryConfig,
    listener_id: u32,
    ebpf_manager: Arc<tokio::sync::Mutex<Option<EbpfManager>>>,
) -> Result<()> {
    let namespace = match cfg.namespace.clone() {
        Some(ns) => ns,
        None => read_incluster_namespace().unwrap_or_else(|| "default".to_string()),
    };

    let client = Client::try_default()
        .await
        .context("creating Kubernetes client (in-cluster or kubeconfig)")?;

    let api: Api<EndpointSlice> = Api::namespaced(client, &namespace);
    let selector = format!("kubernetes.io/service-name={}", cfg.service);

    let lp = ListParams::default().labels(&selector);
    let wc = WatcherConfig {
        label_selector: Some(selector),
        ..Default::default()
    };

    info!(
        listener = %listener_name,
        listener_id,
        namespace = %namespace,
        service = %cfg.service,
        port = cfg.port,
        "starting EndpointSlice watch (tc_ebpf)"
    );

    let mut slice_to_ips: HashMap<String, Vec<IpAddr>> = HashMap::new();
    let mut last_count: usize = usize::MAX;

    let initial = api
        .list(&lp)
        .await
        .context("listing EndpointSlices")?
        .items;
    for es in initial {
        let name = es.name_any();
        slice_to_ips.insert(name, ready_ips_from_slice(&es));
    }
    last_count = publish_snapshot_tc_ebpf(
        &listener_name,
        listener_id,
        cfg.port,
        &slice_to_ips,
        &ebpf_manager,
        last_count,
    )
    .await?;

    loop {
        let mut w = watcher(api.clone(), wc.clone()).boxed();

        while let Some(ev) = w.try_next().await? {
            match ev {
                Event::Applied(es) => {
                    let name = es.name_any();
                    slice_to_ips.insert(name, ready_ips_from_slice(&es));
                }
                Event::Deleted(es) => {
                    let name = es.name_any();
                    slice_to_ips.remove(&name);
                }
                Event::Restarted(ess) => {
                    slice_to_ips.clear();
                    for es in ess {
                        let name = es.name_any();
                        slice_to_ips.insert(name, ready_ips_from_slice(&es));
                    }
                }
            }

            last_count = publish_snapshot_tc_ebpf(
                &listener_name,
                listener_id,
                cfg.port,
                &slice_to_ips,
                &ebpf_manager,
                last_count,
            )
            .await?;
        }

        warn!(
            listener = %listener_name,
            "EndpointSlice watch stream ended (tc_ebpf); retrying"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

fn read_incluster_namespace() -> Option<String> {
    // This is the standard file Kubernetes mounts into pods.
    // If not running in-cluster, the file won't exist.
    std::fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn ready_ips_from_slice(es: &EndpointSlice) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = Vec::new();

    for ep in &es.endpoints {
        let ready = ep
            .conditions
            .as_ref()
            .and_then(|c| c.ready)
            .unwrap_or(false);

        // Prefer skipping terminating endpoints if field is present.
        let terminating = ep
            .conditions
            .as_ref()
            .and_then(|c| c.terminating)
            .unwrap_or(false);

        if !ready || terminating {
            continue;
        }

        for addr in &ep.addresses {
            if let Ok(ip) = addr.parse::<IpAddr>() {
                out.push(ip);
            }
        }
    }

    out
}

fn publish_snapshot(
    listener_name: &str,
    port: u16,
    slice_to_ips: &HashMap<String, Vec<IpAddr>>,
    downstreams: &Arc<ArcSwap<Vec<SocketAddr>>>,
) -> usize {
    let mut set: BTreeSet<SocketAddr> = BTreeSet::new();
    for ips in slice_to_ips.values() {
        for ip in ips {
            set.insert(SocketAddr::new(*ip, port));
        }
    }
    let snapshot: Vec<SocketAddr> = set.into_iter().collect();

    let count = snapshot.len();
    if count == 0 {
        warn!(listener = %listener_name, "k8s discovery: 0 ready endpoints");
    } else {
        debug!(listener = %listener_name, endpoints = count, "updated k8s discovered downstreams");
    }

    downstreams.store(Arc::new(snapshot));
    count
}

async fn publish_snapshot_tc_ebpf(
    listener_name: &str,
    listener_id: u32,
    port: u16,
    slice_to_ips: &HashMap<String, Vec<IpAddr>>,
    ebpf_manager: &Arc<tokio::sync::Mutex<Option<EbpfManager>>>,
    last_count: usize,
) -> Result<usize> {
    let mut set: BTreeSet<SocketAddr> = BTreeSet::new();
    for ips in slice_to_ips.values() {
        for ip in ips {
            set.insert(SocketAddr::new(*ip, port));
        }
    }
    let snapshot: Vec<SocketAddr> = set.into_iter().collect();
    let count = snapshot.len();

    if count != last_count {
        info!(
            listener = %listener_name,
            listener_id,
            endpoints = count,
            "tc_ebpf k8s membership updated"
        );
    } else {
        debug!(
            listener = %listener_name,
            listener_id,
            endpoints = count,
            "updating tc_ebpf downstream table from k8s"
        );
    }

    if let Some(ref mut mgr) = *ebpf_manager.lock().await {
        mgr.replace_downstreams(listener_id, &snapshot)
            .with_context(|| "updating eBPF downstream table")?;
    } else {
        warn!(
            listener = %listener_name,
            "eBPF manager not initialized; cannot apply EndpointSlice update"
        );
    }

    Ok(count)
}

