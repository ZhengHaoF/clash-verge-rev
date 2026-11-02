//! Node IP optimization: resolve proxy `server` domains through multiple DNS
//! channels (UDP 53 + DoH JSON), probe candidates with TCP connect, and
//! persist the fastest IP per (domain, port). The enhance chain rewrites
//! `server` fields at runtime from the stored result, so the profile file
//! itself is never modified and a subscription refresh keeps the optimization.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering};
use std::time::Duration;

use anyhow::{Result, bail};
use clash_verge_logging::{Type, logging};
use futures::StreamExt as _;
use serde::{Deserialize, Serialize};
use serde_yaml_ng::{Mapping, Value};
use tauri::ipc::Channel;

use crate::config::Config;
use crate::constants::files::IP_OPTIMIZE;
use crate::utils::dirs;

/// Direct UDP 53 resolvers, probed concurrently per domain.
pub const UDP_DNS_SERVERS: &[&str] = &[
    "8.8.8.8",
    "114.114.114.114",
    "1.1.1.1",
    "119.29.29.29",
    "182.254.116.116",
    "223.5.5.5",
    "223.6.6.6",
    "180.76.76.76",
    "9.9.9.9",
    "149.112.112.112",
    "208.67.222.222",
    "101.101.101.101",
];

/// DoH JSON API endpoints, used when every UDP resolver failed.
pub const DOH_ENDPOINTS: &[&str] = &[
    "https://1.1.1.1/dns-query",
    "https://dns.alidns.com/resolve",
    "https://dns.google/resolve",
    "https://doh.pub/dns-query",
];

const DEFAULT_CONCURRENCY: u32 = 20;
const DEFAULT_TCP_TIMEOUT_MS: u64 = 1000;
const DEFAULT_DNS_TIMEOUT_MS: u64 = 3000;

static RUNNING: AtomicBool = AtomicBool::new(false);
static STOP: AtomicBool = AtomicBool::new(false);
static QUERY_ID: AtomicU16 = AtomicU16::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "snake_case")]
pub enum IpOptimizePhase {
    Resolve,
    Speed,
}

/// Streamed to the page while a run is in progress.
#[derive(Debug, Clone, Serialize, specta::Type)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IpOptimizeEvent {
    Log {
        message: String,
    },
    Stats {
        total_nodes: u32,
        domain_nodes: u32,
        ip_nodes: u32,
    },
    Progress {
        phase: IpOptimizePhase,
        done: u32,
        total: u32,
    },
    Entry {
        name: String,
        server: String,
        target: String,
        latency_ms: Option<f64>,
        /// ok | skip | fail
        status: std::string::String,
    },
    Done {
        summary: IpOptimizeSummary,
    },
}

/// Fastest IP for one (domain, port) pair.
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
pub struct IpOptimizeBest {
    pub port: u16,
    pub ip: std::string::String,
    pub latency_ms: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, specta::Type)]
pub struct IpOptimizeSummary {
    pub profile_uid: std::string::String,
    /// Unix timestamp of the run, seconds.
    pub updated_at: u64,
    pub domain_nodes: u32,
    pub ip_nodes: u32,
    /// Nodes whose (domain, port) pair got a replacement IP.
    pub optimized_nodes: u32,
    pub domains: BTreeMap<std::string::String, Vec<IpOptimizeBest>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, specta::Type)]
pub struct IpOptimizeStore {
    pub profiles: BTreeMap<std::string::String, IpOptimizeSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
pub struct IpOptimizeParams {
    pub concurrency: u32,
    pub tcp_timeout_ms: u64,
    pub dns_timeout_ms: u64,
    pub enable_doh: bool,
}

impl Default for IpOptimizeParams {
    fn default() -> Self {
        Self {
            concurrency: DEFAULT_CONCURRENCY,
            tcp_timeout_ms: DEFAULT_TCP_TIMEOUT_MS,
            dns_timeout_ms: DEFAULT_DNS_TIMEOUT_MS,
            enable_doh: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, specta::Type)]
pub struct IpOptimizeView {
    pub enabled: bool,
    pub profile_uid: std::string::String,
    pub profiles: BTreeMap<std::string::String, IpOptimizeSummary>,
}

fn is_fake_ip(ip: IpAddr) -> bool {
    // Clash/Mihomo fake-ip range 198.18.0.0/15; such answers mean the query
    // was hijacked by the local core and must not be stored.
    matches!(ip, IpAddr::V4(v4) if [198, 18].contains(&v4.octets()[0]) && v4.octets()[1] == 18)
}

fn is_ip(server: &str) -> bool {
    server.parse::<IpAddr>().is_ok()
}

/// domain -> port -> node names sharing that (server, port) pair.
type OptimizeTargets = (
    BTreeMap<std::string::String, BTreeMap<u16, Vec<std::string::String>>>,
    Vec<(std::string::String, std::string::String)>,
);

fn collect_targets(config: &Mapping) -> OptimizeTargets {
    let mut domains: BTreeMap<std::string::String, BTreeMap<u16, Vec<std::string::String>>> = BTreeMap::new();
    let mut ip_nodes = Vec::new();
    let Some(entries) = config.get("proxies").and_then(Value::as_sequence) else {
        return (domains, ip_nodes);
    };
    for entry in entries {
        let Some(proxy) = entry.as_mapping() else { continue };
        let Some(server) = proxy.get("server").and_then(Value::as_str).map(str::trim) else {
            continue;
        };
        if server.is_empty() {
            continue;
        }
        let name = proxy.get("name").and_then(Value::as_str).unwrap_or_default().to_owned();
        let port = proxy
            .get("port")
            .and_then(Value::as_u64)
            .filter(|port| (1..=65535).contains(port))
            .unwrap_or(443) as u16;
        if is_ip(server) {
            ip_nodes.push((name, server.to_owned()));
        } else {
            domains
                .entry(server.to_owned())
                .or_default()
                .entry(port)
                .or_default()
                .push(name);
        }
    }
    (domains, ip_nodes)
}

fn skip_dns_name(buf: &[u8], mut pos: usize) -> Option<usize> {
    let mut jumps = 0;
    // Position right after the name in the original stream; compression
    // pointers only reference earlier bytes, so this is where the record
    // fields continue.
    let mut tail = pos;
    let mut jumped = false;
    loop {
        let len = *buf.get(pos)?;
        match len & 0xC0 {
            0x00 => {
                pos += 1;
                if len == 0 {
                    return Some(if jumped { tail } else { pos });
                }
                pos += len as usize;
                if !jumped {
                    tail = pos;
                }
            }
            0xC0 => {
                if !jumped {
                    tail = pos + 2;
                }
                let low = *buf.get(pos + 1)?;
                pos = (((len & 0x3F) as usize) << 8) | low as usize;
                jumps += 1;
                jumped = true;
                if jumps > 64 || pos >= buf.len() {
                    return None;
                }
            }
            _ => return None,
        }
    }
}

fn build_dns_query(id: u16, domain: &str) -> Option<Vec<u8>> {
    let domain = domain.strip_suffix('.').unwrap_or(domain);
    if domain.is_empty() {
        return None;
    }
    let mut buf = Vec::with_capacity(17 + domain.len());
    buf.extend_from_slice(&id.to_be_bytes());
    // RD=1, everything else zero; QDCOUNT=1.
    buf.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
    buf.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A, IN
    Some(buf)
}

fn parse_dns_a_records(buf: &[u8], query_id: u16) -> Option<Vec<Ipv4Addr>> {
    if buf.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    if id != query_id {
        return None;
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    if flags & 0x8000 == 0 || flags & 0x000F != 0 {
        // Not a response, or an error rcode.
        return None;
    }
    let answers = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let mut pos = 12;
    let questions = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    for _ in 0..questions {
        pos = skip_dns_name(buf, pos)?;
        pos += 4;
    }
    let mut ips = Vec::new();
    for _ in 0..answers {
        pos = skip_dns_name(buf, pos)?;
        if pos + 10 > buf.len() {
            return None;
        }
        let record_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let rdlength = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;
        let end = pos.checked_add(rdlength)?;
        if end > buf.len() {
            return None;
        }
        if record_type == 1 && rdlength == 4 {
            ips.push(Ipv4Addr::new(buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]));
        }
        pos = end;
    }
    Some(ips)
}

async fn query_udp_nameserver(ns: Ipv4Addr, domain: &str, timeout: Duration) -> Vec<Ipv4Addr> {
    let id = QUERY_ID.fetch_add(1, Ordering::Relaxed);
    let Some(query) = build_dns_query(id, domain) else {
        return Vec::new();
    };
    let Ok(socket) = tokio::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await else {
        return Vec::new();
    };
    if socket.connect((ns, 53)).await.is_err() {
        return Vec::new();
    }
    if socket.send(&query).await.is_err() {
        return Vec::new();
    }
    let mut buf = vec![0u8; 4096];
    // The first reply on an ephemeral port can be a stale response to an
    // earlier query; a mismatched ID is retried once before giving up.
    for _ in 0..2 {
        let received = tokio::time::timeout(timeout, socket.recv(&mut buf)).await;
        match received {
            Ok(Ok(n)) => {
                if let Some(ips) = parse_dns_a_records(&buf[..n], id) {
                    return ips;
                }
            }
            _ => return Vec::new(),
        }
    }
    Vec::new()
}

async fn resolve_udp(domain: &str, timeout: Duration) -> Vec<Ipv4Addr> {
    let queries = UDP_DNS_SERVERS
        .iter()
        .filter_map(|ns| ns.parse::<Ipv4Addr>().ok())
        .map(|ns| query_udp_nameserver(ns, domain, timeout));
    let mut ips = BTreeSet::new();
    for answers in futures::future::join_all(queries).await {
        ips.extend(answers);
    }
    ips.into_iter().collect()
}

#[derive(Deserialize)]
struct DohAnswer {
    #[serde(default)]
    r#type: u16,
    #[serde(default)]
    data: std::string::String,
}

#[derive(Deserialize)]
struct DohResponse {
    #[serde(default)]
    status: i32,
    #[serde(default)]
    answer: Vec<DohAnswer>,
}

impl DohResponse {
    fn a_records(&self) -> Vec<Ipv4Addr> {
        if self.status != 0 {
            return Vec::new();
        }
        self.answer
            .iter()
            .filter(|answer| answer.r#type == 1)
            .filter_map(|answer| answer.data.parse().ok())
            .collect()
    }
}

async fn resolve_doh(domain: &str, timeout: Duration, client: &reqwest::Client) -> Vec<Ipv4Addr> {
    let requests = DOH_ENDPOINTS.iter().map(|endpoint| async move {
        let response = client
            .get(*endpoint)
            .query(&[("name", domain), ("type", "A")])
            .header("accept", "application/dns-json")
            .timeout(timeout)
            .send()
            .await
            .ok()?
            .json::<DohResponse>()
            .await
            .ok()?;
        Some(response.a_records())
    });
    let mut ips = BTreeSet::new();
    for answers in futures::future::join_all(requests).await {
        ips.extend(answers.unwrap_or_default());
    }
    ips.into_iter().collect()
}

fn build_doh_client(proxy_port: Option<u16>) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .user_agent("clash-verge-rev/ip-optimize")
        .use_rustls_tls();
    if let Some(port) = proxy_port {
        builder = builder.proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{port}"))?);
    }
    Ok(builder.build()?)
}

async fn tcp_probe(ip: IpAddr, port: u16, timeout: Duration) -> Option<Duration> {
    let started = std::time::Instant::now();
    tokio::time::timeout(timeout, tokio::net::TcpStream::connect((ip, port)))
        .await
        .ok()?
        .ok()?;
    Some(started.elapsed())
}

fn emit_event(channel: &Channel<IpOptimizeEvent>, event: IpOptimizeEvent) {
    let _ = channel.send(event);
}

/// Resolves and probes against the current runtime configuration and stores
/// the winners for the active profile. Stop through [`stop_run`]; a stopped
/// run still persists the phases it managed to finish.
pub async fn run_ip_optimize(
    params: IpOptimizeParams,
    channel: &Channel<IpOptimizeEvent>,
) -> Result<IpOptimizeSummary> {
    if RUNNING
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        bail!("an optimization run is already in progress");
    }
    let result = run_inner(params, channel).await;
    RUNNING.store(false, Ordering::Release);
    result
}

pub fn stop_run() {
    STOP.store(true, Ordering::Release);
}

async fn run_inner(params: IpOptimizeParams, channel: &Channel<IpOptimizeEvent>) -> Result<IpOptimizeSummary> {
    STOP.store(false, Ordering::Release);
    let profile_uid = {
        let profiles = Config::profiles().await;
        let profiles = profiles.latest_arc();
        profiles.current.clone().map(|uid| uid.to_string()).unwrap_or_default()
    };
    if profile_uid.is_empty() {
        bail!("no active profile");
    }

    let runtime = Config::runtime().await;
    let runtime_arc = runtime.latest_arc();
    let Some(config) = runtime_arc.config.clone() else {
        bail!("runtime configuration is not ready");
    };
    drop(runtime_arc);
    drop(runtime);

    let (domains, ip_nodes) = collect_targets(&config);
    let domain_nodes: u32 = domains
        .values()
        .map(|ports| ports.values().map(Vec::len).sum::<usize>())
        .sum::<usize>() as u32;
    let ip_nodes_count = ip_nodes.len() as u32;
    emit_event(
        channel,
        IpOptimizeEvent::Stats {
            total_nodes: domain_nodes + ip_nodes_count,
            domain_nodes,
            ip_nodes: ip_nodes_count,
        },
    );
    for (name, server) in &ip_nodes {
        emit_event(
            channel,
            IpOptimizeEvent::Entry {
                name: name.clone(),
                server: server.clone(),
                target: server.clone(),
                latency_ms: None,
                status: "skip".into(),
            },
        );
    }

    // ---- resolve ----
    let dns_timeout = Duration::from_millis(params.dns_timeout_ms);
    let doh_clients = if params.enable_doh {
        let port = crate::config::MixedPort::effective().await;
        build_doh_client(Some(port)).ok().zip(build_doh_client(None).ok())
    } else {
        None
    };
    let resolved = resolve_domains(
        &domains,
        dns_timeout,
        doh_clients,
        params.concurrency.max(1) as usize,
        channel,
    )
    .await;
    for (domain, ips) in &resolved {
        if ips.is_empty() {
            continue;
        }
        emit_event(
            channel,
            IpOptimizeEvent::Log {
                message: format!("{domain} resolved {ips_len} candidates", ips_len = ips.len()),
            },
        );
    }

    // ---- probe ----
    let tcp_timeout = Duration::from_millis(params.tcp_timeout_ms);
    let results = probe_domains(
        &domains,
        &resolved,
        tcp_timeout,
        params.concurrency.max(1) as usize,
        channel,
    )
    .await;

    let optimized_nodes: u32 = domains
        .iter()
        .map(|(domain, ports)| {
            let Some(best) = results.get(domain) else {
                return 0usize;
            };
            ports
                .iter()
                .filter(|(port, _)| best.iter().any(|entry| entry.port == **port))
                .map(|(_, names)| names.len())
                .sum::<usize>()
        })
        .sum::<usize>() as u32;

    let summary = IpOptimizeSummary {
        profile_uid: profile_uid.clone(),
        updated_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or_default(),
        domain_nodes,
        ip_nodes: ip_nodes_count,
        optimized_nodes,
        domains: results,
    };

    let mut store = load_store().await;
    store.profiles.insert(profile_uid, summary.clone());
    if let Err(error) = save_store(&store).await {
        logging!(warn, Type::Config, "ip-optimize: failed to persist results: {error}");
    }

    emit_event(
        channel,
        IpOptimizeEvent::Done {
            summary: summary.clone(),
        },
    );
    Ok(summary)
}

/// domain -> port -> node names sharing that (server, port) pair.
type DomainPorts = BTreeMap<u16, Vec<std::string::String>>;
type DomainTargets = BTreeMap<std::string::String, DomainPorts>;

async fn resolve_domains(
    domains: &DomainTargets,
    dns_timeout: Duration,
    doh_clients: Option<(reqwest::Client, reqwest::Client)>,
    concurrency: usize,
    channel: &Channel<IpOptimizeEvent>,
) -> BTreeMap<std::string::String, Vec<IpAddr>> {
    let total = domains.len() as u32;
    let (proxied_doh, direct_doh) = doh_clients.unzip();
    let counter = std::sync::Arc::new(AtomicU32::new(0));
    let shared_channel = channel.clone();
    let work = domains.keys().cloned().map(|domain| {
        let channel = shared_channel.clone();
        let counter = std::sync::Arc::clone(&counter);
        let proxied_doh = proxied_doh.clone();
        let direct_doh = direct_doh.clone();
        async move {
            if STOP.load(Ordering::Relaxed) {
                return (domain, Vec::new());
            }
            let mut ips = resolve_udp(&domain, dns_timeout)
                .await
                .into_iter()
                .map(IpAddr::from)
                .filter(|ip| !is_fake_ip(*ip))
                .collect::<Vec<_>>();
            if ips.is_empty()
                && let Some(client) = &proxied_doh
            {
                ips = resolve_doh(&domain, dns_timeout, client)
                    .await
                    .into_iter()
                    .map(IpAddr::from)
                    .filter(|ip| !is_fake_ip(*ip))
                    .collect();
            }
            if ips.is_empty()
                && let Some(client) = &direct_doh
            {
                ips = resolve_doh(&domain, dns_timeout, client)
                    .await
                    .into_iter()
                    .map(IpAddr::from)
                    .filter(|ip| !is_fake_ip(*ip))
                    .collect();
            }
            let done = counter.fetch_add(1, Ordering::Relaxed) + 1;
            emit_event(
                &channel,
                IpOptimizeEvent::Progress {
                    phase: IpOptimizePhase::Resolve,
                    done,
                    total,
                },
            );
            (domain, ips)
        }
    });
    futures::stream::iter(work)
        .buffer_unordered(concurrency)
        .collect::<BTreeMap<_, _>>()
        .await
}

fn emit_entry_events(
    channel: &Channel<IpOptimizeEvent>,
    domain: &str,
    names: &[std::string::String],
    best: Option<&IpOptimizeBest>,
) {
    let (target, latency_ms, status) = match best {
        Some(best) => (best.ip.clone(), Some(best.latency_ms), "ok"),
        None => (domain.to_owned(), None, "fail"),
    };
    for name in names {
        emit_event(
            channel,
            IpOptimizeEvent::Entry {
                name: name.clone(),
                server: domain.to_owned(),
                target: target.clone(),
                latency_ms,
                status: status.into(),
            },
        );
    }
}

async fn probe_domains(
    domains: &DomainTargets,
    resolved: &BTreeMap<std::string::String, Vec<IpAddr>>,
    tcp_timeout: Duration,
    concurrency: usize,
    channel: &Channel<IpOptimizeEvent>,
) -> BTreeMap<std::string::String, Vec<IpOptimizeBest>> {
    let mut results: BTreeMap<std::string::String, Vec<IpOptimizeBest>> = BTreeMap::new();
    let total = domains.len() as u32;
    for (index, (domain, ports)) in domains.iter().enumerate() {
        if STOP.load(Ordering::Relaxed) {
            emit_event(
                channel,
                IpOptimizeEvent::Log {
                    message: "stopped by user".into(),
                },
            );
            break;
        }
        let done = index as u32 + 1;
        if let Some(ips) = resolved.get(domain)
            && !ips.is_empty()
        {
            let mut pairs: Vec<(IpAddr, u16)> = Vec::with_capacity(ips.len() * ports.len());
            for ip in ips {
                for port in ports.keys() {
                    pairs.push((*ip, *port));
                }
            }
            let probes = pairs
                .into_iter()
                .map(|(ip, port)| async move { (ip, port, tcp_probe(ip, port, tcp_timeout).await) });
            let latencies: Vec<(IpAddr, u16, Option<Duration>)> = futures::stream::iter(probes)
                .buffer_unordered(concurrency)
                .collect()
                .await;
            let mut best: BTreeMap<u16, IpOptimizeBest> = BTreeMap::new();
            for (ip, port, latency) in latencies {
                let Some(latency) = latency else { continue };
                let ms = latency.as_secs_f64() * 1000.0;
                match best.get(&port) {
                    Some(current) if current.latency_ms <= ms => {}
                    _ => {
                        best.insert(
                            port,
                            IpOptimizeBest {
                                port,
                                ip: ip.to_string(),
                                latency_ms: (ms * 10.0).round() / 10.0,
                            },
                        );
                    }
                }
            }
            let best: Vec<IpOptimizeBest> = best.into_values().collect();
            for (port, names) in ports {
                let winner = best.iter().find(|entry| entry.port == *port);
                emit_entry_events(channel, domain, names, winner);
            }
            results.insert(domain.clone(), best);
        } else {
            for names in ports.values() {
                emit_entry_events(channel, domain, names, None);
            }
        }
        emit_event(
            channel,
            IpOptimizeEvent::Progress {
                phase: IpOptimizePhase::Speed,
                done,
                total,
            },
        );
    }
    results
}

fn store_path() -> Result<std::path::PathBuf> {
    Ok(dirs::app_home_dir()?.join(IP_OPTIMIZE))
}

async fn load_store() -> IpOptimizeStore {
    match store_path() {
        Ok(path) => tokio::fs::read_to_string(path)
            .await
            .ok()
            .and_then(|content| serde_json::from_str(&content).ok())
            .unwrap_or_default(),
        Err(_) => IpOptimizeStore::default(),
    }
}

async fn save_store(store: &IpOptimizeStore) -> Result<()> {
    let path = store_path()?;
    let content = serde_json::to_vec_pretty(store)?;
    tokio::fs::write(path, content).await?;
    Ok(())
}

pub async fn load_ip_optimize_view() -> Result<IpOptimizeView> {
    let enabled = {
        let verge = Config::verge().await;
        let verge = verge.latest_arc();
        verge.enable_ip_optimize.unwrap_or(false)
    };
    let profile_uid = {
        let profiles = Config::profiles().await;
        let profiles = profiles.latest_arc();
        profiles.current.clone().map(|uid| uid.to_string()).unwrap_or_default()
    };
    Ok(IpOptimizeView {
        enabled,
        profile_uid,
        profiles: load_store().await.profiles,
    })
}

pub async fn clear_ip_optimize_results(uid: Option<std::string::String>) -> Result<()> {
    let mut store = load_store().await;
    match uid {
        Some(uid) => {
            store.profiles.remove(&uid);
        }
        None => store.profiles.clear(),
    }
    save_store(&store).await
}

/// Enhance-chain step: rewrite `server` fields of the runtime configuration
/// from the stored winners of the active profile.
pub async fn use_ip_optimize(config: Mapping, enabled: bool, profile_uid: &str) -> Mapping {
    if !enabled || profile_uid.is_empty() {
        return config;
    }
    let store = load_store().await;
    let Some(summary) = store.profiles.get(profile_uid) else {
        return config;
    };
    let (config, replaced) = apply_ip_optimize_mapping(config, &summary.domains);
    if replaced > 0 {
        logging!(
            info,
            Type::Config,
            "ip-optimize: replaced {replaced} server fields for profile {profile_uid}"
        );
    }
    config
}

fn apply_ip_optimize_mapping(
    mut config: Mapping,
    domains: &BTreeMap<std::string::String, Vec<IpOptimizeBest>>,
) -> (Mapping, usize) {
    let Some(Value::Sequence(proxies)) = config.get_mut("proxies") else {
        return (config, 0);
    };
    let mut replaced = 0;
    for entry in proxies.iter_mut() {
        let Some(proxy) = entry.as_mapping_mut() else { continue };
        let Some(server) = proxy.get("server").and_then(Value::as_str) else {
            continue;
        };
        if is_ip(server) {
            continue;
        }
        let Some(candidates) = domains.get(server) else {
            continue;
        };
        let port = proxy
            .get("port")
            .and_then(Value::as_u64)
            .filter(|port| (1..=65535).contains(port))
            .unwrap_or(443) as u16;
        let Some(best) = candidates.iter().find(|best| best.port == port) else {
            continue;
        };
        proxy.insert(Value::from("server"), Value::from(best.ip.as_str()));
        replaced += 1;
    }
    (config, replaced)
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "tests assert by panicking"
)]
mod tests {
    use super::*;

    fn proxy_mapping(server: &str, port: u64) -> Value {
        let mut map = Mapping::new();
        map.insert(Value::from("name"), Value::from(format!("node-{server}")));
        map.insert(Value::from("server"), Value::from(server));
        map.insert(Value::from("port"), Value::from(port));
        Value::Mapping(map)
    }

    fn config_with_proxies(proxies: Vec<Value>) -> Mapping {
        let mut config = Mapping::new();
        config.insert(Value::from("proxies"), Value::Sequence(proxies));
        config
    }

    #[test]
    fn fake_ip_range_is_198_18_0_0_15() {
        assert!(is_fake_ip("198.18.0.1".parse().unwrap()));
        assert!(is_fake_ip("198.19.255.255".parse().unwrap()));
        assert!(!is_fake_ip("198.20.0.1".parse().unwrap()));
        assert!(!is_fake_ip("198.17.255.255".parse().unwrap()));
        assert!(!is_fake_ip("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn collect_targets_splits_domains_and_ips() {
        let config = config_with_proxies(vec![
            proxy_mapping("example.com", 443),
            proxy_mapping("example.com", 8443),
            proxy_mapping("1.2.3.4", 443),
            proxy_mapping("198.18.0.1", 443),
            Value::from("not-a-mapping"),
        ]);

        let (domains, ip_nodes) = collect_targets(&config);

        assert_eq!(domains.len(), 1);
        let ports = &domains["example.com"];
        assert_eq!(ports.len(), 2);
        assert_eq!(ports[&443], vec!["node-example.com".to_string()]);
        assert_eq!(ports[&8443].len(), 1);
        assert_eq!(ip_nodes.len(), 2);
    }

    #[test]
    fn dns_query_encodes_domain_and_a_type() {
        let query = build_dns_query(0x1234, "example.com").unwrap();
        assert_eq!(&query[..2], &0x1234u16.to_be_bytes());
        assert_eq!(&query[2..4], &[0x01, 0x00]);
        // QDCOUNT = 1
        assert_eq!(&query[4..6], &[0x00, 0x01]);
        let name = &query[12..query.len() - 4];
        assert_eq!(name[0], 7);
        assert_eq!(&name[1..8], b"example");
        assert_eq!(name[8], 3);
        assert_eq!(&name[9..12], b"com");
        assert_eq!(name[12], 0);
        let tail = &query[query.len() - 4..];
        assert_eq!(tail, &[0x00, 0x01, 0x00, 0x01]);
        assert!(build_dns_query(1, "").is_none());
        assert!(build_dns_query(1, "a..b").is_none());
    }

    /// Builds a response with one question, one CNAME and one A record whose
    /// owner name uses a compression pointer back to the question name.
    fn synthetic_response() -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0xAB, 0xCD, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00]);
        // question: www.example.com A IN
        buf.extend_from_slice(&[
            3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        buf.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        // answer 1: CNAME, owner is a pointer to offset 12
        buf.extend_from_slice(&[0xC0, 0x0C]);
        buf.extend_from_slice(&[0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x0E, 0x10]);
        buf.extend_from_slice(&[0x00, 0x0A]);
        buf.extend_from_slice(&[
            2, b'c', b'd', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        // answer 2: A record for the CNAME target (pointer to the CNAME rdata)
        let cname_rdata_offset = buf.len() as u8;
        buf.extend_from_slice(&[0xC0, cname_rdata_offset]);
        buf.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04]);
        buf.extend_from_slice(&[93, 184, 216, 34]);
        buf
    }

    #[test]
    fn dns_response_parses_a_records_through_compression() {
        let buf = synthetic_response();
        let ips = parse_dns_a_records(&buf, 0xABCD).unwrap();
        assert_eq!(ips, vec![Ipv4Addr::new(93, 184, 216, 34)]);
        assert!(parse_dns_a_records(&buf, 0x1234).is_none());
    }

    #[test]
    fn dns_response_rejects_error_rcode() {
        let mut buf = synthetic_response();
        buf[3] = 0x81 | 0x03; // NXDOMAIN
        assert!(parse_dns_a_records(&buf, 0xABCD).is_none());
    }

    #[test]
    fn ip_optimize_mapping_rewrites_only_matching_domain_port_pairs() {
        let config = config_with_proxies(vec![
            proxy_mapping("example.com", 443),
            proxy_mapping("example.com", 80),
            proxy_mapping("other.com", 443),
            proxy_mapping("1.2.3.4", 443),
        ]);
        let domains = BTreeMap::from([(
            "example.com".to_string(),
            vec![IpOptimizeBest {
                port: 443,
                ip: "5.6.7.8".to_string(),
                latency_ms: 12.3,
            }],
        )]);

        let (config, replaced) = apply_ip_optimize_mapping(config, &domains);

        assert_eq!(replaced, 1);
        let proxies = config.get("proxies").unwrap().as_sequence().unwrap();
        assert_eq!(
            proxies[0].as_mapping().unwrap().get("server").unwrap(),
            &Value::from("5.6.7.8")
        );
        assert_eq!(
            proxies[1].as_mapping().unwrap().get("server").unwrap(),
            &Value::from("example.com")
        );
        assert_eq!(
            proxies[2].as_mapping().unwrap().get("server").unwrap(),
            &Value::from("other.com")
        );
        assert_eq!(
            proxies[3].as_mapping().unwrap().get("server").unwrap(),
            &Value::from("1.2.3.4")
        );
    }

    #[test]
    fn summary_survives_a_store_roundtrip() {
        let summary = IpOptimizeSummary {
            profile_uid: "abc".into(),
            updated_at: 42,
            domain_nodes: 3,
            ip_nodes: 1,
            optimized_nodes: 2,
            domains: BTreeMap::from([(
                "example.com".to_string(),
                vec![IpOptimizeBest {
                    port: 443,
                    ip: "5.6.7.8".into(),
                    latency_ms: 9.5,
                }],
            )]),
        };
        let store = IpOptimizeStore {
            profiles: BTreeMap::from([("abc".to_string(), summary)]),
        };
        let text = serde_json::to_string(&store).unwrap();
        let back: IpOptimizeStore = serde_json::from_str(&text).unwrap();
        assert_eq!(back.profiles["abc"].domain_nodes, 3);
        assert_eq!(back.profiles["abc"].domains["example.com"][0].ip, "5.6.7.8");
    }
}
