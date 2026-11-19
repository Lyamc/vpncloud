// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use super::{
    device::Type,
    types::{Mode, NetworkProfile},
    util::{run_cmd, Duration}
};
pub use crate::crypto::Config as CryptoConfig;

use clap::{Parser, Subcommand};
use clap_complete::Shell;
use std::{
    cmp::max,
    collections::HashMap,
    ffi::OsStr,
    fs, io,
    io::Write,
    path::{Path, PathBuf},
    process, thread
};

pub const DEFAULT_PEER_TIMEOUT: u16 = 300;
pub const DEFAULT_PORT: u16 = 3210;
pub const DEFAULT_SOCKET_BUFFER: usize = 32 * 1024 * 1024;

/// Public STUN servers used when `--stun-server` is not set. Two, so one outage is not fatal.
pub const DEFAULT_STUN_SERVERS: [&str; 2] = ["stun.l.google.com:19302", "stun1.l.google.com:19302"];

/// DATA crypto workers. Tests stay on the wait thread. Otherwise use extra cores, capped at 4.
pub fn default_crypto_threads() -> usize {
    if cfg!(test) {
        return 0;
    }
    match std::thread::available_parallelism() {
        Ok(n) if n.get() >= 3 => n.get().saturating_sub(1).min(4),
        Ok(n) if n.get() == 2 => 1,
        _ => 0
    }
}

/// System-wide config directory. macOS/FreeBSD use `/usr/local/etc` because
/// `/etc` is part of the sealed system volume on modern macOS (SIP).
pub fn system_config_dir() -> &'static Path {
    #[cfg(any(target_os = "freebsd", target_os = "macos"))]
    {
        Path::new("/usr/local/etc/vpncloud")
    }
    #[cfg(not(any(target_os = "freebsd", target_os = "macos")))]
    {
        Path::new("/etc/vpncloud")
    }
}

/// System-wide binary path. macOS/FreeBSD use `/usr/local/bin` because
/// `/usr/bin` is protected by SIP on modern macOS.
pub fn system_bin_path() -> &'static Path {
    #[cfg(any(target_os = "freebsd", target_os = "macos"))]
    {
        Path::new("/usr/local/bin/vpncloud")
    }
    #[cfg(not(any(target_os = "freebsd", target_os = "macos")))]
    {
        Path::new("/usr/bin/vpncloud")
    }
}

/// System-wide man page path.
pub fn system_man_path() -> &'static Path {
    #[cfg(any(target_os = "freebsd", target_os = "macos"))]
    {
        Path::new("/usr/local/share/man/man1/vpncloud.1.gz")
    }
    #[cfg(not(any(target_os = "freebsd", target_os = "macos")))]
    {
        Path::new("/usr/share/man/man1/vpncloud.1.gz")
    }
}

/// One configured peer: a single address, or several alternatives in priority order.
///
/// YAML accepts either a string or a nested list (first address is tried first):
///
/// ```yaml
/// peers:
///   - 172.16.0.1:3210
///   - - 192.168.0.3:3210
///     - 172.16.0.3:3210
/// ```
///
/// TOML:
///
/// ```toml
/// peers = ["172.16.0.1:3210", ["192.168.0.3:3210", "172.16.0.3:3210"]]
/// ```
///
/// On the command line, alternatives are comma-separated:
/// `--peer 192.168.0.3:3210,172.16.0.3:3210`
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(untagged)]
pub enum PeerAddr {
    Single(String),
    Group(Vec<String>)
}

impl PeerAddr {
    pub fn into_config_string(self) -> String {
        match self {
            PeerAddr::Single(s) => s,
            PeerAddr::Group(v) => v.join(",")
        }
    }

    pub fn from_config_string(s: String) -> Self {
        let parts: Vec<String> = s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect();
        if parts.len() > 1 {
            PeerAddr::Group(parts)
        } else {
            PeerAddr::Single(s)
        }
    }
}

#[derive(Deserialize, Debug, PartialEq, Clone)]
pub struct Config {
    pub device_type: Type,
    pub device_name: String,
    pub device_path: Option<String>,
    /// TUN file descriptor from Android VpnService or iOS Packet Tunnel (owned). TAP is rejected.
    pub tun_fd: Option<i32>,
    pub fix_rp_filter: bool,
    pub mtu: Option<usize>,

    pub ip: Option<String>,
    pub advertise_addresses: Vec<String>,
    pub ifup: Option<String>,
    pub ifdown: Option<String>,

    pub crypto: CryptoConfig,

    pub listen: String,
    pub peers: Vec<String>,
    pub peer_timeout: Duration,
    pub keepalive: Option<Duration>,
    pub beacon_store: Option<String>,
    pub beacon_load: Option<String>,
    pub beacon_interval: Duration,
    pub beacon_password: Option<String>,
    pub mode: Mode,
    pub switch_timeout: Duration,
    pub claims: Vec<String>,
    /// Additional overlay IPs assigned locally and announced as /32 claims.
    pub local_addresses: Vec<String>,
    pub auto_claim: bool,
    pub port_forwarding: bool,
    pub daemonize: bool,
    pub pid_file: Option<String>,
    pub stats_file: Option<String>,
    /// Optional JSON status file refreshed every second for `vpncloud status`.
    pub status_file: Option<String>,
    /// Optional bind address for a read-only Prometheus metrics endpoint.
    pub metrics_addr: Option<String>,
    pub statsd_server: Option<String>,
    pub statsd_prefix: Option<String>,
    pub user: Option<String>,
    pub group: Option<String>,
    pub hook: Option<String>,
    pub hooks: HashMap<String, String>,
    /// Windows/macOS: show a tray / menu bar icon with a config context menu.
    pub tray: bool,
    /// macOS: the tray app controls the launchd service instead of running the VPN itself.
    pub tray_controls_service: bool,
    /// Query STUN servers and publish the mapped address.
    pub stun: bool,
    pub stun_servers: Vec<String>,
    /// Only accept underlay peers on local interface prefixes.
    pub lan_only: bool,
    /// Max crypto-init packets per source IP per 10 seconds.
    pub init_rate_limit: u32,
    /// Per-peer overlay token bucket rate in bytes/sec (0 disables). Peers that drain it are penalised.
    pub per_peer_rate_limit: u64,
    /// Install kernel routes for announced overlay claims (needs privileges).
    pub install_routes: bool,
    /// Overlay ACL entries (`allow:10.0.0.0/8`, `deny:0.0.0.0/0`). Empty = allow all.
    pub acl: Vec<String>,
    /// Listen/connect with length-prefixed TCP when UDP is blocked.
    pub tcp_fallback: bool,
    /// DATA encrypt/decrypt worker threads (0 = wait thread).
    pub crypto_threads: usize,
    /// Refuse config files that are not Ed25519-signed.
    pub require_signed_config: bool,
    /// Linux: install a seccomp blacklist after bind/TUN/privdrop.
    pub seccomp: bool,
    /// `SO_RCVBUF` / `SO_SNDBUF` in bytes (default 32 MiB).
    pub socket_buffer_bytes: usize,
    /// `prefix:CIDR` and `group:name` grants. Empty does not enforce claims.
    pub grants: Vec<String>,
    /// Split-tunnel prefixes. Empty forwards every overlay destination.
    pub split: Vec<String>,
    /// Forward a default route to `exit_node` when that node is authorized.
    pub full_tunnel: bool,
    /// Hex node id of the full-tunnel exit.
    pub exit_node: Option<String>,
    /// Hex node ids allowed to be an exit. Empty means `exit_node` itself.
    pub exit_allow: Vec<String>,
    /// `name=overlay-ip` records for the built-in resolver.
    pub peer_names: Vec<String>,
    /// Allow the reverse of a flow this node originated. Drop the unsolicited reverse.
    pub stateful_filter: bool,
    /// Opportunistically LZ4-compress DATA payloads before encryption.
    pub compression: bool,
    /// Group name advertised in node info.
    pub announce_group: Option<String>,
    /// Optional Ed25519 private key (base62) used to sign node announcements.
    /// Enables per-node identity binding without changing the shared-key handshake.
    pub node_key: Option<String>,
    /// Per-node public keys as `node-id-hex=base62-public-key`. When present,
    /// announcements from that node must be signed by the matching key.
    pub trusted_node_keys: Vec<String>,
    /// Require unique per-node keys and explicit node-id -> key trust bindings
    /// instead of a shared password. Each node needs its own private-key and
    /// every peer listed in trusted-node-keys.
    pub per_node_keys: bool,
    /// Network quality priority; sets defaults for MTU, jitter and pacing.
    pub profile: NetworkProfile,
    /// Cap the probed underlay MTU. Latency/consistency default to 1500,
    /// throughput to 9000 (jumbo). `None` follows the profile.
    pub max_underlay_mtu: Option<usize>,
    /// Receive jitter buffer in milliseconds. Consistency defaults to 20.
    /// `None` follows the profile.
    pub jitter_ms: Option<u32>,
    /// Migrate a peer to a new source address when its node id is recognised.
    pub mobility: bool,
    /// Stable node id (hex). If unset, derived from node-key or random.
    pub node_id: Option<String>,
    /// Redistribute broadcasts through the best-connected peer instead of
    /// sending a separate copy to every peer. Helps nodes with poor upload.
    pub flood_relay: bool,
    /// Optional node id (hex) to use as the redistribution peer. If unset,
    /// the lowest-RTT peer is chosen.
    pub flood_relay_via: Option<String>,
    /// On a TAP node, accept IP-only peers (TUN clients) and translate between
    /// their raw IP packets and local Ethernet frames. ARP is answered locally.
    /// Requires device type `tap`; ignored on TUN nodes.
    pub l2_l3_bridge: bool
}

impl Default for Config {
    fn default() -> Self {
        Config {
            device_type: Type::Tun,
            device_name: "vpncloud%d".to_string(),
            device_path: None,
            tun_fd: None,
            fix_rp_filter: false,
            mtu: None,
            ip: None,
            advertise_addresses: vec![],
            ifup: None,
            ifdown: None,
            crypto: CryptoConfig::default(),
            listen: "3210".to_string(),
            peers: vec![],
            peer_timeout: DEFAULT_PEER_TIMEOUT as Duration,
            keepalive: None,
            beacon_store: None,
            beacon_load: None,
            beacon_interval: 3600,
            beacon_password: None,
            mode: Mode::Normal,
            switch_timeout: 300,
            claims: vec![],
            local_addresses: vec![],
            auto_claim: true,
            port_forwarding: true,
            daemonize: false,
            pid_file: None,
            stats_file: None,
            status_file: None,
            metrics_addr: None,
            statsd_server: None,
            statsd_prefix: None,
            user: None,
            group: None,
            hook: None,
            hooks: HashMap::new(),
            tray: false,
            tray_controls_service: false,
            stun: !cfg!(test),
            stun_servers: if cfg!(test) {
                vec![]
            } else {
                DEFAULT_STUN_SERVERS.iter().map(|s| (*s).to_string()).collect()
            },
            lan_only: false,
            init_rate_limit: 20,
            per_peer_rate_limit: 20_000_000,
            install_routes: false,
            acl: vec![],
            tcp_fallback: !cfg!(test),
            crypto_threads: default_crypto_threads(),
            require_signed_config: false,
            seccomp: !cfg!(test),
            socket_buffer_bytes: DEFAULT_SOCKET_BUFFER,
            grants: vec![],
            split: vec![],
            full_tunnel: false,
            exit_node: None,
            exit_allow: vec![],
            peer_names: vec![],
            stateful_filter: false,
            compression: crate::compress::enabled_by_default(),
            announce_group: None,
            node_key: None,
            trusted_node_keys: Vec::new(),
            per_node_keys: false,
            profile: NetworkProfile::Balanced,
            max_underlay_mtu: None,
            jitter_ms: None,
            mobility: true,
            node_id: None,
            flood_relay: false,
            flood_relay_via: None,
            l2_l3_bridge: false
        }
    }
}

impl Config {
    #[allow(clippy::cognitive_complexity)]
    pub fn merge_file(&mut self, mut file: ConfigFile) {
        if let Some(device) = file.device {
            if let Some(val) = device.type_ {
                self.device_type = val;
            }
            if let Some(val) = device.name {
                self.device_name = val;
            }
            if let Some(val) = device.path {
                self.device_path = Some(val);
            }
            if let Some(val) = device.fix_rp_filter {
                self.fix_rp_filter = val;
            }
            if let Some(val) = device.mtu {
                self.mtu = Some(val);
            }
        }
        if let Some(val) = file.ip {
            self.ip = Some(val);
        }
        if let Some(mut val) = file.advertise_addresses {
            self.advertise_addresses.append(&mut val);
        }
        if let Some(val) = file.ifup {
            self.ifup = Some(val);
        }
        if let Some(val) = file.ifdown {
            self.ifdown = Some(val);
        }
        if let Some(val) = file.listen {
            self.listen = val;
        }
        if let Some(val) = file.peers {
            self.peers.extend(val.into_iter().map(PeerAddr::into_config_string));
        }
        if let Some(val) = file.peer_timeout {
            self.peer_timeout = val;
        }
        if let Some(val) = file.keepalive {
            self.keepalive = Some(val);
        }
        if let Some(beacon) = file.beacon {
            if let Some(val) = beacon.store {
                self.beacon_store = Some(val);
            }
            if let Some(val) = beacon.load {
                self.beacon_load = Some(val);
            }
            if let Some(val) = beacon.interval {
                self.beacon_interval = val;
            }
            if let Some(val) = beacon.password {
                self.beacon_password = Some(val);
            }
        }
        if let Some(val) = file.mode {
            self.mode = val;
        }
        if let Some(val) = file.switch_timeout {
            self.switch_timeout = val;
        }
        if let Some(mut val) = file.claims {
            self.claims.append(&mut val);
        }
        if let Some(mut val) = file.local_addresses {
            self.local_addresses.append(&mut val);
        }
        if let Some(val) = file.auto_claim {
            self.auto_claim = val;
        }
        if let Some(val) = file.port_forwarding {
            self.port_forwarding = val;
        }
        if let Some(val) = file.pid_file {
            self.pid_file = Some(val);
        }
        if let Some(val) = file.stats_file {
            self.stats_file = Some(val);
        }
        if let Some(val) = file.status_file {
            self.status_file = Some(val);
        }
        if let Some(val) = file.metrics_addr {
            self.metrics_addr = Some(val);
        }
        if let Some(statsd) = file.statsd {
            if let Some(val) = statsd.server {
                self.statsd_server = Some(val);
            }
            if let Some(val) = statsd.prefix {
                self.statsd_prefix = Some(val);
            }
        }
        if let Some(val) = file.user {
            self.user = Some(val);
        }
        if let Some(val) = file.group {
            self.group = Some(val);
        }
        if let Some(val) = file.crypto.password {
            self.crypto.password = Some(val)
        }
        if let Some(val) = file.crypto.public_key {
            self.crypto.public_key = Some(val)
        }
        if let Some(val) = file.crypto.private_key {
            self.crypto.private_key = Some(val)
        }
        self.crypto.trusted_keys.append(&mut file.crypto.trusted_keys);
        if !file.crypto.algorithms.is_empty() {
            self.crypto.algorithms = file.crypto.algorithms.clone();
        }
        if let Some(val) = file.hook {
            self.hook = Some(val)
        }
        for (k, v) in file.hooks {
            self.hooks.insert(k, v);
        }
        if let Some(val) = file.tray {
            self.tray = val;
        }
        if let Some(val) = file.stun {
            self.stun = val;
        }
        if let Some(val) = file.stun_servers {
            self.stun_servers = val;
        }
        if let Some(val) = file.lan_only {
            self.lan_only = val;
        }
        if let Some(val) = file.init_rate_limit {
            self.init_rate_limit = val;
        }
        if let Some(val) = file.per_peer_rate_limit {
            self.per_peer_rate_limit = val;
        }
        if let Some(val) = file.install_routes {
            self.install_routes = val;
        }
        if let Some(mut val) = file.acl {
            self.acl.append(&mut val);
        }
        if let Some(val) = file.crypto.salt {
            self.crypto.salt = Some(val);
        }
        if let Some(val) = file.crypto.kdf {
            self.crypto.kdf = Some(val);
        }
        if let Some(val) = file.tcp_fallback {
            self.tcp_fallback = val;
        }
        if let Some(val) = file.crypto_threads {
            self.crypto_threads = val;
        }
        if let Some(val) = file.require_signed_config {
            self.require_signed_config = val;
        }
        if let Some(val) = file.seccomp {
            self.seccomp = val;
        }
        if let Some(val) = file.socket_buffer {
            self.socket_buffer_bytes = val;
        }
        if let Some(mut val) = file.grants {
            self.grants.append(&mut val);
        }
        if let Some(mut val) = file.split {
            self.split.append(&mut val);
        }
        if let Some(val) = file.full_tunnel {
            self.full_tunnel = val;
        }
        if let Some(val) = file.exit_node {
            self.exit_node = Some(val);
        }
        if let Some(mut val) = file.exit_allow {
            self.exit_allow.append(&mut val);
        }
        if let Some(mut val) = file.peer_names {
            self.peer_names.append(&mut val);
        }
        if let Some(val) = file.stateful_filter {
            self.stateful_filter = val;
        }
        if let Some(val) = file.compression {
            self.compression = val;
        }
        if let Some(val) = file.announce_group {
            self.announce_group = Some(val);
        }
        if let Some(val) = file.node_key {
            self.node_key = Some(val);
        }
        if let Some(keys) = file.trusted_node_keys {
            self.trusted_node_keys.extend(keys);
        }
        if let Some(val) = file.per_node_keys {
            self.per_node_keys = val;
        }
        if let Some(val) = file.profile {
            self.profile = val;
        }
        if let Some(val) = file.max_underlay_mtu {
            self.max_underlay_mtu = Some(val);
        }
        if let Some(val) = file.jitter_ms {
            self.jitter_ms = Some(val);
        }
        if let Some(val) = file.mobility {
            self.mobility = val;
        }
        if let Some(val) = file.node_id {
            self.node_id = Some(val);
        }
        if let Some(val) = file.flood_relay {
            self.flood_relay = val;
        }
        if let Some(val) = file.flood_relay_via {
            self.flood_relay_via = Some(val);
        }
        if let Some(val) = file.l2_l3_bridge {
            self.l2_l3_bridge = val;
        }
    }

    pub fn merge_args(&mut self, mut args: Args) {
        if let Some(val) = args.type_ {
            self.device_type = val;
        }
        if let Some(val) = args.device {
            self.device_name = val;
        }
        if let Some(val) = args.device_path {
            self.device_path = Some(val);
        }
        if let Some(val) = args.tun_fd {
            self.tun_fd = Some(val);
        }
        if args.fix_rp_filter {
            self.fix_rp_filter = true;
        }
        if let Some(val) = args.mtu {
            self.mtu = Some(val);
        }
        if let Some(val) = args.ip {
            self.ip = Some(val);
        }
        if let Some(val) = args.ifup {
            self.ifup = Some(val);
        }
        self.advertise_addresses.append(&mut args.advertise_addresses);
        if let Some(val) = args.ifdown {
            self.ifdown = Some(val);
        }
        if let Some(val) = args.listen {
            self.listen = val;
        }
        self.peers.append(&mut args.peers);
        if let Some(val) = args.peer_timeout {
            self.peer_timeout = val;
        }
        if let Some(val) = args.keepalive {
            self.keepalive = Some(val);
        }
        if let Some(val) = args.beacon_store {
            self.beacon_store = Some(val);
        }
        if let Some(val) = args.beacon_load {
            self.beacon_load = Some(val);
        }
        if let Some(val) = args.beacon_interval {
            self.beacon_interval = val;
        }
        if let Some(val) = args.beacon_password {
            self.beacon_password = Some(val);
        }
        if let Some(val) = args.mode {
            self.mode = val;
        }
        if let Some(val) = args.switch_timeout {
            self.switch_timeout = val;
        }
        self.claims.append(&mut args.claims);
        self.local_addresses.append(&mut args.local_addresses);
        if args.no_auto_claim {
            self.auto_claim = false;
        }
        if args.no_port_forwarding {
            self.port_forwarding = false;
        }
        if args.daemon {
            self.daemonize = true;
        }
        if let Some(val) = args.pid_file {
            self.pid_file = Some(val);
        }
        if let Some(val) = args.stats_file {
            self.stats_file = Some(val);
        }
        if let Some(val) = args.status_file {
            self.status_file = Some(val);
        }
        if let Some(val) = args.metrics_addr {
            self.metrics_addr = Some(val);
        }
        if let Some(val) = args.statsd_server {
            self.statsd_server = Some(val);
        }
        if let Some(val) = args.statsd_prefix {
            self.statsd_prefix = Some(val);
        }
        if let Some(val) = args.user {
            self.user = Some(val);
        }
        if let Some(val) = args.group {
            self.group = Some(val);
        }
        if let Some(val) = args.password {
            self.crypto.password = Some(val)
        }
        if let Some(val) = args.public_key {
            self.crypto.public_key = Some(val)
        }
        if let Some(val) = args.private_key {
            self.crypto.private_key = Some(val)
        }
        self.crypto.trusted_keys.append(&mut args.trusted_keys);
        if !args.algorithms.is_empty() {
            self.crypto.algorithms = args.algorithms.clone();
        }
        for s in args.hook {
            if s.contains(':') {
                let pos = s.find(':').unwrap();
                let name = &s[..pos];
                let hook = &s[pos + 1..];
                self.hooks.insert(name.to_string(), hook.to_string());
            } else {
                self.hook = Some(s);
            }
        }
        if args.tray {
            self.tray = true;
        }
        if args.no_tray {
            self.tray = false;
        }
        #[cfg(target_os = "macos")]
        if args.tray_controls_service {
            self.tray_controls_service = true;
        }
        if args.no_stun {
            self.stun = false;
        }
        if args.stun {
            self.stun = true;
        }
        if !args.stun_server.is_empty() {
            self.stun_servers = args.stun_server;
        }
        if args.lan_only {
            self.lan_only = true;
        }
        if let Some(val) = args.crypto_salt {
            self.crypto.salt = Some(val);
        }
        if let Some(val) = args.kdf {
            self.crypto.kdf = Some(val);
        }
        if let Some(val) = args.init_rate_limit {
            self.init_rate_limit = val;
        }
        if let Some(val) = args.per_peer_rate_limit {
            self.per_peer_rate_limit = val;
        }
        if args.no_per_peer_rate_limit {
            self.per_peer_rate_limit = 0;
        }
        if args.install_routes {
            self.install_routes = true;
        }
        self.acl.append(&mut args.acl);
        if args.tcp_fallback {
            self.tcp_fallback = true;
        }
        if args.no_tcp_fallback {
            self.tcp_fallback = false;
        }
        if let Some(val) = args.crypto_threads {
            self.crypto_threads = val;
        }
        if args.require_signed_config {
            self.require_signed_config = true;
        }
        if args.seccomp {
            self.seccomp = true;
        }
        if args.no_seccomp {
            self.seccomp = false;
        }
        if let Some(val) = args.socket_buffer {
            self.socket_buffer_bytes = val;
        }
        self.grants.append(&mut args.grants);
        self.split.append(&mut args.split);
        if args.full_tunnel {
            self.full_tunnel = true;
        }
        if let Some(val) = args.exit_node {
            self.exit_node = Some(val);
        }
        self.exit_allow.append(&mut args.exit_allow);
        self.peer_names.append(&mut args.peer_names);
        if args.stateful_filter {
            self.stateful_filter = true;
        }
        if args.compression {
            self.compression = true;
        }
        if args.no_compression {
            self.compression = false;
        }
        if let Some(val) = args.announce_group {
            self.announce_group = Some(val);
        }
        if let Some(val) = args.node_key {
            self.node_key = Some(val);
        }
        self.trusted_node_keys.append(&mut args.trusted_node_keys);
        if args.flood_relay {
            self.flood_relay = true;
        }
        if args.no_flood_relay {
            self.flood_relay = false;
        }
        if let Some(val) = args.flood_relay_via {
            self.flood_relay_via = Some(val);
        }
        if args.l2_l3_bridge {
            self.l2_l3_bridge = true;
        }
        if args.per_node_keys {
            self.per_node_keys = true;
        }
        if let Some(val) = args.profile {
            self.profile = val;
        }
        if let Some(val) = args.max_underlay_mtu {
            self.max_underlay_mtu = Some(val);
        }
        if let Some(val) = args.jitter_ms {
            self.jitter_ms = Some(val);
        }
        if args.no_mobility {
            self.mobility = false;
        }
        if let Some(val) = args.node_id {
            self.node_id = Some(val);
        }
    }

    pub fn into_config_file(self) -> ConfigFile {
        ConfigFile {
            auto_claim: Some(self.auto_claim),
            claims: Some(self.claims),
            local_addresses: if self.local_addresses.is_empty() { None } else { Some(self.local_addresses.clone()) },
            beacon: Some(ConfigFileBeacon {
                store: self.beacon_store,
                load: self.beacon_load,
                interval: Some(self.beacon_interval),
                password: self.beacon_password
            }),
            device: Some(ConfigFileDevice {
                name: Some(self.device_name),
                path: self.device_path,
                type_: Some(self.device_type),
                fix_rp_filter: Some(self.fix_rp_filter),
                mtu: self.mtu
            }),
            crypto: self.crypto,
            group: self.group,
            user: self.user,
            ifup: self.ifup,
            ifdown: self.ifdown,
            ip: self.ip,
            advertise_addresses: Some(self.advertise_addresses),
            keepalive: self.keepalive,
            listen: Some(self.listen),
            mode: Some(self.mode),
            peer_timeout: Some(self.peer_timeout),
            peers: Some(self.peers.into_iter().map(PeerAddr::from_config_string).collect()),
            pid_file: self.pid_file,
            port_forwarding: Some(self.port_forwarding),
            stats_file: self.stats_file,
            status_file: self.status_file,
            metrics_addr: self.metrics_addr,
            statsd: Some(ConfigFileStatsd { server: self.statsd_server, prefix: self.statsd_prefix }),
            switch_timeout: Some(self.switch_timeout),
            hook: self.hook,
            hooks: self.hooks,
            tray: Some(self.tray),
            stun: Some(self.stun),
            stun_servers: Some(self.stun_servers),
            lan_only: Some(self.lan_only),
            init_rate_limit: Some(self.init_rate_limit),
            per_peer_rate_limit: Some(self.per_peer_rate_limit),
            install_routes: Some(self.install_routes),
            acl: if self.acl.is_empty() { None } else { Some(self.acl) },
            tcp_fallback: Some(self.tcp_fallback),
            crypto_threads: Some(self.crypto_threads),
            require_signed_config: Some(self.require_signed_config),
            seccomp: Some(self.seccomp),
            socket_buffer: Some(self.socket_buffer_bytes),
            grants: if self.grants.is_empty() { None } else { Some(self.grants) },
            split: if self.split.is_empty() { None } else { Some(self.split) },
            full_tunnel: Some(self.full_tunnel),
            exit_node: self.exit_node,
            exit_allow: if self.exit_allow.is_empty() { None } else { Some(self.exit_allow) },
            peer_names: if self.peer_names.is_empty() { None } else { Some(self.peer_names) },
            stateful_filter: Some(self.stateful_filter),
            compression: Some(self.compression),
            announce_group: self.announce_group,
            node_key: self.node_key,
            trusted_node_keys: if self.trusted_node_keys.is_empty() { None } else { Some(self.trusted_node_keys) },
            per_node_keys: Some(self.per_node_keys),
            profile: Some(self.profile),
            max_underlay_mtu: self.max_underlay_mtu,
            jitter_ms: self.jitter_ms,
            mobility: Some(self.mobility),
            node_id: self.node_id,
            flood_relay: Some(self.flood_relay),
            flood_relay_via: self.flood_relay_via,
            l2_l3_bridge: Some(self.l2_l3_bridge),
            signature: None
        }
    }

    /// Cap for the underlay MTU after applying the profile.
    pub fn effective_max_underlay_mtu(&self) -> usize {
        self.max_underlay_mtu.unwrap_or(match self.profile {
            NetworkProfile::Throughput | NetworkProfile::Balanced => 9000,
            NetworkProfile::Latency | NetworkProfile::Consistency => 1500
        })
    }

    /// Receive jitter buffer after applying the profile (milliseconds).
    pub fn effective_jitter_ms(&self) -> u32 {
        self.jitter_ms.unwrap_or(match self.profile {
            NetworkProfile::Consistency => 20,
            _ => 0
        })
    }

    /// Config file representation with all secret values replaced, for
    /// `vpncloud config --print` and diagnostics.
    pub fn redacted_yaml(&self) -> String {
        let mut file = self.clone().into_config_file();
        if file.crypto.password.is_some() {
            file.crypto.password = Some("<redacted>".into());
        }
        if file.crypto.private_key.is_some() {
            file.crypto.private_key = Some("<redacted>".into());
        }
        if !file.crypto.trusted_keys.is_empty() {
            file.crypto.trusted_keys = vec!["<redacted>".into()];
        }
        if let Some(ref mut beacon) = file.beacon {
            if beacon.password.is_some() {
                beacon.password = Some("<redacted>".into());
            }
        }
        if file.hook.is_some() {
            file.hook = Some("<redacted>".into());
        }
        if !file.hooks.is_empty() {
            file.hooks.clear();
            file.hooks.insert("(script)".into(), "<redacted>".into());
        }
        serde_norway::to_string(&file).unwrap_or_default()
    }

    /// Semantic validation beyond deserialization. Returns non-fatal warnings;
    /// `Err` means the config cannot be used at all. Used by `check-config`.
    pub fn validate(&self) -> Result<Vec<String>, String> {
        let mut warnings = Vec::new();
        if self.per_node_keys {
            if self.crypto.private_key.is_none() {
                return Err("per-node-keys requires a unique private-key (a shared password is not enough)".into());
            }
            if self.trusted_node_keys.is_empty() {
                return Err("per-node-keys requires trusted-node-key entries (node-id=public-key)".into());
            }
            for entry in &self.trusted_node_keys {
                let Some((id, key)) = entry.split_once('=') else {
                    return Err(format!("invalid trusted-node-key '{}' (expected node-id=key)", entry));
                };
                if crate::util::from_hex(id).ok().and_then(|v| <[u8; 16]>::try_from(v.as_slice()).ok()).is_none() {
                    return Err(format!("invalid node id in trusted-node-key '{}'", entry));
                }
                crate::util::from_base62_fixed::<32>(key)
                    .map_err(|_| format!("invalid public key in trusted-node-key '{}'", entry))?;
            }
        }
        if self.crypto.password.is_none() && self.crypto.private_key.is_none() {
            return Err("no password or private key configured".into());
        }
        if let Ok((plain, _, algos)) = crate::crypto::Crypto::parse_algorithms(&self.crypto.algorithms) {
            if plain {
                warnings.push("unencrypted 'plain' algorithm allowed: traffic can be read on the wire".into());
            }
            if algos.is_empty() && !plain {
                warnings.push("no AEAD algorithm selected".into());
            }
        } else {
            return Err("invalid crypto.algorithms".into());
        }
        if let Some(ref ip) = self.ip {
            let (addr, prefix) = ip.split_once('/').unwrap_or((ip, ""));
            match addr.parse::<std::net::IpAddr>() {
                Ok(std::net::IpAddr::V4(_)) if !prefix.is_empty() && prefix.parse::<u8>().map_or(true, |p| p > 32) => {
                    return Err(format!("invalid IPv4 prefix in ip: {}", ip));
                }
                Ok(std::net::IpAddr::V6(_)) if !prefix.is_empty() && prefix.parse::<u8>().map_or(true, |p| p > 128) => {
                    return Err(format!("invalid IPv6 prefix in ip: {}", ip));
                }
                Ok(_) => {}
                Err(_) => return Err(format!("invalid ip address: {}", ip))
            }
        } else {
            warnings.push("no overlay IP set; the interface will have no address".into());
        }
        if let Some(mtu) = self.mtu {
            if !(68..=65535).contains(&mtu) {
                return Err(format!("mtu {} out of range (68..=65535)", mtu));
            }
        }
        if self.peers.is_empty() {
            warnings.push("no peers configured; the node will not connect to anyone".into());
        }
        for peer in &self.peers {
            let port_ok = if let Some(rest) = peer.strip_prefix('[') {
                match rest.find(']') {
                    Some(end) => {
                        let after = &rest[end + 1..];
                        after.is_empty() || after.strip_prefix(':').and_then(|p| p.parse::<u16>().ok()).is_some()
                    }
                    None => false
                }
            } else if let Some((_, port)) = peer.rsplit_once(':') {
                port.parse::<u16>().is_ok()
            } else {
                true // no port: the default port is added at runtime
            };
            if !port_ok {
                return Err(format!("invalid peer address: {}", peer));
            }
        }
        if self.compression {
            warnings
                .push("compression is enabled: it can leak plaintext length information (CRIME/BREACH-style)".into());
        }
        if self.daemonize && self.pid_file.is_none() {
            warnings.push("daemonizing without a pid file makes the process harder to manage".into());
        }
        Ok(warnings)
    }

    pub fn get_keepalive(&self) -> Duration {
        match self.keepalive {
            Some(dur) => dur,
            None => max(self.peer_timeout / 2 - 60, 1)
        }
    }

    pub fn call_hook(
        &self, event: &'static str, envs: impl IntoIterator<Item = (&'static str, impl AsRef<OsStr>)>, detach: bool
    ) {
        let mut script = None;
        if let Some(ref s) = self.hook {
            script = Some(s);
        }
        if let Some(s) = self.hooks.get(event) {
            script = Some(s);
        }
        if script.is_none() {
            return;
        }
        let script = script.unwrap();
        let mut cmd = process::Command::new("sh");
        cmd.arg("-c").arg(script).envs(envs).env("EVENT", event);
        debug!("Running event script for {}", event);
        if detach {
            thread::spawn(move || run_cmd(cmd));
        } else {
            run_cmd(cmd)
        }
    }
}

const PLATFORM_AFTER_HELP: &str = "\
Android:
  tun    Works on all devices through VpnService (--tun-fd).
  tap    Only on rooted devices with /dev/net/tun. Unrooted TAP fails with an error; see --type.
iOS:
  tun    Packet Tunnel Provider (--tun-fd from utun). Overlay routes only.
  tap    Not available (no Ethernet / no /dev/net/tun).
";

#[derive(Parser, Debug, Default)]
#[command(name = "vpncloud", disable_version_flag = true, after_help = PLATFORM_AFTER_HELP)]
pub struct Args {
    /// Read configuration options from a YAML or TOML file
    #[arg(
        long,
        long_help = "Read configuration options from a YAML (.yaml, .yml, .net) or TOML (.toml) file.\nIf both YAML and TOML exist for the same name, YAML is used."
    )]
    pub config: Option<String>,

    /// Set the type of network [possible values: tun, tap]
    #[arg(
        short,
        long,
        value_name = "type",
        long_help = "Set the type of network: tun (IP packets) or tap (Ethernet frames).\n\nOn Android, tap is only supported on rooted devices (needs /dev/net/tun). Unrooted devices must use tun via VpnService.\nOn iOS, only tun is available (Packet Tunnel Provider); tap is not supported."
    )]
    pub type_: Option<Type>,

    /// Set the path of the base device
    #[arg(long)]
    pub device_path: Option<String>,

    /// Adopt an existing TUN file descriptor (Android VpnService or iOS Packet Tunnel). Cannot be used with TAP.
    #[arg(long = "tun-fd")]
    pub tun_fd: Option<i32>,

    /// MTU of the virtual device (default: auto)
    #[arg(long)]
    pub mtu: Option<usize>,

    /// Fix the rp_filter settings on the host
    #[arg(long)]
    pub fix_rp_filter: bool,

    /// The mode of the VPN [possible values: normal, router, switch, hub]
    #[arg(short, long)]
    pub mode: Option<Mode>,

    /// The shared password to encrypt all traffic
    #[arg(short, long, env = "PASSWORD")]
    pub password: Option<String>,

    /// The private key to use
    #[arg(long, alias = "key", conflicts_with = "password", env = "PRIVATE_KEY")]
    pub private_key: Option<String>,

    /// The public key to use
    #[arg(long)]
    pub public_key: Option<String>,

    /// Other public keys to trust
    #[arg(long = "trusted-key", alias = "trust", value_delimiter = ',')]
    pub trusted_keys: Vec<String>,

    /// Algorithms to allow [possible values: plain, aes128, aes256, chacha20, noise]
    #[arg(long = "algorithm", alias = "algo", value_delimiter = ',', ignore_case = true, value_parser = ["plain", "aes128", "aes256", "chacha20", "noise"])]
    pub algorithms: Vec<String>,

    /// The local subnets to claim (IP or IP/prefix)
    #[arg(long = "claim", value_delimiter = ',')]
    pub claims: Vec<String>,

    /// Additional overlay IPs to assign and announce (repeatable)
    #[arg(long = "local-address", value_delimiter = ',')]
    pub local_addresses: Vec<String>,

    /// Do not automatically claim the device ip
    #[arg(long)]
    pub no_auto_claim: bool,

    /// Name of the virtual device
    #[arg(short, long)]
    pub device: Option<String>,

    /// The port number (or ip:port) on which to listen for data
    #[arg(short, long)]
    pub listen: Option<String>,

    /// Address of a peer to connect to. Comma-separated addresses are tried in order as alternatives for the same
    /// peer.
    #[arg(short = 'c', long = "peer", alias = "connect")]
    pub peers: Vec<String>,

    /// Peer timeout in seconds
    #[arg(long)]
    pub peer_timeout: Option<Duration>,

    /// Periodically send message to keep connections alive
    #[arg(long)]
    pub keepalive: Option<Duration>,

    /// Switch table entry timeout in seconds
    #[arg(long)]
    pub switch_timeout: Option<Duration>,

    /// The file path or |command to store the beacon
    #[arg(long)]
    pub beacon_store: Option<String>,

    /// The file path or |command to load the beacon
    #[arg(long)]
    pub beacon_load: Option<String>,

    /// Beacon store/load interval in seconds
    #[arg(long)]
    pub beacon_interval: Option<Duration>,

    /// Password to encrypt the beacon with
    #[arg(long)]
    pub beacon_password: Option<String>,

    /// Print debug information (-vv adds trace-level wire logging)
    #[arg(short, long, conflicts_with = "quiet", action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Only print errors and warnings
    #[arg(short, long)]
    pub quiet: bool,

    /// Set log level explicitly (off/error/warn/info/debug/trace)
    #[arg(long, value_name = "LEVEL", conflicts_with_all = ["verbose", "quiet"])]
    pub log_level: Option<String>,

    /// Log a hex dump of the first bytes of every wire message (implies trace)
    #[arg(long)]
    pub wire_log: bool,

    /// An IP address (plus optional prefix length) for the interface
    #[arg(long)]
    pub ip: Option<String>,

    /// A list of IP Addresses to advertise as our external address(s)
    #[arg(long = "advertise_addresses", value_delimiter = ',')]
    pub advertise_addresses: Vec<String>,

    /// A command to setup the network interface
    #[arg(long)]
    pub ifup: Option<String>,

    /// A command to bring down the network interface
    #[arg(long)]
    pub ifdown: Option<String>,

    /// Print the version and exit
    #[arg(long)]
    pub version: bool,

    /// Disable automatic port forwarding
    #[arg(long)]
    pub no_port_forwarding: bool,

    /// Run the process in the background
    #[arg(long)]
    pub daemon: bool,

    /// Store the process id in this file when daemonizing
    #[arg(long)]
    pub pid_file: Option<String>,

    /// Print statistics to this file
    #[arg(long)]
    pub stats_file: Option<String>,

    /// Write a JSON status snapshot to this file every second (for `vpncloud status`)
    #[arg(long)]
    pub status_file: Option<String>,

    /// Bind a read-only Prometheus HTTP endpoint here (e.g. 127.0.0.1:9090)
    #[arg(long)]
    pub metrics_addr: Option<String>,

    /// Emit logs as JSON lines instead of human text
    #[arg(long)]
    pub log_json: bool,

    /// Send statistics to this statsd server
    #[arg(long)]
    pub statsd_server: Option<String>,

    /// Use the given prefix for statsd records
    #[arg(long, requires = "statsd_server")]
    pub statsd_prefix: Option<String>,

    /// Run as other user
    #[arg(long)]
    pub user: Option<String>,

    /// Run as other group
    #[arg(long)]
    pub group: Option<String>,

    /// Print logs also to this file
    #[arg(long)]
    pub log_file: Option<String>,

    /// Run as a Windows service (used by the Service Control Manager)
    #[cfg(windows)]
    #[arg(long, hide = true)]
    pub service: bool,

    /// Call script on event
    #[arg(long)]
    pub hook: Vec<String>,

    /// Windows/macOS: show a tray / menu bar icon with a config context menu
    #[arg(long)]
    pub tray: bool,

    /// Windows/macOS: do not show a tray / menu bar icon
    #[arg(long, conflicts_with = "tray")]
    pub no_tray: bool,

    /// macOS: the tray app controls the installed launchd service instead of running the VPN
    #[cfg(target_os = "macos")]
    #[arg(long, hide = true, requires = "tray")]
    pub tray_controls_service: bool,

    /// Enable STUN reflexive-address discovery (default)
    #[arg(long)]
    pub stun: bool,
    /// Disable STUN
    #[arg(long, conflicts_with = "stun")]
    pub no_stun: bool,
    /// STUN server host:port (repeatable)
    #[arg(long = "stun-server")]
    pub stun_server: Vec<String>,
    /// Only accept peers on local interface prefixes
    #[arg(long)]
    pub lan_only: bool,
    /// Password KDF salt (enables PBKDF2-100000)
    #[arg(long = "crypto-salt")]
    pub crypto_salt: Option<String>,
    /// Password KDF: legacy (4096) or pbkdf2 (100000, needs --crypto-salt)
    #[arg(long, value_parser = ["legacy", "pbkdf2"])]
    pub kdf: Option<String>,
    /// Max handshake packets per source IP per 10 seconds
    #[arg(long = "init-rate-limit")]
    pub init_rate_limit: Option<u32>,
    /// Per-peer overlay rate limit in bytes/sec (0 disables)
    #[arg(long = "per-peer-rate-limit")]
    pub per_peer_rate_limit: Option<u64>,
    /// Disable the per-peer overlay rate limit
    #[arg(long = "no-per-peer-rate-limit", conflicts_with = "per_peer_rate_limit")]
    pub no_per_peer_rate_limit: bool,
    /// Install kernel routes for announced overlay claims (needs privileges)
    #[arg(long)]
    pub install_routes: bool,
    /// Overlay ACL `allow:CIDR` / `deny:CIDR` with optional `:tcp|:udp|:icmp[:port[-port]]` (last match wins)
    #[arg(long = "acl")]
    pub acl: Vec<String>,
    /// Listen and connect with length-prefixed TCP as a UDP fallback
    #[arg(long)]
    pub tcp_fallback: bool,
    /// Disable TCP fallback
    #[arg(long, conflicts_with = "tcp_fallback")]
    pub no_tcp_fallback: bool,
    /// Worker threads for DATA encrypt/decrypt (0 = wait thread; default extra cores-1, max 4)
    #[arg(long = "crypto-threads")]
    pub crypto_threads: Option<usize>,
    /// Refuse unsigned config files. Verification keys must be supplied with
    /// --verify-key / --verify-key-file; keys inside the config are not trusted.
    #[arg(long = "require-signed-config")]
    pub require_signed_config: bool,
    /// Ed25519 public key (base62, optional :YYYY-MM-DD) used to verify the
    /// --config signature. Repeatable. Kept separate from peer trusted keys.
    #[arg(long = "verify-key", value_name = "KEY")]
    pub verify_keys: Vec<String>,
    /// File containing config-signature verification keys, one base62 key per
    /// line (# comments allowed). Use a root-owned file for a real trust anchor.
    #[arg(long = "verify-key-file", value_name = "PATH")]
    pub verify_key_file: Option<String>,
    /// Linux: install seccomp blacklist after bind/TUN
    #[arg(long)]
    pub seccomp: bool,
    /// Do not install seccomp
    #[arg(long, conflicts_with = "seccomp")]
    pub no_seccomp: bool,
    /// UDP SO_RCVBUF/SO_SNDBUF in bytes [default: 33554432]
    #[arg(long = "socket-buffer")]
    pub socket_buffer: Option<usize>,
    /// Claim grant `prefix:CIDR` or `group:name`
    #[arg(long = "grant")]
    pub grants: Vec<String>,
    /// Split-tunnel prefix (repeatable). Only these overlay destinations enter the mesh.
    #[arg(long = "split")]
    pub split: Vec<String>,
    /// Send every overlay destination to the authorized exit node
    #[arg(long = "full-tunnel")]
    pub full_tunnel: bool,
    /// Hex node id of the full-tunnel exit
    #[arg(long = "exit-node")]
    pub exit_node: Option<String>,
    /// Hex node id allowed to be an exit (repeatable)
    #[arg(long = "exit-allow")]
    pub exit_allow: Vec<String>,
    /// Built-in DNS record `name=overlay-ip`
    #[arg(long = "peer-name")]
    pub peer_names: Vec<String>,
    /// Stateful filter: allow the reply to a flow this node opened
    #[arg(long = "stateful-filter")]
    pub stateful_filter: bool,
    /// Opportunistically LZ4-compress DATA payloads before encryption (off by default).
    /// Only used with peers that also advertise support. WARNING: compression before
    /// encryption can leak plaintext length information (CRIME/BREACH-style oracles).
    #[arg(long, conflicts_with = "no_compression")]
    pub compression: bool,
    /// Never compress tunnel payloads, overriding a config-file setting
    #[arg(long, conflicts_with = "compression")]
    pub no_compression: bool,
    /// Group name to advertise to peers
    #[arg(long = "announce-group")]
    pub announce_group: Option<String>,
    /// Ed25519 private key (base62) used to sign node announcements
    #[arg(long = "node-key")]
    pub node_key: Option<String>,
    /// Per-node public key as `node-id-hex=base62-public-key` (repeatable)
    #[arg(long = "trusted-node-key", value_name = "NODE=KEY")]
    pub trusted_node_keys: Vec<String>,
    /// Require unique per-node keys and explicit trusted-node-key bindings
    #[arg(long)]
    pub per_node_keys: bool,
    /// Network priority: latency, consistency, throughput, or balanced
    #[arg(long, value_name = "PROFILE")]
    pub profile: Option<NetworkProfile>,
    /// Cap the probed underlay MTU (default: 1500 for latency/consistency, 9000 otherwise)
    #[arg(long)]
    pub max_underlay_mtu: Option<usize>,
    /// Receive jitter buffer in milliseconds (default: 20 for consistency)
    #[arg(long)]
    pub jitter_ms: Option<u32>,
    /// Disable migration of a peer to a new source address
    #[arg(long)]
    pub no_mobility: bool,
    /// Stable node id (hex); otherwise derived from node-key or random
    #[arg(long)]
    pub node_id: Option<String>,
    /// Redistribute broadcasts through the best-connected peer (helps poor upload)
    #[arg(long, conflicts_with = "no_flood_relay")]
    pub flood_relay: bool,
    /// Pin the redistribution peer by node id (hex) instead of lowest RTT
    #[arg(long, value_name = "NODE_ID")]
    pub flood_relay_via: Option<String>,
    /// Always send a separate broadcast copy to each peer
    #[arg(long, conflicts_with = "flood_relay")]
    pub no_flood_relay: bool,
    /// TAP node: accept IP-only (TUN) peers and translate L2<->L3 locally
    #[arg(long)]
    pub l2_l3_bridge: bool,

    #[command(subcommand)]
    pub cmd: Option<Command>
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Validate a config file without starting the VPN
    #[command(name = "check-config", alias = "checkconfig")]
    CheckConfig {
        /// Config file to validate
        #[arg(long = "config", short)]
        config_file: String,
        /// Require and verify a config signature (uses --verify-key / --verify-key-file)
        #[arg(long)]
        verify_signature: bool
    },

    /// List or control per-network service instances
    Network {
        #[command(subcommand)]
        action: NetworkAction
    },

    /// Run preflight checks (TUN access, config, port, clock, DNS) without starting the VPN
    Doctor {
        /// Config file to check (optional)
        #[arg(long = "config", short)]
        config_file: Option<String>
    },

    /// Show runtime status from the JSON status file
    Status {
        /// Read status from this file (default: status_file from the config)
        #[arg(long)]
        status_file: Option<String>,
        /// Config file to read the status_file setting from
        #[arg(long = "config", short)]
        config_file: Option<String>,
        /// Print the raw JSON status
        #[arg(long)]
        json: bool
    },

    /// Generate and print a key-pair and exit
    #[command(name = "genkey", alias = "gen-key")]
    GenKey {
        /// The shared password to encrypt all traffic
        #[arg(short, long, env = "PASSWORD")]
        password: Option<String>,
        /// Write the key pair to this file instead of stdout (created 0600)
        #[arg(long = "out", value_name = "PATH")]
        out: Option<String>
    },

    /// Sign a config file with Ed25519 (private key or password)
    #[command(name = "sign-config", alias = "signconfig")]
    SignConfig {
        /// Config file to sign (rewritten in place)
        #[arg(long = "config", short)]
        config_file: String,
        /// Private key (base62). Default: key from the config or `--password`.
        #[arg(long)]
        private_key: Option<String>,
        /// Password used to derive the signing key
        #[arg(short, long, env = "PASSWORD")]
        password: Option<String>
    },

    /// Run a websocket proxy
    #[cfg(feature = "websocket")]
    #[command(alias = "wsproxy")]
    WsProxy {
        /// Websocket listen address IP:PORT
        #[arg(long, short, default_value = "3210")]
        listen: String
    },

    /// Migrate an old config file
    #[command(alias = "migrate")]
    MigrateConfig {
        /// Config file
        #[arg(long)]
        config_file: String
    },

    /// Generate shell completions
    Completion {
        /// Shell to create completions for
        #[arg(long, default_value = "bash")]
        shell: Shell
    },

    /// Edit the config of a network
    #[cfg(feature = "wizard")]
    Config {
        /// Name of the network
        #[arg(short, long)]
        name: Option<String>,

        /// Path where the configuration file will be written/installed (overrides default
        /// /etc/vpncloud/<name>.net, /usr/local/etc/vpncloud/<name>.net on macOS/FreeBSD)
        /// Example: --config /etc/vpncloud/myvpn.net
        #[arg(long = "config")]
        config_file: Option<String>,

        /// Print the effective config (secrets redacted) instead of launching the wizard
        #[arg(long)]
        print: bool
    },

    /// Install required utility files
    #[cfg(feature = "installer")]
    Install {
        /// Remove installed files again
        #[arg(long)]
        uninstall: bool,
        /// Install a system tray / menu bar icon (prompted on Windows; macOS defaults to yes)
        #[arg(long)]
        tray: bool,
        /// Do not install a tray / menu bar icon
        #[arg(long, conflicts_with = "tray")]
        no_tray: bool,
        /// Windows: start VpnCloud with Windows (registry Run key)
        #[arg(long)]
        autostart: bool,
        /// Register a system service (Windows service / macOS LaunchDaemon)
        #[arg(long)]
        service: bool,
        /// Do not register a system service
        #[arg(long, conflicts_with = "service")]
        no_service: bool
    },

    /// Windows service (install / uninstall / start / stop). Requires Administrator.
    #[cfg(windows)]
    Service {
        #[command(subcommand)]
        action: WindowsServiceAction
    }
}

#[derive(Subcommand, Debug)]
pub enum NetworkAction {
    /// List configured networks
    List,
    /// Start a network's service instance
    Start { name: String },
    /// Stop a network's service instance
    Stop { name: String },
    /// Show whether a network's service is active
    Status { name: String }
}

/// Windows Service Control Manager actions
#[cfg(windows)]
#[derive(Subcommand, Debug)]
pub enum WindowsServiceAction {
    /// Register VpnCloud as a LocalSystem auto-start service
    Install {
        /// Config file the service should load
        #[arg(long)]
        config: Option<String>,
        /// Start the service immediately after installing
        #[arg(long)]
        start: bool
    },
    /// Unregister the Windows service
    Uninstall,
    /// Start the VpnCloud service
    Start,
    /// Stop the VpnCloud service
    Stop,
    /// Reload the reloadable policy config without restarting the service
    Reload
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct ConfigFileDevice {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub type_: Option<Type>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix_rp_filter: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtu: Option<usize>
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct ConfigFileBeacon {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub store: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval: Option<Duration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct ConfigFileStatsd {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct ConfigFile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<ConfigFileDevice>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advertise_addresses: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ifup: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ifdown: Option<String>,

    pub crypto: CryptoConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peers: Option<Vec<PeerAddr>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_timeout: Option<Duration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keepalive: Option<Duration>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub beacon: Option<ConfigFileBeacon>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<Mode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub switch_timeout: Option<Duration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_addresses: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_claim: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_forwarding: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statsd: Option<ConfigFileStatsd>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hook: Option<String>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub hooks: HashMap<String, String>,
    /// Windows system tray icon
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tray: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stun: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stun_servers: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lan_only: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub init_rate_limit: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub per_peer_rate_limit: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub install_routes: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acl: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_fallback: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crypto_threads: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_signed_config: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seccomp: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub socket_buffer: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grants: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub split: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_tunnel: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_node: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_allow: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_names: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stateful_filter: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compression: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub announce_group: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trusted_node_keys: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub per_node_keys: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<NetworkProfile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_underlay_mtu: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jitter_ms: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mobility: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flood_relay: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flood_relay_via: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub l2_l3_bridge: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>
}

/// Config file encoding. YAML covers `.yaml`, `.yml`, `.net`, and unknown extensions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigFormat {
    Yaml,
    Toml
}

const YAML_EXTS: &[&str] = &["yaml", "yml", "net"];

fn ext_lower(path: &Path) -> Option<String> {
    path.extension().and_then(|e| e.to_str()).map(|s| s.to_ascii_lowercase())
}

/// Format from the path extension. `.toml` is TOML; everything else is treated as YAML
/// (including `.yaml`, `.yml`, `.net`, and `example.net.disabled`).
pub fn config_format_from_path(path: &Path) -> ConfigFormat {
    match ext_lower(path).as_deref() {
        Some("toml") => ConfigFormat::Toml,
        _ => ConfigFormat::Yaml
    }
}

fn is_config_ext(ext: &str) -> bool {
    matches!(ext, "yaml" | "yml" | "net" | "toml")
}

fn config_stem(path: &Path) -> PathBuf {
    match ext_lower(path) {
        Some(ext) if is_config_ext(&ext) => path.with_extension(""),
        _ => path.to_path_buf()
    }
}

/// Resolve `--config` / a default path to an existing file.
///
/// If `path` already exists, it is used as-is (explicit `.toml` stays TOML).
/// Otherwise YAML siblings (`.yaml`, `.yml`, `.net`) are tried before `.toml`.
/// When both YAML and TOML exist for the same name, YAML wins.
pub fn resolve_config_path(path: &Path) -> PathBuf {
    if path.is_file() {
        return path.to_path_buf();
    }
    let stem = config_stem(path);
    for ext in YAML_EXTS {
        let candidate = stem.with_extension(ext);
        if candidate.is_file() {
            return candidate;
        }
    }
    let toml_path = stem.with_extension("toml");
    if toml_path.is_file() {
        return toml_path;
    }
    path.to_path_buf()
}

pub fn parse_config_contents(raw: &str, format: ConfigFormat) -> Result<ConfigFile, String> {
    match format {
        ConfigFormat::Toml => toml::from_str(raw).map_err(|e| e.to_string()),
        ConfigFormat::Yaml => serde_norway::from_str(raw).map_err(|e| e.to_string())
    }
}

/// Parse a config blob of unknown type. YAML is tried first, then TOML.
pub fn parse_config_auto(raw: &str) -> Result<ConfigFile, String> {
    match serde_norway::from_str(raw) {
        Ok(file) => Ok(file),
        Err(yaml_err) => {
            toml::from_str(raw)
                .map_err(|toml_err| format!("not valid YAML ({}); not valid TOML ({})", yaml_err, toml_err))
        }
    }
}

/// Read a config file exactly once and return the resolved path, the raw bytes,
/// and the parsed structure. Callers that verify signatures must use this so
/// the bytes they verify are the bytes they execute (no TOCTOU re-read).
pub fn load_config_file_with_raw(path: &Path) -> Result<(PathBuf, String, ConfigFile), crate::error::Error> {
    let resolved = resolve_config_path(path);
    let raw =
        fs::read_to_string(&resolved).map_err(|e| crate::error::Error::FileIo("Failed to open config file", e))?;
    let format = config_format_from_path(&resolved);
    match parse_config_contents(&raw, format) {
        Ok(file) => Ok((resolved, raw, file)),
        Err(err) => {
            Err(crate::error::Error::FileIo(
                "Failed to parse config file",
                io::Error::new(io::ErrorKind::InvalidData, err)
            ))
        }
    }
}

/// Read and parse a config file. Resolves YAML-over-TOML siblings when `path` is missing.
pub fn load_config_file(path: &Path) -> Result<(PathBuf, ConfigFile), crate::error::Error> {
    let (path, _, file) = load_config_file_with_raw(path)?;
    Ok((path, file))
}

/// Create/truncate a file that will hold secrets, with owner-only permissions
/// from creation and no symlink following (Unix). Used for config/key files.
pub fn create_private_file(path: &Path) -> io::Result<fs::File> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = opts.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

pub fn write_config_file(path: &Path, file: &ConfigFile) -> io::Result<()> {
    match config_format_from_path(path) {
        ConfigFormat::Toml => {
            let body = toml::to_string_pretty(file).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            let mut fh = create_private_file(path)?;
            fh.write_all(body.as_bytes())
        }
        ConfigFormat::Yaml => {
            let fh = create_private_file(path)?;
            serde_norway::to_writer(fh, file).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        }
    }
}

#[test]
fn config_file() {
    let config_file = "
device:
  type: tun
  name: vpncloud%d
  path: /dev/net/tun
ip: 10.0.1.1/16
advertise-addresses:
  - 192.168.0.1
  - 192.168.1.1
ifup: ifconfig $IFNAME 10.0.1.1/16 mtu 1400 up
ifdown: 'true'
peers:
  - remote.machine.foo:3210
  - remote.machine.bar:3210
peer-timeout: 600
keepalive: 840
switch-timeout: 300
beacon:
  store: /run/vpncloud.beacon.out
  load: /run/vpncloud.beacon.in
  interval: 3600
  password: test123
mode: normal
claims:
  - 10.0.1.0/24
port-forwarding: true
user: nobody
group: nogroup
pid-file: /run/vpncloud.run
stats-file: /var/log/vpncloud.stats
statsd:
  server: example.com:1234
  prefix: prefix
    ";
    assert_eq!(serde_norway::from_str::<ConfigFile>(config_file).unwrap(), ConfigFile {
        device: Some(ConfigFileDevice {
            type_: Some(Type::Tun),
            name: Some("vpncloud%d".to_string()),
            path: Some("/dev/net/tun".to_string()),
            fix_rp_filter: None,
            mtu: None
        }),
        ip: Some("10.0.1.1/16".to_string()),
        advertise_addresses: Some(vec!["192.168.0.1".to_string(), "192.168.1.1".to_string()]),
        ifup: Some("ifconfig $IFNAME 10.0.1.1/16 mtu 1400 up".to_string()),
        ifdown: Some("true".to_string()),
        crypto: CryptoConfig::default(),
        listen: None,
        peers: Some(vec![
            PeerAddr::Single("remote.machine.foo:3210".to_string()),
            PeerAddr::Single("remote.machine.bar:3210".to_string())
        ]),
        peer_timeout: Some(600),
        keepalive: Some(840),
        beacon: Some(ConfigFileBeacon {
            store: Some("/run/vpncloud.beacon.out".to_string()),
            load: Some("/run/vpncloud.beacon.in".to_string()),
            interval: Some(3600),
            password: Some("test123".to_string())
        }),
        mode: Some(Mode::Normal),
        switch_timeout: Some(300),
        claims: Some(vec!["10.0.1.0/24".to_string()]),
        auto_claim: None,
        port_forwarding: Some(true),
        user: Some("nobody".to_string()),
        group: Some("nogroup".to_string()),
        pid_file: Some("/run/vpncloud.run".to_string()),
        stats_file: Some("/var/log/vpncloud.stats".to_string()),
        statsd: Some(ConfigFileStatsd {
            server: Some("example.com:1234".to_string()),
            prefix: Some("prefix".to_string())
        }),
        hook: None,
        hooks: HashMap::new(),
        tray: None,
        ..Default::default()
    })
}

#[test]
fn parse_example_config() {
    serde_norway::from_str::<ConfigFile>(include_str!("../assets/example.net.disabled")).unwrap();
}

#[test]
fn parse_example_config_toml() {
    parse_config_contents(include_str!("../assets/example.toml.disabled"), ConfigFormat::Toml).unwrap();
}

#[test]
fn config_merge() {
    let mut config = Config::default();
    config.merge_file(ConfigFile {
        device: Some(ConfigFileDevice {
            type_: Some(Type::Tun),
            name: Some("vpncloud%d".to_string()),
            path: None,
            fix_rp_filter: None,
            mtu: None
        }),
        ip: None,
        advertise_addresses: Some(vec![]),
        ifup: Some("ifconfig $IFNAME 10.0.1.1/16 mtu 1400 up".to_string()),
        ifdown: Some("true".to_string()),
        crypto: CryptoConfig::default(),
        listen: None,
        peers: Some(vec![
            PeerAddr::Single("remote.machine.foo:3210".to_string()),
            PeerAddr::Single("remote.machine.bar:3210".to_string()),
        ]),
        peer_timeout: Some(600),
        keepalive: Some(840),
        beacon: Some(ConfigFileBeacon {
            store: Some("/run/vpncloud.beacon.out".to_string()),
            load: Some("/run/vpncloud.beacon.in".to_string()),
            interval: Some(7200),
            password: Some("test123".to_string())
        }),
        mode: Some(Mode::Normal),
        switch_timeout: Some(300),
        claims: Some(vec!["10.0.1.0/24".to_string()]),
        auto_claim: Some(true),
        port_forwarding: Some(true),
        user: Some("nobody".to_string()),
        group: Some("nogroup".to_string()),
        pid_file: Some("/run/vpncloud.run".to_string()),
        stats_file: Some("/var/log/vpncloud.stats".to_string()),
        statsd: Some(ConfigFileStatsd {
            server: Some("example.com:1234".to_string()),
            prefix: Some("prefix".to_string())
        }),
        hook: None,
        hooks: HashMap::new(),
        tray: None,
        ..Default::default()
    });
    assert_eq!(config, Config {
        device_type: Type::Tun,
        device_name: "vpncloud%d".to_string(),
        device_path: None,
        ip: None,
        advertise_addresses: vec![],
        ifup: Some("ifconfig $IFNAME 10.0.1.1/16 mtu 1400 up".to_string()),
        ifdown: Some("true".to_string()),
        listen: "3210".to_string(),
        peers: vec!["remote.machine.foo:3210".to_string(), "remote.machine.bar:3210".to_string()],
        peer_timeout: 600,
        keepalive: Some(840),
        switch_timeout: 300,
        beacon_store: Some("/run/vpncloud.beacon.out".to_string()),
        beacon_load: Some("/run/vpncloud.beacon.in".to_string()),
        beacon_interval: 7200,
        beacon_password: Some("test123".to_string()),
        mode: Mode::Normal,
        port_forwarding: true,
        claims: vec!["10.0.1.0/24".to_string()],
        user: Some("nobody".to_string()),
        group: Some("nogroup".to_string()),
        pid_file: Some("/run/vpncloud.run".to_string()),
        stats_file: Some("/var/log/vpncloud.stats".to_string()),
        statsd_server: Some("example.com:1234".to_string()),
        statsd_prefix: Some("prefix".to_string()),
        ..Default::default()
    });
    config.merge_args(Args {
        type_: Some(Type::Tap),
        device: Some("vpncloud0".to_string()),
        device_path: Some("/dev/null".to_string()),
        ifup: Some("ifconfig $IFNAME 10.0.1.2/16 mtu 1400 up".to_string()),
        ifdown: Some("ifconfig $IFNAME down".to_string()),
        password: Some("anothersecret".to_string()),
        listen: Some("[::]:3211".to_string()),
        peer_timeout: Some(1801),
        keepalive: Some(850),
        switch_timeout: Some(301),
        beacon_store: Some("/run/vpncloud.beacon.out2".to_string()),
        beacon_load: Some("/run/vpncloud.beacon.in2".to_string()),
        beacon_interval: Some(3600),
        beacon_password: Some("test1234".to_string()),
        mode: Some(Mode::Switch),
        claims: vec![],
        peers: vec!["another:3210".to_string()],
        no_port_forwarding: true,
        daemon: true,
        pid_file: Some("/run/vpncloud-mynet.run".to_string()),
        stats_file: Some("/var/log/vpncloud-mynet.stats".to_string()),
        statsd_server: Some("example.com:2345".to_string()),
        statsd_prefix: Some("prefix2".to_string()),
        user: Some("root".to_string()),
        group: Some("root".to_string()),
        ..Default::default()
    });
    assert_eq!(config, Config {
        device_type: Type::Tap,
        device_name: "vpncloud0".to_string(),
        device_path: Some("/dev/null".to_string()),
        tun_fd: None,
        fix_rp_filter: false,
        mtu: None,
        ip: None,
        advertise_addresses: vec![],

        ifup: Some("ifconfig $IFNAME 10.0.1.2/16 mtu 1400 up".to_string()),
        ifdown: Some("ifconfig $IFNAME down".to_string()),
        crypto: CryptoConfig { password: Some("anothersecret".to_string()), ..CryptoConfig::default() },
        listen: "[::]:3211".to_string(),
        peers: vec![
            "remote.machine.foo:3210".to_string(),
            "remote.machine.bar:3210".to_string(),
            "another:3210".to_string()
        ],
        peer_timeout: 1801,
        keepalive: Some(850),
        switch_timeout: 301,
        beacon_store: Some("/run/vpncloud.beacon.out2".to_string()),
        beacon_load: Some("/run/vpncloud.beacon.in2".to_string()),
        beacon_interval: 3600,
        beacon_password: Some("test1234".to_string()),
        mode: Mode::Switch,
        port_forwarding: false,
        claims: vec!["10.0.1.0/24".to_string()],
        auto_claim: true,
        user: Some("root".to_string()),
        group: Some("root".to_string()),
        pid_file: Some("/run/vpncloud-mynet.run".to_string()),
        stats_file: Some("/var/log/vpncloud-mynet.stats".to_string()),
        statsd_server: Some("example.com:2345".to_string()),
        statsd_prefix: Some("prefix2".to_string()),
        daemonize: true,
        hook: None,
        hooks: HashMap::new(),
        tray: false,
        ..Default::default()
    });
}

#[test]
fn peer_group_yaml() {
    let yaml = "
peers:
  - 172.16.0.1:3210
  - - 192.168.0.3:3210
    - 172.16.0.3:3210
";
    let file: ConfigFile = serde_norway::from_str(yaml).unwrap();
    assert_eq!(
        file.peers,
        Some(vec![
            PeerAddr::Single("172.16.0.1:3210".to_string()),
            PeerAddr::Group(vec!["192.168.0.3:3210".to_string(), "172.16.0.3:3210".to_string()])
        ])
    );
    let mut config = Config::default();
    config.merge_file(file);
    assert_eq!(config.peers, vec!["172.16.0.1:3210".to_string(), "192.168.0.3:3210,172.16.0.3:3210".to_string()]);
}

#[test]
fn clap_help_says_android_tap_needs_root() {
    use clap::CommandFactory;
    let help = Args::command().render_long_help().to_string();
    assert!(help.to_lowercase().contains("rooted"), "{}", help);
    assert!(help.contains("tun") || help.contains("TUN"), "{}", help);
}

#[test]
fn clap_help_says_ios_tap_unavailable() {
    use clap::CommandFactory;
    let help = Args::command().render_long_help().to_string();
    assert!(help.contains("iOS"), "{}", help);
    assert!(help.to_lowercase().contains("packet tunnel") || help.contains("Packet Tunnel"), "{}", help);
    assert!(help.contains("tap") || help.contains("TAP"), "{}", help);
}

#[test]
fn tray_yaml() {
    let file: ConfigFile = serde_norway::from_str("tray: true\n").unwrap();
    assert_eq!(file.tray, Some(true));
    let mut config = Config::default();
    config.merge_file(file);
    assert!(config.tray);
}

#[test]
fn validate_accepts_a_sane_config_and_flags_risks() {
    let mut config = Config::default();
    config.crypto.password = Some("secret".into());
    config.ip = Some("10.0.0.1/24".into());
    config.peers = vec!["192.0.2.1:3210".into()];
    let warnings = config.validate().unwrap();
    assert!(warnings.is_empty(), "{:?}", warnings);

    config.compression = true;
    config.peers.clear();
    let warnings = config.validate().unwrap();
    assert!(warnings.iter().any(|w| w.contains("compression")));
    assert!(warnings.iter().any(|w| w.contains("peers")));
}

#[test]
fn validate_rejects_bad_crypto_and_addresses() {
    let mut config = Config::default();
    assert!(config.validate().is_err());
    config.crypto.password = Some("secret".into());
    config.ip = Some("10.0.0.1/99".into());
    assert!(config.validate().is_err());
    config.ip = Some("10.0.0.1/24".into());
    config.peers = vec!["host:notaport".into()];
    assert!(config.validate().is_err());
    config.peers.clear();
    config.mtu = Some(10);
    assert!(config.validate().is_err());
}

#[test]
fn compression_is_opt_in_and_survives_config_roundtrip() {
    assert!(!Config::default().compression);
    let file: ConfigFile = serde_norway::from_str("compression: true\n").unwrap();
    assert_eq!(file.compression, Some(true));
    let mut config = Config::default();
    config.merge_file(file);
    assert!(config.compression);
    let saved: ConfigFile =
        serde_norway::from_str(&serde_norway::to_string(&config.into_config_file()).unwrap()).unwrap();
    assert_eq!(saved.compression, Some(true));
}

#[test]
fn parse_config_toml() {
    let toml = r#"
ip = "10.0.1.1/16"
listen = "3210"
peers = ["remote.machine.foo:3210", ["192.168.0.3:3210", "172.16.0.3:3210"]]
peer-timeout = 600
tray = true

[device]
type = "tun"
name = "vpncloud%d"

[crypto]
password = "secret"
"#;
    let file = parse_config_contents(toml, ConfigFormat::Toml).unwrap();
    assert_eq!(file.ip.as_deref(), Some("10.0.1.1/16"));
    assert_eq!(file.listen.as_deref(), Some("3210"));
    assert_eq!(file.peer_timeout, Some(600));
    assert_eq!(file.tray, Some(true));
    assert_eq!(file.device.as_ref().unwrap().type_, Some(Type::Tun));
    assert_eq!(file.crypto.password.as_deref(), Some("secret"));
    assert_eq!(
        file.peers,
        Some(vec![
            PeerAddr::Single("remote.machine.foo:3210".to_string()),
            PeerAddr::Group(vec!["192.168.0.3:3210".to_string(), "172.16.0.3:3210".to_string()])
        ])
    );
}

#[test]
fn parse_config_auto_prefers_yaml() {
    let yaml = "listen: yaml-port\n";
    let file = parse_config_auto(yaml).unwrap();
    assert_eq!(file.listen.as_deref(), Some("yaml-port"));
}

#[test]
fn parse_config_auto_toml_fallback() {
    let toml = "listen = \"toml-port\"\n";
    let file = parse_config_auto(toml).unwrap();
    assert_eq!(file.listen.as_deref(), Some("toml-port"));
}

#[test]
fn yaml_wins_over_toml_when_both_exist() {
    let dir = tempfile::tempdir().unwrap();
    let yaml = dir.path().join("net.yaml");
    let toml_path = dir.path().join("net.toml");
    fs::write(&yaml, "listen: from-yaml\n").unwrap();
    fs::write(&toml_path, "listen = \"from-toml\"\n").unwrap();

    let by_stem = resolve_config_path(&dir.path().join("net"));
    assert_eq!(by_stem, yaml);
    let (path, file) = load_config_file(&dir.path().join("net")).unwrap();
    assert_eq!(path, yaml);
    assert_eq!(file.listen.as_deref(), Some("from-yaml"));

    let by_yaml = resolve_config_path(&yaml);
    assert_eq!(by_yaml, yaml);
    let by_toml_explicit = resolve_config_path(&toml_path);
    assert_eq!(by_toml_explicit, toml_path);
}

#[test]
fn toml_used_when_yaml_missing() {
    let dir = tempfile::tempdir().unwrap();
    let toml_path = dir.path().join("net.toml");
    fs::write(&toml_path, "listen = \"only-toml\"\n").unwrap();

    let resolved = resolve_config_path(&dir.path().join("net.yaml"));
    assert_eq!(resolved, toml_path);
    let (path, file) = load_config_file(&dir.path().join("net")).unwrap();
    assert_eq!(path, toml_path);
    assert_eq!(file.listen.as_deref(), Some("only-toml"));
}

#[test]
fn write_and_reload_toml() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vpncloud.toml");
    let mut file = ConfigFile::default();
    file.ip = Some("10.0.0.1/24".into());
    file.crypto.password = Some("pw".into());
    write_config_file(&path, &file).unwrap();
    let raw = fs::read_to_string(&path).unwrap();
    assert!(raw.contains("10.0.0.1/24"), "{}", raw);
    let loaded = parse_config_contents(&raw, ConfigFormat::Toml).unwrap();
    assert_eq!(loaded.ip, file.ip);
    assert_eq!(loaded.crypto.password, file.crypto.password);
}

#[test]
fn system_config_dir_is_os_default() {
    #[cfg(any(target_os = "freebsd", target_os = "macos"))]
    {
        assert_eq!(system_config_dir(), Path::new("/usr/local/etc/vpncloud"));
        assert_eq!(system_bin_path(), Path::new("/usr/local/bin/vpncloud"));
        assert_eq!(system_man_path(), Path::new("/usr/local/share/man/man1/vpncloud.1.gz"));
    }
    #[cfg(not(any(target_os = "freebsd", target_os = "macos")))]
    {
        assert_eq!(system_config_dir(), Path::new("/etc/vpncloud"));
        assert_eq!(system_bin_path(), Path::new("/usr/bin/vpncloud"));
        assert_eq!(system_man_path(), Path::new("/usr/share/man/man1/vpncloud.1.gz"));
    }
}

#[test]
fn crypto_threads_default_is_zero_in_tests() {
    assert_eq!(default_crypto_threads(), 0);
    assert_eq!(Config::default().crypto_threads, 0);
}
