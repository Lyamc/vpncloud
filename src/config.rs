// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use super::{
    device::Type,
    types::Mode,
    util::{run_cmd, Duration}
};
pub use crate::crypto::Config as CryptoConfig;

use clap::{Parser, Subcommand};
use clap_complete::Shell;
use std::{
    cmp::max,
    collections::HashMap,
    ffi::OsStr,
    fs,
    io,
    path::{Path, PathBuf},
    process,
    thread
};

pub const DEFAULT_PEER_TIMEOUT: u16 = 300;
pub const DEFAULT_PORT: u16 = 3210;

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
        let parts: Vec<String> =
            s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect();
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
    pub auto_claim: bool,
    pub port_forwarding: bool,
    pub daemonize: bool,
    pub pid_file: Option<String>,
    pub stats_file: Option<String>,
    pub statsd_server: Option<String>,
    pub statsd_prefix: Option<String>,
    pub user: Option<String>,
    pub group: Option<String>,
    pub hook: Option<String>,
    pub hooks: HashMap<String, String>,
    /// Windows: show a system tray icon (Enable / Disable / Exit).
    pub tray: bool
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
            auto_claim: true,
            port_forwarding: true,
            daemonize: false,
            pid_file: None,
            stats_file: None,
            statsd_server: None,
            statsd_prefix: None,
            user: None,
            group: None,
            hook: None,
            hooks: HashMap::new(),
            tray: false
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
    }

    pub fn into_config_file(self) -> ConfigFile {
        ConfigFile {
            auto_claim: Some(self.auto_claim),
            claims: Some(self.claims),
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
            statsd: Some(ConfigFileStatsd { server: self.statsd_server, prefix: self.statsd_prefix }),
            switch_timeout: Some(self.switch_timeout),
            hook: self.hook,
            hooks: self.hooks,
            tray: Some(self.tray)
        }
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
        debug!("Running event script: {:?}", cmd);
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

    /// Algorithms to allow [possible values: plain, aes128, aes256, chacha20]
    #[arg(long = "algorithm", alias = "algo", value_delimiter = ',', ignore_case = true, value_parser = ["plain", "aes128", "aes256", "chacha20"])]
    pub algorithms: Vec<String>,

    /// The local subnets to claim (IP or IP/prefix)
    #[arg(long = "claim", value_delimiter = ',')]
    pub claims: Vec<String>,

    /// Do not automatically claim the device ip
    #[arg(long)]
    pub no_auto_claim: bool,

    /// Name of the virtual device
    #[arg(short, long)]
    pub device: Option<String>,

    /// The port number (or ip:port) on which to listen for data
    #[arg(short, long)]
    pub listen: Option<String>,

    /// Address of a peer to connect to. Comma-separated addresses are tried in order as alternatives for the same peer.
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

    /// Print debug information
    #[arg(short, long, conflicts_with = "quiet")]
    pub verbose: bool,

    /// Only print errors and warnings
    #[arg(short, long)]
    pub quiet: bool,

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

    /// Windows: show a system tray icon (Enable / Disable / Exit)
    #[arg(long)]
    pub tray: bool,

    /// Windows: do not show a system tray icon
    #[arg(long, conflicts_with = "tray")]
    pub no_tray: bool,

    #[command(subcommand)]
    pub cmd: Option<Command>
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Generate and print a key-pair and exit
    #[command(name = "genkey", alias = "gen-key")]
    GenKey {
        /// The shared password to encrypt all traffic
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

        /// Path where the configuration file will be written/installed (overrides default /etc/vpncloud/<name>.net)
        /// Example: --config /etc/vpncloud/myvpn.net
        #[arg(long = "config")]
        config_file: Option<String>
    },

    /// Install required utility files
    #[cfg(feature = "installer")]
    Install {
        /// Remove installed files again
        #[arg(long)]
        uninstall: bool,
        /// Windows: install a system tray icon (prompted if omitted)
        #[arg(long)]
        tray: bool,
        /// Windows: do not install a system tray icon
        #[arg(long, conflicts_with = "tray")]
        no_tray: bool,
        /// Windows: start VpnCloud with Windows (registry Run key)
        #[arg(long)]
        autostart: bool,
        /// Windows: register a system service (requires Administrator)
        #[arg(long)]
        service: bool,
        /// Windows: do not register a system service
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
    Stop
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
    pub auto_claim: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_forwarding: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats_file: Option<String>,
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
    pub tray: Option<bool>
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
        Err(yaml_err) => toml::from_str(raw)
            .map_err(|toml_err| format!("not valid YAML ({}); not valid TOML ({})", yaml_err, toml_err))
    }
}

/// Read and parse a config file. Resolves YAML-over-TOML siblings when `path` is missing.
pub fn load_config_file(path: &Path) -> Result<(PathBuf, ConfigFile), crate::error::Error> {
    let resolved = resolve_config_path(path);
    let raw = fs::read_to_string(&resolved).map_err(|e| crate::error::Error::FileIo("Failed to open config file", e))?;
    let format = config_format_from_path(&resolved);
    match parse_config_contents(&raw, format) {
        Ok(file) => Ok((resolved, file)),
        Err(err) => {
            Err(crate::error::Error::FileIo("Failed to parse config file", io::Error::new(io::ErrorKind::InvalidData, err)))
        }
    }
}

pub fn write_config_file(path: &Path, file: &ConfigFile) -> io::Result<()> {
    match config_format_from_path(path) {
        ConfigFormat::Toml => {
            let body = toml::to_string_pretty(file).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            fs::write(path, body)
        }
        ConfigFormat::Yaml => {
            let fh = fs::File::create(path)?;
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
        tray: None
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
            PeerAddr::Single("remote.machine.bar:3210".to_string())
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
        tray: None
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
        tray: false
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
    assert_eq!(
        config.peers,
        vec!["172.16.0.1:3210".to_string(), "192.168.0.3:3210,172.16.0.3:3210".to_string()]
    );
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
