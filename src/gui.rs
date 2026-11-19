// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! Cross-platform desktop settings window (Iced, software renderer).
//!
//! This is a settings manager: it can load, edit and save every commonly used
//! config field, and run a node in-process for a quick connectivity check.
//! Non-GUI fields present in a config file are preserved on save.

use std::{
    env, fs, io,
    path::{Path, PathBuf},
    thread::{self, JoinHandle},
    time::Duration
};

use iced::{
    widget::{button, checkbox, column, container, radio, row, scrollable, text, text_input, Space},
    Alignment, Element, Length, Task, Theme
};

use crate::{
    config::{
        config_format_from_path, create_private_file, load_config_file, load_config_file_with_raw, resolve_config_path,
        write_config_file, Config, ConfigFile, ConfigFormat, PeerAddr
    },
    config_verify::{verify_loaded_config, VerifyKeys},
    device::Type,
    engine::run_vpn,
    runtime_status,
    types::{Mode, NetworkProfile},
    util::{Bytes, CtrlC}
};

/// Every plain-text setting exposed in the window. Keeping the widget-to-field
/// mapping in one enum avoids dozens of near-identical message variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Password,
    Overlay,
    Peers,
    Listen,
    ConfigPath,
    Mtu,
    PeerTimeout,
    Acl,
    PrivateKey,
    TrustedKeys,
    Algorithms,
    NodeId,
    NodeKey,
    TrustedNodeKeys,
    DeviceName,
    DevicePath,
    Claims,
    SwitchTimeout,
    Keepalive,
    ExitNode,
    ExitAllow,
    Grants,
    Split,
    PeerNames,
    AnnounceGroup,
    LocalAddresses,
    BeaconPassword,
    StunServers,
    AdvertiseAddresses,
    Jitter,
    MaxUnderlayMtu,
    FloodRelayVia,
    InitRateLimit,
    CryptoThreads,
    StatusFile,
    MetricsAddr,
    PerPeerRateLimit
}

/// Every boolean setting exposed in the window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flag {
    Tap,
    PortForwarding,
    Compression,
    StatefulFilter,
    FloodRelay,
    PerNodeKeys,
    RequireSignedConfig,
    AutoClaim,
    FullTunnel,
    Stun,
    LanOnly,
    TcpFallback,
    Mobility,
    Seccomp,
    L2L3Bridge,
    InstallRoutes
}

#[derive(Debug, Clone)]
pub enum Message {
    Edit(Field, String),
    Toggle(Flag, bool),
    Mode(Mode),
    Profile(NetworkProfile),
    Connect,
    Disconnect,
    TogglePause,
    Save,
    Load,
    Tick
}

pub struct Gui {
    // Network basics
    password: String,
    overlay: String,
    peer: String,
    listen: String,
    mtu: String,
    peer_timeout: String,
    acl: String,
    // Security & identity
    private_key: String,
    trusted_keys: String,
    algorithms: String,
    node_id: String,
    node_key: String,
    trusted_node_keys: String,
    // Device
    device_name: String,
    device_path: String,
    // Routing & policy
    claims: String,
    switch_timeout: String,
    keepalive: String,
    exit_node: String,
    exit_allow: String,
    grants: String,
    split: String,
    peer_names: String,
    announce_group: String,
    local_addresses: String,
    // Discovery & transport
    beacon_password: String,
    stun_servers: String,
    advertise_addresses: String,
    // Advanced
    jitter: String,
    max_underlay_mtu: String,
    flood_relay_via: String,
    init_rate_limit: String,
    crypto_threads: String,
    status_file: String,
    metrics_addr: String,
    per_peer_rate_limit: String,
    // Flags
    tap: bool,
    port_forwarding: bool,
    compression: bool,
    stateful_filter: bool,
    flood_relay: bool,
    per_node_keys: bool,
    require_signed_config: bool,
    auto_claim: bool,
    full_tunnel: bool,
    stun: bool,
    lan_only: bool,
    tcp_fallback: bool,
    mobility: bool,
    seccomp: bool,
    l2_l3_bridge: bool,
    install_routes: bool,
    // Enums
    mode: Mode,
    profile: NetworkProfile,
    // File / runtime
    config_path: String,
    status: String,
    peers_text: String,
    sent_history: Vec<u64>,
    recv_history: Vec<u64>,
    sent_bytes: u64,
    recv_bytes: u64,
    last_handshake_unix: i64,
    worker: Option<JoinHandle<()>>
}

impl Gui {
    fn field_mut(&mut self, field: Field) -> &mut String {
        match field {
            Field::Password => &mut self.password,
            Field::Overlay => &mut self.overlay,
            Field::Peers => &mut self.peer,
            Field::Listen => &mut self.listen,
            Field::ConfigPath => &mut self.config_path,
            Field::Mtu => &mut self.mtu,
            Field::PeerTimeout => &mut self.peer_timeout,
            Field::Acl => &mut self.acl,
            Field::PrivateKey => &mut self.private_key,
            Field::TrustedKeys => &mut self.trusted_keys,
            Field::Algorithms => &mut self.algorithms,
            Field::NodeId => &mut self.node_id,
            Field::NodeKey => &mut self.node_key,
            Field::TrustedNodeKeys => &mut self.trusted_node_keys,
            Field::DeviceName => &mut self.device_name,
            Field::DevicePath => &mut self.device_path,
            Field::Claims => &mut self.claims,
            Field::SwitchTimeout => &mut self.switch_timeout,
            Field::Keepalive => &mut self.keepalive,
            Field::ExitNode => &mut self.exit_node,
            Field::ExitAllow => &mut self.exit_allow,
            Field::Grants => &mut self.grants,
            Field::Split => &mut self.split,
            Field::PeerNames => &mut self.peer_names,
            Field::AnnounceGroup => &mut self.announce_group,
            Field::LocalAddresses => &mut self.local_addresses,
            Field::BeaconPassword => &mut self.beacon_password,
            Field::StunServers => &mut self.stun_servers,
            Field::AdvertiseAddresses => &mut self.advertise_addresses,
            Field::Jitter => &mut self.jitter,
            Field::MaxUnderlayMtu => &mut self.max_underlay_mtu,
            Field::FloodRelayVia => &mut self.flood_relay_via,
            Field::InitRateLimit => &mut self.init_rate_limit,
            Field::CryptoThreads => &mut self.crypto_threads,
            Field::StatusFile => &mut self.status_file,
            Field::MetricsAddr => &mut self.metrics_addr,
            Field::PerPeerRateLimit => &mut self.per_peer_rate_limit
        }
    }

    fn flag_mut(&mut self, flag: Flag) -> &mut bool {
        match flag {
            Flag::Tap => &mut self.tap,
            Flag::PortForwarding => &mut self.port_forwarding,
            Flag::Compression => &mut self.compression,
            Flag::StatefulFilter => &mut self.stateful_filter,
            Flag::FloodRelay => &mut self.flood_relay,
            Flag::PerNodeKeys => &mut self.per_node_keys,
            Flag::RequireSignedConfig => &mut self.require_signed_config,
            Flag::AutoClaim => &mut self.auto_claim,
            Flag::FullTunnel => &mut self.full_tunnel,
            Flag::Stun => &mut self.stun,
            Flag::LanOnly => &mut self.lan_only,
            Flag::TcpFallback => &mut self.tcp_fallback,
            Flag::Mobility => &mut self.mobility,
            Flag::Seccomp => &mut self.seccomp,
            Flag::L2L3Bridge => &mut self.l2_l3_bridge,
            Flag::InstallRoutes => &mut self.install_routes
        }
    }
}

impl Default for Gui {
    fn default() -> Self {
        let mut gui = Self {
            password: String::new(),
            overlay: "10.0.0.1/24".into(),
            peer: String::new(),
            listen: "3210".into(),
            mtu: String::new(),
            peer_timeout: "300".into(),
            acl: String::new(),
            private_key: String::new(),
            trusted_keys: String::new(),
            algorithms: String::new(),
            node_id: String::new(),
            node_key: String::new(),
            trusted_node_keys: String::new(),
            device_name: String::new(),
            device_path: String::new(),
            claims: String::new(),
            switch_timeout: String::new(),
            keepalive: String::new(),
            exit_node: String::new(),
            exit_allow: String::new(),
            grants: String::new(),
            split: String::new(),
            peer_names: String::new(),
            announce_group: String::new(),
            local_addresses: String::new(),
            beacon_password: String::new(),
            stun_servers: String::new(),
            advertise_addresses: String::new(),
            jitter: String::new(),
            max_underlay_mtu: String::new(),
            flood_relay_via: String::new(),
            init_rate_limit: String::new(),
            crypto_threads: String::new(),
            status_file: String::new(),
            metrics_addr: String::new(),
            per_peer_rate_limit: String::new(),
            tap: false,
            port_forwarding: true,
            compression: false,
            stateful_filter: false,
            flood_relay: false,
            per_node_keys: false,
            require_signed_config: false,
            auto_claim: true,
            full_tunnel: false,
            // Match Config::default() so opening the GUI does not silently
            // change behaviour when the user connects without touching a flag.
            stun: !cfg!(test),
            lan_only: false,
            tcp_fallback: true,
            mobility: true,
            seccomp: !cfg!(test),
            l2_l3_bridge: false,
            install_routes: false,
            mode: Mode::Normal,
            profile: NetworkProfile::Balanced,
            config_path: default_config_path().display().to_string(),
            status: "Disconnected".into(),
            peers_text: String::new(),
            sent_history: Vec::new(),
            recv_history: Vec::new(),
            sent_bytes: 0,
            recv_bytes: 0,
            last_handshake_unix: 0,
            worker: None
        };
        if Path::new(&gui.config_path).is_file() {
            match load_into(&mut gui) {
                Ok(()) => gui.status = format!("Loaded {}", gui.config_path),
                Err(e) => gui.status = format!("Could not load config: {}", e)
            }
        }
        gui
    }
}

impl Drop for Gui {
    fn drop(&mut self) {
        CtrlC::request_stop();
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
        crate::util::set_fail_panics(false);
    }
}

fn title(_: &Gui) -> String {
    "VpnCloud".to_string()
}

fn theme(_: &Gui) -> Theme {
    Theme::Dark
}

fn format_handshake(unix: i64) -> String {
    if unix <= 0 {
        return "never".into();
    }
    let now =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(unix);
    let ago = (now - unix).max(0);
    if ago < 5 {
        "just now".into()
    } else if ago < 60 {
        format!("{}s ago", ago)
    } else if ago < 3600 {
        format!("{}m ago", ago / 60)
    } else if ago < 86400 {
        format!("{}h ago", ago / 3600)
    } else {
        format!("{}d ago", ago / 86400)
    }
}

fn later_tick() -> Task<Message> {
    Task::perform(
        async {
            std::thread::sleep(Duration::from_millis(400));
        },
        |_| Message::Tick
    )
}

pub fn run() -> iced::Result {
    iced::application(Gui::default, update, view)
        .title(title)
        .theme(theme)
        .window_size(iced::Size::new(520.0, 760.0))
        .antialiasing(false)
        .run()
}

fn update(gui: &mut Gui, message: Message) -> Task<Message> {
    match message {
        Message::Edit(field, value) => *gui.field_mut(field) = value,
        Message::Toggle(flag, value) => *gui.flag_mut(flag) = value,
        Message::Mode(v) => gui.mode = v,
        Message::Profile(v) => gui.profile = v,
        Message::Save => {
            match save(gui) {
                Ok(p) => gui.status = format!("Saved {}", p.display()),
                Err(e) => gui.status = format!("Save failed: {}", e)
            }
        }
        Message::Load => {
            match load_into(gui) {
                Ok(()) => gui.status = format!("Loaded {}", gui.config_path),
                Err(e) => gui.status = format!("Load failed: {}", e)
            }
        }
        Message::Connect => {
            connect(gui);
            if gui.worker.is_some() {
                return later_tick();
            }
        }
        Message::Disconnect => disconnect(gui),
        Message::TogglePause => {
            if gui.worker.is_some() {
                let paused = !CtrlC::is_paused();
                CtrlC::set_paused(paused);
                gui.status = if paused { "Paused".into() } else { "Connected".into() };
            }
        }
        Message::Tick => {
            if let Some(w) = gui.worker.as_ref() {
                if w.is_finished() {
                    let w = gui.worker.take().unwrap();
                    match w.join() {
                        Ok(()) => gui.status = "Disconnected".into(),
                        Err(e) => {
                            let msg = panic_message(&e);
                            gui.status = format!("Stopped: {}", msg);
                        }
                    }
                    crate::util::set_fail_panics(false);
                } else {
                    if !CtrlC::is_paused() {
                        gui.status = "Connected".into();
                    }
                    let snap = runtime_status::snapshot();
                    gui.sent_bytes = snap.sent_bytes;
                    gui.recv_bytes = snap.recv_bytes;
                    gui.last_handshake_unix = snap.last_handshake_unix;
                    gui.sent_history.push(snap.sent_bytes);
                    gui.recv_history.push(snap.recv_bytes);
                    if gui.sent_history.len() > 40 {
                        gui.sent_history.remove(0);
                        gui.recv_history.remove(0);
                    }
                    gui.peers_text = runtime_status::peers()
                        .iter()
                        .map(|p| {
                            let rtt = p.rtt_ms.map(|r| format!("{}ms", r)).unwrap_or_else(|| "n/a".into());
                            format!("{} {} rtt={}", p.addr, p.node_id, rtt)
                        })
                        .collect::<Vec<_>>()
                        .join("\n");
                    return later_tick();
                }
            }
        }
    }
    Task::none()
}

// ---- View helpers -------------------------------------------------------

fn section<'a>(label: &'static str) -> Element<'a, Message> {
    text(label).size(16).into()
}

fn txt<'a>(
    label: &'static str, placeholder: &'static str, field: Field, value: &'a str, secure: bool
) -> Element<'a, Message> {
    let input = text_input(placeholder, value).on_input(move |v| Message::Edit(field, v));
    let input = if secure { input.secure(true) } else { input };
    column![text(label).size(13), input].spacing(2).into()
}

fn chk<'a>(label: &'static str, flag: Flag, value: bool) -> Element<'a, Message> {
    checkbox(value).label(label).on_toggle(move |v| Message::Toggle(flag, v)).into()
}

/// Tiny text sparkline of the last 40 samples, scaled to the peak.
fn sparkline(values: &[u64]) -> String {
    if values.is_empty() {
        return "—".into();
    }
    let peak = values.iter().copied().max().unwrap_or(1).max(1);
    let blocks = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    values
        .iter()
        .map(|v| {
            let idx = ((*v as f64 / peak as f64) * (blocks.len() - 1) as f64).round() as usize;
            blocks[idx.min(blocks.len() - 1)]
        })
        .collect()
}

fn view(gui: &Gui) -> Element<'_, Message> {
    let connected = gui.worker.is_some();
    let fields = column![
        text("VpnCloud settings").size(22),
        text("Connection").size(18),
        txt("Password", "required", Field::Password, &gui.password, true),
        txt("Overlay IP", "10.0.0.1/24", Field::Overlay, &gui.overlay, false),
        txt("Peers (one per line, commas = alternatives)", "host:3210", Field::Peers, &gui.peer, false),
        txt("Listen", "3210", Field::Listen, &gui.listen, false),
        txt("MTU (auto if empty)", "auto", Field::Mtu, &gui.mtu, false),
        txt("Peer timeout (s)", "300", Field::PeerTimeout, &gui.peer_timeout, false),
        section("Security & identity"),
        txt("Private key (per-node mode)", "base62", Field::PrivateKey, &gui.private_key, true),
        txt("Trusted peer keys (one per line)", "base62", Field::TrustedKeys, &gui.trusted_keys, false),
        txt("Algorithms (one per line)", "aes128gcm", Field::Algorithms, &gui.algorithms, false),
        chk("Require unique per-node keys", Flag::PerNodeKeys, gui.per_node_keys),
        chk("Require signed config", Flag::RequireSignedConfig, gui.require_signed_config),
        txt("Node ID (hex, optional)", "16-byte hex", Field::NodeId, &gui.node_id, false),
        txt("Node signing key (base62)", "base62", Field::NodeKey, &gui.node_key, true),
        txt("Trusted node keys (node-id=key, one per line)", "", Field::TrustedNodeKeys, &gui.trusted_node_keys, false),
        section("Device"),
        row![
            radio("TUN", false, Some(gui.tap), |v| Message::Toggle(Flag::Tap, v)),
            radio("TAP", true, Some(gui.tap), |v| Message::Toggle(Flag::Tap, v))
        ]
        .spacing(16),
        txt("Device name (auto if empty)", "vpncloud%d", Field::DeviceName, &gui.device_name, false),
        txt("Device path (auto if empty)", "/dev/net/tun", Field::DevicePath, &gui.device_path, false),
        section("Routing & policy"),
        row![
            radio("normal", Mode::Normal, Some(gui.mode), Message::Mode),
            radio("hub", Mode::Hub, Some(gui.mode), Message::Mode),
            radio("switch", Mode::Switch, Some(gui.mode), Message::Mode),
            radio("router", Mode::Router, Some(gui.mode), Message::Mode),
        ]
        .spacing(10),
        txt("Claims (one per line)", "10.0.0.0/24", Field::Claims, &gui.claims, false),
        chk("Auto claim overlay address", Flag::AutoClaim, gui.auto_claim),
        txt("Switch timeout (s)", "300", Field::SwitchTimeout, &gui.switch_timeout, false),
        txt("Keepalive (s)", "30", Field::Keepalive, &gui.keepalive, false),
        txt("ACL rules (one per line)", "allow:10.0.0.0/8", Field::Acl, &gui.acl, false),
        chk("Full tunnel (default route)", Flag::FullTunnel, gui.full_tunnel),
        txt("Exit node (hex node id)", "", Field::ExitNode, &gui.exit_node, false),
        txt("Exit allow (hex ids, one per line)", "", Field::ExitAllow, &gui.exit_allow, false),
        txt("Grants (one per line)", "group=prefix", Field::Grants, &gui.grants, false),
        txt("Split prefixes (one per line)", "10.0.0.0/8", Field::Split, &gui.split, false),
        txt("Peer names (name=key, one per line)", "", Field::PeerNames, &gui.peer_names, false),
        txt("Announce group", "", Field::AnnounceGroup, &gui.announce_group, false),
        txt("Additional local IPs (one per line)", "10.0.0.2", Field::LocalAddresses, &gui.local_addresses, false),
        section("Discovery & transport"),
        txt("Beacon password", "", Field::BeaconPassword, &gui.beacon_password, true),
        chk("STUN", Flag::Stun, gui.stun),
        txt("STUN servers (one per line)", "stun:3478", Field::StunServers, &gui.stun_servers, false),
        chk("LAN only", Flag::LanOnly, gui.lan_only),
        chk("TCP fallback", Flag::TcpFallback, gui.tcp_fallback),
        chk("Mobility (reconnect peers by node id)", Flag::Mobility, gui.mobility),
        txt(
            "Advertise addresses (one per line)",
            "1.2.3.4:3210",
            Field::AdvertiseAddresses,
            &gui.advertise_addresses,
            false
        ),
        chk("NAT port forwarding", Flag::PortForwarding, gui.port_forwarding),
        chk("Stateful filter (drop unsolicited replies)", Flag::StatefulFilter, gui.stateful_filter),
        chk("Opportunistic LZ4 compression", Flag::Compression, gui.compression),
        chk("Flood broadcasts via best peer", Flag::FloodRelay, gui.flood_relay),
        txt("Flood relay via (node id)", "", Field::FloodRelayVia, &gui.flood_relay_via, false),
        chk("L2/L3 bridge (TAP node accepts TUN clients)", Flag::L2L3Bridge, gui.l2_l3_bridge),
        section("Quality of service"),
        row![
            radio("Balanced", NetworkProfile::Balanced, Some(gui.profile), Message::Profile),
            radio("Latency", NetworkProfile::Latency, Some(gui.profile), Message::Profile),
            radio("Consistency", NetworkProfile::Consistency, Some(gui.profile), Message::Profile),
            radio("Throughput", NetworkProfile::Throughput, Some(gui.profile), Message::Profile),
        ]
        .spacing(10),
        txt("Jitter buffer (ms)", "profile default", Field::Jitter, &gui.jitter, false),
        txt("Max underlay MTU", "profile default", Field::MaxUnderlayMtu, &gui.max_underlay_mtu, false),
        section("Advanced"),
        txt("Init rate limit", "10", Field::InitRateLimit, &gui.init_rate_limit, false),
        txt("Crypto threads", "", Field::CryptoThreads, &gui.crypto_threads, false),
        txt("Status file", "", Field::StatusFile, &gui.status_file, false),
        txt("Metrics address", "127.0.0.1:9090", Field::MetricsAddr, &gui.metrics_addr, false),
        chk("Seccomp sandbox", Flag::Seccomp, gui.seccomp),
        chk("Install kernel routes for claims", Flag::InstallRoutes, gui.install_routes),
        txt(
            "Per-peer rate limit (bytes/sec, 0 = off)",
            "20000000",
            Field::PerPeerRateLimit,
            &gui.per_peer_rate_limit,
            false
        ),
        section("Config file"),
        txt("Path", "vpncloud.yaml", Field::ConfigPath, &gui.config_path, false),
        row![button("Load").on_press(Message::Load), button("Save").on_press(Message::Save)].spacing(8),
        Space::new().height(8),
        row![if connected {
            button("Disconnect").on_press(Message::Disconnect)
        } else {
            button("Connect").on_press(Message::Connect)
        }]
        .spacing(8),
        checkbox(connected && CtrlC::is_paused()).label("Pause forwarding").on_toggle(|_| Message::TogglePause),
        Space::new().height(8),
        text("Status").size(16),
        text(&gui.status).size(14),
        text("Peers").size(16),
        text(if gui.peers_text.is_empty() { "none" } else { &gui.peers_text }).size(13),
        text(format!("Sent: {}", Bytes(gui.sent_bytes))).size(14),
        text(sparkline(&gui.sent_history)).size(14),
        text(format!("Received: {}", Bytes(gui.recv_bytes))).size(14),
        text(sparkline(&gui.recv_history)).size(14),
        text(format!("Last handshake: {}", format_handshake(gui.last_handshake_unix))).size(14),
    ]
    .spacing(6)
    .padding(16)
    .align_x(Alignment::Start);

    container(scrollable(fields)).width(Length::Fill).height(Length::Fill).into()
}

// ---- Config mapping -----------------------------------------------------

/// Split a comma-or-newline separated field. Peers keep commas because a peer
/// may use them for alternative addresses (`host1,host2:3210`).
fn list(value: &str) -> Vec<String> {
    value.split([',', '\n']).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect()
}

fn peers(value: &str) -> Vec<String> {
    value.lines().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect()
}

fn num<T: std::str::FromStr>(value: &str) -> Option<T> {
    value.trim().parse().ok()
}

/// Apply every GUI setting onto a `ConfigFile`, preserving fields the window
/// does not expose (hooks, fix-rp-filter, signature, stats file, ...).
fn apply_gui_to_file(file: &mut ConfigFile, gui: &Gui) {
    file.crypto.password = if gui.password.trim().is_empty() { None } else { Some(gui.password.clone()) };
    file.crypto.private_key = if gui.private_key.trim().is_empty() { None } else { Some(gui.private_key.clone()) };
    file.crypto.trusted_keys = list(&gui.trusted_keys);
    file.crypto.algorithms = list(&gui.algorithms);

    file.ip = if gui.overlay.trim().is_empty() { None } else { Some(gui.overlay.trim().to_string()) };
    file.listen = if gui.listen.trim().is_empty() { None } else { Some(gui.listen.trim().to_string()) };
    file.advertise_addresses =
        if gui.advertise_addresses.trim().is_empty() { None } else { Some(list(&gui.advertise_addresses)) };
    let gui_peers: Vec<PeerAddr> = peers(&gui.peer).into_iter().map(PeerAddr::from_config_string).collect();
    if !gui_peers.is_empty() {
        file.peers = Some(gui_peers);
    }
    file.peer_timeout = num(&gui.peer_timeout);
    file.keepalive = num(&gui.keepalive);

    let mut device = file.device.take().unwrap_or_default();
    device.type_ = Some(if gui.tap { Type::Tap } else { Type::Tun });
    device.name = if gui.device_name.trim().is_empty() { None } else { Some(gui.device_name.trim().to_string()) };
    device.path = if gui.device_path.trim().is_empty() { None } else { Some(gui.device_path.trim().to_string()) };
    device.mtu = num(&gui.mtu);
    file.device = Some(device);

    file.mode = Some(gui.mode);
    file.claims = Some(list(&gui.claims));
    file.auto_claim = Some(gui.auto_claim);
    file.switch_timeout = num(&gui.switch_timeout);
    file.port_forwarding = Some(gui.port_forwarding);
    file.acl = Some(list(&gui.acl));
    file.grants = Some(list(&gui.grants));
    file.split = Some(list(&gui.split));
    file.full_tunnel = Some(gui.full_tunnel);
    file.exit_node = if gui.exit_node.trim().is_empty() { None } else { Some(gui.exit_node.trim().to_string()) };
    file.exit_allow = Some(list(&gui.exit_allow));
    file.peer_names = Some(list(&gui.peer_names));
    file.announce_group =
        if gui.announce_group.trim().is_empty() { None } else { Some(gui.announce_group.trim().to_string()) };
    file.local_addresses = Some(list(&gui.local_addresses));

    if !gui.beacon_password.trim().is_empty() {
        let mut beacon = file.beacon.take().unwrap_or_default();
        beacon.password = Some(gui.beacon_password.clone());
        file.beacon = Some(beacon);
    }
    file.stun = Some(gui.stun);
    file.stun_servers = if gui.stun_servers.trim().is_empty() { None } else { Some(list(&gui.stun_servers)) };
    file.lan_only = Some(gui.lan_only);
    file.tcp_fallback = Some(gui.tcp_fallback);
    file.mobility = Some(gui.mobility);
    file.flood_relay = Some(gui.flood_relay);
    file.flood_relay_via =
        if gui.flood_relay_via.trim().is_empty() { None } else { Some(gui.flood_relay_via.trim().to_string()) };
    file.l2_l3_bridge = Some(gui.l2_l3_bridge);

    file.profile = Some(gui.profile);
    file.jitter_ms = num(&gui.jitter);
    file.max_underlay_mtu = num(&gui.max_underlay_mtu);
    file.init_rate_limit = num(&gui.init_rate_limit);
    file.crypto_threads = num(&gui.crypto_threads);
    file.status_file = if gui.status_file.trim().is_empty() { None } else { Some(gui.status_file.trim().to_string()) };
    file.metrics_addr =
        if gui.metrics_addr.trim().is_empty() { None } else { Some(gui.metrics_addr.trim().to_string()) };
    file.seccomp = Some(gui.seccomp);
    file.install_routes = Some(gui.install_routes);
    file.per_peer_rate_limit = num(&gui.per_peer_rate_limit);
    file.stateful_filter = Some(gui.stateful_filter);
    file.compression = Some(gui.compression);
    file.require_signed_config = Some(gui.require_signed_config);

    file.node_id = if gui.node_id.trim().is_empty() { None } else { Some(gui.node_id.trim().to_string()) };
    file.node_key = if gui.node_key.trim().is_empty() { None } else { Some(gui.node_key.clone()) };
    file.trusted_node_keys = Some(list(&gui.trusted_node_keys));
    file.per_node_keys = Some(gui.per_node_keys);
}

#[cfg(test)]
fn gui_to_config_file(gui: &Gui) -> ConfigFile {
    let mut file = ConfigFile::default();
    apply_gui_to_file(&mut file, gui);
    file
}

#[cfg(test)]
fn to_yaml(gui: &Gui) -> String {
    serde_norway::to_string(&gui_to_config_file(gui)).unwrap_or_default()
}

/// Save the GUI settings, preserving non-GUI fields already in the file.
fn save(gui: &Gui) -> io::Result<PathBuf> {
    let path = PathBuf::from(&gui.config_path);
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            fs::create_dir_all(dir)?;
        }
    }
    let mut file = if path.is_file() {
        match load_config_file(&path) {
            Ok((_, existing)) => existing,
            Err(_) => ConfigFile::default()
        }
    } else {
        ConfigFile::default()
    };
    apply_gui_to_file(&mut file, gui);
    match config_format_from_path(&path) {
        ConfigFormat::Toml => write_config_file(&path, &file)?,
        ConfigFormat::Yaml => {
            use std::io::Write;
            let mut fh = create_private_file(&path)?;
            fh.write_all(serde_norway::to_string(&file).unwrap_or_default().as_bytes())?
        }
    }
    Ok(path)
}

fn load_into(gui: &mut Gui) -> Result<(), String> {
    let path = resolve_config_path(Path::new(&gui.config_path));
    let (path, file) = load_config_file(&path).map_err(|e| e.to_string())?;
    gui.config_path = path.display().to_string();
    let mut config = Config::default();
    config.merge_file(file);
    gui.password = config.crypto.password.unwrap_or_default();
    gui.private_key = config.crypto.private_key.unwrap_or_default();
    gui.trusted_keys = config.crypto.trusted_keys.join("\n");
    gui.algorithms = config.crypto.algorithms.join("\n");
    gui.overlay = config.ip.unwrap_or_else(|| "10.0.0.1/24".into());
    gui.listen = config.listen;
    gui.advertise_addresses = config.advertise_addresses.join("\n");
    gui.peer = config.peers.join("\n");
    gui.mtu = config.mtu.map(|m| m.to_string()).unwrap_or_default();
    gui.peer_timeout = config.peer_timeout.to_string();
    gui.keepalive = config.keepalive.map(|v| v.to_string()).unwrap_or_default();
    gui.tap = config.device_type == Type::Tap;
    gui.device_name = config.device_name;
    gui.device_path = config.device_path.unwrap_or_default();
    gui.mode = config.mode;
    gui.claims = config.claims.join("\n");
    gui.auto_claim = config.auto_claim;
    gui.switch_timeout = config.switch_timeout.to_string();
    gui.port_forwarding = config.port_forwarding;
    gui.acl = config.acl.join("\n");
    gui.grants = config.grants.join("\n");
    gui.split = config.split.join("\n");
    gui.full_tunnel = config.full_tunnel;
    gui.exit_node = config.exit_node.unwrap_or_default();
    gui.exit_allow = config.exit_allow.join("\n");
    gui.peer_names = config.peer_names.join("\n");
    gui.announce_group = config.announce_group.unwrap_or_default();
    gui.local_addresses = config.local_addresses.join("\n");
    gui.beacon_password = config.beacon_password.unwrap_or_default();
    gui.stun = config.stun;
    gui.stun_servers = config.stun_servers.join("\n");
    gui.lan_only = config.lan_only;
    gui.tcp_fallback = config.tcp_fallback;
    gui.mobility = config.mobility;
    gui.flood_relay = config.flood_relay;
    gui.flood_relay_via = config.flood_relay_via.unwrap_or_default();
    gui.profile = config.profile;
    gui.jitter = config.jitter_ms.map(|v| v.to_string()).unwrap_or_default();
    gui.max_underlay_mtu = config.max_underlay_mtu.map(|v| v.to_string()).unwrap_or_default();
    gui.init_rate_limit = config.init_rate_limit.to_string();
    gui.crypto_threads = config.crypto_threads.to_string();
    gui.status_file = config.status_file.unwrap_or_default();
    gui.metrics_addr = config.metrics_addr.unwrap_or_default();
    gui.seccomp = config.seccomp;
    gui.install_routes = config.install_routes;
    gui.per_peer_rate_limit = config.per_peer_rate_limit.to_string();
    gui.stateful_filter = config.stateful_filter;
    gui.compression = config.compression;
    gui.require_signed_config = config.require_signed_config;
    gui.node_id = config.node_id.unwrap_or_default();
    gui.node_key = config.node_key.unwrap_or_default();
    gui.trusted_node_keys = config.trusted_node_keys.join("\n");
    gui.per_node_keys = config.per_node_keys;
    gui.l2_l3_bridge = config.l2_l3_bridge;
    Ok(())
}

fn connect(gui: &mut Gui) {
    if gui.worker.is_some() {
        return;
    }
    if gui.password.trim().is_empty() && gui.private_key.trim().is_empty() {
        gui.status = "Password or private key is required".into();
        return;
    }
    // Windows has no in-box TUN/TAP. Offer the verified download in a native
    // dialog when the driver for the selected device is missing.
    #[cfg(windows)]
    {
        let wanted = if gui.tap { Type::Tap } else { Type::Tun };
        match crate::win_driver::ensure(wanted, crate::win_driver::Ui::MessageBox) {
            Ok(true) => {}
            Ok(false) => {
                gui.status = format!("{} driver not installed — cannot connect", wanted);
                return;
            }
            Err(e) => {
                gui.status = format!("Driver setup failed: {}", e);
                return;
            }
        }
    }
    if let Err(e) = save(gui) {
        gui.status = format!("Save failed: {}", e);
        return;
    }
    let config = match engine_config(gui) {
        Ok(c) => c,
        Err(e) => {
            gui.status = e;
            return;
        }
    };
    CtrlC::clear_stop();
    runtime_status::reset();
    gui.sent_bytes = 0;
    gui.recv_bytes = 0;
    gui.last_handshake_unix = 0;
    crate::util::set_fail_panics(true);
    gui.status = "Connecting…".into();
    gui.worker = Some(
        thread::Builder::new()
            .name("vpncloud".into())
            .spawn(move || {
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run_vpn(config);
                }));
            })
            .expect("spawn vpn worker")
    );
}

fn disconnect(gui: &mut Gui) {
    CtrlC::request_stop();
    gui.status = "Disconnecting…".into();
}

fn engine_config(gui: &Gui) -> Result<Config, String> {
    let path = resolve_config_path(Path::new(&gui.config_path));
    let mut config = Config::default();
    if path.is_file() {
        // Read once and verify the same bytes we merge, so the GUI cannot be
        // tricked into running a different config than the one it checked.
        let (_, raw, file) = load_config_file_with_raw(&path).map_err(|e| e.to_string())?;
        config.merge_file(file);
        let keys = VerifyKeys::from_env();
        // Keep reload verification consistent with the initial load.
        crate::config_verify::set_reload_verify_keys(keys.clone());
        verify_loaded_config(&config, Some(&raw), &keys).map_err(|e| format!("Config signature: {}", e))?;
        // Make SIGHUP/tray reload work for a node started from the GUI.
        CtrlC::set_reload_path(path);
    }
    // Apply GUI fields by assigning directly (Config::merge_file appends lists,
    // which would duplicate entries from the file we just loaded).
    config.crypto.password = if gui.password.trim().is_empty() { None } else { Some(gui.password.clone()) };
    config.crypto.private_key = if gui.private_key.trim().is_empty() { None } else { Some(gui.private_key.clone()) };
    config.crypto.trusted_keys = list(&gui.trusted_keys);
    config.crypto.algorithms = list(&gui.algorithms);
    config.ip = if gui.overlay.trim().is_empty() { None } else { Some(gui.overlay.trim().to_string()) };
    config.listen = if gui.listen.trim().is_empty() { "3210".into() } else { gui.listen.trim().to_string() };
    config.advertise_addresses = list(&gui.advertise_addresses);
    config.peers = peers(&gui.peer);
    config.mtu = num(&gui.mtu);
    config.peer_timeout = num(&gui.peer_timeout).unwrap_or(300);
    config.keepalive = num(&gui.keepalive);
    config.device_type = if gui.tap { Type::Tap } else { Type::Tun };
    if !gui.device_name.trim().is_empty() {
        config.device_name = gui.device_name.trim().to_string();
    }
    if !gui.device_path.trim().is_empty() {
        config.device_path = Some(gui.device_path.trim().to_string());
    }
    config.mode = gui.mode;
    config.claims = list(&gui.claims);
    config.auto_claim = gui.auto_claim;
    config.switch_timeout = num(&gui.switch_timeout).unwrap_or(300);
    config.port_forwarding = gui.port_forwarding;
    config.acl = list(&gui.acl);
    config.grants = list(&gui.grants);
    config.split = list(&gui.split);
    config.full_tunnel = gui.full_tunnel;
    config.exit_node = if gui.exit_node.trim().is_empty() { None } else { Some(gui.exit_node.trim().to_string()) };
    config.exit_allow = list(&gui.exit_allow);
    config.peer_names = list(&gui.peer_names);
    config.announce_group =
        if gui.announce_group.trim().is_empty() { None } else { Some(gui.announce_group.trim().to_string()) };
    config.local_addresses = list(&gui.local_addresses);
    config.beacon_password =
        if gui.beacon_password.trim().is_empty() { None } else { Some(gui.beacon_password.clone()) };
    config.stun = gui.stun;
    if !gui.stun_servers.trim().is_empty() {
        config.stun_servers = list(&gui.stun_servers);
    }
    config.lan_only = gui.lan_only;
    config.tcp_fallback = gui.tcp_fallback;
    config.mobility = gui.mobility;
    config.flood_relay = gui.flood_relay;
    config.flood_relay_via =
        if gui.flood_relay_via.trim().is_empty() { None } else { Some(gui.flood_relay_via.trim().to_string()) };
    config.profile = gui.profile;
    config.jitter_ms = num(&gui.jitter);
    config.max_underlay_mtu = num(&gui.max_underlay_mtu);
    if !gui.init_rate_limit.trim().is_empty() {
        config.init_rate_limit = num(&gui.init_rate_limit).unwrap_or(20);
    }
    if !gui.crypto_threads.trim().is_empty() {
        config.crypto_threads = num(&gui.crypto_threads).unwrap_or(0);
    }
    config.status_file =
        if gui.status_file.trim().is_empty() { None } else { Some(gui.status_file.trim().to_string()) };
    config.metrics_addr =
        if gui.metrics_addr.trim().is_empty() { None } else { Some(gui.metrics_addr.trim().to_string()) };
    config.seccomp = gui.seccomp;
    config.install_routes = gui.install_routes;
    config.per_peer_rate_limit = num(&gui.per_peer_rate_limit).unwrap_or(20_000_000);
    config.stateful_filter = gui.stateful_filter;
    config.compression = gui.compression;
    config.require_signed_config = gui.require_signed_config;
    config.node_id = if gui.node_id.trim().is_empty() { None } else { Some(gui.node_id.trim().to_string()) };
    config.node_key = if gui.node_key.trim().is_empty() { None } else { Some(gui.node_key.clone()) };
    config.trusted_node_keys = list(&gui.trusted_node_keys);
    config.per_node_keys = gui.per_node_keys;
    config.l2_l3_bridge = gui.l2_l3_bridge;
    config.daemonize = false;
    config.tray = false;
    match config.validate() {
        Ok(warnings) => {
            for warning in warnings {
                log::warn!("Config: {}", warning);
            }
        }
        Err(e) => return Err(format!("Invalid config: {}", e))
    }
    Ok(config)
}

fn default_config_path() -> PathBuf {
    if let Some(p) = env::args().nth(1).filter(|s| !s.starts_with('-')) {
        return PathBuf::from(p);
    }
    if let Ok(p) = env::var("VPNCLOUD_CONFIG") {
        return PathBuf::from(p);
    }
    #[cfg(windows)]
    {
        if let Ok(ad) = env::var("LOCALAPPDATA") {
            return resolve_config_path(&PathBuf::from(ad).join("VpnCloud").join("vpncloud.yaml"));
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = env::var_os("HOME") {
            return resolve_config_path(&PathBuf::from(home).join("Library/Application Support/VpnCloud/vpncloud.yaml"));
        }
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        if let Ok(xdg) = env::var("XDG_CONFIG_HOME") {
            return resolve_config_path(&PathBuf::from(xdg).join("vpncloud/vpncloud.yaml"));
        }
        if let Some(home) = env::var_os("HOME") {
            return resolve_config_path(&PathBuf::from(home).join(".config/vpncloud/vpncloud.yaml"));
        }
    }
    resolve_config_path(&PathBuf::from("vpncloud.yaml"))
}

fn panic_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else {
        "worker panicked".into()
    }
}

struct GuiLogger;

impl log::Log for GuiLogger {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            eprintln!("{} - {}", record.level(), record.args());
        }
    }

    fn flush(&self) {}
}

pub fn init_log() {
    let _ = log::set_boxed_logger(Box::new(GuiLogger));
    log::set_max_level(log::LevelFilter::Info);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_gui() -> Gui {
        Gui {
            password: "secret".into(),
            overlay: "10.0.0.2/24".into(),
            peer: "192.0.2.1:3210".into(),
            listen: "3210".into(),
            mtu: "1400".into(),
            peer_timeout: "300".into(),
            acl: "allow:10.0.0.0/8".into(),
            private_key: "base62key".into(),
            trusted_keys: "key1\nkey2".into(),
            algorithms: "aes128gcm".into(),
            node_id: "aabbccddeeff00112233445566778899".into(),
            node_key: "nodekey".into(),
            trusted_node_keys: "aabbccddeeff00112233445566778899=pubkey".into(),
            device_name: "vpncloud0".into(),
            device_path: "/dev/net/tun".into(),
            claims: "10.0.0.0/24".into(),
            switch_timeout: "300".into(),
            keepalive: "30".into(),
            exit_node: "aabbccddeeff00112233445566778899".into(),
            exit_allow: "aabbccddeeff00112233445566778899".into(),
            grants: "group=10.0.0.0/8".into(),
            split: "10.0.0.0/8".into(),
            peer_names: "name=key".into(),
            announce_group: "group".into(),
            local_addresses: "10.9.0.10\n10.9.0.11".into(),
            beacon_password: "beacon".into(),
            stun_servers: "stun.example:3478".into(),
            advertise_addresses: "1.2.3.4:3210".into(),
            jitter: "20".into(),
            max_underlay_mtu: "1400".into(),
            flood_relay_via: "aabbccddeeff00112233445566778899".into(),
            init_rate_limit: "10".into(),
            crypto_threads: "2".into(),
            status_file: "/tmp/status.json".into(),
            metrics_addr: "127.0.0.1:9090".into(),
            per_peer_rate_limit: "20000000".into(),
            tap: false,
            port_forwarding: true,
            compression: false,
            stateful_filter: false,
            flood_relay: true,
            per_node_keys: true,
            l2_l3_bridge: true,
            install_routes: true,
            require_signed_config: false,
            auto_claim: true,
            full_tunnel: true,
            stun: true,
            lan_only: false,
            tcp_fallback: true,
            mobility: true,
            seccomp: false,
            mode: Mode::Switch,
            profile: NetworkProfile::Balanced,
            config_path: String::new(),
            status: String::new(),
            peers_text: String::new(),
            sent_history: Vec::new(),
            recv_history: Vec::new(),
            sent_bytes: 0,
            recv_bytes: 0,
            last_handshake_unix: 0,
            worker: None
        }
    }

    #[test]
    fn yaml_roundtrip_password_and_peer() {
        let gui = sample_gui();
        let yaml = to_yaml(&gui);
        assert!(yaml.contains("password"), "{}", yaml);
        assert!(yaml.contains("10.0.0.2/24"), "{}", yaml);
        assert!(yaml.contains("192.0.2.1:3210"), "{}", yaml);
        assert!(yaml.contains("tun"), "{}", yaml);
        assert!(yaml.contains("1400"), "{}", yaml);
        assert!(yaml.contains("allow:10.0.0.0/8"), "{}", yaml);
        let file: ConfigFile = serde_norway::from_str(&yaml).unwrap();
        assert_eq!(file.crypto.password.as_deref(), Some("secret"));
        assert_eq!(file.device.as_ref().and_then(|d| d.mtu), Some(1400));
    }

    #[test]
    fn yaml_roundtrip_all_exposed_fields() {
        let gui = sample_gui();
        let yaml = to_yaml(&gui);
        let file: ConfigFile = serde_norway::from_str(&yaml).unwrap();
        assert_eq!(file.crypto.private_key.as_deref(), Some("base62key"));
        assert_eq!(file.crypto.trusted_keys, vec!["key1", "key2"]);
        assert_eq!(file.crypto.algorithms, vec!["aes128gcm"]);
        assert_eq!(file.node_id.as_deref(), Some("aabbccddeeff00112233445566778899"));
        assert_eq!(file.per_node_keys, Some(true));
        assert_eq!(file.l2_l3_bridge, Some(true));
        assert_eq!(file.install_routes, Some(true));
        assert_eq!(file.per_peer_rate_limit, Some(20_000_000));
        assert_eq!(file.mode, Some(Mode::Switch));
        assert_eq!(file.claims, Some(vec!["10.0.0.0/24".to_string()]));
        assert_eq!(file.full_tunnel, Some(true));
        assert_eq!(file.exit_node.as_deref(), Some("aabbccddeeff00112233445566778899"));
        assert_eq!(file.grants, Some(vec!["group=10.0.0.0/8".to_string()]));
        assert_eq!(file.split, Some(vec!["10.0.0.0/8".to_string()]));
        assert_eq!(file.flood_relay, Some(true));
        assert_eq!(file.local_addresses, Some(vec!["10.9.0.10".to_string(), "10.9.0.11".to_string()]));
        assert_eq!(file.stun, Some(true));
        assert_eq!(file.mobility, Some(true));
        assert_eq!(file.profile, Some(NetworkProfile::Balanced));
        assert_eq!(file.jitter_ms, Some(20));
        assert_eq!(file.crypto_threads, Some(2));
        assert_eq!(file.metrics_addr.as_deref(), Some("127.0.0.1:9090"));
    }

    #[test]
    fn save_preserves_fields_not_exposed_by_the_gui() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("net.yaml");
        std::fs::write(&path, "crypto:\n  password: old\nhook: /usr/local/bin/on-up\nhooks:\n  up: /bin/true\n")
            .unwrap();
        let mut gui = sample_gui();
        gui.config_path = path.display().to_string();
        let saved = save(&gui).unwrap();
        assert_eq!(saved, path);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("hook"), "unexposed fields must be preserved:\n{}", text);
        let file: ConfigFile = serde_norway::from_str(&text).unwrap();
        assert_eq!(file.hook.as_deref(), Some("/usr/local/bin/on-up"));
        assert_eq!(file.crypto.password.as_deref(), Some("secret"));
    }

    #[test]
    fn list_parses_commas_and_newlines() {
        assert_eq!(list("a, b\nc"), vec!["a", "b", "c"]);
        assert_eq!(peers("a,b:3210\nhost2"), vec!["a,b:3210", "host2"]);
    }

    #[test]
    fn blank_fields_keep_config_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let mut gui = Gui::default();
        gui.config_path = dir.path().join("net.yaml").display().to_string();
        gui.password = "secret".into();
        let config = engine_config(&gui).unwrap();
        let defaults = Config::default();
        assert_eq!(config.device_name, defaults.device_name);
        assert_eq!(config.stun_servers, defaults.stun_servers);
        assert_eq!(config.init_rate_limit, defaults.init_rate_limit);
        assert_eq!(config.crypto_threads, defaults.crypto_threads);
        assert_eq!(config.seccomp, defaults.seccomp);
        assert_eq!(config.stun, defaults.stun);
        assert_eq!(config.auto_claim, defaults.auto_claim);
    }
}
