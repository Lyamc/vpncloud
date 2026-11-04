// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::{
    cmp::{max, min},
    collections::{HashMap, VecDeque},
    fmt,
    fs::{self, File},
    hash::BuildHasherDefault,
    io::{self, Cursor, Seek, SeekFrom, Write},
    marker::PhantomData,
    mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    path::Path,
    str::FromStr,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex
    }
};

use fnv::FnvHasher;
use rand::{
    random, rng,
    seq::{IndexedRandom, SliceRandom}
};
use smallvec::{smallvec, SmallVec};

use crate::{
    beacon::BeaconSerializer,
    config::{Config, DEFAULT_PEER_TIMEOUT, DEFAULT_PORT},
    crypto::{is_init_message, Crypto, MessageResult, PeerCrypto},
    crypto_pool::{CryptoBoxHandle, CryptoDone, CryptoJob, CryptoPool},
    device::{Device, OffloadRead, Type},
    error::Error,
    gso::{GsoMeta, GSO_META_LEN},
    lan,
    messages::{
        AddrList, NodeInfo, PeerInfo, TransitClaim, MESSAGE_TYPE_CLOSE, MESSAGE_TYPE_DATA, MESSAGE_TYPE_DATA_GSO,
        MESSAGE_TYPE_KEEPALIVE, MESSAGE_TYPE_NODE_INFO, MESSAGE_TYPE_RELAY
    },
    natpmp,
    net::{mapped_addr, parse_listen, Socket},
    payload::Protocol,
    policy,
    poll::{Pollable, WaitImpl, WaitResult},
    port_forwarding::PortForwarding,
    rate_limit::InitRateLimit,
    stun,
    table::ClaimTable,
    traffic::TrafficStats,
    types::{Address, Mode, NodeId, Range, RangeList},
    util::{addr_nice, bytes_to_hex, resolve, CtrlC, Duration, MsgBuffer, StatsdMsg, Time, TimeSource}
};

fn is_loopback_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.to_ipv4_mapped().map(|v4| v4.is_loopback()).unwrap_or(false)
    }
}

pub type Hash = BuildHasherDefault<FnvHasher>;

const MAX_RECONNECT_INTERVAL: u16 = 3600;
const RESOLVE_INTERVAL: Time = 300;
pub const STATS_INTERVAL: Time = 60;
const OWN_ADDRESS_RESET_INTERVAL: Time = 30;
const SPACE_BEFORE: usize = 100;
const BATCH_SIZE: usize = 128;
/// Segments to gather before one TUN write. One read at line rate is about
/// eight segments, and flushing there makes the peer ACK every train. Sixteen
/// is past that read, so the hold below collects another before the write.
/// Stretching the hold itself added delay and cut goodput, so it stays.
const GRO_TRAIN: usize = 16;
/// Longest a short batch may sit before it is written. The other direction is
/// still read while this window is open.
const GRO_HOLD_NS: u64 = 150_000;
/// UDP datagrams kept for a paced inject. One recvmmsg is [`BATCH_SIZE`].
/// Above this the pacer writes without waiting so 64 KiB buffers cannot pile up.
const UDP_INJECT_QUEUE_CAP: usize = 160;

/// A TUN batch is ready when it is full, the clock has run out, or no hold was armed.
pub(crate) fn gro_batch_ready(queued: usize, now_ns: u64, deadline_ns: u64) -> bool {
    queued >= GRO_TRAIN || deadline_ns == 0 || now_ns >= deadline_ns
}

fn note_tun_flush(n: usize) {
    static FLUSHES: AtomicU64 = AtomicU64::new(0);
    static PACKETS: AtomicU64 = AtomicU64::new(0);
    static MAX_BATCH: AtomicUsize = AtomicUsize::new(0);
    let flush = FLUSHES.fetch_add(1, Ordering::Relaxed) + 1;
    let packets = PACKETS.fetch_add(n as u64, Ordering::Relaxed) + n as u64;
    let mut max_batch = MAX_BATCH.load(Ordering::Relaxed);
    while n > max_batch {
        match MAX_BATCH.compare_exchange_weak(max_batch, n, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => {
                max_batch = n;
                break;
            }
            Err(cur) => max_batch = cur
        }
    }
    if flush % 4000 == 0 {
        info!("TUN write batches={flush} packets={packets} max={max_batch}");
    }
}

enum PeerCryptoSlot {
    Direct(PeerCrypto<NodeInfo>),
    Shared(CryptoBoxHandle)
}

impl PeerCryptoSlot {
    fn wrap(crypto: PeerCrypto<NodeInfo>, shared: bool) -> Self {
        if shared {
            Self::Shared(Arc::new(Mutex::new(crypto)))
        } else {
            Self::Direct(crypto)
        }
    }

    fn shared_handle(&self) -> Option<CryptoBoxHandle> {
        match self {
            Self::Shared(h) => Some(h.clone()),
            Self::Direct(_) => None
        }
    }

    fn with_mut<R, F: FnOnce(&mut PeerCrypto<NodeInfo>) -> R>(&mut self, f: F) -> Result<R, Error> {
        match self {
            Self::Direct(c) => Ok(f(c)),
            Self::Shared(h) => {
                let mut g = h.lock().map_err(|_| Error::InvalidCryptoState("crypto lock"))?;
                Ok(f(&mut *g))
            }
        }
    }

    fn algorithm_name(&self) -> &'static str {
        match self {
            Self::Direct(c) => c.algorithm_name(),
            Self::Shared(h) => h.lock().map(|g| g.algorithm_name()).unwrap_or("?")
        }
    }
}

struct PeerData {
    addrs: AddrList,
    #[allow(dead_code)] // TODO: export in status
    last_seen: Time,
    timeout: Time,
    peer_timeout: u16,
    node_id: NodeId,
    crypto: PeerCryptoSlot,
    /// Smoothed underlay RTT in microseconds. `u64::MAX` until a sample arrives.
    rtt_us: u64,
    /// When grants are enforced, false rejects this peer's group.
    group_ok: bool,
    /// Prefixes this peer was allowed to claim.
    auth_claims: RangeList
}

#[derive(Clone)]
pub struct ReconnectEntry {
    address: Option<(Vec<String>, Time)>,
    resolved: AddrList,
    tries: u16,
    timeout: u16,
    next: Time,
    final_timeout: Option<Time>,
    /// When true, `resolved` is a priority list: try one address per interval, highest first.
    prefer_order: bool,
    try_index: usize
}

/// Append [`DEFAULT_PORT`] when the peer string has none.
///
/// A colon inside `[ipv6]` is not a port separator. `[fd00::2]:3210` stays as
/// written; `[fd00::2]` and a bare address gain `:3210`.
pub(crate) fn ensure_peer_port(addr: &str) -> String {
    let addr = addr.trim();
    let addr = addr.strip_prefix("ws://").or_else(|| addr.strip_prefix("wss://")).unwrap_or(addr);
    if let Some(inner) = addr.strip_prefix('[') {
        if let Some(bracket) = inner.find(']') {
            let after = &inner[bracket + 1..];
            if after.is_empty() {
                return format!("[{}]:{}", &inner[..bracket], DEFAULT_PORT);
            }
            return addr.to_string();
        }
    }
    if let Ok(ip) = addr.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(v4) => format!("{}:{}", v4, DEFAULT_PORT),
            IpAddr::V6(v6) => format!("[{}]:{}", v6, DEFAULT_PORT)
        };
    }
    if let Some((host, port)) = addr.rsplit_once(':') {
        if !host.is_empty() && !port.is_empty() && !host.contains(':') && port.chars().all(|c| c.is_ascii_digit()) {
            return addr.to_string();
        }
    }
    format!("{}:{}", addr, DEFAULT_PORT)
}

fn split_peer_group(add: &str) -> Vec<String> {
    add.split(',').map(str::trim).filter(|s| !s.is_empty()).map(ensure_peer_port).collect()
}

/// Host route for a configured IPv6 `--ip`. A /64 would match the peer as well.
/// IPv4 keeps the interface /32 from `Device::address`.
fn configured_ipv6_host_claim(spec: Option<&str>) -> Option<Range> {
    let spec = spec?;
    let ip_str = spec.split('/').next().unwrap_or(spec).trim();
    let v6 = ip_str.parse::<Ipv6Addr>().ok()?;
    Some(Range { base: Address::from(v6), prefix_len: 128, metric: 0 })
}

fn resolve_peer_group(names: &[String]) -> AddrList {
    let mut resolved = smallvec![];
    for name in names {
        match resolve(name as &str) {
            Ok(addrs) => resolved.extend(addrs),
            Err(err) => warn!("Failed to resolve {}: {:?}", name, err)
        }
    }
    let prefixes = lan::interface_prefixes();
    lan::sort_lan_first(&mut resolved, &prefixes);
    resolved
}

pub struct GenericCloud<D: Device, P: Protocol, S: Socket, TS: TimeSource> {
    node_id: NodeId,
    config: Config,
    learning: bool,
    broadcast: bool,
    peers: HashMap<SocketAddr, PeerData, Hash>,
    reconnect_peers: SmallVec<[ReconnectEntry; 3]>,
    own_addresses: AddrList,
    pending_inits: HashMap<SocketAddr, PeerCrypto<NodeInfo>, Hash>,
    table: ClaimTable<TS>,
    socket: S,
    device: D,
    claims: RangeList,
    crypto: Crypto,
    crypto_pool: CryptoPool,
    outbox: Vec<(SocketAddr, MsgBuffer)>,
    buf_spare: Vec<MsgBuffer>,
    pending_encrypt: HashMap<SocketAddr, Vec<(u8, MsgBuffer)>, Hash>,
    rx_bufs: Vec<MsgBuffer>,
    rx_addrs: Vec<SocketAddr>,
    tun_bufs: Vec<MsgBuffer>,
    tun_out: Vec<MsgBuffer>,
    /// Monotonic deadline for the current TUN batch. 0 when no batch is held.
    gro_deadline_ns: u64,
    /// Monotonic deadline for the next UDP inject. 0 when not pacing.
    udp_gap_deadline_ns: u64,
    /// Datagrams the pacer may read from the underlay before that deadline.
    udp_gap_budget: usize,
    /// Set by the event loop. Tests flush each batch immediately.
    defer_tun_flush: bool,
    gso_out: VecDeque<(GsoMeta, MsgBuffer)>,
    next_peers: Time,
    peer_timeout_publish: u16,
    update_freq: u16,
    stats_file: Option<File>,
    statsd_server: Option<String>,
    next_housekeep: Time,
    next_stats_out: Time,
    next_beacon: Time,
    next_own_address_reset: Time,
    port_forwarding: Option<PortForwarding>,
    traffic: TrafficStats,
    init_limit: InitRateLimit,
    stun_txid: [u8; 12],
    stun_reflexive: AddrList,
    beacon_serializer: BeaconSerializer<TS>,
    acl: crate::acl::Acl,
    /// Local underlay interface MTU. 0 until [`Self::set_local_underlay`].
    local_l2: usize,
    ipv6_underlay: bool,
    /// Smallest underlay MTU a peer has advertised.
    peer_l2: Option<usize>,
    /// Underlay MTU currently applied to the device. 0 before the first apply.
    applied_l2: usize,
    e2e_secret: [u8; 32],
    e2e_public: [u8; 32],
    known_e2e: HashMap<NodeId, [u8; 32], Hash>,
    grants: policy::Grants,
    flows: policy::FlowTable,
    names: Vec<(String, Address)>,
    split_prefixes: RangeList,
    exit_node: Option<NodeId>,
    exit_allow: Vec<NodeId>,
    last_node_info_ns: u64,
    _dummy_p: PhantomData<P>,
    _dummy_ts: PhantomData<TS>
}

impl<D: Device + Pollable, P: Protocol, S: Socket + Pollable, TS: TimeSource> GenericCloud<D, P, S, TS> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: &Config, socket: S, device: D, port_forwarding: Option<PortForwarding>, stats_file: Option<File>
    ) -> Self {
        let (learning, broadcast) = match config.mode {
            Mode::Normal => {
                match config.device_type {
                    Type::Tap => (true, true),
                    Type::Tun => (false, false)
                }
            }
            Mode::Router => (false, false),
            Mode::Switch => (true, true),
            Mode::Hub => (false, true)
        };
        let mut claims = SmallVec::with_capacity(config.claims.len());
        for s in &config.claims {
            claims.push(try_fail!(Range::from_str(s), "Invalid subnet format: {} ({})", s));
        }
        if device.get_type() == Type::Tun && config.auto_claim {
            let mut claimed = false;
            match device.address() {
                Ok(ip) => {
                    let range = Range { base: Address::from(ip), prefix_len: 32, metric: 0 };
                    info!("Auto-claiming {} due to interface address", range);
                    claims.push(range);
                    claimed = true;
                }
                Err(Error::DeviceIo(_, e)) if e.kind() == io::ErrorKind::AddrNotAvailable => {}
                Err(Error::Device(_)) => {}
                Err(e) => error!("{}", e)
            }
            if let Some(range) = configured_ipv6_host_claim(config.ip.as_deref()) {
                info!("Auto-claiming {} due to interface address", range);
                claims.push(range);
                claimed = true;
            }
            if !claimed {
                info!("No address set on interface.")
            }
        }
        let now = TS::now();
        let update_freq = config.get_keepalive() as u16;
        let node_id = random();
        let crypto = Crypto::new(node_id, &config.crypto).unwrap();
        let (e2e_secret, e2e_public) = policy::generate_e2e_keypair();
        let grants = try_fail!(policy::parse_grants(&config.grants), "Invalid grant: {}");
        let mut split_prefixes = RangeList::new();
        for s in &config.split {
            split_prefixes.push(try_fail!(Range::from_str(s), "Invalid split prefix: {} ({})", s));
        }
        let exit_node = config.exit_node.as_deref().and_then(policy::parse_node_id);
        let mut exit_allow: Vec<NodeId> = config.exit_allow.iter().filter_map(|s| policy::parse_node_id(s)).collect();
        if exit_allow.is_empty() {
            if let Some(id) = exit_node {
                exit_allow.push(id);
            }
        }
        let beacon_key = config.beacon_password.as_ref().map(|s| s.as_bytes()).unwrap_or(&[]);
        let mut res = GenericCloud {
            node_id,
            peers: HashMap::default(),
            claims,
            learning,
            broadcast,
            pending_inits: HashMap::default(),
            reconnect_peers: SmallVec::new(),
            own_addresses: SmallVec::new(),
            peer_timeout_publish: config.peer_timeout as u16,
            table: ClaimTable::new(config.switch_timeout as Duration, config.peer_timeout as Duration),
            socket,
            device,
            next_peers: now,
            update_freq,
            stats_file,
            statsd_server: config.statsd_server.clone(),
            next_housekeep: now,
            next_stats_out: now + STATS_INTERVAL,
            next_beacon: now,
            next_own_address_reset: now + OWN_ADDRESS_RESET_INTERVAL,
            port_forwarding,
            traffic: {
                let mut t = TrafficStats::default();
                t.set_track_payload(config.stats_file.is_some() || config.statsd_server.is_some());
                t
            },
            init_limit: InitRateLimit::new(config.init_rate_limit, 10),
            stun_txid: [0; 12],
            stun_reflexive: SmallVec::new(),
            beacon_serializer: BeaconSerializer::new(beacon_key),
            crypto,
            crypto_pool: CryptoPool::new(config.crypto_threads),
            outbox: Vec::with_capacity(BATCH_SIZE),
            buf_spare: (0..BATCH_SIZE).map(|_| MsgBuffer::new(SPACE_BEFORE)).collect(),
            pending_encrypt: HashMap::default(),
            rx_bufs: (0..BATCH_SIZE).map(|_| MsgBuffer::new(SPACE_BEFORE)).collect(),
            rx_addrs: vec![SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)); BATCH_SIZE],
            tun_bufs: (0..BATCH_SIZE).map(|_| MsgBuffer::new(SPACE_BEFORE)).collect(),
            tun_out: Vec::with_capacity(BATCH_SIZE),
            gro_deadline_ns: 0,
            udp_gap_deadline_ns: 0,
            udp_gap_budget: 0,
            defer_tun_flush: false,
            gso_out: VecDeque::new(),
            acl: try_fail!(crate::acl::Acl::parse(&config.acl), "Invalid ACL: {}"),
            config: config.clone(),
            local_l2: 0,
            ipv6_underlay: false,
            peer_l2: None,
            applied_l2: 0,
            e2e_secret,
            e2e_public,
            known_e2e: HashMap::default(),
            grants,
            flows: policy::FlowTable::default(),
            names: policy::parse_peer_names(&config.peer_names),
            split_prefixes,
            exit_node,
            exit_allow,
            last_node_info_ns: 0,
            _dummy_p: PhantomData,
            _dummy_ts: PhantomData
        };
        res.initialize();
        res
    }

    #[inline]
    pub fn ifname(&self) -> &str {
        self.device.ifname()
    }

    /// Sends the message to all peers
    ///
    /// # Errors
    /// Returns an `Error::SocketError` when the underlying system call fails or only part of the
    /// message could be sent (can this even happen?).
    /// Some messages could have been sent.
    #[inline]
    fn broadcast_msg(&mut self, type_: u8, msg: &mut MsgBuffer) -> Result<(), Error> {
        debug!("Broadcasting message type {}, {:?} bytes to {} peers", type_, msg.len(), self.peers.len());
        let addrs: Vec<SocketAddr> = self.peers.keys().copied().collect();
        for addr in addrs {
            let mut msg_data = msg.clone();
            self.send_msg(addr, type_, &mut msg_data)?;
        }
        Ok(())
    }

    fn take_spare(&mut self) -> MsgBuffer {
        self.buf_spare.pop().unwrap_or_else(|| MsgBuffer::new(SPACE_BEFORE))
    }

    pub fn restart_crypto_pool(&mut self) {
        self.crypto_pool.restart();
    }

    #[inline]
    fn send_to(&mut self, addr: SocketAddr, msg: &mut MsgBuffer) -> Result<(), Error> {
        // HOT PATH
        debug!("Sending msg with {} bytes to {}", msg.len(), addr);
        self.traffic.count_out_traffic(addr, msg.len());
        let mut owned = self.take_spare();
        mem::swap(msg, &mut owned);
        self.outbox.push((addr, owned));
        msg.clear();
        Ok(())
    }

    #[inline]
    fn send_msg(&mut self, addr: SocketAddr, type_: u8, msg: &mut MsgBuffer) -> Result<(), Error> {
        // HOT PATH
        debug!("Sending msg with {} bytes to {}", msg.len(), addr);
        if !self.peers.contains_key(&addr) {
            return Err(Error::Message("Sending to node that is not a peer"));
        }
        if type_ == MESSAGE_TYPE_DATA || type_ == MESSAGE_TYPE_DATA_GSO {
            if self.peers.get(&addr).and_then(|p| p.crypto.shared_handle()).is_some() {
                let mut owned = self.take_spare();
                mem::swap(msg, &mut owned);
                self.pending_encrypt.entry(addr).or_default().push((type_, owned));
                msg.clear();
                return Ok(());
            }
        }
        self.peers
            .get_mut(&addr)
            .ok_or(Error::Message("Sending to node that is not a peer"))?
            .crypto
            .with_mut(|c| c.send_message(type_, msg))??;
        self.send_to(addr, msg)
    }

    fn flush_pending_crypto(&mut self) -> Result<(), Error> {
        let pending = mem::take(&mut self.pending_encrypt);
        if pending.is_empty() {
            return Ok(());
        }
        // One peer cannot split a nonce sequence across workers. A thread hop per
        // batch costs more than AES-GCM on this core, so encrypt in place.
        if !self.use_crypto_pool() {
            for (addr, packets) in pending {
                let encrypted = if let Some(peer) = self.peers.get_mut(&addr) {
                    // One lock for the whole batch. The bench has a single peer, so
                    // the slot is a mutex even though encryption stays on this thread.
                    peer.crypto.with_mut(|c| {
                        let mut out = Vec::with_capacity(packets.len());
                        for (type_, mut data) in packets {
                            let result = c.send_message(type_, &mut data);
                            out.push((result, data));
                        }
                        out
                    })?
                } else {
                    for (_, data) in packets {
                        self.buf_spare.push(data);
                    }
                    continue;
                };
                for (result, mut data) in encrypted {
                    if result.is_err() {
                        self.buf_spare.push(data);
                        continue;
                    }
                    // send_to swaps `data` with an empty spare. Keep that spare.
                    self.send_to(addr, &mut data)?;
                    self.buf_spare.push(data);
                }
            }
            return Ok(());
        }
        let mut jobs = 0;
        for (addr, packets) in pending {
            let Some(crypto) = self.peers.get(&addr).and_then(|p| p.crypto.shared_handle()) else {
                continue;
            };
            self.crypto_pool.submit(CryptoJob::Encrypt { crypto, packets, addr });
            jobs += 1;
        }
        for _ in 0..jobs {
            match self.crypto_pool.recv() {
                Some(CryptoDone::Encrypted { addr, packets }) => {
                    for mut data in packets {
                        self.send_to(addr, &mut data)?;
                        self.buf_spare.push(data);
                    }
                }
                Some(CryptoDone::Failed(e)) => error!("{}", e),
                Some(_) => {}
                None => break
            }
        }
        Ok(())
    }

    fn use_crypto_pool(&self) -> bool {
        self.crypto_pool.enabled() && self.peers.len() > 1
    }

    fn flush_outbox(&mut self) -> Result<(), Error> {
        if self.outbox.is_empty() {
            return Ok(());
        }
        let mut pkts = mem::take(&mut self.outbox);
        // `send_batch` reports how many leading packets were queued. Keep the
        // rest: dropping them is how a full UDP socket turned a line-rate
        // offer into loss. The borrow of `pkts` ends before the split.
        let send_res = {
            let refs: Vec<(&SocketAddr, &[u8])> = pkts.iter().map(|(a, d)| (a, d.message())).collect();
            self.socket.send_batch(&refs)
        };
        match send_res {
            Ok(n) => {
                let sent = n.min(pkts.len());
                let rest = pkts.split_off(sent);
                for (_, buf) in pkts {
                    self.buf_spare.push(buf);
                }
                if !rest.is_empty() {
                    self.outbox = rest;
                }
                Ok(())
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.outbox = pkts;
                Ok(())
            }
            Err(e) => {
                for (_, buf) in pkts {
                    self.buf_spare.push(buf);
                }
                Err(Error::SocketIo("IOError when sending", e))
            }
        }
    }

    fn flush_tun_out(&mut self) -> Result<(), Error> {
        if self.tun_out.is_empty() {
            return Ok(());
        }
        // The airtime clock starts before the write. Time spent injecting
        // counts toward the gap; starting it afterward slept a full gap on
        // top of the write and the underlay socket overflowed.
        #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
        let started = crate::net::mono_now().unwrap_or(0);
        #[cfg(not(all(target_os = "linux", not(target_env = "ohos"))))]
        let started = 0u64;
        let mut pkts = mem::take(&mut self.tun_out);
        match self.device.write_batch(&mut pkts) {
            Ok(n) if n < pkts.len() => {
                note_tun_flush(n);
                // The written prefix is what just hit the TUN. A short count
                // below a chunk is the TUN queue blocking, not a finished inject.
                let udp = n > 0
                    && pkts.first().is_some_and(|b| crate::payload::udp_segment(b.message()).is_some());
                #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
                let blocked = udp && n < crate::device::UDP_INJECT_CHUNK;
                #[cfg(not(all(target_os = "linux", not(target_env = "ohos"))))]
                let blocked = false;
                let rest = pkts.split_off(n);
                for buf in pkts {
                    self.buf_spare.push(buf);
                }
                self.tun_out = rest;
                if udp && !blocked {
                    self.arm_udp_inject_gap(n, started);
                } else {
                    self.udp_gap_deadline_ns = 0;
                    self.udp_gap_budget = 0;
                }
                Ok(())
            }
            Ok(n) => {
                note_tun_flush(n);
                let udp = n > 0
                    && pkts.first().is_some_and(|b| crate::payload::udp_segment(b.message()).is_some());
                for buf in pkts {
                    self.buf_spare.push(buf);
                }
                if udp {
                    self.arm_udp_inject_gap(n, started);
                } else {
                    self.udp_gap_deadline_ns = 0;
                    self.udp_gap_budget = 0;
                }
                Ok(())
            }
            // Keep the packets. Dropping them forces TCP to retransmit and the window collapses.
            Err(Error::DeviceIo(_, ref e)) if e.kind() == io::ErrorKind::WouldBlock => {
                self.tun_out = pkts;
                self.udp_gap_deadline_ns = 0;
                self.udp_gap_budget = 0;
                Ok(())
            }
            Err(e) => {
                for buf in pkts {
                    self.buf_spare.push(buf);
                }
                Err(e)
            }
        }
    }

    fn udp_inject_backlog(&self) -> bool {
        match self.tun_out.first() {
            Some(buf) => crate::payload::udp_segment(buf.message()).is_some(),
            None => false
        }
    }

    fn arm_udp_inject_gap(&mut self, packets: usize, started_ns: u64) {
        self.udp_gap_budget = packets;
        self.udp_gap_deadline_ns = 0;
        #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
        if packets > 0 && started_ns > 0 {
            let ns = (packets as u64).saturating_mul(crate::device::UDP_INJECT_PACKET_NS);
            self.udp_gap_deadline_ns = started_ns.saturating_add(ns.min(crate::device::UDP_INJECT_GAP_NS));
        }
    }

    /// Hold the airtime of the UDP inject that just completed. An empty queue
    /// still waits: that is the common case, a batch shorter than one chunk.
    /// During the wait, read at most as many datagrams as were just written.
    ///
    /// Returns true when the caller must not run the normal socket drain.
    fn pace_udp_inject(&mut self) -> bool {
        #[cfg(not(all(target_os = "linux", not(target_env = "ohos"))))]
        {
            return false;
        }
        #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
        {
            if self.udp_gap_deadline_ns == 0 {
                return false;
            }
            if !self.tun_out.is_empty() && !self.udp_inject_backlog() {
                self.udp_gap_deadline_ns = 0;
                self.udp_gap_budget = 0;
                return false;
            }
            let now = crate::net::mono_now().unwrap_or(0);
            // 512 MsgBuffers is 32MB. Do not sleep on a runaway queue.
            let runaway = self.tun_out.len() >= 512;
            if !runaway && now < self.udp_gap_deadline_ns {
                if self.tun_out.len() < crate::device::UDP_INJECT_CHUNK && self.udp_gap_budget > 0 {
                    let room = crate::device::UDP_INJECT_CHUNK - self.tun_out.len();
                    let quota = room.min(self.udp_gap_budget);
                    if let Some(fd) = self.socket.gro_wait_fd() {
                        if crate::net::wait_for_read(fd, 0) {
                            let _ = self.pull_socket(1, quota, false);
                            self.udp_gap_budget = 0;
                        }
                    }
                }
                let now2 = crate::net::mono_now().unwrap_or(now);
                if now2 < self.udp_gap_deadline_ns {
                    crate::device::hold_udp_inject_gap(self.udp_gap_deadline_ns.saturating_sub(now2));
                }
            }
            if self.tun_out.is_empty() {
                self.udp_gap_deadline_ns = 0;
                self.udp_gap_budget = 0;
                return false;
            }
            if let Err(e) = self.flush_tun_out() {
                error!("{}", e);
            }
            self.udp_gap_deadline_ns != 0
        }
    }

    fn apply_decrypted(
        &mut self, src: SocketAddr, packets: Vec<(Result<MessageResult<NodeInfo>, Error>, MsgBuffer)>
    ) -> Result<(), Error> {
        for (result, mut data) in packets {
            match result {
                Ok(val) => {
                    if let Err(e) = self.handle_message(src, val, &mut data, false) {
                        error!("{}", e);
                    }
                    if data.is_empty() {
                        self.buf_spare.push(data);
                    }
                }
                Err(e @ Error::CryptoInitFatal(_)) => {
                    debug!("Fatal crypto init error from {}: {}", src, e);
                    info!("Closing pending connection to {} due to error in crypto init", addr_nice(src));
                    self.pending_inits.remove(&src);
                }
                Err(e @ Error::CryptoInit(_)) => {
                    debug!("Recoverable init error from {}: {}", src, e);
                }
                Err(e) => {
                    self.traffic.count_invalid_protocol(data.len());
                    error!("{}", e);
                }
            }
        }
        Ok(())
    }

    pub fn reset_own_addresses(&mut self) -> io::Result<()> {
        self.own_addresses.clear();
        let socket_addr = self.socket.address().map(mapped_addr)?;
        // 1) Specified advertise addresses
        for addr in &self.config.advertise_addresses {
            self.own_addresses.push(parse_listen(addr, socket_addr.port()));
        }
        // 2) Address of UDP socket
        self.own_addresses.push(socket_addr);
        // 3) Addresses from port forwarding
        if let Some(ref pfw) = self.port_forwarding {
            self.own_addresses.push(pfw.get_internal_ip().into());
            self.own_addresses.push(pfw.get_external_ip().into());
        }
        for addr in &self.stun_reflexive {
            if !self.own_addresses.contains(addr) {
                self.own_addresses.push(*addr);
            }
        }
        debug!("Own addresses: {:?}", self.own_addresses);
        // TODO: detect address changes and call event
        Ok(())
    }

    /// Returns the number of peers
    #[allow(dead_code)]
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Adds a peer to the reconnect list
    ///
    /// This method adds a peer to the list of nodes to reconnect to. A periodic task will try to
    /// connect to the peer if it is not already connected.
    pub fn add_reconnect_peer(&mut self, add: String) {
        let now = TS::now();
        let names = split_peer_group(&add);
        let resolved = resolve_peer_group(&names);
        self.reconnect_peers.push(ReconnectEntry {
            prefer_order: names.len() > 1,
            address: Some((names, now)),
            tries: 0,
            timeout: 1,
            resolved,
            next: now,
            final_timeout: None,
            try_index: 0
        })
    }

    /// Connects to a node given by its address
    ///
    /// This method connects to node by sending a `Message::Init` to it. If `addr` is a name that
    /// resolves to multiple addresses, one message is sent to each of them.
    /// If the node is already a connected peer or the address is blacklisted, no message is sent.
    ///
    /// # Errors
    /// This method returns `Error::NameError` if the address is a name that fails to resolve.
    pub fn connect<Addr: ToSocketAddrs + fmt::Debug + Clone>(&mut self, addr: Addr) -> Result<(), Error> {
        let addrs = resolve(&addr)?.into_iter().map(mapped_addr).collect::<SmallVec<[SocketAddr; 3]>>();
        for addr in &addrs {
            if self.own_addresses.contains(addr)
                || self.peers.contains_key(addr)
                || self.pending_inits.contains_key(addr)
            {
                return Ok(());
            }
        }
        if !addrs.is_empty() {
            self.config.call_hook(
                "peer_connecting",
                vec![("PEER", format!("{:?}", addr_nice(addrs[0]))), ("IFNAME", self.device.ifname().to_owned())],
                true
            );
        }
        // Send a message to each resolved address
        for a in addrs {
            if let Err(e) = self.connect_sock(a) {
                warn!("Failed to connect to {}: {}", addr_nice(a), e);
            }
        }
        Ok(())
    }

    fn create_node_info(&self) -> NodeInfo {
        let mut peers = smallvec![];
        for peer in self.peers.values() {
            peers.push(PeerInfo { node_id: Some(peer.node_id), addrs: peer.addrs.clone() })
        }
        if peers.len() > 20 {
            let mut rng = rng();
            let _ = peers.partial_shuffle(&mut rng, 20);
            peers.truncate(20);
        }
        let mut peer_e2e = Vec::new();
        for (id, pk) in self.known_e2e.iter().take(16) {
            peer_e2e.push((*id, *pk));
        }
        let mut transit = Vec::new();
        for (addr, node_id, claim) in self.table.export_claims() {
            if transit.len() >= 32 {
                break;
            }
            if node_id == self.node_id {
                continue;
            }
            transit.push(TransitClaim { node_id, addr, claim });
        }
        NodeInfo {
            node_id: self.node_id,
            peers,
            claims: self.claims.clone(),
            peer_timeout: Some(self.peer_timeout_publish),
            addrs: self.own_addresses.clone(),
            underlay_mtu: u16::try_from(self.local_l2).ok().filter(|_| self.local_l2 >= 68),
            group: self.config.announce_group.clone(),
            e2e_public: Some(self.e2e_public),
            peer_e2e,
            transit
        }
    }

    /// Remember the local NIC MTU and size the tunnel for it. A later peer
    /// advertisement can only lower this.
    pub fn set_local_underlay(&mut self, l2_mtu: usize, ipv6: bool) {
        if !(68..=65535).contains(&l2_mtu) {
            return;
        }
        self.local_l2 = l2_mtu;
        self.ipv6_underlay = ipv6;
        self.apply_underlay_limit();
    }

    fn note_peer_underlay(&mut self, mtu: Option<u16>) {
        let Some(mtu) = mtu else {
            return;
        };
        let mtu = mtu as usize;
        if !(68..=65535).contains(&mtu) {
            return;
        }
        let next = self.peer_l2.map_or(mtu, |cur| cur.min(mtu));
        if self.peer_l2 == Some(next) {
            return;
        }
        self.peer_l2 = Some(next);
        self.apply_underlay_limit();
    }

    fn apply_underlay_limit(&mut self) {
        if self.local_l2 == 0 {
            return;
        }
        let l2 = crate::mtu::limiting_l2(self.local_l2, self.peer_l2);
        if self.applied_l2 == l2 || (self.applied_l2 != 0 && l2 > self.applied_l2) {
            return;
        }
        match self.device.set_path_budget(self.config.mtu, l2, self.ipv6_underlay) {
            Ok(()) => {
                info!(
                    "Underlay MTU {} (peer {:?}), tunnel payload {} gso {}",
                    l2,
                    self.peer_l2,
                    self.device.max_plain_payload(),
                    self.device.max_gso_payload()
                );
                self.applied_l2 = l2;
            }
            Err(err) => warn!("Could not apply underlay MTU {}: {}", l2, err)
        }
    }

    fn connect_sock(&mut self, addr: SocketAddr) -> Result<(), Error> {
        let addr = mapped_addr(addr);
        if self.config.lan_only && !lan::addr_on_local_prefix(addr, &lan::interface_prefixes()) {
            debug!("lan-only: skipping non-local {}", addr_nice(addr));
            return Ok(());
        }
        if self.peers.contains_key(&addr)
            || self.own_addresses.contains(&addr)
            || self.pending_inits.contains_key(&addr)
        {
            return Ok(());
        }
        debug!("Connecting to {:?}", addr);
        let payload = self.create_node_info();
        let mut peer_crypto = self.crypto.peer_instance(payload);
        let mut msg = MsgBuffer::new(SPACE_BEFORE);
        peer_crypto.initialize(&mut msg)?;
        self.pending_inits.insert(addr, peer_crypto);
        self.send_to(addr, &mut msg)?;
        self.flush_outbox()
    }

    fn crypto_housekeep(&mut self) -> Result<(), Error> {
        let mut msg = MsgBuffer::new(SPACE_BEFORE);
        let mut del: SmallVec<[SocketAddr; 4]> = smallvec![];
        for addr in self.pending_inits.keys().copied().collect::<SmallVec<[SocketAddr; 4]>>() {
            msg.clear();
            match self.pending_inits.get_mut(&addr).unwrap().every_second(&mut msg) {
                Err(_) => del.push(addr),
                Ok(MessageResult::None) => (),
                Ok(MessageResult::Reply) => self.send_to(addr, &mut msg)?,
                Ok(_) => unreachable!()
            }
        }
        for addr in self.peers.keys().copied().collect::<SmallVec<[SocketAddr; 16]>>() {
            msg.clear();
            let result = self.peers.get_mut(&addr).unwrap().crypto.with_mut(|c| c.every_second(&mut msg))?;
            match result {
                Err(_) => del.push(addr),
                Ok(MessageResult::None) => (),
                Ok(MessageResult::Reply) => self.send_to(addr, &mut msg)?,
                Ok(_) => unreachable!()
            }
        }
        for addr in del {
            self.pending_inits.remove(&addr);
            if self.peers.remove(&addr).is_some() {
                // Same as the timeout path. Leaving the claim in place makes the
                // next lookup miss the direct peer and relay that prefix elsewhere.
                self.table.remove_claims(addr);
                self.connect_sock(addr)?;
            }
        }
        Ok(())
    }

    fn reconnect_to_peers(&mut self) -> Result<(), Error> {
        let now = TS::now();
        // Connect to those reconnect_peers that are due
        for entry in self.reconnect_peers.clone() {
            if entry.next > now {
                continue;
            }
            if entry.prefer_order {
                if entry.resolved.iter().any(|a| self.peers.contains_key(a) || self.pending_inits.contains_key(a)) {
                    continue;
                }
                if !entry.resolved.is_empty() {
                    let addr = entry.resolved[entry.try_index % entry.resolved.len()];
                    self.connect_sock(addr)?;
                }
            } else {
                self.connect(&entry.resolved as &[SocketAddr])?;
            }
        }
        for entry in &mut self.reconnect_peers {
            // Wait out an in-flight handshake before rotating to a fallback address
            if entry.resolved.iter().any(|addr| self.pending_inits.contains_key(addr)) {
                entry.next = now + 1;
                continue;
            }
            // Schedule for next second if node is connected via any grouped address
            if entry.resolved.iter().any(|addr| self.peers.contains_key(addr)) {
                entry.tries = 0;
                entry.timeout = 1;
                entry.try_index = 0;
                entry.next = now + 1;
                continue;
            }
            // Resolve entries anew
            if let Some((ref names, ref mut next_resolve)) = entry.address {
                if *next_resolve <= now {
                    entry.resolved = resolve_peer_group(names);
                    *next_resolve = now + RESOLVE_INTERVAL;
                }
            }
            // Ignore if next attempt is already in the future
            if entry.next > now {
                continue;
            }
            if entry.prefer_order && !entry.resolved.is_empty() {
                entry.try_index = (entry.try_index + 1) % entry.resolved.len();
            }
            // Exponential back-off: every 10 tries, the interval doubles
            entry.tries += 1;
            if entry.tries > 10 {
                entry.tries = 0;
                entry.timeout *= 2;
            }
            // Maximum interval is one hour
            if entry.timeout > MAX_RECONNECT_INTERVAL {
                entry.timeout = MAX_RECONNECT_INTERVAL;
            }
            // Schedule next connection attempt
            entry.next = now + Time::from(entry.timeout);
        }
        self.reconnect_peers.retain(|e| e.final_timeout.unwrap_or(now) >= now);
        Ok(())
    }

    fn housekeep(&mut self) -> Result<(), Error> {
        let now = TS::now();
        let mut buffer = MsgBuffer::new(SPACE_BEFORE);
        let mut del: SmallVec<[SocketAddr; 3]> = SmallVec::new();
        for (&addr, data) in &self.peers {
            if data.timeout < now {
                del.push(addr);
            }
        }
        for addr in del {
            info!("Forgot peer {} due to timeout", addr_nice(addr));
            self.peers.remove(&addr);
            self.table.remove_claims(addr);
            self.connect_sock(addr)?; // Try to reconnect
        }
        self.table.housekeep();
        self.init_limit.housekeep(now);
        self.crypto_housekeep()?;
        if self.config.tcp_fallback {
            for addr in self.pending_inits.keys().copied().collect::<SmallVec<[SocketAddr; 4]>>() {
                if let Err(e) = self.socket.connect_stream(addr) {
                    debug!("TCP fallback connect to {} failed: {}", addr_nice(addr), e);
                }
            }
        }
        // Periodically extend the port-forwarding
        if let Some(ref mut pfw) = self.port_forwarding {
            pfw.check_extend();
        }
        let now = TS::now();
        // Periodically send peer list to peers
        if self.next_peers <= now {
            debug!("Send peer list to all peers");
            let info = self.create_node_info();
            info.encode(&mut buffer);
            self.last_node_info_ns = crate::net::mono_now().unwrap_or(0);
            self.broadcast_msg(MESSAGE_TYPE_NODE_INFO, &mut buffer)?;
            // Reschedule for next update
            let min_peer_timeout = self.peers.iter().map(|p| p.1.peer_timeout).min().unwrap_or(DEFAULT_PEER_TIMEOUT);
            // peer_timeout/2 - 60 underflows on u16 when a peer publishes a timeout < 120s (#384).
            let interval = min(self.update_freq, max((min_peer_timeout / 2).saturating_sub(60), 1));
            self.next_peers = now + Time::from(interval);
        }
        self.reconnect_to_peers()?;
        if self.next_stats_out < now {
            // Write out the statistics
            self.write_out_stats().map_err(|err| Error::FileIo("Failed to write stats file", err))?;
            self.send_stats_to_statsd()?;
            self.next_stats_out = now + STATS_INTERVAL;
            self.traffic.period(Some(5));
        }
        if let Some(peers) = self.beacon_serializer.get_cmd_results() {
            debug!("Loaded beacon with peers: {:?}", peers);
            for peer in peers {
                self.connect_sock(peer)?;
            }
        }
        if self.next_beacon < now {
            self.store_beacon()?;
            self.load_beacon()?;
            self.next_beacon = now + Time::from(self.config.beacon_interval);
        }
        // Periodically re-detect local/public addresses (dynamic WAN IP, #326).
        if self.next_own_address_reset <= now {
            let prev = self.own_addresses.clone();
            self.reset_own_addresses().map_err(|err| Error::SocketIo("Failed to get own addresses", err))?;
            if self.own_addresses != prev {
                info!("Local addresses changed, publishing update: {:?}", self.own_addresses);
                let info = self.create_node_info();
                info.encode(&mut buffer);
                self.last_node_info_ns = crate::net::mono_now().unwrap_or(0);
                self.broadcast_msg(MESSAGE_TYPE_NODE_INFO, &mut buffer)?;
                self.reconnect_to_peers()?;
            }
            self.next_own_address_reset = now + OWN_ADDRESS_RESET_INTERVAL;
            self.send_stun_probes();
        }
        self.flush_pending_crypto()?;
        self.flush_tun_out_due()?;
        self.flush_outbox()?;
        Ok(())
    }

    fn send_stun_probes(&mut self) {
        if !self.config.stun || self.config.stun_servers.is_empty() {
            return;
        }
        self.stun_txid = random();
        let req = stun::encode_binding_request(&self.stun_txid);
        for server in stun::resolve_stun_servers(&self.config.stun_servers) {
            if let Err(e) = self.socket.send(&req, server) {
                debug!("STUN send to {} failed: {}", addr_nice(server), e);
            }
        }
        if let Ok(local) = self.socket.address() {
            if let std::net::IpAddr::V4(v4) = crate::net::send_addr(local).ip() {
                let gw = natpmp::guess_gateway(v4);
                let pkt = natpmp::encode_udp_mapping(local.port(), local.port(), 1800);
                let _ = self.socket.send(&pkt, gw);
            }
        }
    }

    /// Stores the beacon
    fn store_beacon(&mut self) -> Result<(), Error> {
        if let Some(ref path) = self.config.beacon_store {
            let peers: SmallVec<[SocketAddr; 3]> = self.own_addresses.sample(&mut rng(), 3).cloned().collect();
            if let Some(path) = path.strip_prefix('|') {
                self.beacon_serializer
                    .write_to_cmd(&peers, path)
                    .map_err(|e| Error::BeaconIo("Failed to call beacon command", e))?;
            } else {
                self.beacon_serializer
                    .write_to_file(&peers, path)
                    .map_err(|e| Error::BeaconIo("Failed to write beacon to file", e))?;
            }
        }
        Ok(())
    }

    /// Loads the beacon
    fn load_beacon(&mut self) -> Result<(), Error> {
        let peers;
        if let Some(ref path) = self.config.beacon_load {
            if let Some(path) = path.strip_prefix('|') {
                self.beacon_serializer
                    .read_from_cmd(path, Some(50))
                    .map_err(|e| Error::BeaconIo("Failed to call beacon command", e))?;
                return Ok(());
            } else {
                peers = self
                    .beacon_serializer
                    .read_from_file(path, Some(50))
                    .map_err(|e| Error::BeaconIo("Failed to read beacon from file", e))?;
            }
        } else {
            return Ok(());
        }
        debug!("Loaded beacon with peers: {:?}", peers);
        for peer in peers {
            self.connect_sock(peer)?;
        }
        Ok(())
    }

    /// Writes out the statistics to a file
    fn write_out_stats(&mut self) -> Result<(), io::Error> {
        if let Some(ref mut f) = self.stats_file {
            debug!("Writing out stats");
            f.seek(SeekFrom::Start(0))?;
            f.set_len(0)?;
            writeln!(f, "peers:")?;
            let now = TS::now();
            for (addr, data) in &self.peers {
                writeln!(
                    f,
                    "  - \"{}\": {{ ttl_secs: {}, crypto: {} }}",
                    addr_nice(*addr),
                    data.timeout - now,
                    data.crypto.algorithm_name()
                )?;
            }
            writeln!(f)?;
            self.table.write_out(f)?;
            writeln!(f)?;
            self.traffic.write_out(f)?;
            writeln!(f)?;
        }
        Ok(())
    }

    /// Sends the statistics to a statsd endpoint
    fn send_stats_to_statsd(&mut self) -> Result<(), Error> {
        if let Some(ref endpoint) = self.statsd_server {
            let peer_traffic = self.traffic.total_peer_traffic();
            let payload_traffic = self.traffic.total_payload_traffic();
            let dropped = &self.traffic.dropped;
            let prefix = self.config.statsd_prefix.as_ref().map(|s| s as &str).unwrap_or("vpncloud");
            let msg = StatsdMsg::new()
                .with_ns(prefix, |msg| {
                    msg.add("peer_count", self.peers.len(), "g");
                    msg.add("table_cache_entries", self.table.cache_len(), "g");
                    msg.add("table_claims", self.table.claim_len(), "g");
                    msg.with_ns("traffic", |msg| {
                        msg.with_ns("protocol", |msg| {
                            msg.with_ns("inbound", |msg| {
                                msg.add("bytes", peer_traffic.in_bytes, "c");
                                msg.add("packets", peer_traffic.in_packets, "c");
                            });
                            msg.with_ns("outbound", |msg| {
                                msg.add("bytes", peer_traffic.out_bytes, "c");
                                msg.add("packets", peer_traffic.out_packets, "c");
                            });
                        });
                        msg.with_ns("payload", |msg| {
                            msg.with_ns("inbound", |msg| {
                                msg.add("bytes", payload_traffic.in_bytes, "c");
                                msg.add("packets", payload_traffic.in_packets, "c");
                            });
                            msg.with_ns("outbound", |msg| {
                                msg.add("bytes", payload_traffic.out_bytes, "c");
                                msg.add("packets", payload_traffic.out_packets, "c");
                            });
                        });
                    });
                    msg.with_ns("invalid_protocol_traffic", |msg| {
                        msg.add("bytes", dropped.in_bytes, "c");
                        msg.add("packets", dropped.in_packets, "c");
                    });
                    msg.with_ns("dropped_payload", |msg| {
                        msg.add("bytes", dropped.out_bytes, "c");
                        msg.add("packets", dropped.out_packets, "c");
                    });
                })
                .build();
            let msg_data = msg.as_bytes();
            let addrs = resolve(endpoint)?;
            if let Some(addr) = addrs.first() {
                match self.socket.send(msg_data, *addr) {
                    Ok(written) if written == msg_data.len() => Ok(()),
                    Ok(_) => Err(Error::Socket("Sent out truncated packet")),
                    Err(e) => Err(Error::SocketIo("IOError when sending", e))
                }?
            } else {
                error!("Failed to resolve statsd server {}", endpoint);
            }
        }
        Ok(())
    }

    fn relay_hops(&self) -> Vec<policy::RelayHop> {
        self.peers
            .iter()
            .map(|(addr, peer)| policy::RelayHop {
                node_id: peer.node_id,
                addr: *addr,
                rtt_us: peer.rtt_us,
                alive: true
            })
            .collect()
    }

    fn pick_relay(&self, except: SocketAddr) -> Option<SocketAddr> {
        match policy::choose_delivery(false, &self.relay_hops(), except) {
            policy::Delivery::Relay(addr) => Some(addr),
            _ => None
        }
    }

    fn send_relay(&mut self, via: SocketAddr, dest: NodeId, inner: u8, msg: &mut MsgBuffer) -> Result<(), Error> {
        let plain = msg.message().to_vec();
        let Some(pk) = self.known_e2e.get(&dest).copied() else {
            debug!("Dropping relay: no end-to-end key for destination");
            self.traffic.count_dropped_payload(plain.len());
            return Ok(());
        };
        let Some(body) = policy::seal_relay_body(&self.e2e_secret, &self.e2e_public, &pk, &plain) else {
            debug!("Dropping relay: end-to-end seal failed");
            self.traffic.count_dropped_payload(plain.len());
            return Ok(());
        };
        let frame = policy::encode_relay(&dest, inner, &body);
        msg.clear();
        msg.clone_from(&frame);
        debug!("Relaying type {} for node via {}", inner, addr_nice(via));
        self.send_msg(via, MESSAGE_TYPE_RELAY, msg)
    }

    fn handle_relay(&mut self, src: SocketAddr, data: &mut MsgBuffer) -> Result<(), Error> {
        let hops = self.relay_hops();
        let decision = policy::decide_relay(&self.node_id, data.message(), &hops, Some(src));
        match decision {
            policy::RelayDecision::Drop => {
                debug!("Relay dest unknown, dropping");
                Ok(())
            }
            policy::RelayDecision::Deliver { inner_type, inner } => {
                let Some(plain) = policy::open_relay_body(&self.e2e_secret, &inner) else {
                    debug!("Dropping relay: end-to-end open failed");
                    self.traffic.count_dropped_payload(inner.len());
                    return Ok(());
                };
                let mut buf = self.take_spare();
                buf.clone_from(&plain);
                let result = self.handle_message(src, MessageResult::Message(inner_type), &mut buf, true);
                self.buf_spare.push(buf);
                result
            }
            policy::RelayDecision::Forward { via, dest, inner_type, inner } => {
                let frame = policy::encode_relay(&dest, inner_type, &inner);
                let mut buf = self.take_spare();
                buf.clone_from(&frame);
                let result = self.send_msg(via, MESSAGE_TYPE_RELAY, &mut buf);
                self.buf_spare.push(buf);
                result
            }
        }
    }

    fn route_message(&mut self, dst: Address, type_: u8, data: &mut MsgBuffer) -> Result<(), Error> {
        if self.config.full_tunnel {
            let exit = policy::full_tunnel_target(&self.exit_allow, self.exit_node);
            if let Some(exit) = exit {
                if let Some(addr) = self.peers.iter().find(|(_, peer)| peer.node_id == exit).map(|(addr, _)| *addr) {
                    match policy::choose_delivery(true, &[], addr) {
                        policy::Delivery::Direct => self.send_msg(addr, type_, data)?,
                        _ => self.traffic.count_dropped_payload(data.len())
                    }
                    return Ok(());
                }
            }
            self.traffic.count_dropped_payload(data.len());
            return Ok(());
        }
        match self.table.lookup(dst) {
            Some((addr, dest_id)) => {
                if self.peers.contains_key(&addr)
                    && policy::choose_delivery(true, &[], addr) == policy::Delivery::Direct
                {
                    self.send_msg(addr, type_, data)?;
                } else if let Some(via) = self.pick_relay(addr) {
                    self.send_relay(via, dest_id, type_, data)?;
                    self.connect_sock(addr)?;
                } else {
                    warn!("Destination for {} not found in peers: {}", dst, addr_nice(addr));
                    self.table.remove_claims(addr);
                    self.connect_sock(addr)?;
                }
            }
            None => {
                if self.broadcast {
                    self.broadcast_msg(type_, data)?;
                } else {
                    self.traffic.count_dropped_payload(data.len());
                }
            }
        }
        Ok(())
    }

    /// Forward one kernel GSO aggregate as a single encrypted message.
    fn handle_gso_from_tun(&mut self, data: &mut MsgBuffer, meta: GsoMeta) -> Result<(), Error> {
        if !meta.sane(data.len()) {
            debug!("Dropping TUN GSO aggregate with unusable virtio header");
            self.traffic.count_dropped_payload(data.len());
            return Ok(());
        }
        let gso_limit = self.device.max_gso_payload();
        if data.len() > gso_limit {
            debug!("Dropping {} byte GSO aggregate; underlay fits {}", data.len(), gso_limit);
            self.traffic.count_dropped_payload(data.len());
            return Ok(());
        }
        let (src, dst) = P::parse(data.message())?;
        self.traffic.count_out_payload(dst, src, data.len());
        if data.get_start() < GSO_META_LEN {
            return Err(Error::Message("No headroom for GSO metadata"));
        }
        data.prepend_zero(GSO_META_LEN);
        meta.write(data.message_mut());
        self.route_message(dst, MESSAGE_TYPE_DATA_GSO, data)
    }

    fn handle_gso_payload_from(&mut self, peer: SocketAddr, data: &mut MsgBuffer, relayed: bool) -> Result<(), Error> {
        let Some(meta) = GsoMeta::read(data.message()) else {
            self.traffic.count_invalid_protocol(data.len());
            return Err(Error::Message("Truncated GSO message"));
        };
        if data.len() < GSO_META_LEN || !meta.sane(data.len() - GSO_META_LEN) {
            self.traffic.count_invalid_protocol(data.len());
            return Err(Error::Message("Invalid GSO message"));
        }
        let (src, dst) = {
            let ip = &data.message()[GSO_META_LEN..];
            let (src, dst) = P::parse(ip)?;
            if !self.ingress_allowed(peer, ip, src, relayed) {
                return Ok(());
            }
            if !self.acl.is_empty() {
                let tap = self.config.device_type == Type::Tap;
                let l4 = crate::payload::overlay_l4(ip, tap);
                let match_src = l4.ip_src.unwrap_or(src);
                if !self.acl.allows(match_src, l4.proto, l4.dport) {
                    debug!("ACL dropped GSO src {} proto {:?} dport {:?}", match_src, l4.proto, l4.dport);
                    return Ok(());
                }
            }
            (src, dst)
        };
        data.skip(GSO_META_LEN);
        let len = data.len();
        self.traffic.count_in_payload(src, dst, len);
        if self.learning {
            let nid = self.peers.get(&peer).map(|p| p.node_id).unwrap_or([0; 16]);
            self.table.cache(src, peer, nid);
        }
        match self.device.write_offload(data, &meta) {
            Ok(()) => Ok(()),
            Err(Error::DeviceIo(_, ref e)) if e.kind() == io::ErrorKind::WouldBlock => {
                let mut owned = self.take_spare();
                mem::swap(data, &mut owned);
                self.gso_out.push_back((meta, owned));
                data.clear();
                Ok(())
            }
            Err(e) => Err(e)
        }
    }

    fn flush_gso_out(&mut self) -> Result<(), Error> {
        while let Some((meta, mut buf)) = self.gso_out.pop_front() {
            match self.device.write_offload(&mut buf, &meta) {
                Ok(()) => self.buf_spare.push(buf),
                Err(Error::DeviceIo(_, ref e)) if e.kind() == io::ErrorKind::WouldBlock => {
                    self.gso_out.push_front((meta, buf));
                    break;
                }
                Err(e) => {
                    self.buf_spare.push(buf);
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    pub fn handle_interface_data(&mut self, data: &mut MsgBuffer) -> Result<(), Error> {
        // HOT PATH
        let (src, dst) = P::parse(data.message())?;
        if !self.names.is_empty() {
            if let Some(mut resp) = policy::answer_dns(data.message(), &self.names) {
                crate::payload::fix_ipv4_checksums(&mut resp);
                let _ = self.device.write(&resp);
                return Ok(());
            }
        }
        if !self.split_prefixes.is_empty() && !policy::split_forwards(&self.split_prefixes, dst) {
            debug!("Split tunnel dropped {}", dst);
            self.traffic.count_dropped_payload(data.len());
            return Ok(());
        }
        if self.config.stateful_filter {
            if let Some(flow) = policy::ipv4_flow(data.message()) {
                self.flows.note_outbound(flow);
            }
        }
        debug!("Read data from interface: src: {}, dst: {}, {} bytes", src, dst, data.len());
        self.traffic.count_out_payload(dst, src, data.len());
        self.route_message(dst, MESSAGE_TYPE_DATA, data)
    }

    fn add_new_peer(&mut self, addr: SocketAddr, info: NodeInfo) -> Result<(), Error> {
        info!("Added peer {}", addr_nice(addr));
        crate::runtime_status::note_handshake();
        self.config.call_hook(
            "peer_connected",
            vec![
                ("PEER", format!("{:?}", addr_nice(addr))),
                ("IFNAME", self.device.ifname().to_owned()),
                ("CLAIMS", info.claims.iter().map(|r| format!("{:?}", r)).collect::<Vec<String>>().join(" ")),
                ("NODE_ID", bytes_to_hex(&info.node_id)),
            ],
            true
        );
        if let Some(init) = self.pending_inits.remove(&addr) {
            self.peers.insert(addr, PeerData {
                addrs: info.addrs.clone(),
                crypto: PeerCryptoSlot::wrap(init, self.crypto_pool.enabled()),
                node_id: info.node_id,
                peer_timeout: info.peer_timeout.unwrap_or(DEFAULT_PEER_TIMEOUT),
                last_seen: TS::now(),
                timeout: TS::now() + self.config.peer_timeout as Time,
                rtt_us: u64::MAX,
                group_ok: true,
                auth_claims: RangeList::new()
            });
            self.update_peer_info(addr, Some(info))?;
        } else {
            error!("No init for new peer {}", addr_nice(addr));
        }
        Ok(())
    }

    fn remove_peer(&mut self, addr: SocketAddr) {
        if let Some(peer) = self.peers.remove(&addr) {
            info!("Closing connection to {}", addr_nice(addr));
            self.table.remove_claims(addr);
            self.config.call_hook(
                "peer_disconnected",
                vec![
                    ("PEER", format!("{:?}", addr)),
                    ("IFNAME", self.device.ifname().to_owned()),
                    ("NODE_ID", bytes_to_hex(&peer.node_id)),
                ],
                true
            );
        }
    }

    /// Install prefixes whose underlay address is not a connected peer.
    /// Lookup then misses `self.peers` and `route_message` seals a relay.
    fn install_transit(&mut self, transit: &[TransitClaim]) {
        let mut grouped: Vec<(SocketAddr, NodeId, RangeList)> = Vec::new();
        for hop in transit {
            if hop.node_id == self.node_id {
                continue;
            }
            let addr = mapped_addr(hop.addr);
            if self.own_addresses.contains(&addr) || self.peers.contains_key(&addr) {
                continue;
            }
            if self.peers.values().any(|peer| peer.node_id == hop.node_id) {
                continue;
            }
            if let Some(slot) = grouped.iter_mut().find(|slot| slot.0 == addr && slot.1 == hop.node_id) {
                slot.2.push(hop.claim);
            } else {
                let mut claims = RangeList::new();
                claims.push(hop.claim);
                grouped.push((addr, hop.node_id, claims));
            }
        }
        for (addr, node_id, claims) in grouped {
            let decision = policy::filter_announcement(
                &self.grants,
                &policy::Announcement { claims: claims.iter().copied().collect(), group: None }
            );
            if decision.claims.is_empty() {
                continue;
            }
            let mut kept = RangeList::new();
            kept.extend(decision.claims.iter().copied());
            debug!("Transit route {} via {}", addr_nice(addr), kept.len());
            self.table.set_claims(addr, node_id, kept);
        }
    }

    fn connect_to_peers(&mut self, peers: &[PeerInfo]) -> Result<(), Error> {
        'outer: for peer in peers {
            for addr in &peer.addrs {
                if self.peers.contains_key(addr) {
                    continue 'outer;
                }
            }
            if let Some(node_id) = peer.node_id {
                if self.node_id == node_id {
                    // Check addresses and add addresses that we don't know to own addresses
                    for addr in &peer.addrs {
                        if !self.own_addresses.contains(addr) {
                            self.own_addresses.push(*addr)
                        }
                    }
                    continue 'outer;
                }
                for p in self.peers.values() {
                    if p.node_id == node_id {
                        continue 'outer;
                    }
                }
            }
            self.connect(&peer.addrs as &[SocketAddr])?;
        }
        Ok(())
    }

    fn update_peer_info(&mut self, addr: SocketAddr, info: Option<NodeInfo>) -> Result<(), Error> {
        let peer_mtu = info.as_ref().and_then(|info| info.underlay_mtu);
        if let Some(peer) = self.peers.get_mut(&addr) {
            peer.last_seen = TS::now();
            peer.timeout = TS::now() + self.config.peer_timeout as Time;
            if let Some(info) = &info {
                // Update peer addresses, always add seen address
                peer.addrs.clear();
                peer.addrs.push(addr);
                for addr in &info.addrs {
                    if !peer.addrs.contains(addr) {
                        peer.addrs.push(*addr);
                    }
                }
                let prefixes = lan::interface_prefixes();
                lan::sort_lan_first(&mut peer.addrs, &prefixes);
            }
            if self.last_node_info_ns > 0 {
                if let Some(now) = crate::net::mono_now() {
                    if now >= self.last_node_info_ns {
                        peer.rtt_us = ((now - self.last_node_info_ns) / 1_000).max(1);
                    }
                }
            }
        } else {
            error!("Received peer update from non peer {}", addr_nice(addr));
            return Ok(());
        }
        if let Some(info) = info {
            if let Some(pk) = info.e2e_public {
                self.known_e2e.insert(info.node_id, pk);
            }
            for (id, pk) in &info.peer_e2e {
                self.known_e2e.entry(*id).or_insert(*pk);
            }
            let decision = policy::filter_announcement(
                &self.grants,
                &policy::Announcement { claims: info.claims.iter().copied().collect(), group: info.group.clone() }
            );
            if self.grants.enforcing {
                if let Some(peer) = self.peers.get_mut(&addr) {
                    peer.group_ok = decision.group_ok;
                    peer.auth_claims.clear();
                    peer.auth_claims.extend(decision.claims.iter().copied());
                }
            }
            let mut claims = RangeList::new();
            claims.extend(decision.claims.iter().copied());
            debug!("Adding claims of peer {}: {:?}", addr_nice(addr), claims);
            self.table.set_claims(addr, info.node_id, claims);
            self.install_transit(&info.transit);
            debug!("Received {} peers from {}: {:?}", info.peers.len(), addr_nice(addr), info.peers);
            self.connect_to_peers(&info.peers)?;
        }
        self.note_peer_underlay(peer_mtu);
        Ok(())
    }

    fn handle_payload_from(&mut self, peer: SocketAddr, data: &mut MsgBuffer, relayed: bool) -> Result<(), Error> {
        // HOT PATH
        let (src, dst) = P::parse(data.message())?;
        if !self.ingress_allowed(peer, data.message(), src, relayed) {
            self.traffic.count_dropped_payload(data.len());
            return Ok(());
        }
        if !self.acl.is_empty() {
            let tap = self.config.device_type == Type::Tap;
            let l4 = crate::payload::overlay_l4(data.message(), tap);
            let match_src = l4.ip_src.unwrap_or(src);
            if !self.acl.allows(match_src, l4.proto, l4.dport) {
                debug!("ACL dropped overlay src {} proto {:?} dport {:?}", match_src, l4.proto, l4.dport);
                return Ok(());
            }
        }
        let len = data.len();
        debug!("Writing data to device: {} bytes", len);
        self.traffic.count_in_payload(src, dst, len);
        if self.learning {
            let nid = self.peers.get(&peer).map(|p| p.node_id).unwrap_or([0; 16]);
            self.table.cache(src, peer, nid);
        }
        let tcp_data = crate::payload::ipv4_tcp_data(data.message());
        let tcp = tcp_data || crate::payload::ipv4_tcp_segment(data.message());
        let mut owned = self.take_spare();
        mem::swap(data, &mut owned);
        self.tun_out.push(owned);
        if tcp_data {
            self.arm_gro_hold();
        } else if !tcp {
            // UDP was sitting in the TCP train and arrived short. A pure ACK
            // does not start a train and does not flush one already gathering.
            self.gro_deadline_ns = 0;
        }
        data.clear();
        Ok(())
    }

    fn ingress_allowed(&self, peer: SocketAddr, pkt: &[u8], src: Address, relayed: bool) -> bool {
        if self.config.stateful_filter {
            if let Some(flow) = policy::ipv4_flow(pkt) {
                if !self.flows.allow_inbound(&flow) {
                    debug!("Stateful filter dropped unsolicited flow");
                    return false;
                }
            }
        }
        if self.grants.enforcing {
            let allowed = if relayed {
                self.relay_source_allowed(src)
            } else {
                self.peers
                    .get(&peer)
                    .map(|p| policy::source_allowed(true, p.group_ok, &p.auth_claims, src))
                    .unwrap_or(false)
            };
            if !allowed {
                debug!("Capability dropped source {}", src);
                return false;
            }
        }
        true
    }

    /// A relayed packet's previous hop is not the origin. The source has to
    /// match the origin's installed claim. That row already passed the grants.
    fn relay_source_allowed(&self, src: Address) -> bool {
        let Some((_, origin_id, _)) = self.table.best_claim(src) else {
            return false;
        };
        if let Some(peer) = self.peers.values().find(|peer| peer.node_id == origin_id) {
            return policy::source_allowed(true, peer.group_ok, &peer.auth_claims, src);
        }
        true
    }

    fn arm_gro_hold(&mut self) {
        if !self.defer_tun_flush || self.gro_deadline_ns != 0 {
            return;
        }
        #[cfg(target_os = "linux")]
        if let Some(now) = crate::net::mono_now() {
            self.gro_deadline_ns = now.saturating_add(GRO_HOLD_NS);
        }
    }

    fn gro_hold_active(&self) -> bool {
        if !self.defer_tun_flush || self.tun_out.is_empty() {
            return false;
        }
        #[cfg(target_os = "linux")]
        {
            let now = crate::net::mono_now().unwrap_or(u64::MAX);
            return !gro_batch_ready(self.tun_out.len(), now, self.gro_deadline_ns);
        }
        #[cfg(not(target_os = "linux"))]
        false
    }

    /// Write the TUN batch unless a short train is still gathering.
    fn flush_tun_out_due(&mut self) -> Result<(), Error> {
        if self.gro_hold_active() {
            return Ok(());
        }
        let result = self.flush_tun_out();
        if self.tun_out.is_empty() {
            self.gro_deadline_ns = 0;
        }
        result
    }

    fn handle_message(
        &mut self, src: SocketAddr, msg_result: MessageResult<NodeInfo>, data: &mut MsgBuffer, relayed: bool
    ) -> Result<(), Error> {
        // HOT PATH
        match msg_result {
            MessageResult::Message(type_) => {
                // HOT PATH
                match type_ {
                    MESSAGE_TYPE_DATA => {
                        // HOT PATH
                        self.handle_payload_from(src, data, relayed)?
                    }
                    MESSAGE_TYPE_DATA_GSO => {
                        // HOT PATH
                        self.handle_gso_payload_from(src, data, relayed)?
                    }
                    MESSAGE_TYPE_RELAY => self.handle_relay(src, data)?,
                    MESSAGE_TYPE_NODE_INFO => {
                        // COLD PATH
                        let info = match NodeInfo::decode(Cursor::new(data.message())) {
                            Ok(val) => val,
                            Err(err) => {
                                self.traffic.count_invalid_protocol(data.len());
                                return Err(err);
                            }
                        };
                        self.update_peer_info(src, Some(info))?
                    }
                    MESSAGE_TYPE_KEEPALIVE => {
                        // COLD PATH
                        self.update_peer_info(src, None)?
                    }
                    MESSAGE_TYPE_CLOSE => {
                        // COLD PATH
                        self.remove_peer(src)
                    }
                    _ => {
                        // COLD PATH
                        self.traffic.count_invalid_protocol(data.len());
                        return Err(Error::Message("Unknown message type"));
                    }
                }
            }
            MessageResult::Initialized(info) => {
                // COLD PATH
                self.add_new_peer(src, info)?
            }
            MessageResult::InitializedWithReply(info) => {
                // COLD PATH
                self.add_new_peer(src, info)?;
                self.send_to(src, data)?
            }
            MessageResult::Reply => {
                // COLD PATH
                self.send_to(src, data)?
            }
            MessageResult::None => {
                // COLD PATH
            }
        }
        Ok(())
    }

    pub fn handle_net_message(&mut self, src: SocketAddr, data: &mut MsgBuffer) -> Result<(), Error> {
        // HOT PATH
        let src = mapped_addr(src);
        if natpmp::is_natpmp_response(data.message()) {
            if let Some((_, ext, _)) = natpmp::parse_udp_mapping(data.message()) {
                if let Ok(local) = self.socket.address() {
                    let mapped = SocketAddr::new(local.ip(), ext);
                    let mapped = mapped_addr(mapped);
                    if !self.stun_reflexive.contains(&mapped) {
                        info!("NAT-PMP mapped port {}", ext);
                        self.stun_reflexive.push(mapped);
                        let _ = self.reset_own_addresses();
                    }
                }
            }
            return Ok(());
        }
        if stun::is_stun_message(data.message()) {
            if let Some(mapped) = stun::parse_binding_success(data.message(), &self.stun_txid) {
                let mapped = mapped_addr(mapped);
                if !self.stun_reflexive.contains(&mapped) {
                    info!("STUN mapped address {}", addr_nice(mapped));
                    self.stun_reflexive.push(mapped);
                    let _ = self.reset_own_addresses();
                }
            }
            return Ok(());
        }
        if self.config.lan_only && !lan::addr_on_local_prefix(src, &lan::interface_prefixes()) {
            debug!("lan-only: ignoring {}", addr_nice(src));
            return Ok(());
        }
        if is_loopback_ip(src.ip()) {
            // Peers (or this process) hitting the listen port via 127.0.0.1 spam crypto-init
            // failures (#313). Loopback is never a real remote node.
            debug!("Ignoring packet from loopback {}", addr_nice(src));
            return Ok(());
        }
        debug!("Received {} bytes from {}", data.len(), src);
        let msg_result = if let Some(init) = self.pending_inits.get_mut(&src) {
            // COLD PATH
            init.handle_message(data)
        } else if is_init_message(data.message()) {
            // COLD PATH
            if !self.init_limit.allow(src.ip(), TS::now()) {
                debug!("Rate-limited handshake from {}", addr_nice(src));
                return Ok(());
            }
            let mut result = None;
            if let Some(peer) = self.peers.get_mut(&src) {
                result = peer.crypto.with_mut(|c| if c.has_init() { Some(c.handle_message(data)) } else { None })?;
            }
            if let Some(result) = result {
                result
            } else {
                let mut init = self.crypto.peer_instance(self.create_node_info());
                let msg_result = init.handle_message(data);
                match msg_result {
                    Ok(res) => {
                        self.config.call_hook(
                            "peer_connecting",
                            vec![
                                ("PEER", format!("{:?}", addr_nice(src))),
                                ("IFNAME", self.device.ifname().to_owned()),
                            ],
                            true
                        );
                        self.pending_inits.insert(src, init);
                        Ok(res)
                    }
                    Err(err) => {
                        self.traffic.count_invalid_protocol(data.len());
                        return Err(err);
                    }
                }
            }
        } else if let Some(peer) = self.peers.get_mut(&src) {
            // HOT PATH
            peer.crypto.with_mut(|c| c.handle_message(data))?
        } else {
            // COLD PATH
            info!("Ignoring non-init message from unknown peer {}", addr_nice(src));
            self.traffic.count_invalid_protocol(data.len());
            return Ok(());
        };
        // HOT PATH
        match msg_result {
            Ok(val) => {
                // HOT PATH
                self.handle_message(src, val, data, false)
            }
            Err(err) => {
                // COLD PATH
                self.traffic.count_invalid_protocol(data.len());
                Err(err)
            }
        }
    }

    fn initialize(&mut self) {
        if let Err(err) = self.reset_own_addresses() {
            error!("Failed to obtain local addresses: {}", err)
        }
    }

    fn handle_socket_event(&mut self, _buffer: &mut MsgBuffer) -> bool {
        self.pull_socket(4, usize::MAX, true)
    }

    /// Read at most `max_rounds` recvmmsg calls and `max_pkts` datagrams.
    /// `flush` writes the TUN queue. The UDP pacer uses one short round and
    /// writes the next chunk on its own deadline.
    fn pull_socket(&mut self, max_rounds: usize, max_pkts: usize, flush: bool) -> bool {
        // HOT PATH
        // A side-thread TUN read copied every frame and lost more than the
        // syscall it hid. Read the TUN on this thread.
        let mut bufs = mem::take(&mut self.rx_bufs);
        let mut addrs = mem::take(&mut self.rx_addrs);
        let mut got = false;
        let mut again = false;
        let mut rounds = 0usize;
        let mut taken = 0usize;
        loop {
            if rounds >= max_rounds {
                again = flush && max_rounds >= 4;
                break;
            }
            // UDP already queued is paced a chunk at a time. Another full
            // batch here is how the inject outran iperf.
            if flush && self.udp_inject_backlog() {
                break;
            }
            if taken >= max_pkts {
                break;
            }
            rounds += 1;
            let room = max_pkts.saturating_sub(taken).min(bufs.len()).min(addrs.len());
            if room == 0 {
                break;
            }
            let n = match self.socket.receive_batch(&mut bufs[..room], &mut addrs[..room]) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => try_fail!(Err(e), "Failed to read from network socket: {}")
            };
            got = true;
            taken += n;
            let mut decrypt: HashMap<SocketAddr, (CryptoBoxHandle, Vec<MsgBuffer>), Hash> = HashMap::default();
            for i in 0..n {
                if bufs[i].is_empty() {
                    continue;
                }
                let src = mapped_addr(addrs[i]);
                self.traffic.count_in_traffic(src, bufs[i].len());
                let offload = self.use_crypto_pool()
                    && !is_init_message(bufs[i].message())
                    && self.peers.get(&src).and_then(|p| p.crypto.shared_handle()).is_some();
                if offload {
                    let crypto = self.peers.get(&src).unwrap().crypto.shared_handle().unwrap();
                    let packet = mem::replace(&mut bufs[i], self.take_spare());
                    decrypt.entry(src).or_insert_with(|| (crypto, Vec::new())).1.push(packet);
                    continue;
                }
                match self.handle_net_message(src, &mut bufs[i]) {
                    Err(e @ Error::CryptoInitFatal(_)) => {
                        debug!("Fatal crypto init error from {}: {}", src, e);
                        info!("Closing pending connection to {} due to error in crypto init", addr_nice(src));
                        self.pending_inits.remove(&src);
                        self.config.call_hook(
                            "peer_disconnected",
                            vec![
                                ("PEER", format!("{:?}", addr_nice(src))),
                                ("IFNAME", self.device.ifname().to_owned()),
                            ],
                            true
                        );
                    }
                    Err(e @ Error::CryptoInit(_)) => {
                        debug!("Recoverable init error from {}: {}", src, e);
                        info!("Ignoring invalid init message from peer {}", addr_nice(src));
                    }
                    Err(e) => error!("{}", e),
                    Ok(_) => {}
                }
            }
            let jobs = decrypt.len();
            for (src, (crypto, packets)) in decrypt {
                self.crypto_pool.submit(CryptoJob::Decrypt { crypto, packets, src });
            }
            for _ in 0..jobs {
                match self.crypto_pool.recv() {
                    Some(CryptoDone::Decrypted { src, packets }) => {
                        let _ = self.apply_decrypted(src, packets);
                    }
                    Some(CryptoDone::Failed(e)) => error!("{}", e),
                    Some(_) => {}
                    None => break
                }
            }
        }
        self.rx_bufs = bufs;
        self.rx_addrs = addrs;
        let _ = self.flush_pending_crypto();
        // A gap already armed owns the queue. Flushing with nothing new
        // would write the next chunk before its airtime.
        if flush && !(taken == 0 && self.udp_gap_deadline_ns != 0) {
            if let Err(e) = self.flush_tun_out_due() {
                error!("{}", e);
            }
        }
        if let Err(e) = self.flush_gso_out() {
            error!("{}", e);
        }
        let _ = self.flush_outbox();
        let _ = got;
        if again {
            return true;
        }
        if self.gro_hold_active() {
            return false;
        }
        if !self.tun_out.is_empty() || !self.gso_out.is_empty() || !self.outbox.is_empty() {
            return false;
        }
        false
    }

    /// Finish checksums and, for a run of equal UDP datagrams, ship one GSO aggregate.
    ///
    /// The span stops at [`Device::max_gso_payload`], which is one underlay
    /// datagram. Two MTU-sized datagrams therefore stay separate.
    fn udp_span_front(rest: &VecDeque<(MsgBuffer, Option<(u16, u16)>)>, max_len: usize) -> usize {
        if rest.len() < 2 {
            return 0;
        }
        let Some((first, _)) = rest.front() else {
            return 0;
        };
        // TCP segments and pure ACKs are not UDP trains. Skip the view allocation.
        if crate::payload::udp_segment(first.message()).is_none() {
            return 0;
        }
        let views: Vec<&[u8]> = rest.iter().map(|(buf, _)| buf.message()).collect();
        crate::payload::udp_gso_span(&views, max_len)
    }

    fn forward_plain_batch(&mut self, batch: &mut Vec<(MsgBuffer, Option<(u16, u16)>)>) {
        // Pop from the front. Shifting a Vec with `remove(0)`, and allocating a
        // view of every remaining packet, ran once per TCP segment. TCP is not
        // a UDP aggregate, so that work never coalesced anything.
        let mut rest = VecDeque::from(mem::take(batch));
        let max = self.device.max_gso_payload();
        while !rest.is_empty() {
            let n = Self::udp_span_front(&rest, max);
            if n >= 2 {
                let mut run = Vec::with_capacity(n);
                for _ in 0..n {
                    if let Some(pkt) = rest.pop_front() {
                        run.push(pkt);
                    }
                }
                self.emit_udp_gso(run);
            } else if let Some((buf, partial)) = rest.pop_front() {
                self.forward_one_plain(buf, partial);
            }
        }
    }

    fn forward_one_plain(&mut self, mut buf: MsgBuffer, partial: Option<(u16, u16)>) {
        let limit = self.device.max_plain_payload();
        if buf.len() > limit {
            // One datagram this large becomes an outer datagram the path
            // cannot carry. Drop it instead of IP-fragmenting it.
            debug!("Dropping {} byte inner packet; underlay fits {}", buf.len(), limit);
            self.traffic.count_dropped_payload(buf.len());
            self.buf_spare.push(buf);
            return;
        }
        if let Some((start, off)) = partial {
            crate::payload::finish_virtio_l4_csum(buf.message_mut(), start, off);
        }
        crate::payload::fix_ipv4_checksums(buf.message_mut());
        if let Err(e) = self.handle_interface_data(&mut buf) {
            error!("{}", e);
        }
        self.buf_spare.push(buf);
    }

    fn emit_udp_gso(&mut self, mut run: Vec<(MsgBuffer, Option<(u16, u16)>)>) {
        let Some((hdr, gso_size)) = crate::payload::udp_segment(run[0].0.message()) else {
            for (buf, partial) in run {
                self.forward_one_plain(buf, partial);
            }
            return;
        };
        let (mut acc, _) = run.remove(0);
        for (nxt, _) in run {
            let add = nxt.len().saturating_sub(hdr);
            let old = acc.len();
            if add == 0 || old + add > acc.remaining_capacity() {
                error!("UDP GSO aggregate exceeded the message buffer");
                self.buf_spare.push(nxt);
                continue;
            }
            acc.set_length(old + add);
            acc.message_mut()[old..].copy_from_slice(&nxt.message()[hdr..hdr + add]);
            self.buf_spare.push(nxt);
        }
        match crate::payload::seal_udp_gso(acc.message_mut(), hdr, gso_size) {
            Some(meta) => {
                if let Err(e) = self.handle_gso_from_tun(&mut acc, meta) {
                    error!("{}", e);
                }
            }
            None => error!("Failed to seal UDP GSO aggregate")
        }
        self.buf_spare.push(acc);
    }

    fn handle_device_event(&mut self, _buffer: &mut MsgBuffer) -> bool {
        // HOT PATH
        // The prefetch thread is the other reader of this TUN. Finish its batch
        // before this thread calls read, or the two reads split one packet stream.
        self.device.join_tun_prefetch();
        // mio registers the TUN fd edge-triggered. One read leaves the rest queued
        // with no further wakeup, so TCP stalls after a single batch. Drain until
        // the device would block, then encrypt and send once.
        if !self.outbox.is_empty() {
            let _ = self.flush_outbox();
            if !self.outbox.is_empty() {
                // The UDP socket is full. Reading more from the TUN would only
                // grow a queue the NIC cannot take, and then we would drop it.
                return false;
            }
        }
        if !self.tun_out.is_empty() {
            // The pacer writes this queue. Flushing here drops the airtime gap,
            // and the following socket read then outruns the inject.
            if self.udp_gap_deadline_ns != 0 {
                return false;
            }
            let _ = self.flush_tun_out_due();
            // A held batch is not a full TX queue. Keep reading the TUN so the
            // other direction moves while segments gather.
            if !self.tun_out.is_empty() && !self.gro_hold_active() {
                return false;
            }
        }
        if !self.gso_out.is_empty() {
            let _ = self.flush_gso_out();
            if !self.gso_out.is_empty() {
                return false;
            }
        }
        let mut got = false;
        let mut again = false;
        let mut plain_n = 0usize;
        let mut gso_n = 0usize;
        // `read_offload` returns Unsupported only when this device has no GSO reader.
        // A Blocked result means the TUN was drained; falling through into `read_batch`
        // would read and split the next aggregate.
        let mut use_batch = false;
        let mut plain_batch: Vec<(MsgBuffer, Option<(u16, u16)>)> = Vec::with_capacity(64);
        loop {
            let mut one = self.take_spare();
            match self.device.read_offload(&mut one) {
                Ok(OffloadRead::Unsupported) => {
                    self.buf_spare.push(one);
                    use_batch = true;
                    break;
                }
                Ok(OffloadRead::Blocked) => {
                    self.buf_spare.push(one);
                    break;
                }
                Ok(OffloadRead::Plain(partial)) => {
                    got = true;
                    plain_n += 1;
                    plain_batch.push((one, partial));
                    // A UDP flood never returns WouldBlock if we keep up with the
                    // writer. Cap the drain so this batch is flushed and the UDP
                    // socket is serviced before the spare pool allocates without bound.
                    if plain_n >= 64 {
                        again = true;
                        break;
                    }
                }
                Ok(OffloadRead::Gso(meta)) => {
                    got = true;
                    gso_n += 1;
                    // Keep datagrams that arrived before this aggregate in order.
                    self.forward_plain_batch(&mut plain_batch);
                    if let Err(e) = self.handle_gso_from_tun(&mut one, meta) {
                        error!("{}", e);
                    }
                    self.buf_spare.push(one);
                    // One aggregate is already a full segment train. Ship it before
                    // reading the next so TCP does not wait on a second 64KB encrypt.
                    let _ = self.flush_pending_crypto();
                    let _ = self.flush_outbox();
                    if gso_n >= 8 {
                        again = true;
                        break;
                    }
                }
                Err(e) => {
                    self.buf_spare.push(one);
                    self.forward_plain_batch(&mut plain_batch);
                    try_fail!(Err(e), "Failed to read from device: {}");
                }
            }
        }
        self.forward_plain_batch(&mut plain_batch);
        if use_batch {
            loop {
                let mut bufs = mem::take(&mut self.tun_bufs);
                let n = match self.device.read_batch(&mut bufs) {
                    Ok(0) => {
                        self.tun_bufs = bufs;
                        break;
                    }
                    Ok(n) => n,
                    Err(Error::DeviceIo(_, ref e)) if e.kind() == io::ErrorKind::WouldBlock => {
                        self.tun_bufs = bufs;
                        break;
                    }
                    Err(Error::Device(_)) => {
                        self.tun_bufs = bufs;
                        break;
                    }
                    Err(e) => try_fail!(Err(e), "Failed to read from device: {}")
                };
                got = true;
                for buf in bufs.iter_mut().take(n) {
                    if let Err(e) = self.handle_interface_data(buf) {
                        error!("{}", e);
                    }
                }
                self.tun_bufs = bufs;
            }
        }
        let _ = self.flush_pending_crypto();
        if let Err(e) = self.flush_tun_out_due() {
            error!("{}", e);
        }
        if let Err(e) = self.flush_gso_out() {
            error!("{}", e);
        }
        let _ = self.flush_outbox();
        let _ = got;
        if again {
            return true;
        }
        if self.gro_hold_active() {
            return false;
        }
        if !self.tun_out.is_empty() || !self.gso_out.is_empty() || !self.outbox.is_empty() {
            return false;
        }
        false
    }

    /// The main method of the node
    ///
    /// This method will use epoll to wait in the sockets and the device at the same time.
    /// It will read from the sockets, decode and decrypt the message and then call the
    /// `handle_net_message` method. It will also read from the device and call
    /// `handle_interface_data` for each packet read.
    /// Also, this method will call `housekeep` every second.
    pub fn run(&mut self) {
        pin_datapath_thread();
        let mut ctrlc = CtrlC::new();
        let mut waiter = try_fail!(WaitImpl::new(&self.socket, &self.device, 1000), "Failed to setup poll: {}");
        let mut buffer = MsgBuffer::new(SPACE_BEFORE);
        let mut poll_error = false;
        self.defer_tun_flush = true;
        self.config.call_hook("vpn_started", vec![("IFNAME", self.device.ifname())], true);
        // mio is edge-triggered. On every wakeup, drain both the TUN and the UDP
        // socket until they would block so a single edge cannot leave packets stuck.
        for evt in waiter {
            match evt {
                WaitResult::Error(err) => {
                    if poll_error {
                        fail!("Poll wait failed again: {}", err);
                    }
                    debug!("Poll wait failed: {}, retrying...", err);
                    poll_error = true;
                }
                WaitResult::Timeout => {
                    let _ = self.flush_tun_out_due();
                    let _ = self.flush_gso_out();
                    let _ = self.flush_outbox();
                }
                WaitResult::Socket | WaitResult::Device if !CtrlC::is_paused() => {
                    // mio is edge-triggered, so leave this only after both fds
                    // would block. Each handler flushes after a bounded batch and
                    // returns true when the peer is still producing, which keeps
                    // the UDP socket and the TUN interleaved.
                    loop {
                        if self.pace_udp_inject() {
                            if self.next_housekeep < TS::now() {
                                if !CtrlC::is_paused() {
                                    if let Err(e) = self.housekeep() {
                                        error!("{}", e)
                                    }
                                }
                                self.next_housekeep = TS::now() + 1
                            }
                            continue;
                        }
                        let more_dev = self.handle_device_event(&mut buffer);
                        let more_sock = self.handle_socket_event(&mut buffer);
                        if self.next_housekeep < TS::now() {
                            if !CtrlC::is_paused() {
                                if let Err(e) = self.housekeep() {
                                    error!("{}", e)
                                }
                            }
                            self.next_housekeep = TS::now() + 1
                        }
                        if more_dev || more_sock {
                            continue;
                        }
                        // The socket handler kicked a TUN read. Drain it before
                        // sleeping: the bytes are no longer in the kernel queue,
                        // so an edge-triggered poll will not wake for them.
                        self.device.join_tun_prefetch();
                        if self.device.tun_prefetch_pending() {
                            continue;
                        }
                        // Gather a few more inbound segments before the TUN write.
                        // Wait only for the next datagram. The TUN and a UDP socket
                        // that is not full are always writable, so watching that
                        // wakes immediately and the batch never grows. Watching the
                        // TUN for reads also busy-spins when the queue stays
                        // readable, and that stall dropped a whole TCP run. The TUN
                        // is read at the top of this loop, between datagrams.
                        // An inject gap stays armed after a short batch, when the
                        // queue is already empty. wait_for_io on a writable TUN
                        // would return immediately and the next read would write
                        // with no airtime.
                        if self.udp_gap_deadline_ns != 0 {
                            continue;
                        }
                        #[cfg(target_os = "linux")]
                        if self.gro_hold_active() {
                            let now = crate::net::mono_now().unwrap_or(0);
                            let remain_ns = self.gro_deadline_ns.saturating_sub(now);
                            let remain_us = (remain_ns / 1_000).clamp(1, 1_000_000) as i64;
                            let _ = crate::net::wait_for_read(self.socket.get_fd(), remain_us);
                            continue;
                        }
                        // A full UDP socket used to be waited out inside send, which
                        // left the opposite direction unread. Wait until that socket
                        // can take the outbox or deliver inbound packets. Do not
                        // watch the TUN for read: it stays readable, and polling it
                        // spins without draining it.
                        #[cfg(target_os = "linux")]
                        if !self.outbox.is_empty() || !self.tun_out.is_empty() || !self.gso_out.is_empty() {
                            let _ = crate::net::wait_for_io(
                                self.socket.get_fd(),
                                self.device.get_fd(),
                                !self.outbox.is_empty(),
                                !self.tun_out.is_empty() || !self.gso_out.is_empty(),
                                1
                            );
                            continue;
                        }
                        break;
                    }
                }
                WaitResult::Socket | WaitResult::Device => {}
            }
            if self.next_housekeep < TS::now() {
                // COLD PATH
                poll_error = false;
                if ctrlc.was_pressed() {
                    break;
                }
                if !CtrlC::is_paused() {
                    if let Err(e) = self.housekeep() {
                        error!("{}", e)
                    }
                }
                self.next_housekeep = TS::now() + 1
            }
        }
        info!("Shutting down...");
        self.config.call_hook("vpn_shutdown", vec![("IFNAME", self.device.ifname())], true);
        buffer.clear();
        self.broadcast_msg(MESSAGE_TYPE_CLOSE, &mut buffer).ok();
        if let Some(ref path) = self.config.beacon_store {
            let path = Path::new(path);
            if path.exists() {
                info!("Removing beacon file");
                if let Err(e) = fs::remove_file(path) {
                    error!("Failed to remove beacon file: {}", e)
                }
            }
        }
    }
}

#[cfg(test)] use super::device::MockDevice;
#[cfg(test)] use super::net::MockSocket;
#[cfg(test)] use super::util::MockTimeSource;

#[cfg(test)]
impl<P: Protocol> GenericCloud<MockDevice, P, MockSocket, MockTimeSource> {
    pub fn socket(&mut self) -> &mut MockSocket {
        &mut self.socket
    }

    pub fn device(&mut self) -> &mut MockDevice {
        &mut self.device
    }

    pub fn trigger_socket_event(&mut self) {
        let mut buffer = MsgBuffer::new(SPACE_BEFORE);
        self.handle_socket_event(&mut buffer);
    }

    pub fn trigger_device_event(&mut self) {
        let mut buffer = MsgBuffer::new(SPACE_BEFORE);
        self.handle_device_event(&mut buffer);
    }

    pub fn trigger_housekeep(&mut self) {
        assert!(self.housekeep().is_ok())
    }

    pub fn is_connected(&self, addr: &SocketAddr) -> bool {
        self.peers.contains_key(addr)
    }

    pub fn own_addresses(&self) -> &[SocketAddr] {
        &self.own_addresses
    }

    pub fn get_num(&self) -> usize {
        self.socket.address().unwrap().port() as usize
    }

    #[cfg(test)]
    pub fn test_node_id(&self) -> NodeId {
        self.node_id
    }

    #[cfg(test)]
    pub fn test_peer_rtt(&self, addr: &SocketAddr) -> Option<u64> {
        self.peers.get(addr).map(|peer| peer.rtt_us)
    }

    #[cfg(test)]
    pub fn test_forget_e2e(&mut self, id: &NodeId) {
        self.known_e2e.remove(id);
    }

    #[cfg(test)]
    pub fn test_fail_peer_crypto(&mut self, addr: &SocketAddr) {
        if let Some(peer) = self.peers.get_mut(addr) {
            let _ = peer.crypto.with_mut(|crypto| crypto.fail_housekeep());
        }
    }
}

#[cfg(test)]
mod gro_hold_tests {
    use super::gro_batch_ready;

    #[test]
    fn gro_batch_waits_for_a_train_and_then_flushes() {
        let start = 1_000_000u64;
        let deadline = start + super::GRO_HOLD_NS;
        // One socket read is about eight segments. Flushing there ACKs every
        // eight. The train has to outlast that read; the deadline still writes
        // a short batch, and an unarmed hold still writes immediately.
        assert!(super::GRO_TRAIN > 8);
        assert!(!gro_batch_ready(1, start, deadline));
        assert!(!gro_batch_ready(8, start, deadline));
        assert!(!gro_batch_ready(super::GRO_TRAIN - 1, start, deadline));
        assert!(gro_batch_ready(super::GRO_TRAIN, start, deadline));
        assert!(gro_batch_ready(8, deadline, deadline));
        assert!(gro_batch_ready(3, 0, 0));
    }
}

#[cfg(test)]
mod ensure_peer_port_tests {
    use super::ensure_peer_port;

    #[test]
    fn bracketed_ipv6_keeps_an_explicit_port() {
        assert_eq!(ensure_peer_port("[fd00:88::2]:3210"), "[fd00:88::2]:3210");
        assert_eq!(ensure_peer_port("wss://[fd00:88::2]:3210"), "[fd00:88::2]:3210");
        assert_eq!(ensure_peer_port("[fd00:88::2]"), "[fd00:88::2]:3210");
        assert_eq!(ensure_peer_port("fd00:88::2"), "[fd00:88::2]:3210");
    }

    #[test]
    fn ipv4_and_hostnames_gain_a_port_once() {
        assert_eq!(ensure_peer_port("192.168.88.2"), "192.168.88.2:3210");
        assert_eq!(ensure_peer_port("192.168.88.2:3210"), "192.168.88.2:3210");
        assert_eq!(ensure_peer_port("example.com"), "example.com:3210");
        assert_eq!(ensure_peer_port("example.com:3210"), "example.com:3210");
        assert_eq!(ensure_peer_port("ws://example.com"), "example.com:3210");
    }
}

#[cfg(test)]
mod ipv6_claim_tests {
    use super::configured_ipv6_host_claim;
    use crate::types::Address;
    use std::str::FromStr;

    #[test]
    fn ipv6_overlay_claims_the_host_not_the_prefix() {
        let range = configured_ipv6_host_claim(Some("fd00:8::1/64")).unwrap();
        assert_eq!(range.prefix_len, 128);
        assert!(range.matches(Address::from_str("fd00:8::1").unwrap()));
        assert!(!range.matches(Address::from_str("fd00:8::2").unwrap()));
        assert!(configured_ipv6_host_claim(Some("10.8.0.1/24")).is_none());
        assert!(configured_ipv6_host_claim(None).is_none());
    }
}

/// CPUs in the fastest frequency cluster, lowest id first. Empty when every
/// CPU reports the same maximum, so a uniform machine is left unpinned.
pub(crate) fn fast_cluster(freqs: &[(usize, u64)]) -> Vec<usize> {
    let Some(max) = freqs.iter().map(|(_, freq)| *freq).max() else {
        return Vec::new();
    };
    let Some(min) = freqs.iter().map(|(_, freq)| *freq).min() else {
        return Vec::new();
    };
    if max == 0 || max == min {
        return Vec::new();
    }
    let mut cpus: Vec<usize> = freqs.iter().filter(|(_, freq)| *freq == max).map(|(cpu, _)| *cpu).collect();
    cpus.sort_unstable();
    cpus.dedup();
    cpus
}

#[cfg(target_os = "linux")]
fn online_cpu_freqs() -> Vec<(usize, u64)> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir("/sys/devices/system/cpu") else {
        return out;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some(rest) = name.strip_prefix("cpu") else {
            continue;
        };
        let Ok(cpu) = rest.parse::<usize>() else {
            continue;
        };
        let Ok(text) = fs::read_to_string(entry.path().join("cpufreq/cpuinfo_max_freq")) else {
            continue;
        };
        let Ok(freq) = text.trim().parse::<u64>() else {
            continue;
        };
        out.push((cpu, freq));
    }
    out
}

#[cfg(target_os = "linux")]
fn set_thread_affinity(cpus: &[usize]) -> bool {
    if cpus.is_empty() || cpus.iter().any(|cpu| *cpu >= 1024) {
        return false;
    }
    let mut mask = [0u64; 16];
    for cpu in cpus {
        mask[cpu / 64] |= 1u64 << (cpu % 64);
    }
    let rc = unsafe {
        libc::sched_setaffinity(0, std::mem::size_of_val(&mask), mask.as_ptr() as *const libc::cpu_set_t)
    };
    rc == 0
}

/// One sibling group inside the fast cluster. Two processes with different
/// pids land on different physical cores. Pinning both to every fast CPU let
/// the scheduler park them on the interrupt core together.
#[cfg(target_os = "linux")]
pub(crate) fn datapath_cpus(groups: &[Vec<usize>], slot: usize) -> Vec<usize> {
    if groups.is_empty() {
        return Vec::new();
    }
    groups[slot % groups.len()].clone()
}

/// A different physical core from [`datapath_cpus`] for the same pid, so the
/// TUN read overlaps encryption instead of sharing one core.
#[cfg(target_os = "linux")]
pub(crate) fn reader_slot(ngroups: usize, main_slot: usize) -> usize {
    if ngroups < 2 {
        return main_slot;
    }
    (main_slot + ngroups / 2) % ngroups
}

#[cfg(target_os = "linux")]
fn sibling_groups(cluster: &[usize]) -> Vec<Vec<usize>> {
    let members: std::collections::BTreeSet<usize> = cluster.iter().copied().collect();
    let mut seen = std::collections::BTreeSet::new();
    let mut groups = Vec::new();
    for cpu in cluster {
        if !seen.insert(*cpu) {
            continue;
        }
        let path = format!("/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list");
        let text = fs::read_to_string(path).unwrap_or_default();
        let mut group: Vec<usize> = parse_cpu_list(&text).into_iter().filter(|cpu| members.contains(cpu)).collect();
        if group.is_empty() {
            group.push(*cpu);
        }
        group.sort_unstable();
        group.dedup();
        for cpu in &group {
            seen.insert(*cpu);
        }
        groups.push(group);
    }
    groups
}

#[cfg(target_os = "linux")]
fn parse_cpu_list(list: &str) -> Vec<usize> {
    let mut out = Vec::new();
    for part in list.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((start, end)) = part.split_once('-') {
            let Ok(start) = start.parse::<usize>() else {
                continue;
            };
            let Ok(end) = end.parse::<usize>() else {
                continue;
            };
            if end >= start && end - start < 4096 {
                out.extend(start..=end);
            }
        } else if let Ok(cpu) = part.parse::<usize>() {
            out.push(cpu);
        }
    }
    out
}

/// Hybrid chips report the same capacity for a 4.7 GHz core and a 3.5 GHz
/// core, so the scheduler will park this thread on the slow cluster. Pin this
/// thread to every fast CPU. One sibling group was slower: the thread stayed
/// on a busy core. Leaving out the interrupt cores was slower too. A uniform
/// machine is left alone.
#[cfg(target_os = "linux")]
fn pin_datapath_thread() {
    let cpus = fast_cluster(&online_cpu_freqs());
    if cpus.is_empty() {
        return;
    }
    if set_thread_affinity(&cpus) {
        info!("Pinned datapath thread to cpus {cpus:?}");
    }
}

/// The TUN prefetch thread inherits the datapath pin. Move it to another fast
/// core so the read is not fighting the encrypt loop for the same core.
#[cfg(target_os = "linux")]
pub(crate) fn pin_reader_thread() {
    let groups = sibling_groups(&fast_cluster(&online_cpu_freqs()));
    if groups.len() < 2 {
        return;
    }
    let slot = reader_slot(groups.len(), std::process::id() as usize);
    let cpus = datapath_cpus(&groups, slot);
    if set_thread_affinity(&cpus) {
        info!("Pinned TUN read thread to cpus {cpus:?}");
    }
}

#[cfg(not(target_os = "linux"))]
fn pin_datapath_thread() {}

#[cfg(test)]
mod affinity_tests {
    use super::fast_cluster;

    #[test]
    fn fast_cluster_skips_a_uniform_machine() {
        assert!(fast_cluster(&[]).is_empty());
        assert!(fast_cluster(&[(0, 0), (1, 0)]).is_empty());
        assert!(fast_cluster(&[(0, 4700), (1, 4700), (2, 4700)]).is_empty());
    }

    #[test]
    fn fast_cluster_is_every_cpu_at_the_top_frequency() {
        assert_eq!(fast_cluster(&[(0, 4700), (12, 3500), (2, 4700)]), vec![0, 2]);
        assert_eq!(fast_cluster(&[(3, 2000), (8, 4000), (1, 4000)]), vec![1, 8]);
    }

    #[test]
    fn datapath_cpus_are_one_sibling_group() {
        let groups = vec![vec![0, 1], vec![2, 3], vec![4, 5]];
        assert_eq!(super::datapath_cpus(&groups, 0), vec![0, 1]);
        assert_eq!(super::datapath_cpus(&groups, 1), vec![2, 3]);
        assert_eq!(super::datapath_cpus(&groups, 5), vec![4, 5]);
        assert!(super::datapath_cpus(&[], 3).is_empty());
        assert_eq!(super::reader_slot(4, 1), 3);
        assert_ne!(1 % 4, super::reader_slot(4, 1));
        assert_eq!(super::reader_slot(1, 0), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn datapath_thread_pins_only_when_a_slower_cluster_exists() {
        let freqs = super::online_cpu_freqs();
        let want = fast_cluster(&freqs);
        let before = allowed_cpus();
        let _restore = AffinityGuard(before.clone());
        super::pin_datapath_thread();
        let after = allowed_cpus();
        if want.is_empty() {
            assert_eq!(after, before, "uniform machine changed affinity");
        } else {
            assert_eq!(after, want, "freqs {freqs:?}");
        }
    }

    #[cfg(target_os = "linux")]
    struct AffinityGuard(Vec<usize>);

    #[cfg(target_os = "linux")]
    impl Drop for AffinityGuard {
        fn drop(&mut self) {
            let _ = super::set_thread_affinity(&self.0);
        }
    }

    #[cfg(target_os = "linux")]
    fn allowed_cpus() -> Vec<usize> {
        let text = std::fs::read_to_string("/proc/thread-self/status").expect("status");
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("Cpus_allowed_list:") {
                return parse_cpu_list(rest);
            }
        }
        panic!("Cpus_allowed_list missing:\n{text}");
    }

    #[cfg(target_os = "linux")]
    fn parse_cpu_list(list: &str) -> Vec<usize> {
        let mut out = Vec::new();
        for part in list.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if let Some((start, end)) = part.split_once('-') {
                let start: usize = start.parse().expect(start);
                let end: usize = end.parse().expect(end);
                out.extend(start..=end);
            } else {
                out.push(part.parse().expect(part));
            }
        }
        out
    }
}
