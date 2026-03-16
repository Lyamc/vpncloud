// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::{collections::HashMap, fs::File, hash::BuildHasherDefault, marker::PhantomData, net::SocketAddr};

use fnv::FnvHasher;
use smallvec::SmallVec;

use crate::{
    beacon::BeaconSerializer,
    config::Config,
    crypto::{Crypto, PeerCrypto},
    device::Device,
    messages::{AddrList, NodeInfo},
    net::Socket,
    payload::Protocol,
    poll::Pollable,
    port_forwarding::PortForwarding,
    table::ClaimTable,
    traffic::TrafficStats,
    types::{NodeId, RangeList},
    util::{Time, TimeSource}
};

pub type Hash = BuildHasherDefault<FnvHasher>;

pub(super) struct PeerData {
    pub(super) addrs: AddrList,
    #[allow(dead_code)] // TODO: export in status
    pub(super) last_seen: Time,
    pub(super) timeout: Time,
    pub(super) peer_timeout: u16,
    pub(super) node_id: NodeId,
    pub(super) crypto: PeerCrypto<NodeInfo>
}

#[derive(Clone)]
pub struct ReconnectEntry {
    pub(super) address: Option<(String, Time)>,
    pub(super) resolved: AddrList,
    pub(super) tries: u16,
    pub(super) timeout: u16,
    pub(super) next: Time,
    pub(super) final_timeout: Option<Time>
}

pub struct GenericCloud<D: Device + Pollable, P: Protocol, S: Socket + Pollable, TS: TimeSource> {
    pub(crate) node_id: NodeId,
    pub(crate) config: Config,
    pub(crate) learning: bool,
    pub(crate) broadcast: bool,
    pub(super) peers: HashMap<SocketAddr, PeerData, Hash>,
    pub(super) reconnect_peers: SmallVec<[ReconnectEntry; 3]>,
    pub(super) own_addresses: AddrList,
    pub(super) pending_inits: HashMap<SocketAddr, PeerCrypto<NodeInfo>, Hash>,
    pub(crate) table: ClaimTable<TS>,
    pub(crate) socket: S,
    pub(crate) device: D,
    pub(crate) claims: RangeList,
    pub(crate) crypto: Crypto,
    pub(super) next_peers: Time,
    pub(super) peer_timeout_publish: u16,
    pub(super) update_freq: u16,
    pub(crate) stats_file: Option<File>,
    pub(crate) statsd_server: Option<String>,
    pub(super) next_housekeep: Time,
    pub(super) next_stats_out: Time,
    pub(super) next_beacon: Time,
    pub(super) next_own_address_reset: Time,
    pub(crate) port_forwarding: Option<PortForwarding>,
    pub(crate) traffic: TrafficStats,
    pub(crate) beacon_serializer: BeaconSerializer<TS>,
    pub(crate) _dummy_p: PhantomData<P>,
    pub(crate) _dummy_ts: PhantomData<TS>
}
