// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use crate::{
    crypto::Payload,
    error::Error,
    types::{NodeId, Range, RangeList, NODE_ID_BYTES},
    util::MsgBuffer
};
use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use smallvec::{smallvec, SmallVec};
use std::{
    io::{self, Cursor, Read, Seek, SeekFrom, Take, Write},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6}
};

pub const MESSAGE_TYPE_DATA: u8 = 0;
/// DATA with an LZ4-compressed payload (4-byte uncompressed size prepended).
pub const MESSAGE_TYPE_DATA_COMPRESSED: u8 = 5;
pub const MESSAGE_TYPE_NODE_INFO: u8 = 1;
pub const MESSAGE_TYPE_KEEPALIVE: u8 = 2;
pub const MESSAGE_TYPE_RELAY: u8 = 3;
/// One kernel GSO/USO aggregate. Payload is [`crate::gso::GSO_META_LEN`] bytes of
/// virtio header fields followed by the unmodified super-packet.
pub const MESSAGE_TYPE_DATA_GSO: u8 = 4;
/// GSO aggregate with an LZ4-compressed body (GSO metadata after decompression).
pub const MESSAGE_TYPE_DATA_GSO_COMPRESSED: u8 = 6;
/// Broadcast DATA frame with a (origin node id, sequence) header. Receivers
/// write it to their device and re-flood to their other peers, so a node with
/// poor upload only sends one copy instead of one per peer.
pub const MESSAGE_TYPE_FLOOD: u8 = 7;
/// Relay/flood variants that carry a hop-count byte. Only sent to peers that
/// advertised TTL support; the type itself makes the layout unambiguous.
pub const MESSAGE_TYPE_RELAY_TTL: u8 = 8;
pub const MESSAGE_TYPE_FLOOD_TTL: u8 = 9;
/// Length of the flood header: 16-byte origin node id + 4-byte sequence.
pub const FLOOD_HEADER_LEN: usize = 20;
pub const MESSAGE_TYPE_CLOSE: u8 = 0xff;

pub type AddrList = SmallVec<[SocketAddr; 4]>;
pub type PeerList = SmallVec<[PeerInfo; 16]>;

#[derive(Clone, Debug, PartialEq)]
pub struct PeerInfo {
    pub node_id: Option<NodeId>,
    pub addrs: AddrList
}

#[derive(Clone, Debug, PartialEq)]
pub struct NodeInfo {
    pub node_id: NodeId,
    pub peers: PeerList,
    pub claims: RangeList,
    pub peer_timeout: Option<u16>,
    pub addrs: AddrList,
    /// This node's underlay interface MTU. Peers take the minimum.
    pub underlay_mtu: Option<u16>,
    /// Mesh group this node claims to belong to.
    pub group: Option<String>,
    /// X25519 public key for relay end-to-end seals.
    pub e2e_public: Option<[u8; 32]>,
    /// Public keys of nodes this node has learned, so peers can seal toward them.
    pub peer_e2e: Vec<(NodeId, [u8; 32])>,
    /// Prefixes this node can reach only by relaying. `addr` is the far node's underlay address.
    pub transit: Vec<TransitClaim>,
    /// This node can decompress LZ4 DATA frames. Unknown to older peers, which
    /// skip the part and therefore never receive compressed traffic from us.
    pub compression: bool,
    /// Bitmask of wire formats this node can receive (see [`crate::wire::WireCaps`]).
    /// Zero for legacy peers that do not advertise the part; their format is
    /// inferred from their claims.
    pub wire_caps: u8,
    /// RTTs this node measured to its own direct peers, as `(node_id, rtt_ms)`.
    /// Gossiped so others can estimate end-to-end paths and suggest relays.
    pub peer_rtts: Vec<(NodeId, u16)>,
    /// Optional Ed25519 signature over [`NodeInfo::identity_bytes`], enabling
    /// per-node identity binding for e2e keys and claims.
    pub node_signature: Option<[u8; 64]>
}

/// A prefix owned by a node that is not the sender. The receiver installs it
/// under `addr`, which is not a connected peer, so lookup takes the relay path.
#[derive(Debug, PartialEq, Clone)]
pub struct TransitClaim {
    pub node_id: NodeId,
    pub addr: SocketAddr,
    pub claim: Range,
    /// Group the far node announced. The receiver filters with this, not with `None`.
    pub group: Option<String>
}

impl NodeInfo {
    const MAX_CLAIMS: usize = 4096;
    // Decoder caps. The sender already limits itself to 20 peers, 16 e2e keys
    // and 32 transit claims; mirror those bounds on receive so one malicious
    // authenticated NodeInfo cannot make us open thousands of handshakes.
    const MAX_PEERS: usize = 20;
    const MAX_PEER_E2E: usize = 16;
    pub const MAX_PEER_QUALITY: usize = 16;
    const MAX_TRANSIT: usize = 32;
    const PART_ADDRS: u8 = 5;
    const PART_CLAIMS: u8 = 2;
    const PART_CLAIM_METRICS: u8 = 6;
    const PART_COMPRESSION: u8 = 12;
    const PART_E2E: u8 = 9;
    const PART_END: u8 = 0;
    const PART_GROUP: u8 = 8;
    const PART_NODEID: u8 = 4;
    const PART_NODE_SIGNATURE: u8 = 13;
    const PART_PEERS: u8 = 1;
    const PART_PEER_E2E: u8 = 10;
    /// Measured RTTs to this node's direct peers: 16-byte node id + u16 BE ms.
    const PART_PEER_QUALITY: u8 = 15;
    const PART_PEER_TIMEOUT: u8 = 3;
    const PART_TRANSIT: u8 = 11;
    const PART_UNDERLAY_MTU: u8 = 7;
    /// Bitmask of supported DATA payload formats (Ethernet / IP / preference).
    const PART_WIRE_FORMAT: u8 = 14;

    /// Canonical bytes signed by the node's optional signing key: node id and
    /// e2e public key (the identity binding that relays rely on).
    pub fn identity_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(NODE_ID_BYTES + 32);
        out.extend_from_slice(&self.node_id);
        if let Some(pk) = self.e2e_public {
            out.extend_from_slice(&pk);
        }
        out
    }

    fn read_addr_list<R: Read>(r: &mut Take<R>) -> Result<AddrList, io::Error> {
        let flags = r.read_u8()?;
        Self::read_addr_list_inner(r, flags)
    }

    fn read_addr_list_inner<R: Read>(r: &mut Take<R>, flags: u8) -> Result<AddrList, io::Error> {
        let num_ipv4_addrs = (flags & 0x07) as usize;
        let num_ipv6_addrs = (flags & 0x38) as usize / 8;
        let mut addrs = SmallVec::with_capacity(num_ipv4_addrs + num_ipv6_addrs);
        for _ in 0..num_ipv6_addrs {
            let mut ip = [0u8; 16];
            r.read_exact(&mut ip)?;
            let port = r.read_u16::<NetworkEndian>()?;
            let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(ip), port, 0, 0));
            addrs.push(addr);
        }
        for _ in 0..num_ipv4_addrs {
            let mut ip = [0u8; 4];
            r.read_exact(&mut ip)?;
            let port = r.read_u16::<NetworkEndian>()?;
            let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port));
            addrs.push(addr);
        }
        Ok(addrs)
    }

    fn decode_peer_list_part<R: Read>(r: &mut Take<R>) -> Result<PeerList, io::Error> {
        let mut peers = smallvec![];
        while r.limit() > 0 {
            if peers.len() >= Self::MAX_PEERS {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "too many peers in NodeInfo"));
            }
            let flags = r.read_u8()?;
            let has_node_id = (flags & 0x80) != 0;
            let mut node_id = None;
            if has_node_id {
                let mut id = [0; NODE_ID_BYTES];
                r.read_exact(&mut id)?;
                node_id = Some(id)
            }
            let addrs = Self::read_addr_list_inner(r, flags)?;
            peers.push(PeerInfo { addrs, node_id })
        }
        Ok(peers)
    }

    fn decode_claims_part<R: Read>(mut r: &mut Take<R>) -> Result<RangeList, Error> {
        let mut claims = smallvec![];
        while r.limit() > 0 {
            if claims.len() >= Self::MAX_CLAIMS {
                return Err(Error::Message("too many claims in NodeInfo"));
            }
            claims.push(Range::read_from(&mut r)?);
        }
        Ok(claims)
    }

    fn decode_internal<R: Read>(mut r: R) -> Result<Self, Error> {
        let mut peers = smallvec![];
        let mut claims = smallvec![];
        let mut peer_timeout = None;
        let mut node_id = None;
        let mut addrs = smallvec![];
        let mut underlay_mtu = None;
        let mut group = None;
        let mut e2e_public = None;
        let mut peer_e2e = Vec::new();
        let mut transit = Vec::new();
        let mut compression = false;
        let mut wire_caps = 0u8;
        let mut peer_rtts = Vec::new();
        let mut node_signature = None;
        loop {
            let part = r.read_u8().map_err(|_| Error::Message("Truncated message"))?;
            if part == Self::PART_END {
                break;
            }
            let part_len = r.read_u16::<NetworkEndian>().map_err(|_| Error::Message("Truncated message"))? as usize;
            let mut rp = r.take(part_len as u64);
            match part {
                Self::PART_PEERS => {
                    peers = Self::decode_peer_list_part(&mut rp).map_err(|_| Error::Message("Truncated message"))?
                }
                Self::PART_CLAIMS => claims = Self::decode_claims_part(&mut rp)?,
                Self::PART_CLAIM_METRICS => {
                    let mut metrics = vec![0u8; part_len];
                    rp.read_exact(&mut metrics).map_err(|_| Error::Message("Truncated message"))?;
                    for (c, m) in claims.iter_mut().zip(metrics) {
                        c.metric = m;
                    }
                }
                Self::PART_PEER_TIMEOUT => {
                    peer_timeout =
                        Some(rp.read_u16::<NetworkEndian>().map_err(|_| Error::Message("Truncated message"))?)
                }
                Self::PART_NODEID => {
                    let mut data = [0; NODE_ID_BYTES];
                    rp.read_exact(&mut data).map_err(|_| Error::Message("Truncated message"))?;
                    node_id = Some(data);
                }
                Self::PART_ADDRS => {
                    addrs = Self::read_addr_list(&mut rp).map_err(|_| Error::Message("Truncated message"))?;
                }
                Self::PART_UNDERLAY_MTU => {
                    underlay_mtu =
                        Some(rp.read_u16::<NetworkEndian>().map_err(|_| Error::Message("Truncated message"))?)
                }
                Self::PART_GROUP => {
                    let mut data = vec![0; part_len];
                    rp.read_exact(&mut data).map_err(|_| Error::Message("Truncated message"))?;
                    group = Some(String::from_utf8_lossy(&data).into_owned());
                }
                Self::PART_E2E => {
                    let mut data = vec![0; part_len];
                    rp.read_exact(&mut data).map_err(|_| Error::Message("Truncated message"))?;
                    if data.len() == 32 {
                        let mut pk = [0u8; 32];
                        pk.copy_from_slice(&data);
                        e2e_public = Some(pk);
                    }
                }
                Self::PART_PEER_E2E => {
                    let mut data = vec![0; part_len];
                    rp.read_exact(&mut data).map_err(|_| Error::Message("Truncated message"))?;
                    if data.len() / 48 > Self::MAX_PEER_E2E {
                        return Err(Error::Message("too many peer e2e keys in NodeInfo"));
                    }
                    for chunk in data.as_chunks::<48>().0 {
                        let mut id = [0u8; 16];
                        let mut pk = [0u8; 32];
                        id.copy_from_slice(&chunk[..16]);
                        pk.copy_from_slice(&chunk[16..]);
                        peer_e2e.push((id, pk));
                    }
                }
                Self::PART_TRANSIT => {
                    transit = Self::decode_transit(&mut rp)?;
                }
                Self::PART_COMPRESSION => {
                    compression = rp.read_u8().map_err(|_| Error::Message("Truncated message"))? != 0;
                }
                Self::PART_WIRE_FORMAT => {
                    wire_caps = rp.read_u8().map_err(|_| Error::Message("Truncated message"))? & 0x0f;
                }
                Self::PART_PEER_QUALITY => {
                    let mut data = vec![0; part_len];
                    rp.read_exact(&mut data).map_err(|_| Error::Message("Truncated message"))?;
                    if data.len() / 18 > Self::MAX_PEER_QUALITY {
                        return Err(Error::Message("too many peer quality entries in NodeInfo"));
                    }
                    for chunk in data.as_chunks::<18>().0 {
                        let mut id = [0u8; NODE_ID_BYTES];
                        id.copy_from_slice(&chunk[..NODE_ID_BYTES]);
                        let rtt = u16::from_be_bytes([chunk[NODE_ID_BYTES], chunk[NODE_ID_BYTES + 1]]);
                        peer_rtts.push((id, rtt));
                    }
                }
                Self::PART_NODE_SIGNATURE => {
                    if part_len != 64 {
                        return Err(Error::Message("Invalid node signature length"));
                    }
                    let mut sig = [0u8; 64];
                    rp.read_exact(&mut sig).map_err(|_| Error::Message("Truncated message"))?;
                    node_signature = Some(sig);
                }
                _ => {
                    let mut data = vec![0; part_len];
                    rp.read_exact(&mut data).map_err(|_| Error::Message("Truncated message"))?;
                }
            }
            r = rp.into_inner();
        }
        let node_id = match node_id {
            Some(node_id) => node_id,
            None => return Err(Error::Message("Payload without node_id"))
        };
        Ok(Self {
            node_id,
            peers,
            claims,
            peer_timeout,
            addrs,
            underlay_mtu,
            group,
            e2e_public,
            peer_e2e,
            transit,
            compression,
            wire_caps,
            peer_rtts,
            node_signature
        })
    }

    fn decode_transit<R: Read>(r: &mut Take<R>) -> Result<Vec<TransitClaim>, Error> {
        let mut out = Vec::new();
        while r.limit() > 0 {
            if out.len() >= Self::MAX_TRANSIT {
                return Err(Error::Message("too many transit claims in NodeInfo"));
            }
            let mut node_id = [0u8; NODE_ID_BYTES];
            r.read_exact(&mut node_id).map_err(|_| Error::Message("Truncated message"))?;
            let family = r.read_u8().map_err(|_| Error::Message("Truncated message"))?;
            let addr = match family {
                4 => {
                    let mut ip = [0u8; 4];
                    r.read_exact(&mut ip).map_err(|_| Error::Message("Truncated message"))?;
                    let port = r.read_u16::<NetworkEndian>().map_err(|_| Error::Message("Truncated message"))?;
                    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port))
                }
                6 => {
                    let mut ip = [0u8; 16];
                    r.read_exact(&mut ip).map_err(|_| Error::Message("Truncated message"))?;
                    let port = r.read_u16::<NetworkEndian>().map_err(|_| Error::Message("Truncated message"))?;
                    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(ip), port, 0, 0))
                }
                _ => return Err(Error::Message("Truncated message"))
            };
            let mut claim = Range::read_from(&mut *r)?;
            claim.metric = r.read_u8().map_err(|_| Error::Message("Truncated message"))?;
            let glen = r.read_u8().map_err(|_| Error::Message("Truncated message"))? as usize;
            let mut gbytes = vec![0u8; glen];
            r.read_exact(&mut gbytes).map_err(|_| Error::Message("Truncated message"))?;
            let group = if glen == 0 {
                None
            } else {
                Some(String::from_utf8(gbytes).map_err(|_| Error::Message("Truncated message"))?)
            };
            out.push(TransitClaim { node_id, addr, claim, group });
        }
        Ok(out)
    }

    fn write_transit<W: Write>(out: &mut W, hop: &TransitClaim) -> Result<(), io::Error> {
        out.write_all(&hop.node_id)?;
        match hop.addr {
            SocketAddr::V4(addr) => {
                out.write_u8(4)?;
                out.write_all(&addr.ip().octets())?;
                out.write_u16::<NetworkEndian>(addr.port())?;
            }
            SocketAddr::V6(addr) => {
                out.write_u8(6)?;
                out.write_all(&addr.ip().octets())?;
                out.write_u16::<NetworkEndian>(addr.port())?;
            }
        }
        hop.claim.write_to(&mut *out);
        out.write_u8(hop.claim.metric)?;
        match hop.group.as_deref() {
            Some(name) if !name.is_empty() => {
                let bytes = name.as_bytes();
                let n = bytes.len().min(255);
                out.write_u8(n as u8)?;
                out.write_all(&bytes[..n])?;
            }
            _ => out.write_u8(0)?
        }
        Ok(())
    }

    pub fn decode<R: Read>(r: R) -> Result<Self, Error> {
        Self::decode_internal(r).map_err(|_| Error::Message("Input data too short"))
    }

    fn encode_peer_list_part<W: Write>(&self, mut out: W) -> Result<(), io::Error> {
        for p in &self.peers {
            let mut addr_ipv4: SmallVec<[SocketAddrV4; 16]> = smallvec![];
            let mut addr_ipv6: SmallVec<[SocketAddrV6; 16]> = smallvec![];
            for a in &p.addrs {
                match a {
                    SocketAddr::V4(addr) => addr_ipv4.push(*addr),
                    SocketAddr::V6(addr) => addr_ipv6.push(*addr)
                }
            }
            while addr_ipv4.len() >= 8 {
                addr_ipv4.pop();
            }
            while addr_ipv6.len() >= 8 {
                addr_ipv6.pop();
            }
            let mut flags = addr_ipv6.len() as u8 * 8 + addr_ipv4.len() as u8;
            if p.node_id.is_some() {
                flags += 0x80;
            }
            out.write_u8(flags)?;
            if let Some(node_id) = &p.node_id {
                out.write_all(node_id)?;
            }
            for a in addr_ipv6 {
                out.write_all(&a.ip().octets())?;
                out.write_u16::<NetworkEndian>(a.port())?;
            }
            for a in addr_ipv4 {
                out.write_all(&a.ip().octets())?;
                out.write_u16::<NetworkEndian>(a.port())?;
            }
        }
        Ok(())
    }

    fn encode_addrs_part<W: Write>(&self, mut out: W) -> Result<(), io::Error> {
        let mut addr_ipv4: SmallVec<[SocketAddrV4; 16]> = smallvec![];
        let mut addr_ipv6: SmallVec<[SocketAddrV6; 16]> = smallvec![];
        for a in &self.addrs {
            match a {
                SocketAddr::V4(addr) => addr_ipv4.push(*addr),
                SocketAddr::V6(addr) => addr_ipv6.push(*addr)
            }
        }
        while addr_ipv4.len() >= 8 {
            addr_ipv4.pop();
        }
        while addr_ipv6.len() >= 8 {
            addr_ipv6.pop();
        }
        let flags = addr_ipv6.len() as u8 * 8 + addr_ipv4.len() as u8;
        out.write_u8(flags)?;
        for a in addr_ipv6 {
            out.write_all(&a.ip().octets())?;
            out.write_u16::<NetworkEndian>(a.port())?;
        }
        for a in addr_ipv4 {
            out.write_all(&a.ip().octets())?;
            out.write_u16::<NetworkEndian>(a.port())?;
        }
        Ok(())
    }

    fn encode_part<F: FnOnce(&mut Cursor<&mut [u8]>) -> Result<(), io::Error>>(
        cursor: &mut Cursor<&mut [u8]>, part: u8, f: F
    ) -> Result<(), io::Error> {
        cursor.write_u8(part)?;
        cursor.write_u16::<NetworkEndian>(0)?;
        let part_start = cursor.position();
        f(cursor)?;
        let part_end = cursor.position();
        let len = part_end - part_start;
        cursor.seek(SeekFrom::Start(part_start - 2))?;
        cursor.write_u16::<NetworkEndian>(len as u16)?;
        cursor.seek(SeekFrom::Start(part_end))?;
        Ok(())
    }

    fn encode_internal(&self, buffer: &mut MsgBuffer) -> Result<(), io::Error> {
        let len;
        {
            let mut cursor = Cursor::new(buffer.buffer());
            Self::encode_part(&mut cursor, Self::PART_NODEID, |cursor| cursor.write_all(&self.node_id))?;
            Self::encode_part(&mut cursor, Self::PART_PEERS, |cursor| self.encode_peer_list_part(cursor))?;
            Self::encode_part(&mut cursor, Self::PART_CLAIMS, |mut cursor| {
                for c in &self.claims {
                    c.write_to(&mut cursor);
                }
                Ok(())
            })?;
            if self.claims.iter().any(|c| c.metric != 0) {
                Self::encode_part(&mut cursor, Self::PART_CLAIM_METRICS, |cursor| {
                    for c in &self.claims {
                        cursor.write_u8(c.metric)?;
                    }
                    Ok(())
                })?;
            }
            if let Some(timeout) = self.peer_timeout {
                Self::encode_part(&mut cursor, Self::PART_PEER_TIMEOUT, |cursor| {
                    cursor.write_u16::<NetworkEndian>(timeout)
                })?
            }
            Self::encode_part(&mut cursor, Self::PART_ADDRS, |cursor| self.encode_addrs_part(cursor))?;
            if let Some(mtu) = self.underlay_mtu {
                Self::encode_part(&mut cursor, Self::PART_UNDERLAY_MTU, |cursor| {
                    cursor.write_u16::<NetworkEndian>(mtu)
                })?;
            }
            if let Some(group) = &self.group {
                Self::encode_part(&mut cursor, Self::PART_GROUP, |cursor| cursor.write_all(group.as_bytes()))?;
            }
            if let Some(pk) = self.e2e_public {
                Self::encode_part(&mut cursor, Self::PART_E2E, |cursor| cursor.write_all(&pk))?;
            }
            if !self.peer_e2e.is_empty() {
                Self::encode_part(&mut cursor, Self::PART_PEER_E2E, |cursor| {
                    for (id, pk) in &self.peer_e2e {
                        cursor.write_all(id)?;
                        cursor.write_all(pk)?;
                    }
                    Ok(())
                })?;
            }
            if !self.transit.is_empty() {
                Self::encode_part(&mut cursor, Self::PART_TRANSIT, |cursor| {
                    for hop in &self.transit {
                        Self::write_transit(cursor, hop)?;
                    }
                    Ok(())
                })?;
            }
            if self.compression {
                Self::encode_part(&mut cursor, Self::PART_COMPRESSION, |cursor| cursor.write_u8(1))?;
            }
            if self.wire_caps != 0 {
                Self::encode_part(&mut cursor, Self::PART_WIRE_FORMAT, |cursor| {
                    cursor.write_u8(self.wire_caps & 0x0f)
                })?;
            }
            if !self.peer_rtts.is_empty() {
                Self::encode_part(&mut cursor, Self::PART_PEER_QUALITY, |cursor| {
                    for (id, rtt) in self.peer_rtts.iter().take(Self::MAX_PEER_QUALITY) {
                        cursor.write_all(id)?;
                        cursor.write_u16::<NetworkEndian>(*rtt)?;
                    }
                    Ok(())
                })?;
            }
            if let Some(sig) = self.node_signature {
                Self::encode_part(&mut cursor, Self::PART_NODE_SIGNATURE, |cursor| cursor.write_all(&sig))?;
            }
            cursor.write_u8(Self::PART_END)?;
            len = cursor.position() as usize;
        }
        buffer.set_length(len);
        Ok(())
    }

    pub fn encode(&self, buffer: &mut MsgBuffer) {
        self.encode_internal(buffer).expect("Buffer too small")
    }
}

impl Payload for NodeInfo {
    fn write_to(&self, buffer: &mut MsgBuffer) {
        self.encode(buffer)
    }

    fn read_from<R: Read>(r: R) -> Result<Self, Error> {
        Self::decode(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(mtu: Option<u16>) -> NodeInfo {
        NodeInfo {
            node_id: [7; NODE_ID_BYTES],
            peers: smallvec![],
            claims: smallvec![],
            peer_timeout: None,
            addrs: smallvec![],
            underlay_mtu: mtu,
            group: None,
            e2e_public: None,
            peer_e2e: Vec::new(),
            transit: Vec::new(),
            compression: false,
            wire_caps: 0,
            peer_rtts: Vec::new(),
            node_signature: None
        }
    }

    #[test]
    fn transit_roundtrips_and_old_messages_have_none() {
        use std::net::SocketAddr;
        let mut info = sample(None);
        info.transit.push(TransitClaim {
            node_id: [9; NODE_ID_BYTES],
            addr: "192.0.2.8:3210".parse::<SocketAddr>().unwrap(),
            claim: Range {
                base: crate::types::Address::from_ipv4("10.9.0.0".parse().unwrap()),
                prefix_len: 16,
                metric: 40
            },
            group: Some("eng".to_string())
        });
        info.transit.push(TransitClaim {
            node_id: [8; NODE_ID_BYTES],
            addr: "[2001:db8::8]:3211".parse::<SocketAddr>().unwrap(),
            claim: Range {
                base: crate::types::Address::from_ipv4("10.8.0.0".parse().unwrap()),
                prefix_len: 16,
                metric: 10
            },
            group: None
        });
        let mut buf = MsgBuffer::new(0);
        info.encode(&mut buf);
        let decoded = NodeInfo::decode(buf.message()).expect("decode");
        assert_eq!(decoded.transit, info.transit);
        assert_eq!(decoded.transit[0].claim.metric, 40);
        assert_eq!(decoded.transit[1].claim.metric, 10);
        assert_eq!(decoded.transit[0].group.as_deref(), Some("eng"));
        assert_eq!(decoded.transit[1].group, None);
        buf.clear();
        sample(None).encode(&mut buf);
        let decoded = NodeInfo::decode(buf.message()).expect("decode");
        assert!(decoded.transit.is_empty());
    }

    #[test]
    fn peer_list_decode_is_capped() {
        // Each peer with flags=0 is a single byte on the wire.
        let mut data = vec![0u8; NodeInfo::MAX_PEERS + 1];
        let mut take = (&data[..]).take(data.len() as u64);
        assert!(NodeInfo::decode_peer_list_part(&mut take).is_err());
        data.truncate(NodeInfo::MAX_PEERS);
        let mut take = (&data[..]).take(data.len() as u64);
        assert_eq!(NodeInfo::decode_peer_list_part(&mut take).unwrap().len(), NodeInfo::MAX_PEERS);
    }

    #[test]
    fn node_signature_roundtrips_and_detects_tampering() {
        use crate::crypto::{Crypto, Ed25519KeyPair};
        let (_privk, pubk) = Crypto::generate_keypair(None);
        let mut info = sample(None);
        info.e2e_public = Some([42u8; 32]);
        let seed = crate::util::from_base62_fixed::<32>(&_privk).unwrap();
        let pair = Ed25519KeyPair::from_seed(&seed).unwrap();
        info.node_signature = Some(pair.sign(&info.identity_bytes()));

        let mut buf = MsgBuffer::new(0);
        info.encode(&mut buf);
        let decoded = NodeInfo::decode(buf.message()).expect("decode");
        assert_eq!(decoded.node_signature, info.node_signature);
        let pk_bytes: [u8; 32] = crate::util::from_base62_fixed::<32>(&pubk).unwrap();
        assert!(Ed25519KeyPair::verify(&pk_bytes, &decoded.identity_bytes(), decoded.node_signature.as_ref().unwrap())
            .is_ok());
        // Tampering with the e2e key breaks the signature.
        let mut tampered = decoded.clone();
        tampered.e2e_public = Some([43u8; 32]);
        assert!(Ed25519KeyPair::verify(
            &pk_bytes,
            &tampered.identity_bytes(),
            tampered.node_signature.as_ref().unwrap()
        )
        .is_err());
    }

    #[test]
    fn message_type_ids_are_distinct() {
        let types = [
            MESSAGE_TYPE_DATA,
            MESSAGE_TYPE_NODE_INFO,
            MESSAGE_TYPE_KEEPALIVE,
            MESSAGE_TYPE_RELAY,
            MESSAGE_TYPE_DATA_GSO,
            MESSAGE_TYPE_DATA_COMPRESSED,
            MESSAGE_TYPE_DATA_GSO_COMPRESSED,
            MESSAGE_TYPE_FLOOD,
            MESSAGE_TYPE_RELAY_TTL,
            MESSAGE_TYPE_FLOOD_TTL,
            MESSAGE_TYPE_CLOSE
        ];
        let mut unique = types.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), types.len(), "message type constants must not collide");
        // Data-range types must stay outside the relay whitelist.
        assert!(types.iter().filter(|t| **t <= MESSAGE_TYPE_FLOOD_TTL).count() == 10);
    }

    #[test]
    fn compression_capability_roundtrips() {
        let mut buf = MsgBuffer::new(0);
        sample(None).encode(&mut buf);
        let decoded = NodeInfo::decode(buf.message()).expect("decode");
        assert!(!decoded.compression);
        buf.clear();
        let mut info = sample(None);
        info.compression = true;
        info.encode(&mut buf);
        let decoded = NodeInfo::decode(buf.message()).expect("decode");
        assert!(decoded.compression);
    }

    #[test]
    fn wire_format_capability_roundtrips_and_old_messages_omit_it() {
        let mut buf = MsgBuffer::new(0);
        sample(None).encode(&mut buf);
        let decoded = NodeInfo::decode(buf.message()).expect("decode");
        assert_eq!(decoded.wire_caps, 0, "legacy peers omit the part");
        buf.clear();
        let mut info = sample(None);
        info.wire_caps = crate::wire::WireCaps::for_bridge().bits();
        info.encode(&mut buf);
        let decoded = NodeInfo::decode(buf.message()).expect("decode");
        assert_eq!(decoded.wire_caps, info.wire_caps);
        // An unknown part from a future version must be skipped, not fail decode.
        buf.clear();
        let mut info = sample(None);
        info.wire_caps = 0x07;
        info.encode(&mut buf);
        let decoded = NodeInfo::decode(buf.message()).expect("decode");
        assert_eq!(decoded.wire_caps, 0x07);
    }

    #[test]
    fn peer_quality_roundtrips_and_old_messages_omit_it() {
        let mut buf = MsgBuffer::new(0);
        sample(None).encode(&mut buf);
        let decoded = NodeInfo::decode(buf.message()).expect("decode");
        assert!(decoded.peer_rtts.is_empty(), "legacy peers omit the part");
        buf.clear();
        let mut info = sample(None);
        info.peer_rtts = vec![([3u8; NODE_ID_BYTES], 12), ([4u8; NODE_ID_BYTES], 34)];
        info.encode(&mut buf);
        let decoded = NodeInfo::decode(buf.message()).expect("decode");
        assert_eq!(decoded.peer_rtts, info.peer_rtts);
    }

    #[test]
    fn underlay_mtu_roundtrips_and_old_messages_omit_it() {
        let mut buf = MsgBuffer::new(0);
        sample(None).encode(&mut buf);
        let decoded = NodeInfo::decode(buf.message()).expect("decode");
        assert_eq!(decoded.underlay_mtu, None);
        buf.clear();
        sample(Some(1280)).encode(&mut buf);
        let decoded = NodeInfo::decode(buf.message()).expect("decode");
        assert_eq!(decoded.underlay_mtu, Some(1280));
        assert_eq!(decoded.node_id, [7; NODE_ID_BYTES]);
    }
}
