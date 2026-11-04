// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use fnv::FnvHasher;
use std::{
    cmp::min, collections::HashMap, hash::BuildHasherDefault, io, io::Write, marker::PhantomData, net::SocketAddr
};

use crate::{
    types::{Address, NodeId, Range, RangeList},
    util::{addr_nice, Duration, Time, TimeSource}
};

type Hash = BuildHasherDefault<FnvHasher>;

struct CacheValue {
    peer: SocketAddr,
    node_id: NodeId,
    timeout: Time
}

struct ClaimEntry {
    peer: SocketAddr,
    node_id: NodeId,
    claim: Range,
    timeout: Time
}

pub struct ClaimTable<TS: TimeSource> {
    cache: HashMap<Address, CacheValue, Hash>,
    cache_timeout: Duration,
    claims: Vec<ClaimEntry>,
    claim_timeout: Duration,
    _dummy: PhantomData<TS>
}

impl<TS: TimeSource> ClaimTable<TS> {
    pub fn new(cache_timeout: Duration, claim_timeout: Duration) -> Self {
        Self { cache: HashMap::default(), cache_timeout, claims: vec![], claim_timeout, _dummy: PhantomData }
    }

    pub fn cache(&mut self, addr: Address, peer: SocketAddr, node_id: NodeId) {
        // HOT PATH
        self.cache.insert(addr, CacheValue { peer, node_id, timeout: TS::now() + self.cache_timeout as Time });
    }

    pub fn clear_cache(&mut self) {
        self.cache.clear()
    }

    pub fn set_claims(&mut self, peer: SocketAddr, node_id: NodeId, mut claims: RangeList) {
        let mut removed_claim = false;
        for entry in &mut self.claims {
            if entry.peer == peer {
                let pos = claims.iter().position(|r| r == &entry.claim);
                if let Some(pos) = pos {
                    entry.timeout = TS::now() + self.claim_timeout as Time;
                    entry.node_id = node_id;
                    claims.swap_remove(pos);
                    if claims.is_empty() {
                        break;
                    }
                } else {
                    entry.timeout = 0;
                    removed_claim = true;
                }
            }
        }
        for claim in claims {
            self.claims.push(ClaimEntry { peer, node_id, claim, timeout: TS::now() + self.claim_timeout as Time })
        }
        if removed_claim {
            for entry in self.cache.values_mut() {
                if entry.peer == peer {
                    entry.timeout = 0
                }
            }
        }
        self.housekeep()
    }

    pub fn remove_claims(&mut self, peer: SocketAddr) {
        // Drop immediately. Zeroing the timeout and then housekeeping keeps the
        // row when `now == 0`, and the next lookup would still relay it.
        self.claims.retain(|entry| entry.peer != peer);
        self.cache.retain(|_, entry| entry.peer != peer);
        self.housekeep()
    }

    fn best_index(&self, addr: Address) -> Option<usize> {
        let mut found = None;
        let mut prefix_len = -1isize;
        let mut metric = u8::MAX;
        for (i, entry) in self.claims.iter().enumerate() {
            if !entry.claim.matches(addr) {
                continue;
            }
            let pl = entry.claim.prefix_len as isize;
            if pl > prefix_len || (pl == prefix_len && entry.claim.metric < metric) {
                found = Some(i);
                prefix_len = pl;
                metric = entry.claim.metric;
            }
        }
        found
    }

    pub fn lookup(&mut self, addr: Address) -> Option<(SocketAddr, NodeId)> {
        // HOT PATH
        if let Some(entry) = self.cache.get(&addr) {
            return Some((entry.peer, entry.node_id));
        }
        // COLD PATH
        let idx = self.best_index(addr)?;
        let entry = &self.claims[idx];
        let peer = entry.peer;
        let node_id = entry.node_id;
        let timeout = min(TS::now() + self.cache_timeout as Time, entry.timeout);
        self.cache.insert(addr, CacheValue { peer, node_id, timeout });
        Some((peer, node_id))
    }

    pub fn housekeep(&mut self) {
        let now = TS::now();
        self.cache.retain(|_, v| v.timeout >= now);
        self.claims.retain(|e| e.timeout >= now);
    }

    pub fn cache_len(&self) -> usize {
        self.cache.len()
    }

    pub fn claim_len(&self) -> usize {
        self.claims.len()
    }

    /// Claims learned from peers, including prefixes those peers only reach indirectly.
    pub fn export_claims(&self) -> Vec<(SocketAddr, NodeId, Range)> {
        self.claims.iter().map(|entry| (entry.peer, entry.node_id, entry.claim)).collect()
    }

    /// Write out the table
    pub fn write_out<W: Write>(&self, out: &mut W) -> Result<(), io::Error> {
        let now = TS::now();
        writeln!(out, "forwarding_table:")?;
        writeln!(out, "  claims:")?;
        for entry in &self.claims {
            writeln!(
                out,
                "    - \"{}\": {{ peer: \"{}\", timeout: {} }}",
                entry.claim,
                addr_nice(entry.peer),
                entry.timeout - now
            )?;
        }
        writeln!(out, "  cache:")?;
        for (addr, entry) in &self.cache {
            writeln!(
                out,
                "    - \"{}\": {{ peer: \"{}\", timeout: {} }}",
                addr,
                addr_nice(entry.peer),
                entry.timeout - now
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::MockTimeSource;
    use std::str::FromStr;

    #[test]
    fn lowest_metric_wins_on_equal_prefix() {
        MockTimeSource::set_time(1_000);
        let mut table = ClaimTable::<MockTimeSource>::new(60, 300);
        let worse: SocketAddr = "1.1.1.1:1".parse().unwrap();
        let better: SocketAddr = "2.2.2.2:2".parse().unwrap();
        let mut high = RangeList::new();
        high.push(Range::from_str("10.0.0.0/16@50").unwrap());
        table.set_claims(worse, [1; 16], high);
        let mut low = RangeList::new();
        low.push(Range::from_str("10.0.0.0/16@10").unwrap());
        table.set_claims(better, [2; 16], low);
        let (peer, node) = table.lookup(Address::from_str("10.0.1.9").unwrap()).unwrap();
        assert_eq!(peer, better);
        assert_eq!(node, [2; 16]);
    }
}
