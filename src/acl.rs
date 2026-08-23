// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::str::FromStr;

use crate::types::{Address, Range};

#[derive(Clone, Debug, PartialEq)]
struct Rule {
    allow: bool,
    range: Range,
    proto: Option<u8>,
    ports: Option<(u16, u16)>
}

#[derive(Clone, Debug, PartialEq, Default)]
pub struct Acl {
    rules: Vec<Rule>
}

impl Acl {
    pub fn parse(lines: &[String]) -> Result<Self, &'static str> {
        let mut rules = Vec::new();
        for line in lines {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let (allow, rest) = if let Some(r) = line.strip_prefix("allow:") {
                (true, r)
            } else if let Some(r) = line.strip_prefix("deny:") {
                (false, r)
            } else {
                return Err("ACL entries must start with allow: or deny:");
            };
            let (range, proto, ports) = parse_spec(rest)?;
            rules.push(Rule { allow, range, proto, ports });
        }
        Ok(Self { rules })
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Last matching rule wins. CIDR matches overlay source; optional proto/port match L4 dest.
    pub fn allows(&self, addr: Address, proto: Option<u8>, dport: Option<u16>) -> bool {
        if self.rules.is_empty() {
            return true;
        }
        let mut hit = None;
        for rule in &self.rules {
            if !rule.range.matches(addr) {
                continue;
            }
            if let Some(want) = rule.proto {
                if proto != Some(want) {
                    continue;
                }
            }
            if let Some((lo, hi)) = rule.ports {
                let Some(p) = dport else { continue };
                if p < lo || p > hi {
                    continue;
                }
            }
            hit = Some(rule.allow);
        }
        hit.unwrap_or(true)
    }
}

fn parse_spec(rest: &str) -> Result<(Range, Option<u8>, Option<(u16, u16)>), &'static str> {
    if let Ok(range) = Range::from_str(rest) {
        return Ok((range, None, None));
    }
    let Some((left, last)) = rest.rsplit_once(':') else {
        return Err("Invalid ACL subnet");
    };
    let last_l = last.to_ascii_lowercase();
    if let Some(proto) = parse_proto(&last_l) {
        let range = Range::from_str(left).map_err(|_| "Invalid ACL subnet")?;
        return Ok((range, Some(proto), None));
    }
    let Some(ports) = parse_ports(last) else {
        return Err("Invalid ACL port");
    };
    let Some((cidr, proto_s)) = left.rsplit_once(':') else {
        return Err("ACL port requires a protocol (tcp or udp)");
    };
    let proto = parse_proto(&proto_s.to_ascii_lowercase()).ok_or("Invalid ACL protocol")?;
    let range = Range::from_str(cidr).map_err(|_| "Invalid ACL subnet")?;
    Ok((range, Some(proto), Some(ports)))
}

fn parse_proto(s: &str) -> Option<u8> {
    match s {
        "tcp" => Some(6),
        "udp" => Some(17),
        "icmp" => Some(1),
        "icmpv6" | "icmp6" => Some(58),
        _ => None
    }
}

fn parse_ports(s: &str) -> Option<(u16, u16)> {
    if let Some((a, b)) = s.split_once('-') {
        let lo = a.parse().ok()?;
        let hi = b.parse().ok()?;
        if lo > hi {
            return None;
        }
        return Some((lo, hi));
    }
    let p = s.parse().ok()?;
    Some((p, p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_then_allow() {
        let acl = Acl::parse(&["deny:0.0.0.0/0".into(), "allow:10.0.0.0/8".into()]).unwrap();
        assert!(acl.allows(Address::from_str("10.1.2.3").unwrap(), None, None));
        assert!(!acl.allows(Address::from_str("8.8.8.8").unwrap(), None, None));
    }

    #[test]
    fn proto_and_port() {
        let acl = Acl::parse(&["deny:0.0.0.0/0".into(), "allow:10.0.0.0/8:tcp:22".into()]).unwrap();
        let src = Address::from_str("10.1.2.3").unwrap();
        assert!(acl.allows(src, Some(6), Some(22)));
        assert!(!acl.allows(src, Some(6), Some(23)));
        assert!(!acl.allows(src, Some(17), Some(22)));
        assert!(!acl.allows(Address::from_str("8.8.8.8").unwrap(), Some(6), Some(22)));
    }

    #[test]
    fn port_range_and_ipv6() {
        let acl = Acl::parse(&["deny:::0/0".into(), "allow:fd00::/8:udp:60000-61000".into()]).unwrap();
        let src = Address::from_str("fd00::1").unwrap();
        assert!(acl.allows(src, Some(17), Some(60001)));
        assert!(!acl.allows(src, Some(17), Some(59)));
    }
}
