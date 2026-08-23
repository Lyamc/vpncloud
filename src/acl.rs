// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::str::FromStr;

use crate::types::{Address, Range};

#[derive(Clone, Debug, PartialEq)]
pub struct Acl {
    rules: Vec<(bool, Range)>
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
            let range = Range::from_str(rest).map_err(|_| "Invalid ACL subnet")?;
            rules.push((allow, range));
        }
        Ok(Self { rules })
    }

    pub fn allows(&self, addr: Address) -> bool {
        if self.rules.is_empty() {
            return true;
        }
        for (allow, range) in self.rules.iter().rev() {
            if range.matches(addr) {
                return *allow;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_then_allow() {
        let acl = Acl::parse(&["deny:0.0.0.0/0".into(), "allow:10.0.0.0/8".into()]).unwrap();
        assert!(acl.allows(Address::from_str("10.1.2.3").unwrap()));
        assert!(!acl.allows(Address::from_str("8.8.8.8").unwrap()));
    }
}
