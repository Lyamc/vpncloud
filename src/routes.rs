// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! Optional installation of kernel routes for announced overlay claims.
//!
//! VpnCloud normally only advertises claims and routes inside the mesh. With
//! `--install-routes` it also adds a route for each announced prefix pointing
//! at the local TUN interface, so hosts behind the mesh become reachable
//! without a separate `ip route` command. This is opt-in because it changes
//! the host routing table and needs elevated privileges.

#[cfg(not(target_os = "android"))]
use std::process::Command;
use std::{collections::HashSet, io};

use crate::types::Range;

pub struct RouteManager {
    enabled: bool,
    ifname: String,
    installed: HashSet<String>
}

impl RouteManager {
    pub fn new(enabled: bool, ifname: String) -> Self {
        Self { enabled, ifname, installed: HashSet::new() }
    }

    /// A `0.0.0.0/0` or `::/0` claim would hijack the host's default route.
    /// Those are deliberately never installed automatically.
    fn safe_to_install(range: &Range) -> bool {
        !(range.base.len == 4 || range.base.len == 16) || range.prefix_len > 0
    }

    fn run(args: &[&str]) -> io::Result<()> {
        #[cfg(target_os = "android")]
        {
            crate::android_tun::run_ip(args)
        }
        #[cfg(not(target_os = "android"))]
        {
            let status = Command::new("ip").args(args).status()?;
            if status.success() {
                Ok(())
            } else {
                Err(io::Error::other(format!("ip {} failed: {}", args.join(" "), status)))
            }
        }
    }

    /// Reconcile the installed routes with the desired set.
    pub fn sync(&mut self, desired: &[Range]) {
        if !self.enabled {
            return;
        }
        let wanted: HashSet<String> =
            desired.iter().filter(|range| Self::safe_to_install(range)).map(|range| range.to_string()).collect();
        for stale in self.installed.difference(&wanted).cloned().collect::<Vec<_>>() {
            match Self::run(&["route", "del", &stale, "dev", &self.ifname]) {
                Ok(()) => {
                    self.installed.remove(&stale);
                }
                Err(e) => log::debug!("Failed to remove overlay route {}: {}", stale, e)
            }
        }
        for fresh in wanted.difference(&self.installed).cloned().collect::<Vec<_>>() {
            match Self::run(&["route", "add", &fresh, "dev", &self.ifname]) {
                Ok(()) => {
                    self.installed.insert(fresh);
                }
                Err(e) => log::warn!("Failed to install overlay route {}: {}", fresh, e)
            }
        }
    }

    pub fn clear(&mut self) {
        if !self.enabled {
            return;
        }
        for route in self.installed.drain() {
            let _ = Self::run(&["route", "del", &route, "dev", &self.ifname]);
        }
    }

    #[cfg(test)]
    pub fn installed_routes(&self) -> &HashSet<String> {
        &self.installed
    }
}

impl Drop for RouteManager {
    fn drop(&mut self) {
        self.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn default_routes_are_rejected() {
        assert!(!RouteManager::safe_to_install(&Range::from_str("0.0.0.0/0").unwrap()));
        assert!(!RouteManager::safe_to_install(&Range::from_str("::/0").unwrap()));
        assert!(RouteManager::safe_to_install(&Range::from_str("10.0.0.0/8").unwrap()));
    }

    #[test]
    fn disabled_manager_does_nothing() {
        let mut manager = RouteManager::new(false, "tun0".into());
        manager.sync(&[Range::from_str("10.0.0.0/8").unwrap()]);
        assert!(manager.installed_routes().is_empty());
    }
}
