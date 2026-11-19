// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! Preflight checks for `vpncloud doctor`. No TUN is opened and no packets are
//! sent; every check is safe to run as an unprivileged user.

use std::{
    net::{ToSocketAddrs, UdpSocket},
    path::Path,
    time::SystemTime
};

use crate::config::Config;
#[cfg(windows)] use crate::device::Type;

struct Check {
    name: &'static str,
    ok: bool,
    detail: String
}

fn check(name: &'static str, ok: bool, detail: impl Into<String>) -> Check {
    Check { name, ok, detail: detail.into() }
}

#[cfg(all(unix, not(windows)))]
#[allow(dead_code)] // unused on platforms where the driver check needs no root
fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(unix))]
#[allow(dead_code)] // only used by some non-Unix driver checks
fn is_root() -> bool {
    false
}

#[cfg_attr(not(windows), allow(unused_variables))]
fn driver_check(config: &Config) -> Check {
    #[cfg(windows)]
    {
        let needed = if config.device_type == Type::Tap { Type::Tap } else { Type::Tun };
        let present = crate::win_driver::is_installed(needed);
        check(
            "Driver",
            present,
            format!(
                "{} driver {}",
                needed,
                if present { "installed" } else { "MISSING (run vpncloud install or allow the download)" }
            )
        )
    }
    #[cfg(target_os = "linux")]
    {
        let path = Path::new("/dev/net/tun");
        let present = path.exists();
        let accessible =
            present && (is_root() || std::fs::OpenOptions::new().read(true).write(true).open(path).is_ok());
        check(
            "TUN device",
            accessible,
            if accessible {
                format!("/dev/net/tun available (root={})", is_root())
            } else if present {
                "device exists but is not accessible; run as root or grant access".into()
            } else {
                "/dev/net/tun missing; load the tun module".into()
            }
        )
    }
    #[cfg(target_os = "android")]
    {
        let ok = crate::device::android_has_tuntap_access();
        check(
            "TUN device",
            ok,
            if ok { "/dev/net/tun accessible" } else { "no TUN access (needs VpnService fd or root)" }
        )
    }
    #[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd", target_os = "dragonfly"))]
    {
        let ok = Path::new("/dev/tun").exists() || is_root();
        check("TUN device", ok, if ok { "tun(4) available" } else { "/dev/tun missing; kldload if_tuntap" })
    }
    #[cfg(target_os = "macos")]
    {
        let ok = is_root();
        check(
            "TUN device",
            ok,
            if ok {
                String::from("utun available (running as root)")
            } else {
                String::from("utun requires root; use 'sudo vpncloud doctor' for this check")
            }
        )
    }
    #[cfg(target_os = "ios")]
    {
        check("TUN device", true, "Packet Tunnel Provider supplies the fd")
    }
    #[cfg(not(any(
        windows,
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "macos",
        target_os = "ios"
    )))]
    {
        check("TUN device", true, "platform not recognized; cannot check")
    }
}

fn config_check(path: Option<&Path>) -> (Check, Option<Config>) {
    let Some(path) = path else {
        return (check("Config", true, "not provided"), None);
    };
    match crate::config::load_config_file_with_raw(path) {
        Ok((resolved, _, file)) => {
            #[cfg(unix)]
            let perm_note = {
                use std::os::unix::fs::PermissionsExt;
                match std::fs::metadata(&resolved) {
                    Ok(meta) => {
                        let mode = meta.permissions().mode() & 0o777;
                        if mode & 0o077 != 0 {
                            format!(" (mode {:o} is group/world accessible)", mode)
                        } else {
                            format!(" (mode {:o})", mode)
                        }
                    }
                    Err(_) => String::new()
                }
            };
            #[cfg(not(unix))]
            let perm_note = String::new();
            let mut config = Config::default();
            config.merge_file(file);
            match config.validate() {
                Ok(warnings) => {
                    let detail = format!(
                        "{} valid{}{}",
                        resolved.display(),
                        perm_note,
                        if warnings.is_empty() { String::new() } else { format!(", {} warning(s)", warnings.len()) }
                    );
                    (check("Config", true, detail), Some(config))
                }
                Err(e) => (check("Config", false, format!("{}: {}", resolved.display(), e)), Some(config))
            }
        }
        Err(e) => (check("Config", false, format!("{}: {}", path.display(), e)), None)
    }
}

/// Run all checks and return the process exit code (0 = all passed).
pub fn run(config_path: Option<&Path>) -> i32 {
    println!("VpnCloud doctor");
    println!("  Platform: {} {}", std::env::consts::OS, std::env::consts::ARCH);

    let (cfg_check, config) = config_check(config_path);
    let config = config.unwrap_or_default();
    let mut checks = vec![cfg_check, driver_check(&config)];

    let listen = crate::net::parse_listen(&config.listen, crate::config::DEFAULT_PORT);
    match UdpSocket::bind(listen) {
        Ok(_) => checks.push(check("Listen socket", true, format!("{} available", listen))),
        Err(e) => checks.push(check("Listen socket", false, format!("{}: {}", listen, e)))
    }

    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let clock_ok = now > 1_700_000_000; // Nov 2023; catches wildly wrong system clocks
    checks.push(check(
        "Clock",
        clock_ok,
        format!("unix time {} ({})", now, if clock_ok { "OK" } else { " implausible" })
    ));

    if !config.peers.is_empty() {
        let mut resolved = 0usize;
        for peer in &config.peers {
            let with_port = crate::cloud::ensure_peer_port(peer);
            if with_port.to_socket_addrs().map(|mut addrs| addrs.next().is_some()).unwrap_or(false) {
                resolved += 1;
            }
        }
        checks.push(check(
            "Peer DNS",
            resolved > 0,
            format!("{}/{} peer address(es) resolve", resolved, config.peers.len())
        ));
    }

    let mut failed = 0;
    for c in &checks {
        println!("  [{}] {}: {}", if c.ok { "OK" } else { "!!" }, c.name, c.detail);
        if !c.ok {
            failed += 1;
        }
    }
    println!("Doctor: {} passed, {} failed", checks.len() - failed, failed);
    if failed == 0 {
        0
    } else {
        1
    }
}
