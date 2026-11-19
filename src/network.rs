// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! `vpncloud network` — list and control per-network service instances.
//! Linux uses systemd `vpncloud@<name>`; macOS uses launchd labels derived
//! from the config name; other platforms only support listing and guidance.

use std::fs;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::Command;

pub fn list() {
    let dir = crate::config::system_config_dir();
    let Ok(entries) = fs::read_dir(dir) else {
        println!("No config directory at {} (run 'vpncloud install' first)", dir.display());
        return;
    };
    let mut names = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !matches!(ext, "net" | "yaml" | "yml" | "toml") {
            continue;
        }
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        if stem == "vpncloud" || stem.ends_with(".disabled") {
            continue;
        }
        names.push(stem.to_string());
    }
    names.sort();
    names.dedup();
    if names.is_empty() {
        println!("No networks configured in {}", dir.display());
    } else {
        println!("Networks in {}:", dir.display());
        for name in names {
            println!("  {}", name);
        }
    }
}

fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.') {
        return Err(format!("invalid network name '{}'", name));
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn service_name(name: &str) -> String {
    #[cfg(target_os = "linux")]
    {
        format!("vpncloud@{}", name)
    }
    #[cfg(not(target_os = "linux"))]
    {
        format!("ca.witherow.vpncloud.{}", name)
    }
}

#[cfg_attr(any(target_os = "linux", target_os = "macos"), allow(dead_code))]
fn unsupported(action: &str, name: &str) {
    let path = std::path::Path::new(crate::config::system_config_dir()).join(format!("{}.net", name));
    println!("{} of a named network is not supported on this platform.", action);
    println!("Run manually: vpncloud --config {}", path.display());
}

pub fn start(name: &str) -> Result<(), String> {
    validate_name(name)?;
    #[cfg(target_os = "linux")]
    {
        let svc = service_name(name);
        match Command::new("systemctl").args(["start", &svc]).status() {
            Ok(s) if s.success() => {
                println!("Started {}", svc);
                Ok(())
            }
            Ok(s) => Err(format!("{} exited with {}", svc, s)),
            Err(e) => Err(format!("failed to start {}: {}", svc, e))
        }
    }
    #[cfg(target_os = "macos")]
    {
        let svc = service_name(name);
        match Command::new("launchctl").args(["start", &format!("system/{}", svc)]).status() {
            Ok(s) if s.success() => {
                println!("Started {}", svc);
                Ok(())
            }
            Ok(s) => Err(format!("{} exited with {}", svc, s)),
            Err(e) => Err(format!("failed to start {}: {}", svc, e))
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        unsupported("Starting", name);
        Ok(())
    }
}

pub fn stop(name: &str) -> Result<(), String> {
    validate_name(name)?;
    #[cfg(target_os = "linux")]
    {
        let svc = service_name(name);
        match Command::new("systemctl").args(["stop", &svc]).status() {
            Ok(s) if s.success() => {
                println!("Stopped {}", svc);
                Ok(())
            }
            Ok(s) => Err(format!("{} exited with {}", svc, s)),
            Err(e) => Err(format!("failed to stop {}: {}", svc, e))
        }
    }
    #[cfg(target_os = "macos")]
    {
        let svc = service_name(name);
        match Command::new("launchctl").args(["stop", &format!("system/{}", svc)]).status() {
            Ok(s) if s.success() => {
                println!("Stopped {}", svc);
                Ok(())
            }
            Ok(s) => Err(format!("{} exited with {}", svc, s)),
            Err(e) => Err(format!("failed to stop {}: {}", svc, e))
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        unsupported("Stopping", name);
        Ok(())
    }
}

pub fn status(name: &str) -> Result<(), String> {
    validate_name(name)?;
    #[cfg(target_os = "linux")]
    {
        let svc = service_name(name);
        match Command::new("systemctl").args(["is-active", &svc]).output() {
            Ok(out) => {
                println!("{}: {}", svc, if out.status.success() { "active" } else { "inactive" });
                Ok(())
            }
            Err(e) => Err(format!("failed to query {}: {}", svc, e))
        }
    }
    #[cfg(target_os = "macos")]
    {
        let svc = service_name(name);
        match Command::new("launchctl").args(["print", &format!("system/{}", svc)]).output() {
            Ok(out) => {
                println!("{}: {}", svc, if out.status.success() { "active" } else { "inactive" });
                Ok(())
            }
            Err(e) => Err(format!("failed to query {}: {}", svc, e))
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        unsupported("Querying", name);
        Ok(())
    }
}
