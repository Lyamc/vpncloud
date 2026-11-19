// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

// Clippy misfires on const-initialised thread_local! on the Android cross target.
#![cfg_attr(target_os = "android", allow(clippy::missing_const_for_thread_local))]

#[macro_use] extern crate log;
#[macro_use] extern crate serde;

#[cfg(test)] extern crate tempfile;

#[macro_use]
pub mod util;
#[cfg(test)]
#[macro_use]
mod tests;
pub mod acl;
pub mod affinity;
pub mod beacon;
pub mod cloud;
pub mod compress;
pub mod config;
pub mod config_verify;
#[cfg(target_os = "linux")] pub mod container;
pub mod crypto;
pub mod crypto_pool;
pub mod device;
pub mod discover;
pub mod doctor;
pub mod engine;
pub mod enroll;
pub mod error;
pub mod gso;
#[cfg(feature = "installer")] pub mod installer;
pub mod kernel_fwd;
pub mod lan;
pub mod mesh;
pub mod messages;
pub mod metrics;
pub mod mtu;
pub mod multipath;
pub mod natclass;
pub mod natpmp;
pub mod net;
pub mod network;
pub mod oldconfig;
pub mod payload;
pub mod pcp;
pub mod peers;
pub mod policy;
pub mod poll;
pub mod port_forwarding;
#[cfg(target_os = "linux")] pub mod queues;
pub mod quic_link;
pub mod rate_limit;
pub mod routes;
pub mod runtime_status;
pub mod seccomp;
pub mod sign;
pub mod statecache;
pub mod status_report;
pub mod stun;
pub mod svc;
pub mod symnat;
pub mod table;
pub mod traffic;
pub mod types;
pub mod ustack;
#[cfg(feature = "wizard")] pub mod wire;
pub mod wizard;
#[cfg(feature = "websocket")] pub mod wsproxy;

#[cfg(target_os = "android")] mod android;
#[cfg(target_os = "android")] pub mod android_tun;

#[cfg(target_os = "ios")] mod ios;

#[cfg(feature = "gui")] pub mod gui;
pub mod identity;

#[cfg(windows)] pub mod tray;

#[cfg(target_os = "macos")] pub mod tray_macos;
pub mod tun_linux;

#[cfg(windows)] pub mod win_driver;

#[cfg(windows)] pub mod winservice;

pub use engine::run_vpn;
