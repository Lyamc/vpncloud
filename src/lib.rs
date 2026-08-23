// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

#[macro_use]
extern crate log;
#[macro_use]
extern crate serde;

#[cfg(test)]
extern crate tempfile;

#[macro_use]
pub mod util;
#[cfg(test)]
#[macro_use]
mod tests;
pub mod beacon;
pub mod cloud;
pub mod config;
pub mod crypto;
pub mod device;
pub mod engine;
pub mod error;
#[cfg(feature = "installer")]
pub mod installer;
pub mod messages;
pub mod net;
pub mod oldconfig;
pub mod payload;
pub mod poll;
pub mod port_forwarding;
pub mod svc;
pub mod table;
pub mod traffic;
pub mod types;
#[cfg(feature = "wizard")]
pub mod wizard;
#[cfg(feature = "websocket")]
pub mod wsproxy;

#[cfg(target_os = "android")]
mod android;

#[cfg(target_os = "ios")]
mod ios;

#[cfg(feature = "gui")]
pub mod gui;

#[cfg(windows)]
pub mod tray;

#[cfg(windows)]
pub mod winservice;

pub use engine::run_vpn;
