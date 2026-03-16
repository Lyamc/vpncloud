// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos", target_os = "windows"))]
mod epoll;

#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos", target_os = "windows"))]
pub use self::epoll::{EpollWait as WaitImpl, Pollable};

use std::io;

pub enum WaitResult {
    Timeout,
    Socket,
    Device,
    Error(io::Error)
}
