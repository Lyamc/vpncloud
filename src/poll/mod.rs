// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

#[cfg(unix)] mod epoll;

#[cfg(unix)]
pub use self::epoll::{EpollWait as WaitImpl, Pollable};

#[cfg(windows)] mod windows;

#[cfg(windows)]
pub use self::windows::{Pollable, WaitImpl, WindowsDeviceSource};

use std::io;

pub enum WaitResult {
    Timeout,
    Socket,
    Device,
    Error(io::Error)
}
