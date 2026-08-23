// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

mod common;
mod core;
mod init;
#[cfg(feature = "noise")] mod noise;
mod rotate;

pub use self::core::{EXTRA_LEN, TAG_LEN};
pub use common::*;
#[cfg(feature = "noise")]
pub use noise::is_noise_frame;

#[cfg(not(feature = "noise"))]
pub fn is_noise_frame(_msg: &[u8]) -> bool {
    false
}
