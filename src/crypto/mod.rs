// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

mod common;
mod core;
mod init;
#[cfg(feature = "noise")] mod noise;
mod prim;
pub mod pq;
mod rotate;

pub use self::core::{open_raw, seal_raw, EXTRA_LEN, TAG_LEN};
pub use common::*;
pub use prim::{
    fill_random, pbkdf2_hmac_sha256, sha256, sha512, AeadAlgo, AeadKey, Ed25519KeyPair, ED25519_PUBLIC_KEY_LEN
};
#[cfg(feature = "noise")]
pub use noise::is_noise_frame;

#[cfg(not(feature = "noise"))]
pub fn is_noise_frame(_msg: &[u8]) -> bool {
    false
}
