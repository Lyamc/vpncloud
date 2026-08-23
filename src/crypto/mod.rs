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

/// ECDH that works with both `ring` 0.17 and `aws-lc-rs` (ring 0.16-style error argument).
pub(crate) fn agree_ephemeral<B, R>(
    my_private_key: crate::crypto_ring::agreement::EphemeralPrivateKey,
    peer_public_key: &crate::crypto_ring::agreement::UnparsedPublicKey<B>, kdf: impl FnOnce(&[u8]) -> R
) -> Result<R, crate::crypto_ring::error::Unspecified>
where
    B: AsRef<[u8]>
{
    #[cfg(not(feature = "aws-lc"))]
    {
        crate::crypto_ring::agreement::agree_ephemeral(my_private_key, peer_public_key, kdf)
    }
    #[cfg(feature = "aws-lc")]
    {
        crate::crypto_ring::agreement::agree_ephemeral(
            my_private_key,
            peer_public_key,
            crate::crypto_ring::error::Unspecified,
            |k| Ok(kdf(k))
        )
    }
}

#[cfg(not(feature = "noise"))]
pub fn is_noise_frame(_msg: &[u8]) -> bool {
    false
}
