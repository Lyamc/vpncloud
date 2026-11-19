// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! Opt-in LZ4 block compression for DATA tunnel payloads.
//!
//! Compression runs **before** encryption and only on DATA / DATA_GSO messages
//! sent directly to a peer that advertised LZ4 support. It is opportunistic:
//! when the compressed bytes are not smaller than the original, the frame is
//! sent uncompressed. That automatically skips PNG/JPEG/gzip/zstd/TLS payloads
//! without any content sniffing, while still compressing repeated headers and
//! plaintext protocols.
//!
//! Note: compressing attacker-controlled plaintext before encryption can leak
//! information through ciphertext lengths (CRIME/BREACH-style oracles). This
//! is why compression defaults to off and is only enabled between peers that
//! both opt in. Do not enable it for traffic where an adversary can inject
//! chosen plaintext and observe packet sizes.

use std::io;

/// Largest possible tunnel payload (one UDP datagram minus headroom). Also the
/// ceiling for the declared uncompressed size in an LZ4 block, so a corrupt or
/// hostile frame cannot make us allocate more than this.
const MAX_UNCOMPRESSED: usize = 65535;

pub fn enabled_by_default() -> bool {
    false
}

/// Compress `src` and return the LZ4 block (with the 4-byte uncompressed size
/// prepended) only when it is strictly smaller than the input. `None` means
/// "send the original bytes" — the caller keeps the uncompressed message type.
pub fn maybe_compress(src: &[u8]) -> Option<Vec<u8>> {
    if src.len() < 32 {
        // Short packets cannot benefit and the framing overhead is pure loss.
        return None;
    }
    let compressed = lz4_flex::block::compress_prepend_size(src);
    if compressed.len() < src.len() {
        Some(compressed)
    } else {
        None
    }
}

/// Decompress an LZ4 block produced by [`maybe_compress`].
pub fn decompress(src: &[u8]) -> Result<Vec<u8>, &'static str> {
    if src.len() < 4 {
        return Err("compressed frame too short");
    }
    let declared = u32::from_le_bytes([src[0], src[1], src[2], src[3]]) as usize;
    if declared == 0 || declared > MAX_UNCOMPRESSED {
        return Err("invalid decompressed size");
    }
    lz4_flex::block::decompress_size_prepended(src).map_err(|_| "lz4 decompression failed")
}

/// Decompress into a caller-provided buffer, used to avoid a second allocation
/// on the receive hot path. Returns the number of bytes written.
pub fn decompress_into(src: &[u8], out: &mut [u8]) -> Result<usize, &'static str> {
    if src.len() < 4 {
        return Err("compressed frame too short");
    }
    let declared = u32::from_le_bytes([src[0], src[1], src[2], src[3]]) as usize;
    if declared == 0 || declared > out.len() || declared > MAX_UNCOMPRESSED {
        return Err("invalid decompressed size");
    }
    let plain = lz4_flex::block::decompress(&src[4..], declared).map_err(|_| "lz4 decompression failed")?;
    if plain.len() != declared {
        return Err("decompressed size mismatch");
    }
    out[..plain.len()].copy_from_slice(&plain);
    Ok(plain.len())
}

/// Map a decompression failure to an IO error for the packet pipeline.
pub fn io_error(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compressible_payload_shrinks_and_roundtrips() {
        let mut payload = b"vpncloud-tunnel".to_vec();
        payload.extend(std::iter::repeat(b'A').take(2048));
        let compressed = maybe_compress(&payload).expect("compressible payload");
        assert!(compressed.len() < payload.len());
        assert_eq!(decompress(&compressed).unwrap(), payload);
    }

    #[test]
    fn incompressible_payload_is_left_alone() {
        // A fixed pseudo-random sequence stands in for PNG/gzip/TLS bytes.
        let mut payload = Vec::new();
        let mut x = 0x1234_5678u32;
        for _ in 0..4096 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            payload.extend_from_slice(&x.to_le_bytes());
        }
        assert!(maybe_compress(&payload).is_none());
    }

    #[test]
    fn short_payloads_are_left_alone() {
        assert!(maybe_compress(b"tiny").is_none());
    }

    #[test]
    fn compression_is_off_by_default() {
        assert!(!enabled_by_default());
    }

    #[test]
    fn rejects_oversized_and_truncated_frames() {
        assert!(decompress(&[1, 2, 3]).is_err());
        let mut frame = vec![0u8; 8];
        frame[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(decompress(&frame).is_err());
        let mut out = [0u8; 16];
        assert!(decompress_into(&frame, &mut out).is_err());
    }

    #[test]
    fn decompress_into_matches_allocating_version() {
        let payload: Vec<u8> = (0..1024).map(|i| (i % 7) as u8).collect();
        let compressed = maybe_compress(&payload).unwrap();
        let mut out = [0u8; 1024];
        let n = decompress_into(&compressed, &mut out).unwrap();
        assert_eq!(&out[..n], &payload[..]);
    }
}
