// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! Virtio GSO metadata carried inside an encrypted data message.
//!
//! A Linux TUN with offload hands us one large TCP/UDP aggregate instead of
//! MTU-sized packets. Forwarding that aggregate as a single AEAD message keeps
//! the inner bytes unmodified and lets the peer write it back with the same
//! virtio header so the kernel segments it. The 10-byte prefix matches the
//! little-endian `virtio_net_hdr` fields (no `num_buffers`).

pub const GSO_META_LEN: usize = 10;

pub const VIRTIO_F_NEEDS_CSUM: u8 = 1;
pub const GSO_TCPV4: u8 = 1;
pub const GSO_TCPV6: u8 = 4;
pub const GSO_UDP_L4: u8 = 5;
const GSO_ECN: u8 = 0x80;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GsoMeta {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16
}

impl GsoMeta {
    pub fn write(self, dst: &mut [u8]) {
        debug_assert!(dst.len() >= GSO_META_LEN);
        dst[0] = self.flags;
        dst[1] = self.gso_type;
        dst[2..4].copy_from_slice(&self.hdr_len.to_le_bytes());
        dst[4..6].copy_from_slice(&self.gso_size.to_le_bytes());
        dst[6..8].copy_from_slice(&self.csum_start.to_le_bytes());
        dst[8..10].copy_from_slice(&self.csum_offset.to_le_bytes());
    }

    pub fn read(src: &[u8]) -> Option<Self> {
        if src.len() < GSO_META_LEN {
            return None;
        }
        Some(Self {
            flags: src[0],
            gso_type: src[1],
            hdr_len: u16::from_le_bytes([src[2], src[3]]),
            gso_size: u16::from_le_bytes([src[4], src[5]]),
            csum_start: u16::from_le_bytes([src[6], src[7]]),
            csum_offset: u16::from_le_bytes([src[8], src[9]])
        })
    }

    /// TCP/UDP segmentation offload (the ECN bit may be set on top of the type).
    pub fn segmented(self) -> bool {
        let kind = self.gso_type & !GSO_ECN;
        matches!(kind, GSO_TCPV4 | GSO_TCPV6 | GSO_UDP_L4) && self.gso_size > 0
    }

    /// True when this header describes a segmented aggregate of at least an IP header.
    /// `hdr_len` from the kernel is not trusted: it can be the first segment's full length.
    pub fn sane(self, payload_len: usize) -> bool {
        self.segmented() && payload_len >= 20
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gso_meta_roundtrip_little_endian() {
        let meta = GsoMeta {
            flags: VIRTIO_F_NEEDS_CSUM,
            gso_type: GSO_TCPV4 | GSO_ECN,
            hdr_len: 0x28,
            gso_size: 0x05b4,
            csum_start: 0x14,
            csum_offset: 0x10
        };
        let mut buf = [0u8; 10];
        meta.write(&mut buf);
        assert_eq!(buf, [1, 0x81, 0x28, 0x00, 0xb4, 0x05, 0x14, 0x00, 0x10, 0x00]);
        assert_eq!(GsoMeta::read(&buf), Some(meta));
        assert!(meta.sane(1500));
        assert!(!meta.sane(10));
        let mut bad = meta;
        bad.gso_size = 0;
        assert!(!bad.segmented());
    }
}
