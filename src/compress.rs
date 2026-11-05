// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! Optional LZSS for tunnel payloads. The default is off, and off leaves
//! the payload bytes unchanged.

const MIN_MATCH: usize = 4;
const MAX_MATCH: usize = 255;
const WINDOW: usize = 4096;

pub fn enabled_by_default() -> bool {
    false
}

pub fn on_wire(payload: &[u8], enabled: bool) -> Vec<u8> {
    if !enabled {
        return payload.to_vec();
    }
    compress(payload)
}

pub fn from_wire(frame: &[u8], enabled: bool) -> Result<Vec<u8>, &'static str> {
    if !enabled {
        return Ok(frame.to_vec());
    }
    decompress(frame)
}

fn compress(src: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < src.len() {
        let flag_at = out.len();
        out.push(0);
        for bit in 0..8 {
            if i >= src.len() {
                break;
            }
            let (pos, len) = find_match(src, i);
            if len >= MIN_MATCH {
                out[flag_at] |= 1 << bit;
                let dist = (i - pos) as u16;
                out.push(dist as u8);
                out.push((dist >> 8) as u8);
                out.push(len as u8);
                i += len;
            } else {
                out.push(src[i]);
                i += 1;
            }
        }
    }
    out
}

fn find_match(src: &[u8], i: usize) -> (usize, usize) {
    let start = i.saturating_sub(WINDOW);
    let max_len = (src.len() - i).min(MAX_MATCH);
    if max_len < MIN_MATCH {
        return (0, 0);
    }
    let mut best_pos = 0;
    let mut best_len = 0;
    for j in start..i {
        let mut len = 0;
        while len < max_len && src[j + len] == src[i + len] {
            len += 1;
        }
        if len > best_len {
            best_len = len;
            best_pos = j;
        }
    }
    (best_pos, best_len)
}

fn decompress(src: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < src.len() {
        let flags = src[i];
        i += 1;
        for bit in 0..8 {
            if i >= src.len() {
                break;
            }
            if flags & (1 << bit) != 0 {
                if i + 3 > src.len() {
                    return Err("truncated match");
                }
                let dist = u16::from_le_bytes([src[i], src[i + 1]]) as usize;
                let len = src[i + 2] as usize;
                i += 3;
                if dist == 0 || dist > out.len() || len < MIN_MATCH {
                    return Err("bad match");
                }
                for _ in 0..len {
                    let byte = out[out.len() - dist];
                    out.push(byte);
                }
            } else {
                out.push(src[i]);
                i += 1;
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<u8> {
        let mut payload = b"vpncloud-tunnel".to_vec();
        payload.extend(std::iter::repeat(b'A').take(240));
        payload
    }

    #[test]
    fn tunnel_compression() {
        println!("row: tunnel compression");
        let payload = sample();
        let wire = on_wire(&payload, true);
        assert!(wire.len() < payload.len(), "compressed {} vs {}", wire.len(), payload.len());
        assert_eq!(from_wire(&wire, true).unwrap(), payload);
    }

    #[test]
    fn configurable_compression() {
        println!("row: configurable compression");
        assert!(!enabled_by_default());
        let payload = sample();
        let off = on_wire(&payload, false);
        assert_eq!(off, payload);
        assert_eq!(from_wire(&off, false).unwrap(), payload);
        let on = on_wire(&payload, true);
        assert!(on.len() < off.len());
        assert_ne!(on, off);
    }
}
