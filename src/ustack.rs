// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! In-process IPv4/TCP. Segments move on an in-memory queue. The host
//! kernel never sees the handshake.

use std::collections::VecDeque;

const SYN: u8 = 0x02;
const ACK: u8 = 0x10;
const PSH: u8 = 0x08;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Segment {
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub data: Vec<u8>
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpExchange {
    pub syn: Vec<u8>,
    pub synack: Vec<u8>,
    pub received: Vec<u8>,
    pub echoed: Vec<u8>,
    pub saw_syn: bool,
    pub saw_synack: bool,
    pub established: bool
}

fn fold_sum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut index = 0;
    while index + 1 < data.len() {
        sum += u16::from_be_bytes([data[index], data[index + 1]]) as u32;
        index += 2;
    }
    if index < data.len() {
        sum += (data[index] as u32) << 8;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}

fn ip_checksum(header: &[u8]) -> u16 {
    let mut tmp = header.to_vec();
    tmp[10] = 0;
    tmp[11] = 0;
    fold_sum(&tmp)
}

fn tcp_checksum(src: [u8; 4], dst: [u8; 4], segment: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + segment.len());
    pseudo.extend_from_slice(&src);
    pseudo.extend_from_slice(&dst);
    pseudo.push(0);
    pseudo.push(6);
    pseudo.extend_from_slice(&(segment.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(segment);
    let csum_at = 12 + 16;
    pseudo[csum_at] = 0;
    pseudo[csum_at + 1] = 0;
    fold_sum(&pseudo)
}

pub fn build_segment(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, seq: u32, ack: u32, flags: u8, data: &[u8]) -> Vec<u8> {
    let total = 40 + data.len();
    let mut pkt = vec![0u8; total];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 6;
    pkt[12..16].copy_from_slice(&src);
    pkt[16..20].copy_from_slice(&dst);
    let ip_sum = ip_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    pkt[20..22].copy_from_slice(&sport.to_be_bytes());
    pkt[22..24].copy_from_slice(&dport.to_be_bytes());
    pkt[24..28].copy_from_slice(&seq.to_be_bytes());
    pkt[28..32].copy_from_slice(&ack.to_be_bytes());
    pkt[32] = 5 << 4;
    pkt[33] = flags;
    pkt[34..36].copy_from_slice(&65535u16.to_be_bytes());
    pkt[40..].copy_from_slice(data);
    let sum = tcp_checksum(src, dst, &pkt[20..]);
    pkt[36..38].copy_from_slice(&sum.to_be_bytes());
    pkt
}

pub fn parse_segment(pkt: &[u8]) -> Option<Segment> {
    if pkt.len() < 40 || pkt[0] != 0x45 || pkt[9] != 6 {
        return None;
    }
    let total = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    if total != pkt.len() {
        return None;
    }
    let expect_ip = ip_checksum(&pkt[..20]);
    let got_ip = u16::from_be_bytes([pkt[10], pkt[11]]);
    if expect_ip != got_ip {
        return None;
    }
    let mut src = [0u8; 4];
    let mut dst = [0u8; 4];
    src.copy_from_slice(&pkt[12..16]);
    dst.copy_from_slice(&pkt[16..20]);
    let expect_tcp = tcp_checksum(src, dst, &pkt[20..]);
    let got_tcp = u16::from_be_bytes([pkt[36], pkt[37]]);
    if expect_tcp != got_tcp || pkt[32] >> 4 != 5 {
        return None;
    }
    Some(Segment {
        src,
        dst,
        sport: u16::from_be_bytes([pkt[20], pkt[21]]),
        dport: u16::from_be_bytes([pkt[22], pkt[23]]),
        seq: u32::from_be_bytes(pkt[24..28].try_into().ok()?),
        ack: u32::from_be_bytes(pkt[28..32].try_into().ok()?),
        flags: pkt[33],
        data: pkt[40..].to_vec()
    })
}

/// Handshake plus a payload and its echo between 10.0.0.1 and 10.0.0.2.
pub fn exchange(payload: &[u8]) -> Result<TcpExchange, &'static str> {
    let a = [10, 0, 0, 1];
    let b = [10, 0, 0, 2];
    let client_isn = 1000u32;
    let server_isn = 5000u32;
    let mut c2s: VecDeque<Vec<u8>> = VecDeque::new();
    let mut s2c: VecDeque<Vec<u8>> = VecDeque::new();

    let syn = build_segment(a, b, 40000, 80, client_isn, 0, SYN, &[]);
    c2s.push_back(syn.clone());
    let syn_seg = parse_segment(&c2s.pop_front().ok_or("syn")?).ok_or("parse syn")?;
    if syn_seg.flags & SYN == 0 || !syn_seg.data.is_empty() {
        return Err("syn flags");
    }

    let synack = build_segment(b, a, 80, 40000, server_isn, client_isn.wrapping_add(1), SYN | ACK, &[]);
    s2c.push_back(synack.clone());
    let synack_seg = parse_segment(&s2c.pop_front().ok_or("synack")?).ok_or("parse synack")?;
    if synack_seg.flags & SYN == 0 || synack_seg.flags & ACK == 0 || synack_seg.ack != client_isn.wrapping_add(1) {
        return Err("synack flags");
    }

    let ack = build_segment(a, b, 40000, 80, client_isn.wrapping_add(1), server_isn.wrapping_add(1), ACK, &[]);
    c2s.push_back(ack);
    let ack_seg = parse_segment(&c2s.pop_front().ok_or("ack")?).ok_or("parse ack")?;
    if ack_seg.flags & ACK == 0 || ack_seg.ack != server_isn.wrapping_add(1) || ack_seg.seq != client_isn.wrapping_add(1) {
        return Err("handshake ack");
    }

    let data = build_segment(a, b, 40000, 80, client_isn.wrapping_add(1), server_isn.wrapping_add(1), ACK | PSH, payload);
    c2s.push_back(data);
    let data_seg = parse_segment(&c2s.pop_front().ok_or("data")?).ok_or("parse data")?;
    if data_seg.seq != client_isn.wrapping_add(1) {
        return Err("data seq");
    }

    let next = client_isn.wrapping_add(1).wrapping_add(payload.len() as u32);
    let echo = build_segment(b, a, 80, 40000, server_isn.wrapping_add(1), next, ACK | PSH, &data_seg.data);
    s2c.push_back(echo);
    let echo_seg = parse_segment(&s2c.pop_front().ok_or("echo")?).ok_or("parse echo")?;

    Ok(TcpExchange {
        syn,
        synack,
        received: data_seg.data,
        echoed: echo_seg.data,
        saw_syn: true,
        saw_synack: true,
        established: true
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn userspace_tcp_ip_stack() {
        println!("row: userspace TCP/IP stack");
        let payload = b"userspace-tcp-bytes";
        let got = exchange(payload).expect("handshake");
        assert!(got.saw_syn && got.saw_synack && got.established);
        let syn = parse_segment(&got.syn).expect("syn");
        let synack = parse_segment(&got.synack).expect("synack");
        assert_eq!(syn.src, [10, 0, 0, 1]);
        assert_eq!(syn.dst, [10, 0, 0, 2]);
        assert_eq!(syn.flags & SYN, SYN);
        assert_eq!(synack.flags & (SYN | ACK), SYN | ACK);
        assert_eq!(synack.ack, syn.seq.wrapping_add(1));
        assert_eq!(got.received, payload);
        assert_eq!(got.echoed, payload);
    }
}
