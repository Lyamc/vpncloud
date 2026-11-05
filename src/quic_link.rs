// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! QUIC v1 packet protection for one sealed mesh payload.
//!
//! Initial keys follow RFC 9001. The CRYPTO frames carry X25519 publics.
//! 1-RTT keys are HKDF(shared secret) with the same `tls13 ` labels. This
//! path is opt-in: nothing in the default UDP peer calls it.

use std::{
    io::{self, ErrorKind},
    net::UdpSocket,
    time::Duration
};

use aes::cipher::BlockEncrypt;
use aes_gcm::aead::{Aead, Payload};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::crypto::fill_random;

const INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectionKeys {
    pub secret: [u8; 32],
    pub key: [u8; 16],
    pub iv: [u8; 12],
    pub hp: [u8; 16]
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitialSecrets {
    pub initial_secret: [u8; 32],
    pub client: DirectionKeys,
    pub server: DirectionKeys
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac key");
    mac.update(data);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    hmac_sha256(salt, ikm)
}

fn hkdf_expand(prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut prev = Vec::new();
    let mut counter = 1u8;
    while out.len() < len {
        let mut mac = Hmac::<Sha256>::new_from_slice(prk).expect("hkdf prk");
        mac.update(&prev);
        mac.update(info);
        mac.update(&[counter]);
        prev = mac.finalize().into_bytes().to_vec();
        out.extend_from_slice(&prev);
        counter = counter.wrapping_add(1);
    }
    out.truncate(len);
    out
}

fn hkdf_expand_label(prk: &[u8], label: &str, len: usize) -> Vec<u8> {
    let full = format!("tls13 {label}");
    let mut info = Vec::with_capacity(2 + 1 + full.len() + 1);
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(0);
    hkdf_expand(prk, &info, len)
}

fn direction_keys(secret_prk: &[u8; 32], label: &str) -> DirectionKeys {
    let secret_bytes = hkdf_expand_label(secret_prk, label, 32);
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&secret_bytes);
    let key_b = hkdf_expand_label(&secret, "quic key", 16);
    let iv_b = hkdf_expand_label(&secret, "quic iv", 12);
    let hp_b = hkdf_expand_label(&secret, "quic hp", 16);
    let mut key = [0u8; 16];
    let mut iv = [0u8; 12];
    let mut hp = [0u8; 16];
    key.copy_from_slice(&key_b);
    iv.copy_from_slice(&iv_b);
    hp.copy_from_slice(&hp_b);
    DirectionKeys { secret, key, iv, hp }
}

/// RFC 9001 initial secrets from the client's original destination connection id.
pub fn initial_secrets(client_dst_cid: &[u8]) -> InitialSecrets {
    let initial_secret = hkdf_extract(&INITIAL_SALT, client_dst_cid);
    InitialSecrets {
        initial_secret,
        client: direction_keys(&initial_secret, "client in"),
        server: direction_keys(&initial_secret, "server in")
    }
}

pub fn rtt_keys(shared: &[u8]) -> DirectionKeys {
    let secret = hkdf_extract(b"vpncloud quic v1", shared);
    let key_b = hkdf_expand_label(&secret, "quic key", 16);
    let iv_b = hkdf_expand_label(&secret, "quic iv", 12);
    let hp_b = hkdf_expand_label(&secret, "quic hp", 16);
    let mut key = [0u8; 16];
    let mut iv = [0u8; 12];
    let mut hp = [0u8; 16];
    key.copy_from_slice(&key_b);
    iv.copy_from_slice(&iv_b);
    hp.copy_from_slice(&hp_b);
    DirectionKeys { secret, key, iv, hp }
}

fn put_varint(out: &mut Vec<u8>, value: u64) {
    if value < 64 {
        out.push(value as u8);
    } else if value < 16384 {
        let encoded = (value as u16) | 0x4000;
        out.extend_from_slice(&encoded.to_be_bytes());
    } else {
        let encoded = (value as u32) | 0x8000_0000;
        out.extend_from_slice(&encoded.to_be_bytes());
    }
}

fn take_varint(data: &[u8], index: &mut usize) -> Option<u64> {
    let first = *data.get(*index)?;
    let len = 1usize << (first >> 6);
    if *index + len > data.len() {
        return None;
    }
    let mut value = 0u64;
    for _ in 0..len {
        value = (value << 8) | data[*index] as u64;
        *index += 1;
    }
    let shift = len * 8 - 2;
    value &= !(0b11u64 << shift);
    Some(value)
}

fn aes128_ecb(key: &[u8], block: &[u8; 16]) -> [u8; 16] {
    use aes::cipher::KeyInit;
    let cipher = aes::Aes128::new_from_slice(key).expect("header protection key");
    let mut out = aes::cipher::generic_array::GenericArray::from(*block);
    cipher.encrypt_block(&mut out);
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&out);
    bytes
}

fn xor_pn(iv: &mut [u8; 12], pn: u32) {
    let bytes = pn.to_be_bytes();
    for i in 0..4 {
        iv[8 + i] ^= bytes[i];
    }
}

fn seal_packet(key: &[u8; 16], iv: &[u8; 12], hp: &[u8; 16], header: &[u8], pn_offset: usize, plain: &[u8], long: bool) -> Vec<u8> {
    use aes_gcm::aead::KeyInit;
    let cipher = aes_gcm::Aes128Gcm::new_from_slice(key).expect("quic key");
    let nonce = aes_gcm::Nonce::from_slice(iv);
    let ct = cipher.encrypt(nonce, Payload { msg: plain, aad: header }).expect("quic seal");
    let mut packet = Vec::with_capacity(header.len() + ct.len());
    packet.extend_from_slice(header);
    packet.extend_from_slice(&ct);
    let mut sample = [0u8; 16];
    sample.copy_from_slice(&packet[pn_offset + 4..pn_offset + 20]);
    let mask = aes128_ecb(hp, &sample);
    let first_mask = if long { 0x0f } else { 0x1f };
    packet[0] ^= mask[0] & first_mask;
    for i in 0..4 {
        packet[pn_offset + i] ^= mask[1 + i];
    }
    packet
}

fn open_aead(key: &[u8; 16], iv: &[u8; 12], header: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    use aes_gcm::aead::KeyInit;
    let cipher = aes_gcm::Aes128Gcm::new_from_slice(key).ok()?;
    let nonce = aes_gcm::Nonce::from_slice(iv);
    cipher.decrypt(nonce, Payload { msg: ct, aad: header }).ok()
}

fn apply_hp(packet: &mut [u8], hp: &[u8; 16], pn_offset: usize, long: bool) -> Option<u32> {
    if packet.len() < pn_offset + 4 + 16 {
        return None;
    }
    let mut sample = [0u8; 16];
    sample.copy_from_slice(&packet[pn_offset + 4..pn_offset + 20]);
    let mask = aes128_ecb(hp, &sample);
    let first_mask = if long { 0x0f } else { 0x1f };
    packet[0] ^= mask[0] & first_mask;
    let pn_len = ((packet[0] & 0x03) + 1) as usize;
    if pn_len != 4 {
        return None;
    }
    for i in 0..4 {
        packet[pn_offset + i] ^= mask[1 + i];
    }
    Some(u32::from_be_bytes(packet[pn_offset..pn_offset + 4].try_into().ok()?))
}

fn build_initial(dcid: &[u8], scid: &[u8], pn: u32, plain: &[u8], keys: &DirectionKeys) -> Vec<u8> {
    let ct_len = plain.len() + 16;
    let mut header = Vec::new();
    header.push(0xc3);
    header.extend_from_slice(&1u32.to_be_bytes());
    header.push(dcid.len() as u8);
    header.extend_from_slice(dcid);
    header.push(scid.len() as u8);
    header.extend_from_slice(scid);
    put_varint(&mut header, 0);
    put_varint(&mut header, (4 + ct_len) as u64);
    let pn_offset = header.len();
    header.extend_from_slice(&pn.to_be_bytes());
    let mut iv = keys.iv;
    xor_pn(&mut iv, pn);
    seal_packet(&keys.key, &iv, &keys.hp, &header, pn_offset, plain, true)
}

fn open_initial(packet: &[u8], keys: &DirectionKeys) -> Option<Vec<u8>> {
    if packet.first().copied().unwrap_or(0) & 0x80 == 0 || packet.len() < 7 {
        return None;
    }
    let mut index = 5;
    let dcid_len = *packet.get(index)? as usize;
    index += 1 + dcid_len;
    let scid_len = *packet.get(index)? as usize;
    index += 1 + scid_len;
    let token_len = take_varint(packet, &mut index)? as usize;
    index += token_len;
    let length = take_varint(packet, &mut index)? as usize;
    let pn_offset = index;
    if pn_offset + length > packet.len() {
        return None;
    }
    let mut pkt = packet.to_vec();
    let pn = apply_hp(&mut pkt, &keys.hp, pn_offset, true)?;
    let mut iv = keys.iv;
    xor_pn(&mut iv, pn);
    let header = &pkt[..pn_offset + 4];
    let ct = &pkt[pn_offset + 4..pn_offset + length];
    open_aead(&keys.key, &iv, header, ct)
}

fn build_short(dcid: &[u8], pn: u32, plain: &[u8], keys: &DirectionKeys) -> Vec<u8> {
    let mut header = Vec::new();
    header.push(0x43);
    header.extend_from_slice(dcid);
    let pn_offset = header.len();
    header.extend_from_slice(&pn.to_be_bytes());
    let mut iv = keys.iv;
    xor_pn(&mut iv, pn);
    seal_packet(&keys.key, &iv, &keys.hp, &header, pn_offset, plain, false)
}

fn open_short(packet: &[u8], dcid: &[u8], keys: &DirectionKeys) -> Option<Vec<u8>> {
    if packet.len() < 1 + dcid.len() + 4 + 16 {
        return None;
    }
    if &packet[1..1 + dcid.len()] != dcid {
        return None;
    }
    let pn_offset = 1 + dcid.len();
    let mut pkt = packet.to_vec();
    let pn = apply_hp(&mut pkt, &keys.hp, pn_offset, false)?;
    let mut iv = keys.iv;
    xor_pn(&mut iv, pn);
    let header = &pkt[..pn_offset + 4];
    let ct = &pkt[pn_offset + 4..];
    open_aead(&keys.key, &iv, header, ct)
}

fn crypto_frame(data: &[u8]) -> Vec<u8> {
    let mut frame = vec![0x06];
    put_varint(&mut frame, 0);
    put_varint(&mut frame, data.len() as u64);
    frame.extend_from_slice(data);
    frame
}

fn stream_frame(data: &[u8]) -> Vec<u8> {
    let mut frame = vec![0x0a];
    put_varint(&mut frame, data.len() as u64);
    frame.extend_from_slice(data);
    frame
}

fn parse_crypto(plain: &[u8]) -> Option<Vec<u8>> {
    if plain.first() != Some(&0x06) {
        return None;
    }
    let mut index = 1;
    let _offset = take_varint(plain, &mut index)?;
    let len = take_varint(plain, &mut index)? as usize;
    if index + len > plain.len() {
        return None;
    }
    Some(plain[index..index + len].to_vec())
}

fn parse_stream(plain: &[u8]) -> Option<Vec<u8>> {
    let kind = *plain.first()?;
    if kind & 0xf8 != 0x08 {
        return None;
    }
    let mut index = 1;
    if kind & 0x04 != 0 {
        let _off = take_varint(plain, &mut index)?;
    }
    if kind & 0x02 != 0 {
        let len = take_varint(plain, &mut index)? as usize;
        if index + len > plain.len() {
            return None;
        }
        return Some(plain[index..index + len].to_vec());
    }
    Some(plain[index..].to_vec())
}

fn random_cid() -> [u8; 8] {
    let mut cid = [0u8; 8];
    fill_random(&mut cid);
    cid
}

fn recv(sock: &UdpSocket) -> io::Result<Vec<u8>> {
    let mut buf = [0u8; 2048];
    let (n, _) = sock.recv_from(&mut buf)?;
    Ok(buf[..n].to_vec())
}

/// Carry `frame` from a QUIC client to a QUIC server on localhost UDP.
/// The returned bytes are the STREAM payload the server decrypted.
pub fn deliver_sealed(frame: &[u8]) -> io::Result<Vec<u8>> {
    let server = UdpSocket::bind("127.0.0.1:0")?;
    let client = UdpSocket::bind("127.0.0.1:0")?;
    server.set_read_timeout(Some(Duration::from_millis(500)))?;
    client.set_read_timeout(Some(Duration::from_millis(500)))?;
    let server_addr = server.local_addr()?;

    let server_cid = random_cid();
    let client_cid = random_cid();
    let secrets = initial_secrets(&server_cid);

    let mut client_seed = [0u8; 32];
    let mut server_seed = [0u8; 32];
    fill_random(&mut client_seed);
    fill_random(&mut server_seed);
    let client_sk = StaticSecret::from(client_seed);
    let server_sk = StaticSecret::from(server_seed);
    let client_pk = PublicKey::from(&client_sk);
    let server_pk = PublicKey::from(&server_sk);

    let initial = build_initial(&server_cid, &client_cid, 0, &crypto_frame(client_pk.as_bytes()), &secrets.client);
    client.send_to(&initial, server_addr)?;
    let got = recv(&server)?;
    let opened = open_initial(&got, &secrets.client).ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "client initial"))?;
    let their_pk = parse_crypto(&opened).ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "client crypto"))?;
    if their_pk.as_slice() != client_pk.as_bytes() {
        return Err(io::Error::new(ErrorKind::InvalidData, "client public"));
    }

    let reply = build_initial(&client_cid, &server_cid, 0, &crypto_frame(server_pk.as_bytes()), &secrets.server);
    server.send_to(&reply, client.local_addr()?)?;
    let got = recv(&client)?;
    let opened = open_initial(&got, &secrets.server).ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "server initial"))?;
    let their_pk = parse_crypto(&opened).ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "server crypto"))?;
    if their_pk.as_slice() != server_pk.as_bytes() {
        return Err(io::Error::new(ErrorKind::InvalidData, "server public"));
    }

    let shared_c = client_sk.diffie_hellman(&server_pk);
    let shared_s = server_sk.diffie_hellman(&client_pk);
    if shared_c.as_bytes() != shared_s.as_bytes() {
        return Err(io::Error::new(ErrorKind::InvalidData, "x25519"));
    }
    let app = rtt_keys(shared_c.as_bytes());
    let short = build_short(&server_cid, 1, &stream_frame(frame), &app);
    client.send_to(&short, server_addr)?;
    let got = recv(&server)?;
    let opened = open_short(&got, &server_cid, &app).ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "1rtt"))?;
    parse_stream(&opened).ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "stream"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn quic_support() {
        println!("row: QUIC support");
        let dcid = unhex("8394c8f03e515708");
        let secrets = initial_secrets(&dcid);
        assert_eq!(secrets.initial_secret.as_slice(), unhex("7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44"));
        assert_eq!(secrets.client.secret.as_slice(), unhex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"));
        assert_eq!(secrets.client.key.as_slice(), unhex("1f369613dd76d5467730efcbe3b1a22d"));
        assert_eq!(secrets.client.iv.as_slice(), unhex("fa044b2f42a3fd3b46fb255c"));
        assert_eq!(secrets.client.hp.as_slice(), unhex("9f50449e04a0e810283a1e9933adedd2"));

        let (secret_a, pub_a) = crate::policy::generate_e2e_keypair();
        let (secret_b, pub_b) = crate::policy::generate_e2e_keypair();
        let payload = b"tcp-relay-secret";
        let sealed = crate::policy::seal_relay_body(&secret_a, &pub_a, &pub_b, payload).expect("seal");
        let frame = crate::policy::encode_relay(&[9u8; 16], crate::messages::MESSAGE_TYPE_DATA, &sealed);
        let got = deliver_sealed(&frame).expect("quic");
        assert_eq!(got, frame);
        let (sealer, plain) = crate::policy::open_relay_body(&secret_b, &got[17..]).expect("open");
        assert_eq!(sealer, pub_a);
        assert_eq!(plain, payload);
        let (unencrypted, _, algos) = crate::crypto::Crypto::parse_algorithms(&[]).unwrap();
        assert!(!unencrypted);
        assert!(algos.contains(&crate::crypto::AeadAlgo::Aes128Gcm));
        assert!(algos.contains(&crate::crypto::AeadAlgo::Aes256Gcm));
        assert!(algos.contains(&crate::crypto::AeadAlgo::ChaCha20Poly1305));
    }
}
