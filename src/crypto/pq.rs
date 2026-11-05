// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! Opt-in hybrid handshake: X25519 plus ML-KEM-768. Off leaves
//! [`crate::crypto::Crypto::parse_algorithms`] on the default AEAD list.

use x25519_dalek::{PublicKey, StaticSecret};

use super::{fill_random, sha256, AeadAlgo, AeadKey, Crypto};

pub const KEM_PUBLIC: usize = 1184;
pub const KEM_SECRET: usize = 2400;
pub const KEM_CIPHERTEXT: usize = 1088;
pub const KEM_SHARED: usize = 32;

extern "C" {
    fn PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> i32;
    fn PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(pk: *mut u8, sk: *mut u8, coins: *const u8) -> i32;
    fn PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> i32;
    fn PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand(ct: *mut u8, ss: *mut u8, pk: *const u8, coins: *const u8) -> i32;
    fn PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> i32;
}

#[derive(Clone, Debug)]
pub struct Hybrid {
    pub plaintext: Vec<u8>,
    pub used_hybrid: bool,
    pub unencrypted: bool,
    pub algorithms: Vec<AeadAlgo>,
    pub kem_public_len: usize,
    pub kem_ciphertext_len: usize,
    pub kem_agreed: bool
}

pub fn kem_roundtrip() -> Result<bool, &'static str> {
    let mut pk = vec![0u8; KEM_PUBLIC];
    let mut sk = vec![0u8; KEM_SECRET];
    let mut ct = vec![0u8; KEM_CIPHERTEXT];
    let mut ss_enc = [0u8; KEM_SHARED];
    let mut ss_dec = [0u8; KEM_SHARED];
    let rc = unsafe { PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()) };
    if rc != 0 {
        return Err("keypair");
    }
    let rc = unsafe { PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ct.as_mut_ptr(), ss_enc.as_mut_ptr(), pk.as_ptr()) };
    if rc != 0 {
        return Err("enc");
    }
    let rc = unsafe { PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss_dec.as_mut_ptr(), ct.as_ptr(), sk.as_ptr()) };
    if rc != 0 {
        return Err("dec");
    }
    if pk.iter().all(|b| *b == 0) || ct.iter().all(|b| *b == 0) || ss_enc == [0u8; 32] {
        return Err("empty kem output");
    }
    Ok(ss_enc == ss_dec)
}

/// Same coins always produce the same public key and shared secret.
pub fn kem_derand_fingerprint(coins_kp: &[u8; 64], coins_enc: &[u8; 32]) -> Result<[u8; 32], &'static str> {
    let mut pk = vec![0u8; KEM_PUBLIC];
    let mut sk = vec![0u8; KEM_SECRET];
    let mut ct = vec![0u8; KEM_CIPHERTEXT];
    let mut ss = [0u8; KEM_SHARED];
    let mut ss2 = [0u8; KEM_SHARED];
    let rc = unsafe { PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(pk.as_mut_ptr(), sk.as_mut_ptr(), coins_kp.as_ptr()) };
    if rc != 0 {
        return Err("derand keypair");
    }
    let rc = unsafe { PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand(ct.as_mut_ptr(), ss.as_mut_ptr(), pk.as_ptr(), coins_enc.as_ptr()) };
    if rc != 0 {
        return Err("derand enc");
    }
    let rc = unsafe { PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr()) };
    if rc != 0 || ss != ss2 {
        return Err("derand dec");
    }
    let mut material = Vec::with_capacity(KEM_PUBLIC + KEM_SHARED);
    material.extend_from_slice(&pk);
    material.extend_from_slice(&ss);
    Ok(sha256(&material))
}

fn default_algorithms() -> Result<(bool, Vec<AeadAlgo>), &'static str> {
    let (unencrypted, _, algos) = Crypto::parse_algorithms(&[]).map_err(|_| "algorithms")?;
    Ok((unencrypted, algos))
}

/// `enabled` runs the hybrid handshake and opens the payload.
/// Off reports the default algorithm list and does not encapsulate.
pub fn handshake(payload: &[u8], enabled: bool) -> Result<Hybrid, &'static str> {
    let (unencrypted, algorithms) = default_algorithms()?;
    if !enabled {
        return Ok(Hybrid {
            plaintext: payload.to_vec(),
            used_hybrid: false,
            unencrypted,
            algorithms,
            kem_public_len: 0,
            kem_ciphertext_len: 0,
            kem_agreed: false
        });
    }

    let mut pk = vec![0u8; KEM_PUBLIC];
    let mut sk = vec![0u8; KEM_SECRET];
    let mut ct = vec![0u8; KEM_CIPHERTEXT];
    let mut ss_i = [0u8; KEM_SHARED];
    let mut ss_r = [0u8; KEM_SHARED];
    let rc = unsafe { PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()) };
    if rc != 0 {
        return Err("keypair");
    }
    let rc = unsafe { PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ct.as_mut_ptr(), ss_i.as_mut_ptr(), pk.as_ptr()) };
    if rc != 0 {
        return Err("enc");
    }
    let rc = unsafe { PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss_r.as_mut_ptr(), ct.as_ptr(), sk.as_ptr()) };
    if rc != 0 {
        return Err("dec");
    }
    let agreed = ss_i == ss_r;

    let mut seed_i = [0u8; 32];
    let mut seed_r = [0u8; 32];
    fill_random(&mut seed_i);
    fill_random(&mut seed_r);
    let sk_i = StaticSecret::from(seed_i);
    let sk_r = StaticSecret::from(seed_r);
    let pk_i = PublicKey::from(&sk_i);
    let pk_r = PublicKey::from(&sk_r);
    let dh_i = sk_i.diffie_hellman(&pk_r);
    let dh_r = sk_r.diffie_hellman(&pk_i);
    if dh_i.as_bytes() != dh_r.as_bytes() {
        return Err("x25519");
    }

    let mut material = Vec::with_capacity(64);
    material.extend_from_slice(dh_i.as_bytes());
    material.extend_from_slice(&ss_i);
    let key = sha256(&material);
    let aead = AeadKey::new(AeadAlgo::ChaCha20Poly1305, &key).map_err(|_| "aead")?;
    let nonce = [0u8; 12];
    let mut buf = payload.to_vec();
    let tag = aead.seal(&nonce, &mut buf).map_err(|_| "seal")?;
    buf.extend_from_slice(&tag);

    let mut material_r = Vec::with_capacity(64);
    material_r.extend_from_slice(dh_r.as_bytes());
    material_r.extend_from_slice(&ss_r);
    let key_r = sha256(&material_r);
    let aead_r = AeadKey::new(AeadAlgo::ChaCha20Poly1305, &key_r).map_err(|_| "aead")?;
    aead_r.open(&nonce, &mut buf).map_err(|_| "open")?;
    buf.truncate(buf.len() - 16);

    Ok(Hybrid {
        plaintext: buf,
        used_hybrid: true,
        unencrypted,
        algorithms,
        kem_public_len: pk.len(),
        kem_ciphertext_len: ct.len(),
        kem_agreed: agreed
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn post_quantum_readiness() {
        println!("row: post-quantum readiness");
        let off = handshake(b"default-payload", false).unwrap();
        assert!(!off.used_hybrid);
        assert!(!off.unencrypted);
        assert!(!off.kem_agreed);
        assert_eq!(off.kem_ciphertext_len, 0);
        assert_eq!(
            off.algorithms,
            vec![AeadAlgo::Aes128Gcm, AeadAlgo::Aes256Gcm, AeadAlgo::ChaCha20Poly1305]
        );
        assert_eq!(off.plaintext, b"default-payload");

        assert!(kem_roundtrip().unwrap());
        let mut coins_kp = [0u8; 64];
        let mut coins_enc = [0u8; 32];
        for (i, b) in coins_kp.iter_mut().enumerate() {
            *b = i as u8;
        }
        for (i, b) in coins_enc.iter_mut().enumerate() {
            *b = (255 - i) as u8;
        }
        let finger = kem_derand_fingerprint(&coins_kp, &coins_enc).unwrap();
        let again = kem_derand_fingerprint(&coins_kp, &coins_enc).unwrap();
        assert_eq!(finger, again);
        assert_ne!(finger, [0u8; 32]);

        let on = handshake(b"pq-payload", true).unwrap();
        assert!(on.used_hybrid);
        assert!(on.kem_agreed);
        assert_eq!(on.kem_public_len, KEM_PUBLIC);
        assert_eq!(on.kem_ciphertext_len, KEM_CIPHERTEXT);
        assert_eq!(on.plaintext, b"pq-payload");
        assert_eq!(
            on.algorithms,
            vec![AeadAlgo::Aes128Gcm, AeadAlgo::Aes256Gcm, AeadAlgo::ChaCha20Poly1305]
        );
    }
}
