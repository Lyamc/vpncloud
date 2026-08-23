// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! Ed25519 signatures over config file bodies (signature lines stripped).

use crate::crypto_ring::signature::{Ed25519KeyPair, UnparsedPublicKey, ED25519};

use crate::{
    crypto::Crypto,
    error::Error,
    util::{from_base62, to_base62}
};

pub fn strip_signature_lines(raw: &str) -> String {
    raw.lines()
        .filter(|line| {
            let t = line.trim();
            !(t.starts_with("signature:") || t.starts_with("signature =") || t.starts_with("signature="))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn canonical_body(raw: &str) -> String {
    strip_signature_lines(raw).trim_end().to_string()
}

pub fn sign_body(body: &str, private_key_b62: &str) -> Result<String, Error> {
    let seed = from_base62(private_key_b62).map_err(|_| Error::InvalidConfig("Failed to parse private key"))?;
    if seed.len() != 32 {
        return Err(Error::InvalidConfig("Failed to parse private key"));
    }
    let pair = Ed25519KeyPair::from_seed_unchecked(&seed)
        .map_err(|_| Error::InvalidConfig("Key rejected by crypto library"))?;
    Ok(to_base62(pair.sign(body.as_bytes()).as_ref()))
}

pub fn sign_with_password(body: &str, password: &str, salt: Option<&str>, kdf: Option<&str>) -> Result<String, Error> {
    let seed = Crypto::password_seed(password, salt, kdf)?;
    let pair = Ed25519KeyPair::from_seed_unchecked(&seed)
        .map_err(|_| Error::InvalidConfig("Key rejected by crypto library"))?;
    Ok(to_base62(pair.sign(body.as_bytes()).as_ref()))
}

pub fn verify_body(body: &str, signature_b62: &str, public_key_b62: &str) -> Result<(), Error> {
    let sig = from_base62(signature_b62).map_err(|_| Error::InvalidConfig("Invalid config signature"))?;
    let pk = from_base62(public_key_b62).map_err(|_| Error::InvalidConfig("Failed to parse public key"))?;
    UnparsedPublicKey::new(&ED25519, pk)
        .verify(body.as_bytes(), &sig)
        .map_err(|_| Error::InvalidConfig("Config signature verification failed"))
}

pub fn extract_signature(raw: &str) -> Option<String> {
    for line in raw.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("signature:") {
            let v = rest.trim().trim_matches('"').trim().to_string();
            if !v.is_empty() {
                return Some(v);
            }
        } else if let Some(rest) = t.strip_prefix("signature =") {
            let v = rest.trim().trim_matches('"').trim().to_string();
            if !v.is_empty() {
                return Some(v);
            }
        } else if let Some(rest) = t.strip_prefix("signature=") {
            let v = rest.trim().trim_matches('"').trim().to_string();
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

fn key_id(entry: &str) -> Option<&str> {
    if let Some((key, rest)) = entry.rsplit_once(':') {
        if rest.len() == 10 && rest.as_bytes().get(4) == Some(&b'-') {
            if Crypto::date_expired(rest) {
                return None;
            }
            return Some(key);
        }
    }
    Some(entry)
}

/// Verify `raw` against any of `public_keys` (base62, optional `:YYYY-MM-DD` expiry).
pub fn verify_config(raw: &str, public_keys: &[String]) -> Result<(), Error> {
    let sig = extract_signature(raw).ok_or(Error::InvalidConfig("Config file is not signed"))?;
    let body = canonical_body(raw);
    let mut last = Error::InvalidConfig("Config signature verification failed");
    for entry in public_keys {
        let Some(key) = key_id(entry) else {
            continue;
        };
        match verify_body(&body, &sig, key) {
            Ok(()) => return Ok(()),
            Err(e) => last = e
        }
    }
    Err(last)
}

pub fn append_signature_line(raw: &str, signature_b62: &str, toml: bool) -> String {
    let body = strip_signature_lines(raw).trim_end().to_string();
    if toml {
        format!("{}\nsignature = \"{}\"\n", body, signature_b62)
    } else {
        format!("{}\nsignature: {}\n", body, signature_b62)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Crypto;

    #[test]
    fn sign_verify_roundtrip() {
        let (privk, pubk) = Crypto::generate_keypair(None);
        let body = "listen: 3210\npeers: []\n";
        let sig = sign_body(body, &privk).unwrap();
        verify_body(body, &sig, &pubk).unwrap();
        assert!(verify_body("tampered", &sig, &pubk).is_err());
    }

    #[test]
    fn strip_drops_signature_line() {
        let raw = "listen: 3210\nsignature: abc\npeers: []\n";
        let body = strip_signature_lines(raw);
        assert!(!body.contains("signature"));
        assert!(body.contains("listen: 3210"));
    }

    #[test]
    fn verify_config_roundtrip() {
        let (privk, pubk) = Crypto::generate_keypair(None);
        let raw = "listen: 3210\npeers: []\n";
        let body = canonical_body(raw);
        let sig = sign_body(&body, &privk).unwrap();
        let signed = append_signature_line(raw, &sig, false);
        verify_config(&signed, &[pubk.clone()]).unwrap();
        assert!(verify_config(raw, &[pubk]).is_err());
    }
}
