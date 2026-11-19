// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! Ed25519 signatures over config file bodies.
//!
//! Canonicalization is deliberately strict: exactly one signature entry, at
//! column zero, as the last non-empty line. This prevents an attacker from
//! changing parsed config semantics by inserting `signature:`-prefixed lines
//! inside a YAML multi-line scalar (the old line-based filter would strip
//! those while leaving the rest of the signed body unchanged).

use crate::{
    crypto::{Crypto, Ed25519KeyPair},
    error::Error,
    util::{from_base62_fixed, to_base62}
};

/// True when a trimmed line starts with a config-signature key.
fn is_signature_line(trimmed: &str) -> bool {
    trimmed.starts_with("signature:") || trimmed.starts_with("signature =") || trimmed.starts_with("signature=")
}

/// Locate the single signature line and return its index and value.
///
/// Rules: exactly one candidate, no leading whitespace, last non-empty line.
pub fn find_signature(raw: &str) -> Result<(usize, String), Error> {
    let lines: Vec<&str> = raw.lines().collect();
    let mut found = None;
    for (i, line) in lines.iter().enumerate() {
        if is_signature_line(line.trim()) {
            if found.is_some() {
                return Err(Error::InvalidConfig("Multiple signature lines in config"));
            }
            if line.starts_with(char::is_whitespace) {
                return Err(Error::InvalidConfig("Signature line must start at column zero"));
            }
            found = Some((i, line));
        }
    }
    let (idx, line) = found.ok_or(Error::InvalidConfig("Config file is not signed"))?;
    if lines[idx + 1..].iter().any(|l| !l.trim().is_empty()) {
        return Err(Error::InvalidConfig("Signature line must be the last non-empty line"));
    }
    let value = line
        .trim()
        .strip_prefix("signature:")
        .or_else(|| line.trim().strip_prefix("signature ="))
        .or_else(|| line.trim().strip_prefix("signature="))
        .unwrap_or("")
        .trim()
        .trim_matches('"')
        .trim()
        .to_string();
    if value.is_empty() {
        return Err(Error::InvalidConfig("Empty config signature"));
    }
    Ok((idx, value))
}

/// The signed body: every line before the signature line, trailing blank
/// lines removed. Strict parsing makes this unambiguous with respect to the
/// parsed config structure.
pub fn canonical_body(raw: &str) -> Result<String, Error> {
    let (idx, _) = find_signature(raw)?;
    let body = raw.lines().take(idx).collect::<Vec<_>>().join("\n");
    Ok(body.trim_end().to_string())
}

/// Body to sign: the whole file when unsigned, or the canonical body when
/// re-signing an already signed file.
pub fn body_for_signing(raw: &str) -> String {
    match find_signature(raw) {
        Ok(_) => canonical_body(raw).unwrap_or_else(|_| raw.trim_end().to_string()),
        Err(_) => raw.trim_end().to_string()
    }
}

pub fn sign_body(body: &str, private_key_b62: &str) -> Result<String, Error> {
    let seed =
        from_base62_fixed::<32>(private_key_b62).map_err(|_| Error::InvalidConfig("Failed to parse private key"))?;
    if seed.len() != 32 {
        return Err(Error::InvalidConfig("Failed to parse private key"));
    }
    let pair = Ed25519KeyPair::from_seed(&seed).map_err(|_| Error::InvalidConfig("Key rejected by crypto library"))?;
    Ok(to_base62(&pair.sign(body.as_bytes())))
}

pub fn sign_with_password(body: &str, password: &str, salt: Option<&str>, kdf: Option<&str>) -> Result<String, Error> {
    let seed = Crypto::password_seed(password, salt, kdf)?;
    let pair = Ed25519KeyPair::from_seed(&seed).map_err(|_| Error::InvalidConfig("Key rejected by crypto library"))?;
    Ok(to_base62(&pair.sign(body.as_bytes())))
}

pub fn verify_body(body: &str, signature_b62: &str, public_key_b62: &str) -> Result<(), Error> {
    let sig = from_base62_fixed::<64>(signature_b62).map_err(|_| Error::InvalidConfig("Invalid config signature"))?;
    let pk = from_base62_fixed::<32>(public_key_b62).map_err(|_| Error::InvalidConfig("Failed to parse public key"))?;
    Ed25519KeyPair::verify(&pk, body.as_bytes(), &sig)
        .map_err(|_| Error::InvalidConfig("Config signature verification failed"))
}

/// Extract the signature value using the same strict rules as verification.
pub fn extract_signature(raw: &str) -> Option<String> {
    find_signature(raw).ok().map(|(_, value)| value)
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
    let (_, sig) = find_signature(raw)?;
    let body = canonical_body(raw)?;
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

/// Replace any existing signature entry with `signature_b62`, appending at
/// column zero as the last line.
pub fn append_signature_line(raw: &str, signature_b62: &str, toml: bool) -> String {
    // Strip a single well-formed trailing signature if present; otherwise use
    // the whole file. This keeps re-signing idempotent.
    let body = body_for_signing(raw);
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
    fn verify_config_roundtrip() {
        let (privk, pubk) = Crypto::generate_keypair(None);
        let raw = "listen: 3210\npeers: []\n";
        let body = canonical_body(&format!("{}\nsignature: placeholder\n", raw)).unwrap();
        assert_eq!(body, raw.trim_end());
        let sig = sign_body(&body, &privk).unwrap();
        let signed = append_signature_line(raw, &sig, false);
        verify_config(&signed, &[pubk.clone()]).unwrap();
        assert!(verify_config(raw, &[pubk.clone()]).is_err());
        let expired = format!("{}:2000-01-01", pubk);
        assert!(verify_config(&signed, &[expired]).is_err());
        let live = format!("{}:2099-01-01", pubk);
        verify_config(&signed, &[live]).unwrap();
    }

    #[test]
    fn rejects_indented_signature_lines() {
        let raw = "hook: |\n  echo hi\n  signature: evil\nsignature: real\n";
        assert!(find_signature(raw).is_err());
        assert!(canonical_body(raw).is_err());
    }

    #[test]
    fn rejects_multiple_or_non_final_signature_lines() {
        let raw = "signature: a\nsignature: b\n";
        assert!(find_signature(raw).is_err());
        let raw = "signature: a\npeers: []\n";
        assert!(find_signature(raw).is_err());
    }

    #[test]
    fn canonical_body_excludes_only_signature_line() {
        let raw = "listen: 3210\nsignature: abc\npeers: []\n";
        // signature not last -> strict rejection
        assert!(canonical_body(raw).is_err());
        let raw = "listen: 3210\npeers: []\nsignature: abc\n";
        assert_eq!(canonical_body(raw).unwrap(), "listen: 3210\npeers: []");
    }
}
