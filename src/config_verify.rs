// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! Config-signature verification with an out-of-band trust anchor.
//!
//! `--require-signed-config` is only meaningful if the verification keys come
//! from somewhere the config file cannot influence. This module keeps those
//! keys separate from `Config::crypto.trusted_keys` (which are peer-trust keys
//! and *are* loaded from the file under verification).

use std::sync::Mutex;

use crate::{
    config::Config,
    crypto::{Crypto, Ed25519KeyPair},
    sign,
    util::to_base62
};

/// Verification keys supplied outside the config being verified.
#[derive(Debug, Clone, Default)]
pub struct VerifyKeys {
    pub keys: Vec<String>,
    /// Whether the caller explicitly asked for signature verification.
    pub provided: bool
}

/// Out-of-band verification keys remembered at startup so that a SIGHUP reload
/// enforces the same signature policy as the initial config load. Mirrors
/// `CtrlC::set_reload_path`.
static RELOAD_VERIFY_KEYS: Mutex<VerifyKeys> = Mutex::new(VerifyKeys { keys: Vec::new(), provided: false });

/// Remember the verification keys for later config reloads. Call before the
/// VPN worker starts; a Mutex (rather than OnceLock) lets library/GUI callers
/// replace it between runs in the same process.
pub fn set_reload_verify_keys(keys: VerifyKeys) {
    if let Ok(mut guard) = RELOAD_VERIFY_KEYS.lock() {
        *guard = keys;
    }
}

/// The verification keys configured at startup, cloned so callers do not hold
/// the lock while verifying.
pub fn reload_verify_keys() -> VerifyKeys {
    RELOAD_VERIFY_KEYS.lock().map(|g| g.clone()).unwrap_or_default()
}

impl VerifyKeys {
    pub fn none() -> Self {
        Self { keys: Vec::new(), provided: false }
    }

    /// Build from CLI flags: `--verify-key` (repeatable) and/or a key file.
    pub fn from_cli(cli_keys: &[String], key_file: Option<&str>) -> Result<Self, String> {
        let mut keys = cli_keys.to_vec();
        if let Some(path) = key_file {
            let text = std::fs::read_to_string(path)
                .map_err(|e| format!("Failed to read signature key file {}: {}", path, e))?;
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                keys.push(line.to_string());
            }
        }
        let provided = !keys.is_empty() || key_file.is_some();
        Ok(Self { keys, provided })
    }

    /// Keys from the environment, for library/GUI callers that have no CLI.
    /// `VPNCLOUD_VERIFY_KEY` accepts one or more base62 keys separated by
    /// commas or semicolons.
    pub fn from_env() -> Self {
        let mut keys = Vec::new();
        if let Ok(value) = std::env::var("VPNCLOUD_VERIFY_KEY") {
            for key in value.split([',', ';']) {
                let key = key.trim();
                if !key.is_empty() {
                    keys.push(key.to_string());
                }
            }
        }
        let provided = !keys.is_empty();
        Self { keys, provided }
    }
}

/// Verify a loaded config against `keys`.
///
/// When verification is required (CLI flag, config setting, or explicit keys)
/// the *only* trust anchor is `keys`; keys from the file are never used. The
/// legacy best-effort path is kept for configs that carry a signature but do
/// not require verification — it is not a security control.
pub fn verify_loaded_config(config: &Config, raw: Option<&str>, keys: &VerifyKeys) -> Result<(), String> {
    let signed = raw.and_then(sign::extract_signature);
    let required = config.require_signed_config || keys.provided;

    if required {
        let raw = raw.ok_or("--require-signed-config needs a --config file")?;
        if signed.is_none() {
            return Err("Config file is not signed (--require-signed-config)".into());
        }
        if keys.keys.is_empty() {
            return Err(concat!(
                "Config signature verification needs an out-of-band key: ",
                "pass --verify-key / --verify-key-file or set VPNCLOUD_VERIFY_KEY"
            )
            .into());
        }
        // Never derive the verification key from the artifact being verified.
        sign::verify_config(raw, &keys.keys).map_err(|e| format!("{}", e))
    } else if let (Some(raw), Some(_)) = (raw, signed) {
        // Best-effort integrity check for legacy configs. The keys here come
        // from the file itself and cannot protect against an active attacker.
        let mut derived = config.crypto.trusted_keys.clone();
        if let Some(ref pk) = config.crypto.public_key {
            derived.push(pk.clone());
        }
        if derived.is_empty() {
            if let Some(ref password) = config.crypto.password {
                if let Ok(seed) =
                    Crypto::password_seed(password, config.crypto.salt.as_deref(), config.crypto.kdf.as_deref())
                {
                    if let Ok(pair) = Ed25519KeyPair::from_seed(&seed) {
                        derived.push(to_base62(pair.public_key()));
                    }
                }
            }
        }
        if !derived.is_empty() {
            sign::verify_config(raw, &derived).map_err(|e| format!("{}", e))?;
        }
        Ok(())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::CryptoConfig, sign};

    fn signed_config(_pubk: &str, privk: &str) -> String {
        let raw = "listen: 3210\npeers: []\n";
        let body = sign::canonical_body(&format!("{}\nsignature: placeholder\n", raw)).unwrap();
        let sig = sign::sign_body(&body, privk).unwrap();
        sign::append_signature_line(raw, &sig, false)
    }

    #[test]
    fn out_of_band_key_verifies() {
        let (privk, pubk) = Crypto::generate_keypair(None);
        let raw = signed_config(&pubk, &privk);
        let mut config = Config::default();
        config.require_signed_config = true;
        let keys = VerifyKeys { keys: vec![pubk.clone()], provided: true };
        verify_loaded_config(&config, Some(&raw), &keys).unwrap();
    }

    #[test]
    fn key_from_config_is_not_accepted_as_trust_anchor() {
        let (privk, pubk) = Crypto::generate_keypair(None);
        let raw = signed_config(&pubk, &privk);
        let mut config = Config::default();
        config.require_signed_config = true;
        config.crypto.trusted_keys = vec![pubk.clone()];
        // No out-of-band keys supplied: must fail closed.
        let keys = VerifyKeys::none();
        assert!(verify_loaded_config(&config, Some(&raw), &keys).is_err());
        // Even with provided=true but empty keys it must fail.
        let keys = VerifyKeys { keys: vec![], provided: true };
        assert!(verify_loaded_config(&config, Some(&raw), &keys).is_err());
    }

    #[test]
    fn attacker_self_signed_config_is_rejected() {
        let (attacker_priv, attacker_pub) = Crypto::generate_keypair(None);
        let raw = signed_config(&attacker_pub, &attacker_priv);
        let mut config = Config::default();
        config.require_signed_config = true;
        config.crypto.trusted_keys = vec![attacker_pub.clone()];
        let (_, admin_pub) = Crypto::generate_keypair(None);
        let keys = VerifyKeys { keys: vec![admin_pub], provided: true };
        assert!(verify_loaded_config(&config, Some(&raw), &keys).is_err());
    }

    #[test]
    fn legacy_best_effort_path_still_works() {
        let (privk, pubk) = Crypto::generate_keypair(None);
        let raw = signed_config(&pubk, &privk);
        let mut config = Config::default();
        config.crypto = CryptoConfig { public_key: Some(pubk), ..CryptoConfig::default() };
        verify_loaded_config(&config, Some(&raw), &VerifyKeys::none()).unwrap();
    }
}
