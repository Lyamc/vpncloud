//! AEAD, signatures, hashing, agreement, and random bytes.
//!
//! Wire formats stay AES-GCM, ChaCha20-Poly1305, Ed25519, X25519,
//! SHA-256/SHA-512, and PBKDF2-HMAC-SHA256. Nothing here compiles C.

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::Digest;
use smallvec::SmallVec;
use x25519_dalek::{PublicKey as DalekPublic, StaticSecret};

pub const ED25519_PUBLIC_KEY_LEN: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AeadAlgo {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305
}

impl AeadAlgo {
    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32
        }
    }

    /// Init-message algorithm id. 1, 2, and 3 are the on-wire values.
    pub fn wire_id(self) -> u8 {
        match self {
            Self::Aes128Gcm => 1,
            Self::Aes256Gcm => 2,
            Self::ChaCha20Poly1305 => 3
        }
    }

    pub fn from_wire_id(id: u8) -> Option<Self> {
        match id {
            1 => Some(Self::Aes128Gcm),
            2 => Some(Self::Aes256Gcm),
            3 => Some(Self::ChaCha20Poly1305),
            _ => None
        }
    }
}

enum Inner {
    Aes128(Aes128Gcm),
    Aes256(Aes256Gcm),
    ChaCha(ChaCha20Poly1305)
}

pub struct AeadKey {
    inner: Inner
}

impl AeadKey {
    pub fn new(algo: AeadAlgo, key: &[u8]) -> Result<Self, ()> {
        if key.len() != algo.key_len() {
            return Err(());
        }
        let inner = match algo {
            AeadAlgo::Aes128Gcm => Inner::Aes128(Aes128Gcm::new_from_slice(key).map_err(|_| ())?),
            AeadAlgo::Aes256Gcm => Inner::Aes256(Aes256Gcm::new_from_slice(key).map_err(|_| ())?),
            AeadAlgo::ChaCha20Poly1305 => Inner::ChaCha(ChaCha20Poly1305::new_from_slice(key).map_err(|_| ())?)
        };
        Ok(Self { inner })
    }

    pub fn algorithm(&self) -> AeadAlgo {
        match self.inner {
            Inner::Aes128(_) => AeadAlgo::Aes128Gcm,
            Inner::Aes256(_) => AeadAlgo::Aes256Gcm,
            Inner::ChaCha(_) => AeadAlgo::ChaCha20Poly1305
        }
    }

    /// Encrypt `buf` in place with an empty AAD. Returns the 16-byte tag.
    pub fn seal(&self, nonce: &[u8; 12], buf: &mut [u8]) -> Result<[u8; 16], ()> {
        let tag = match &self.inner {
            Inner::Aes128(key) => {
                let n = aes_gcm::Nonce::from_slice(nonce);
                key.encrypt_in_place_detached(n, &[], buf).map_err(|_| ())?
            }
            Inner::Aes256(key) => {
                let n = aes_gcm::Nonce::from_slice(nonce);
                key.encrypt_in_place_detached(n, &[], buf).map_err(|_| ())?
            }
            Inner::ChaCha(key) => {
                let n = chacha20poly1305::Nonce::from_slice(nonce);
                key.encrypt_in_place_detached(n, &[], buf).map_err(|_| ())?
            }
        };
        let mut out = [0u8; 16];
        out.copy_from_slice(&tag);
        Ok(out)
    }

    /// `buf` is ciphertext followed by a 16-byte tag. Plaintext stays at the front.
    pub fn open(&self, nonce: &[u8; 12], buf: &mut [u8]) -> Result<(), ()> {
        if buf.len() < 16 {
            return Err(());
        }
        let split = buf.len() - 16;
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&buf[split..]);
        let plain = &mut buf[..split];
        match &self.inner {
            Inner::Aes128(key) => {
                let n = aes_gcm::Nonce::from_slice(nonce);
                let t = aes_gcm::Tag::from_slice(&tag);
                key.decrypt_in_place_detached(n, &[], plain, t).map_err(|_| ())
            }
            Inner::Aes256(key) => {
                let n = aes_gcm::Nonce::from_slice(nonce);
                let t = aes_gcm::Tag::from_slice(&tag);
                key.decrypt_in_place_detached(n, &[], plain, t).map_err(|_| ())
            }
            Inner::ChaCha(key) => {
                let n = chacha20poly1305::Nonce::from_slice(nonce);
                let t = chacha20poly1305::Tag::from_slice(&tag);
                key.decrypt_in_place_detached(n, &[], plain, t).map_err(|_| ())
            }
        }
    }
}

pub fn fill_random(dest: &mut [u8]) {
    rand::Rng::fill_bytes(&mut rand::rng(), dest);
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(data).into()
}

pub fn sha512(data: &[u8]) -> [u8; 64] {
    sha2::Sha512::digest(data).into()
}

pub fn pbkdf2_hmac_sha256(secret: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(secret, salt, iterations, out);
}

pub struct Ed25519KeyPair {
    signing: SigningKey,
    public_key: [u8; 32]
}

impl Ed25519KeyPair {
    pub fn from_seed(seed: &[u8]) -> Result<Self, ()> {
        let seed: [u8; 32] = seed.try_into().map_err(|_| ())?;
        Ok(Self::from_seed_bytes(seed))
    }

    pub fn from_seed_and_public(seed: &[u8], public_key: &[u8]) -> Result<Self, ()> {
        let pair = Self::from_seed(seed)?;
        if public_key != pair.public_key.as_slice() {
            return Err(());
        }
        Ok(pair)
    }

    pub fn generate_pkcs8() -> [u8; 48] {
        let mut seed = [0u8; 32];
        fill_random(&mut seed);
        pkcs8_from_seed(&seed)
    }

    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, ()> {
        let seed = pkcs8_seed(pkcs8).ok_or(())?;
        Ok(Self::from_seed_bytes(seed))
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing.sign(msg).to_bytes()
    }

    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    pub fn verify(public_key: &[u8], msg: &[u8], signature: &[u8]) -> Result<(), ()> {
        let pk: [u8; 32] = public_key.try_into().map_err(|_| ())?;
        let vk = VerifyingKey::from_bytes(&pk).map_err(|_| ())?;
        let sig = Signature::from_slice(signature).map_err(|_| ())?;
        vk.verify(msg, &sig).map_err(|_| ())
    }

    fn from_seed_bytes(seed: [u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(&seed);
        let public_key = signing.verifying_key().to_bytes();
        Self { signing, public_key }
    }
}

/// PKCS#8 v1 Ed25519 private key (RFC 8410): a 32-byte seed in a nested octet string.
const PKCS8_PREFIX: [u8; 16] =
    [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];

fn pkcs8_from_seed(seed: &[u8; 32]) -> [u8; 48] {
    let mut bytes = [0u8; 48];
    bytes[..16].copy_from_slice(&PKCS8_PREFIX);
    bytes[16..].copy_from_slice(seed);
    bytes
}

fn pkcs8_seed(pkcs8: &[u8]) -> Option<[u8; 32]> {
    if pkcs8.len() != 48 || pkcs8[..16] != PKCS8_PREFIX {
        return None;
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&pkcs8[16..]);
    Some(seed)
}

/// Ephemeral X25519 scalar. Consumed by [`EcdhSecret::agree`].
pub struct EcdhSecret {
    secret: [u8; 32]
}

impl EcdhSecret {
    pub fn generate() -> Self {
        let mut secret = [0u8; 32];
        fill_random(&mut secret);
        Self { secret }
    }

    pub fn public_key(&self) -> [u8; 32] {
        let public = DalekPublic::from(&StaticSecret::from(self.secret));
        *public.as_bytes()
    }

    /// Raw 32-byte shared secret. A peer key that is not 32 bytes is rejected.
    pub fn agree(self, peer: &[u8]) -> Result<[u8; 32], ()> {
        let peer: [u8; 32] = peer.try_into().map_err(|_| ())?;
        let shared = StaticSecret::from(self.secret).diffie_hellman(&DalekPublic::from(peer));
        Ok(*shared.as_bytes())
    }
}

/// X25519 public key bytes as carried on init and rotation messages.
#[derive(Clone)]
pub struct EcdhPublic {
    bytes: SmallVec<[u8; 96]>
}

impl EcdhPublic {
    pub fn new(bytes: SmallVec<[u8; 96]>) -> Self {
        Self { bytes }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
