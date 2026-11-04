//! Pure-Rust stand-in for the slice of the `ring` API this mesh uses.
//!
//! Wire formats stay the standard ones: AES-GCM, ChaCha20-Poly1305, Ed25519,
//! X25519, SHA-256/SHA-512, and PBKDF2-HMAC-SHA256. Nothing here compiles C.

use sha2::Digest;

pub mod error {
    /// Operation failed. Callers map this onto their own error type.
    #[derive(Clone, Copy, Debug)]
    pub struct Unspecified;

    /// Key bytes were the wrong length or did not match the public key.
    #[derive(Clone, Copy, Debug)]
    pub struct KeyRejected;
}

pub mod rand {
    use super::error::Unspecified;

    pub trait SecureRandom {
        fn fill(&self, dest: &mut [u8]) -> Result<(), Unspecified>;
    }

    #[derive(Clone, Copy, Debug)]
    pub struct SystemRandom;

    impl SystemRandom {
        pub fn new() -> Self {
            Self
        }
    }

    impl SecureRandom for SystemRandom {
        fn fill(&self, dest: &mut [u8]) -> Result<(), Unspecified> {
            rand::Rng::fill_bytes(&mut rand::rng(), dest);
            Ok(())
        }
    }
}

pub mod digest {
    use super::Digest as _;
    use sha2::{Sha256, Sha512};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Kind {
        Sha256,
        Sha512
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Algorithm {
        kind: Kind
    }

    pub static SHA256: Algorithm = Algorithm { kind: Kind::Sha256 };
    pub static SHA512: Algorithm = Algorithm { kind: Kind::Sha512 };

    pub struct DigestValue {
        bytes: [u8; 64],
        len: usize
    }

    impl AsRef<[u8]> for DigestValue {
        fn as_ref(&self) -> &[u8] {
            &self.bytes[..self.len]
        }
    }

    pub fn digest(algorithm: &Algorithm, data: &[u8]) -> DigestValue {
        let mut out = DigestValue { bytes: [0; 64], len: 0 };
        match algorithm.kind {
            Kind::Sha256 => {
                let hash = Sha256::digest(data);
                out.bytes[..32].copy_from_slice(&hash);
                out.len = 32;
            }
            Kind::Sha512 => {
                let hash = Sha512::digest(data);
                out.bytes[..64].copy_from_slice(&hash);
                out.len = 64;
            }
        }
        out
    }
}

pub mod pbkdf2 {
    use core::num::NonZeroU32;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Algorithm;

    pub static PBKDF2_HMAC_SHA256: Algorithm = Algorithm;

    pub fn derive(_algorithm: Algorithm, iterations: NonZeroU32, salt: &[u8], secret: &[u8], out: &mut [u8]) {
        ::pbkdf2::pbkdf2_hmac::<sha2::Sha256>(secret, salt, iterations.get(), out);
    }
}

pub mod aead {
    use super::error::Unspecified;
    use aes_gcm::aead::{AeadInPlace, KeyInit};
    use aes_gcm::{Aes128Gcm, Aes256Gcm};
    use chacha20poly1305::ChaCha20Poly1305;

    const TAG_LEN: usize = 16;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Kind {
        Aes128,
        Aes256,
        ChaCha
    }

    #[derive(Debug, PartialEq, Eq)]
    pub struct Algorithm {
        kind: Kind,
        key_len: usize
    }

    impl Algorithm {
        pub fn key_len(&self) -> usize {
            self.key_len
        }
    }

    pub static AES_128_GCM: Algorithm = Algorithm { kind: Kind::Aes128, key_len: 16 };
    pub static AES_256_GCM: Algorithm = Algorithm { kind: Kind::Aes256, key_len: 32 };
    pub static CHACHA20_POLY1305: Algorithm = Algorithm { kind: Kind::ChaCha, key_len: 32 };

    enum Inner {
        Aes128(Aes128Gcm),
        Aes256(Aes256Gcm),
        ChaCha(ChaCha20Poly1305)
    }

    pub struct UnboundKey {
        algorithm: &'static Algorithm,
        inner: Inner
    }

    impl UnboundKey {
        pub fn new(algorithm: &'static Algorithm, key: &[u8]) -> Result<Self, Unspecified> {
            if key.len() != algorithm.key_len {
                return Err(Unspecified);
            }
            let inner = match algorithm.kind {
                Kind::Aes128 => Inner::Aes128(Aes128Gcm::new_from_slice(key).map_err(|_| Unspecified)?),
                Kind::Aes256 => Inner::Aes256(Aes256Gcm::new_from_slice(key).map_err(|_| Unspecified)?),
                Kind::ChaCha => Inner::ChaCha(ChaCha20Poly1305::new_from_slice(key).map_err(|_| Unspecified)?)
            };
            Ok(Self { algorithm, inner })
        }

        pub fn algorithm(&self) -> &'static Algorithm {
            self.algorithm
        }
    }

    pub struct LessSafeKey {
        algorithm: &'static Algorithm,
        inner: Inner
    }

    impl LessSafeKey {
        pub fn new(key: UnboundKey) -> Self {
            Self { algorithm: key.algorithm, inner: key.inner }
        }

        pub fn algorithm(&self) -> &'static Algorithm {
            self.algorithm
        }

        pub fn seal_in_place_separate_tag<A: AsRef<[u8]>>(
            &self, nonce: Nonce, aad: Aad<A>, in_out: &mut [u8]
        ) -> Result<Tag, Unspecified> {
            let tag = seal_detached(&self.inner, nonce.0, aad.0.as_ref(), in_out)?;
            Ok(Tag(tag))
        }

        pub fn open_in_place<'a, A: AsRef<[u8]>>(
            &self, nonce: Nonce, aad: Aad<A>, in_out: &'a mut [u8]
        ) -> Result<&'a mut [u8], Unspecified> {
            if in_out.len() < TAG_LEN {
                return Err(Unspecified);
            }
            let split = in_out.len() - TAG_LEN;
            let mut tag = [0u8; TAG_LEN];
            tag.copy_from_slice(&in_out[split..]);
            let buf = &mut in_out[..split];
            open_detached(&self.inner, nonce.0, aad.0.as_ref(), buf, &tag)?;
            Ok(buf)
        }
    }

    fn seal_detached(inner: &Inner, nonce: [u8; 12], aad: &[u8], buf: &mut [u8]) -> Result<[u8; 16], Unspecified> {
        let tag = match inner {
            Inner::Aes128(key) => {
                let n = aes_gcm::Nonce::from_slice(&nonce);
                key.encrypt_in_place_detached(n, aad, buf).map_err(|_| Unspecified)?
            }
            Inner::Aes256(key) => {
                let n = aes_gcm::Nonce::from_slice(&nonce);
                key.encrypt_in_place_detached(n, aad, buf).map_err(|_| Unspecified)?
            }
            Inner::ChaCha(key) => {
                let n = chacha20poly1305::Nonce::from_slice(&nonce);
                key.encrypt_in_place_detached(n, aad, buf).map_err(|_| Unspecified)?
            }
        };
        let mut out = [0u8; 16];
        out.copy_from_slice(&tag);
        Ok(out)
    }

    fn open_detached(
        inner: &Inner, nonce: [u8; 12], aad: &[u8], buf: &mut [u8], tag: &[u8; 16]
    ) -> Result<(), Unspecified> {
        match inner {
            Inner::Aes128(key) => {
                let n = aes_gcm::Nonce::from_slice(&nonce);
                let t = aes_gcm::Tag::from_slice(tag);
                key.decrypt_in_place_detached(n, aad, buf, t).map_err(|_| Unspecified)
            }
            Inner::Aes256(key) => {
                let n = aes_gcm::Nonce::from_slice(&nonce);
                let t = aes_gcm::Tag::from_slice(tag);
                key.decrypt_in_place_detached(n, aad, buf, t).map_err(|_| Unspecified)
            }
            Inner::ChaCha(key) => {
                let n = chacha20poly1305::Nonce::from_slice(&nonce);
                let t = chacha20poly1305::Tag::from_slice(tag);
                key.decrypt_in_place_detached(n, aad, buf, t).map_err(|_| Unspecified)
            }
        }
    }

    pub struct Nonce([u8; 12]);

    impl Nonce {
        pub fn assume_unique_for_key(value: [u8; 12]) -> Self {
            Self(value)
        }
    }

    pub struct Aad<A>(A);

    impl Aad<[u8; 0]> {
        pub fn empty() -> Self {
            Self([])
        }
    }

    pub struct Tag([u8; 16]);

    impl AsRef<[u8]> for Tag {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }
}

pub mod agreement {
    use super::error::Unspecified;
    use super::rand::SecureRandom;
    use x25519_dalek::{PublicKey as DalekPublic, StaticSecret};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Algorithm;

    pub static X25519: Algorithm = Algorithm;

    pub struct EphemeralPrivateKey {
        secret: [u8; 32]
    }

    impl EphemeralPrivateKey {
        pub fn generate(alg: &'static Algorithm, rng: &dyn SecureRandom) -> Result<Self, Unspecified> {
            if !core::ptr::eq(alg, &X25519) {
                return Err(Unspecified);
            }
            let mut secret = [0u8; 32];
            rng.fill(&mut secret)?;
            Ok(Self { secret })
        }

        pub fn compute_public_key(&self) -> Result<PublicKey, Unspecified> {
            let public = DalekPublic::from(&StaticSecret::from(self.secret));
            Ok(PublicKey { bytes: *public.as_bytes() })
        }
    }

    pub struct PublicKey {
        bytes: [u8; 32]
    }

    impl AsRef<[u8]> for PublicKey {
        fn as_ref(&self) -> &[u8] {
            &self.bytes
        }
    }

    #[derive(Clone)]
    pub struct UnparsedPublicKey<B> {
        algorithm: &'static Algorithm,
        bytes: B
    }

    impl<B> UnparsedPublicKey<B> {
        pub fn new(algorithm: &'static Algorithm, bytes: B) -> Self {
            Self { algorithm, bytes }
        }

        pub fn bytes(&self) -> &B {
            &self.bytes
        }
    }

    pub fn agree_ephemeral<B: AsRef<[u8]>, R>(
        my_private_key: EphemeralPrivateKey, peer_public_key: &UnparsedPublicKey<B>, kdf: impl FnOnce(&[u8]) -> R
    ) -> Result<R, Unspecified> {
        if !core::ptr::eq(peer_public_key.algorithm, &X25519) {
            return Err(Unspecified);
        }
        let bytes = peer_public_key.bytes.as_ref();
        let peer: [u8; 32] = bytes.try_into().map_err(|_| Unspecified)?;
        let shared = StaticSecret::from(my_private_key.secret).diffie_hellman(&DalekPublic::from(peer));
        Ok(kdf(shared.as_bytes()))
    }
}

pub mod signature {
    use super::error::{KeyRejected, Unspecified};
    use super::rand::SecureRandom;
    use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

    pub const ED25519_PUBLIC_KEY_LEN: usize = 32;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Algorithm;

    pub static ED25519: Algorithm = Algorithm;

    #[derive(Clone, Copy)]
    pub struct PublicKey([u8; 32]);

    impl AsRef<[u8]> for PublicKey {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    pub struct Ed25519KeyPair {
        signing: SigningKey,
        public_key: PublicKey
    }

    impl Ed25519KeyPair {
        pub fn from_seed_unchecked(seed: &[u8]) -> Result<Self, KeyRejected> {
            let seed: [u8; 32] = seed.try_into().map_err(|_| KeyRejected)?;
            Ok(Self::from_seed(seed))
        }

        pub fn from_seed_and_public_key(seed: &[u8], public_key: &[u8]) -> Result<Self, KeyRejected> {
            let pair = Self::from_seed_unchecked(seed)?;
            if public_key != pair.public_key.as_ref() {
                return Err(KeyRejected);
            }
            Ok(pair)
        }

        pub fn generate_pkcs8(rng: &dyn SecureRandom) -> Result<Document, Unspecified> {
            let mut seed = [0u8; 32];
            rng.fill(&mut seed)?;
            Ok(Document::from_seed(&seed))
        }

        pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, KeyRejected> {
            let seed = Document::seed(pkcs8).ok_or(KeyRejected)?;
            Ok(Self::from_seed(seed))
        }

        pub fn sign(&self, msg: &[u8]) -> SignatureBytes {
            SignatureBytes(self.signing.sign(msg).to_bytes())
        }

        fn from_seed(seed: [u8; 32]) -> Self {
            let signing = SigningKey::from_bytes(&seed);
            let public_key = PublicKey(signing.verifying_key().to_bytes());
            Self { signing, public_key }
        }
    }

    pub trait KeyPair {
        type PublicKey: AsRef<[u8]>;
        fn public_key(&self) -> &Self::PublicKey;
    }

    impl KeyPair for Ed25519KeyPair {
        type PublicKey = PublicKey;

        fn public_key(&self) -> &Self::PublicKey {
            &self.public_key
        }
    }

    pub struct SignatureBytes([u8; 64]);

    impl AsRef<[u8]> for SignatureBytes {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    pub struct UnparsedPublicKey<B> {
        bytes: B
    }

    impl<B: AsRef<[u8]>> UnparsedPublicKey<B> {
        pub fn new(_algorithm: &'static Algorithm, bytes: B) -> Self {
            Self { bytes }
        }

        pub fn verify(&self, msg: &[u8], signature: &[u8]) -> Result<(), Unspecified> {
            let pk: [u8; 32] = self.bytes.as_ref().try_into().map_err(|_| Unspecified)?;
            let vk = VerifyingKey::from_bytes(&pk).map_err(|_| Unspecified)?;
            let sig = Signature::from_slice(signature).map_err(|_| Unspecified)?;
            vk.verify(msg, &sig).map_err(|_| Unspecified)
        }
    }

    /// PKCS#8 v1 Ed25519 private key (RFC 8410): a 32-byte seed in a nested octet string.
    pub struct Document {
        bytes: [u8; 48]
    }

    impl Document {
        const PREFIX: [u8; 16] = [
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20
        ];

        fn from_seed(seed: &[u8; 32]) -> Self {
            let mut bytes = [0u8; 48];
            bytes[..16].copy_from_slice(&Self::PREFIX);
            bytes[16..].copy_from_slice(seed);
            Self { bytes }
        }

        fn seed(pkcs8: &[u8]) -> Option<[u8; 32]> {
            if pkcs8.len() != 48 || pkcs8[..16] != Self::PREFIX {
                return None;
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&pkcs8[16..]);
            Some(seed)
        }
    }

    impl AsRef<[u8]> for Document {
        fn as_ref(&self) -> &[u8] {
            &self.bytes
        }
    }
}
