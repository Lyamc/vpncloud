#[cfg(feature = "noise")]
use super::noise::{self, NoiseInit, NoiseTransport};
use super::{
    core::{test_speed, CryptoCore},
    init::{self, InitResult, InitState, CLOSING},
    rotate::RotationState
};
use crate::{
    error::Error,
    types::NodeId,
    util::{from_base62, to_base62, MsgBuffer}
};
use ring::{
    aead::{self, Algorithm, LessSafeKey, UnboundKey},
    agreement::{EphemeralPrivateKey, UnparsedPublicKey},
    pbkdf2,
    rand::{SecureRandom, SystemRandom},
    signature::{Ed25519KeyPair, KeyPair, ED25519_PUBLIC_KEY_LEN}
};
use smallvec::{smallvec, SmallVec};
use std::{fmt::Debug, io::Read, num::NonZeroU32, sync::Arc, time::Duration};

const SALT: &[u8; 32] = b"vpncloudVPNCLOUDvpncl0udVpnCloud";
const INIT_MESSAGE_FIRST_BYTE: u8 = 0xff;
const MESSAGE_TYPE_ROTATION: u8 = 0x10;

pub type Ed25519PublicKey = [u8; ED25519_PUBLIC_KEY_LEN];
pub type EcdhPublicKey = UnparsedPublicKey<SmallVec<[u8; 96]>>;
pub type EcdhPrivateKey = EphemeralPrivateKey;
pub type Key = SmallVec<[u8; 32]>;

const DEFAULT_ALGORITHMS: [&str; 3] = ["AES128", "AES256", "CHACHA20"];

#[cfg(test)]
const SPEED_TEST_TIME: f32 = 0.02;
#[cfg(not(test))]
const SPEED_TEST_TIME: f32 = 0.1;

const ROTATE_INTERVAL: usize = 120;

pub trait Payload: Debug + PartialEq + Sized {
    fn write_to(&self, buffer: &mut MsgBuffer);
    fn read_from<R: Read>(r: R) -> Result<Self, Error>;
}

#[derive(Clone)]
pub struct Algorithms {
    pub algorithm_speeds: SmallVec<[(&'static Algorithm, f32); 3]>,
    pub allow_unencrypted: bool
}

#[derive(Debug, Default, Deserialize, Serialize, Clone, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct Config {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub trusted_keys: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub algorithms: Vec<String>,
    /// Optional KDF salt (base62 or raw). When set, password derivation uses PBKDF2-100000.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub salt: Option<String>,
    /// `legacy` (PBKDF2-4096, default if no salt) or `pbkdf2` (100000 iterations, requires salt).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf: Option<String>
}

pub struct Crypto {
    node_id: NodeId,
    key_pair: Arc<Ed25519KeyPair>,
    trusted_keys: Arc<[Ed25519PublicKey]>,
    algorithms: Algorithms,
    use_noise: bool,
    #[cfg(feature = "noise")]
    dh_private: [u8; 32],
    #[cfg(feature = "noise")]
    dh_public: [u8; 32],
    #[cfg(feature = "noise")]
    trusted_dh: Arc<[[u8; 32]]>
}

impl Crypto {
    pub fn parse_algorithms(algos: &[String]) -> Result<(bool, bool, Vec<&'static aead::Algorithm>), Error> {
        let algorithms = algos.iter().map(|a| a as &str).collect::<Vec<_>>();
        let allowed = if algorithms.is_empty() { &DEFAULT_ALGORITHMS } else { &algorithms as &[&str] };
        let mut algos = vec![];
        let mut unencrypted = false;
        let mut use_noise = false;
        for name in allowed {
            let upper = name.to_uppercase();
            match &upper as &str {
                "UNENCRYPTED" | "NONE" | "PLAIN" => {
                    unencrypted = true;
                }
                "NOISE" | "NOISEXX" | "NOISE_XX" | "NOISE-XX" => {
                    #[cfg(feature = "noise")]
                    {
                        use_noise = true;
                    }
                    #[cfg(not(feature = "noise"))]
                    {
                        return Err(Error::InvalidConfig(
                            "Noise support was not compiled in (rebuild with --features noise)"
                        ));
                    }
                }
                "AES128" | "AES128_GCM" | "AES_128" | "AES_128_GCM" => algos.push(&aead::AES_128_GCM),
                "AES256" | "AES256_GCM" | "AES_256" | "AES_256_GCM" => algos.push(&aead::AES_256_GCM),
                "CHACHA" | "CHACHA20" | "CHACHA20_POLY1305" => algos.push(&aead::CHACHA20_POLY1305),
                _ => return Err(Error::InvalidConfig("Unknown crypto method"))
            }
        }
        if use_noise && unencrypted {
            return Err(Error::InvalidConfig("Noise cannot be combined with plain/unencrypted"));
        }
        Ok((unencrypted, use_noise, algos))
    }

    fn identity_seed(config: &Config) -> Result<[u8; 32], Error> {
        if let Some(priv_key) = &config.private_key {
            let privkey = from_base62(priv_key).map_err(|_| Error::InvalidConfig("Failed to parse private key"))?;
            if privkey.len() != 32 {
                return Err(Error::InvalidConfig("Failed to parse private key"));
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&privkey);
            Ok(seed)
        } else if let Some(password) = &config.password {
            Ok(Self::password_seed(password, config.salt.as_deref(), config.kdf.as_deref())?)
        } else {
            Err(Error::InvalidConfig("Either private_key or password must be set"))
        }
    }

    pub fn password_seed(password: &str, salt: Option<&str>, kdf: Option<&str>) -> Result<[u8; 32], Error> {
        let mut key = [0; 32];
        let kdf = kdf.unwrap_or("").to_ascii_lowercase();
        let (iters, salt_bytes): (u32, &[u8]) = if kdf == "pbkdf2" || salt.is_some() {
            let s = salt.ok_or(Error::InvalidConfig("crypto.kdf=pbkdf2 requires crypto.salt"))?;
            (100_000, s.as_bytes())
        } else {
            (4096, SALT.as_ref())
        };
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            NonZeroU32::new(iters).expect("kdf iterations"),
            salt_bytes,
            password.as_bytes(),
            &mut key
        );
        Ok(key)
    }

    pub fn new(node_id: NodeId, config: &Config) -> Result<Self, Error> {
        let seed = Self::identity_seed(config)?;
        let key_pair = if let Some(priv_key) = &config.private_key {
            if let Some(pub_key) = &config.public_key {
                Self::parse_keypair(priv_key, pub_key)?
            } else {
                Self::parse_private_key(priv_key)?
            }
        } else {
            Ed25519KeyPair::from_seed_unchecked(&seed)
                .map_err(|_| Error::InvalidConfig("Key rejected by crypto library"))?
        };
        let mut trusted_keys = vec![];
        for tn in &config.trusted_keys {
            if let Some((key, rest)) = tn.rsplit_once(':') {
                if rest.len() == 10 && rest.as_bytes().get(4) == Some(&b'-') {
                    if Self::date_expired(rest) {
                        warn!("Ignoring expired trusted key (until {})", rest);
                        continue;
                    }
                    trusted_keys.push(Self::parse_public_key(key)?);
                    continue;
                }
            }
            trusted_keys.push(Self::parse_public_key(tn)?);
        }
        if trusted_keys.is_empty() {
            info!("Trusted keys not set, trusting only own public key");
            let mut key = [0; ED25519_PUBLIC_KEY_LEN];
            key.clone_from_slice(key_pair.public_key().as_ref());
            trusted_keys.push(key);
        }
        let (unencrypted, use_noise, allowed_algos) = Self::parse_algorithms(&config.algorithms)?;
        if unencrypted {
            warn!("Crypto settings allow unencrypted connections")
        }
        #[cfg(feature = "noise")]
        let (dh_private, dh_public) = noise::dh_keypair_from_seed(&seed);
        #[cfg(feature = "noise")]
        if use_noise {
            info!("Using {} (X25519 / ChaCha20-Poly1305 / SHA-256)", noise::PATTERN);
            info!("Noise static public key: {}", to_base62(&dh_public));
            if !allowed_algos.is_empty() {
                info!("Noise handshake selected; AES/ChaCha algorithm list is unused for this node");
            }
        }
        let mut algos = Algorithms { algorithm_speeds: smallvec![], allow_unencrypted: unencrypted };
        let duration = Duration::from_secs_f32(SPEED_TEST_TIME);
        let mut speeds = Vec::new();
        if !use_noise {
            for algo in allowed_algos {
                let speed = test_speed(algo, &duration);
                algos.algorithm_speeds.push((algo, speed as f32));
                speeds.push((format!("{:?}", algo), speed as f32));
            }
        }
        if !speeds.is_empty() {
            info!(
                "Crypto speeds: {}",
                speeds.into_iter().map(|(a, s)| format!("{}: {:.1} MiB/s", a, s)).collect::<Vec<_>>().join(", ")
            );
        }
        #[cfg(feature = "noise")]
        let trusted_dh: Arc<[[u8; 32]]> =
            if config.trusted_keys.is_empty() { Arc::from(vec![dh_public]) } else { Arc::from(trusted_keys.clone()) };
        Ok(Self {
            node_id,
            key_pair: Arc::new(key_pair),
            trusted_keys: trusted_keys.into_boxed_slice().into(),
            algorithms: algos,
            use_noise,
            #[cfg(feature = "noise")]
            dh_private,
            #[cfg(feature = "noise")]
            dh_public,
            #[cfg(feature = "noise")]
            trusted_dh
        })
    }

    pub fn generate_keypair(password: Option<&str>) -> (String, String) {
        let mut bytes = [0; 32];
        match password {
            None => {
                let rng = SystemRandom::new();
                rng.fill(&mut bytes).unwrap();
            }
            Some(password) => {
                pbkdf2::derive(
                    pbkdf2::PBKDF2_HMAC_SHA256,
                    NonZeroU32::new(4096).unwrap(),
                    SALT,
                    password.as_bytes(),
                    &mut bytes
                );
            }
        }
        let keypair = Ed25519KeyPair::from_seed_unchecked(&bytes).unwrap();
        let privkey = to_base62(&bytes);
        let pubkey = to_base62(keypair.public_key().as_ref());
        (privkey, pubkey)
    }

    #[allow(dead_code)]
    fn keypair_from_password(password: &str) -> Ed25519KeyPair {
        let mut key = [0; 32];
        pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA256, NonZeroU32::new(4096).unwrap(), SALT, password.as_bytes(), &mut key);
        Ed25519KeyPair::from_seed_unchecked(&key).unwrap()
    }

    fn parse_keypair(privkey: &str, pubkey: &str) -> Result<Ed25519KeyPair, Error> {
        let privkey = from_base62(privkey).map_err(|_| Error::InvalidConfig("Failed to parse private key"))?;
        let pubkey = from_base62(pubkey).map_err(|_| Error::InvalidConfig("Failed to parse public key"))?;
        let keypair = Ed25519KeyPair::from_seed_and_public_key(&privkey, &pubkey)
            .map_err(|_| Error::InvalidConfig("Keys rejected by crypto library"))?;
        Ok(keypair)
    }

    fn parse_private_key(privkey: &str) -> Result<Ed25519KeyPair, Error> {
        let privkey = from_base62(privkey).map_err(|_| Error::InvalidConfig("Failed to parse private key"))?;
        let keypair = Ed25519KeyPair::from_seed_unchecked(&privkey)
            .map_err(|_| Error::InvalidConfig("Key rejected by crypto library"))?;
        Ok(keypair)
    }

    pub(crate) fn date_expired(ymd: &str) -> bool {
        let Ok(parts) = ymd.split('-').map(|s| s.parse::<u32>()).collect::<Result<Vec<_>, _>>() else {
            return true;
        };
        if parts.len() != 3 {
            return true;
        }
        let (y, m, d) = (parts[0], parts[1], parts[2]);
        let today = chrono::Utc::now().date_naive();
        match chrono::NaiveDate::from_ymd_opt(y as i32, m, d) {
            Some(until) => today > until,
            None => true
        }
    }

    fn parse_public_key(pubkey: &str) -> Result<Ed25519PublicKey, Error> {
        let pubkey = from_base62(pubkey).map_err(|_| Error::InvalidConfig("Failed to parse public key"))?;
        if pubkey.len() != ED25519_PUBLIC_KEY_LEN {
            return Err(Error::InvalidConfig("Failed to parse public key"));
        }
        let mut result = [0; ED25519_PUBLIC_KEY_LEN];
        result.clone_from_slice(&pubkey);
        Ok(result)
    }

    pub fn public_key_from_private_key(privkey: &str) -> Result<String, Error> {
        let keypair = Self::parse_private_key(privkey)?;
        Ok(to_base62(keypair.public_key().as_ref()))
    }

    pub fn peer_instance<P: Payload>(&self, payload: P) -> PeerCrypto<P> {
        PeerCrypto::new(
            self.node_id,
            payload,
            self.key_pair.clone(),
            self.trusted_keys.clone(),
            self.algorithms.clone(),
            self.use_noise,
            #[cfg(feature = "noise")]
            self.dh_private,
            #[cfg(feature = "noise")]
            self.dh_public,
            #[cfg(feature = "noise")]
            self.trusted_dh.clone()
        )
    }
}

#[derive(Debug, PartialEq)]
pub enum MessageResult<P: Payload> {
    Message(u8),
    Initialized(P),
    InitializedWithReply(P),
    Reply,
    None
}

pub struct PeerCrypto<P: Payload> {
    #[allow(dead_code)]
    node_id: NodeId,
    init: Option<InitState<P>>,
    #[cfg(feature = "noise")]
    noise: Option<NoiseInit<P>>,
    rotation: Option<RotationState>,
    unencrypted: bool,
    core: Option<CryptoCore>,
    #[cfg(feature = "noise")]
    noise_transport: Option<NoiseTransport>,
    rotate_counter: usize
}

impl<P: Payload> PeerCrypto<P> {
    pub fn new(
        node_id: NodeId, init_payload: P, key_pair: Arc<Ed25519KeyPair>, trusted_keys: Arc<[Ed25519PublicKey]>,
        algorithms: Algorithms, use_noise: bool, #[cfg(feature = "noise")] dh_private: [u8; 32],
        #[cfg(feature = "noise")] dh_public: [u8; 32], #[cfg(feature = "noise")] trusted_dh: Arc<[[u8; 32]]>
    ) -> Self {
        #[cfg(feature = "noise")]
        if use_noise {
            return Self {
                node_id,
                init: None,
                noise: Some(NoiseInit::new(node_id, init_payload, dh_private, dh_public, trusted_dh)),
                rotation: None,
                unencrypted: false,
                core: None,
                noise_transport: None,
                rotate_counter: 0
            };
        }
        let _ = use_noise;
        Self {
            node_id,
            init: Some(InitState::new(node_id, init_payload, key_pair, trusted_keys, algorithms)),
            #[cfg(feature = "noise")]
            noise: None,
            rotation: None,
            unencrypted: false,
            core: None,
            #[cfg(feature = "noise")]
            noise_transport: None,
            rotate_counter: 0
        }
    }

    fn get_init(&mut self) -> Result<&mut InitState<P>, Error> {
        if let Some(init) = &mut self.init {
            Ok(init)
        } else {
            Err(Error::InvalidCryptoState("Initialization already finished"))
        }
    }

    fn get_core(&mut self) -> Result<&mut CryptoCore, Error> {
        if let Some(core) = &mut self.core {
            Ok(core)
        } else {
            Err(Error::InvalidCryptoState("Crypto core not ready yet"))
        }
    }

    fn get_rotation(&mut self) -> Result<&mut RotationState, Error> {
        if let Some(rotation) = &mut self.rotation {
            Ok(rotation)
        } else {
            Err(Error::InvalidCryptoState("Key rotation not initialized"))
        }
    }

    pub fn initialize(&mut self, out: &mut MsgBuffer) -> Result<(), Error> {
        #[cfg(feature = "noise")]
        if let Some(noise) = &mut self.noise {
            if noise.stage() != init::STAGE_PING {
                return Err(Error::InvalidCryptoState("Initialization already ongoing"));
            }
            noise.send_ping(out);
            out.prepend_byte(INIT_MESSAGE_FIRST_BYTE);
            return Ok(());
        }
        let init = self.get_init()?;
        if init.stage() != init::STAGE_PING {
            Err(Error::InvalidCryptoState("Initialization already ongoing"))
        } else {
            init.send_ping(out);
            out.prepend_byte(INIT_MESSAGE_FIRST_BYTE);
            Ok(())
        }
    }

    pub fn has_init(&self) -> bool {
        #[cfg(feature = "noise")]
        {
            self.init.is_some() || self.noise.is_some()
        }
        #[cfg(not(feature = "noise"))]
        {
            self.init.is_some()
        }
    }

    pub fn is_ready(&self) -> bool {
        #[cfg(feature = "noise")]
        {
            self.core.is_some() || self.noise_transport.is_some()
        }
        #[cfg(not(feature = "noise"))]
        {
            self.core.is_some()
        }
    }

    pub fn algorithm_name(&self) -> &'static str {
        #[cfg(feature = "noise")]
        if self.noise_transport.is_some() {
            return "NOISE";
        }
        if let Some(ref core) = self.core {
            let algo = core.algorithm();
            if algo == &aead::CHACHA20_POLY1305 {
                "CHACHA20"
            } else if algo == &aead::AES_128_GCM {
                "AES128"
            } else if algo == &aead::AES_256_GCM {
                "AES256"
            } else {
                unreachable!()
            }
        } else {
            "PLAIN"
        }
    }

    fn handle_init_message(&mut self, buffer: &mut MsgBuffer) -> Result<MessageResult<P>, Error> {
        #[cfg(feature = "noise")]
        if self.noise.is_some() {
            if !super::is_noise_frame(buffer.buffer()) {
                return Err(Error::CryptoInit("Peer is not using Noise"));
            }
            let result = self.noise.as_mut().unwrap().handle(buffer)?;
            if !buffer.is_empty() {
                buffer.prepend_byte(INIT_MESSAGE_FIRST_BYTE);
            }
            return match result {
                InitResult::Continue => Ok(MessageResult::Reply),
                InitResult::Success { peer_payload, is_initiator } => {
                    self.noise_transport = self.noise.as_mut().unwrap().take_transport();
                    if self.noise.as_ref().map(|n| n.stage()).unwrap_or(CLOSING) == CLOSING {
                        self.noise = None;
                    }
                    if is_initiator {
                        Ok(MessageResult::InitializedWithReply(peer_payload))
                    } else {
                        Ok(MessageResult::Initialized(peer_payload))
                    }
                }
            };
        }
        if super::is_noise_frame(buffer.buffer()) {
            return Err(Error::CryptoInit("Peer requires Noise; this node does not"));
        }
        let result = self.get_init()?.handle_init(buffer)?;
        if !buffer.is_empty() {
            buffer.prepend_byte(INIT_MESSAGE_FIRST_BYTE);
        }
        match result {
            InitResult::Continue => Ok(MessageResult::Reply),
            InitResult::Success { peer_payload, is_initiator } => {
                self.core = self.get_init()?.take_core();
                if self.core.is_none() {
                    self.unencrypted = true;
                }
                if self.get_init()?.stage() == init::CLOSING {
                    self.init = None
                }
                if self.core.is_some() {
                    self.rotation = Some(RotationState::new(!is_initiator, buffer));
                }
                if !is_initiator {
                    if self.unencrypted {
                        return Ok(MessageResult::Initialized(peer_payload));
                    }
                    assert!(!buffer.is_empty());
                    buffer.prepend_byte(MESSAGE_TYPE_ROTATION);
                    self.encrypt_message(buffer)?;
                }
                Ok(MessageResult::InitializedWithReply(peer_payload))
            }
        }
    }

    fn handle_rotate_message(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.unencrypted {
            return Ok(());
        }
        if let Some(rot) = self.get_rotation()?.handle_message(data)? {
            let core = self.get_core()?;
            let algo = core.algorithm();
            let key = LessSafeKey::new(UnboundKey::new(algo, &rot.key[..algo.key_len()]).unwrap());
            core.rotate_key(key, rot.id, rot.use_for_sending);
        }
        Ok(())
    }

    fn encrypt_message(&mut self, buffer: &mut MsgBuffer) -> Result<(), Error> {
        if self.unencrypted {
            return Ok(());
        }
        #[cfg(feature = "noise")]
        if let Some(ref mut noise) = self.noise_transport {
            return noise.encrypt(buffer);
        }
        self.get_core()?.encrypt(buffer);
        Ok(())
    }

    fn decrypt_message(&mut self, buffer: &mut MsgBuffer) -> Result<(), Error> {
        // HOT PATH
        if self.unencrypted {
            return Ok(());
        }
        #[cfg(feature = "noise")]
        if let Some(ref mut noise) = self.noise_transport {
            return noise.decrypt(buffer);
        }
        self.get_core()?.decrypt(buffer)
    }

    pub fn handle_message(&mut self, buffer: &mut MsgBuffer) -> Result<MessageResult<P>, Error> {
        // HOT PATH
        if buffer.is_empty() {
            return Err(Error::InvalidCryptoState("No message in buffer"));
        }
        if is_init_message(buffer.buffer()) {
            // COLD PATH
            debug!("Received init message");
            buffer.take_prefix();
            self.handle_init_message(buffer)
        } else {
            // HOT PATH
            debug!("Received encrypted message");
            self.decrypt_message(buffer)?;
            let msg_type = buffer.take_prefix();
            if msg_type == MESSAGE_TYPE_ROTATION {
                // COLD PATH
                debug!("Received rotation message");
                self.handle_rotate_message(buffer.buffer())?;
                buffer.clear();
                Ok(MessageResult::None)
            } else {
                Ok(MessageResult::Message(msg_type))
            }
        }
    }

    pub fn send_message(&mut self, type_: u8, buffer: &mut MsgBuffer) -> Result<(), Error> {
        // HOT PATH
        assert_ne!(type_, MESSAGE_TYPE_ROTATION);
        buffer.prepend_byte(type_);
        self.encrypt_message(buffer)
    }

    pub fn every_second(&mut self, out: &mut MsgBuffer) -> Result<MessageResult<P>, Error> {
        out.clear();
        if let Some(ref mut core) = self.core {
            core.every_second()
        }
        if let Some(ref mut init) = self.init {
            init.every_second(out)?;
        }
        #[cfg(feature = "noise")]
        if let Some(ref mut noise) = self.noise {
            noise.every_second(out)?;
        }
        if self.init.as_ref().map(|i| i.stage()).unwrap_or(CLOSING) == CLOSING {
            self.init = None
        }
        #[cfg(feature = "noise")]
        if self.noise.as_ref().map(|n| n.stage()).unwrap_or(CLOSING) == CLOSING {
            self.noise = None
        }
        if !out.is_empty() {
            out.prepend_byte(INIT_MESSAGE_FIRST_BYTE);
            return Ok(MessageResult::Reply);
        }
        #[cfg(feature = "noise")]
        if self.noise_transport.is_some() {
            return Ok(MessageResult::None);
        }
        if let Some(ref mut rotate) = self.rotation {
            self.rotate_counter += 1;
            if self.rotate_counter >= ROTATE_INTERVAL {
                self.rotate_counter = 0;
                if let Some(rot) = rotate.cycle(out) {
                    let core = self.get_core()?;
                    let algo = core.algorithm();
                    let key = LessSafeKey::new(UnboundKey::new(algo, &rot.key[..algo.key_len()]).unwrap());
                    core.rotate_key(key, rot.id, rot.use_for_sending);
                }
                if !out.is_empty() {
                    out.prepend_byte(MESSAGE_TYPE_ROTATION);
                    self.encrypt_message(out)?;
                    return Ok(MessageResult::Reply);
                }
            }
        }
        Ok(MessageResult::None)
    }
}

pub fn is_init_message(msg: &[u8]) -> bool {
    // HOT PATH
    !msg.is_empty() && msg[0] == INIT_MESSAGE_FIRST_BYTE
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::types::NODE_ID_BYTES;

    fn create_node(config: &Config) -> PeerCrypto<Vec<u8>> {
        let rng = SystemRandom::new();
        let mut node_id = [0; NODE_ID_BYTES];
        rng.fill(&mut node_id).unwrap();
        let crypto = Crypto::new(node_id, config).unwrap();
        crypto.peer_instance(vec![])
    }

    #[test]
    fn normal() {
        let config = Config { password: Some("test".to_string()), ..Default::default() };
        let mut node1 = create_node(&config);
        let mut node2 = create_node(&config);
        let mut msg = MsgBuffer::new(16);

        node1.initialize(&mut msg).unwrap();
        assert!(!msg.is_empty());

        debug!("Node1 -> Node2");
        let res = node2.handle_message(&mut msg).unwrap();
        assert_eq!(res, MessageResult::Reply);
        assert!(!msg.is_empty());

        debug!("Node1 <- Node2");
        let res = node1.handle_message(&mut msg).unwrap();
        assert_eq!(res, MessageResult::InitializedWithReply(vec![]));
        assert!(!msg.is_empty());

        debug!("Node1 -> Node2");
        let res = node2.handle_message(&mut msg).unwrap();
        assert_eq!(res, MessageResult::InitializedWithReply(vec![]));
        assert!(!msg.is_empty());

        debug!("Node1 <- Node2");
        let res = node1.handle_message(&mut msg).unwrap();
        assert_eq!(res, MessageResult::None);
        assert!(msg.is_empty());

        let mut buffer = MsgBuffer::new(16);
        let rng = SystemRandom::new();
        buffer.set_length(1000);
        rng.fill(buffer.message_mut()).unwrap();
        for _ in 0..1000 {
            node1.send_message(1, &mut buffer).unwrap();
            let res = node2.handle_message(&mut buffer).unwrap();
            assert_eq!(res, MessageResult::Message(1));

            match node1.every_second(&mut msg).unwrap() {
                MessageResult::None => (),
                MessageResult::Reply => {
                    let res = node2.handle_message(&mut msg).unwrap();
                    assert_eq!(res, MessageResult::None);
                }
                other => assert_eq!(other, MessageResult::None)
            }
            match node2.every_second(&mut msg).unwrap() {
                MessageResult::None => (),
                MessageResult::Reply => {
                    let res = node1.handle_message(&mut msg).unwrap();
                    assert_eq!(res, MessageResult::None);
                }
                other => assert_eq!(other, MessageResult::None)
            }
        }
    }

    #[cfg(feature = "noise")]
    #[test]
    fn noise_handshake_and_messages() {
        let config =
            Config { password: Some("test".to_string()), algorithms: vec!["noise".to_string()], ..Default::default() };
        let mut node1 = create_node(&config);
        let mut node2 = create_node(&config);
        let mut msg = MsgBuffer::new(16);

        node1.initialize(&mut msg).unwrap();
        assert!(super::is_init_message(msg.buffer()));

        let res = node2.handle_message(&mut msg).unwrap();
        assert_eq!(res, MessageResult::Reply);

        let res = node1.handle_message(&mut msg).unwrap();
        assert_eq!(res, MessageResult::InitializedWithReply(vec![]));
        assert!(!msg.is_empty());

        let res = node2.handle_message(&mut msg).unwrap();
        assert_eq!(res, MessageResult::Initialized(vec![]));
        assert!(msg.is_empty());

        assert_eq!(node1.algorithm_name(), "NOISE");
        assert_eq!(node2.algorithm_name(), "NOISE");

        let mut buffer = MsgBuffer::new(16);
        buffer.set_length(64);
        node1.send_message(1, &mut buffer).unwrap();
        let res = node2.handle_message(&mut buffer).unwrap();
        assert_eq!(res, MessageResult::Message(1));
        node2.send_message(2, &mut buffer).unwrap();
        let res = node1.handle_message(&mut buffer).unwrap();
        assert_eq!(res, MessageResult::Message(2));
    }

    #[test]
    fn legacy_and_salted_kdf_differ() {
        let a = Crypto::password_seed("secret", None, None).unwrap();
        let b = Crypto::password_seed("secret", Some("netsalt"), Some("pbkdf2")).unwrap();
        assert_ne!(a, b);
        assert_eq!(a, Crypto::password_seed("secret", None, None).unwrap());
    }

    #[test]
    fn pbkdf2_requires_salt() {
        assert!(Crypto::password_seed("secret", None, Some("pbkdf2")).is_err());
    }
}
