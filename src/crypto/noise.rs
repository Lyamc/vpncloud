// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! Noise_XX handshake and transport (X25519, ChaCha20-Poly1305, SHA-256).
//!
//! Frames are sent as init messages (`0xff` prefix) with a `NOIS` magic so classic
//! peers ignore them. After three messages both sides split into transport mode.

use super::{
    init::{CLOSING, MAX_FAILED_RETRIES, STAGE_PENG, STAGE_PING, STAGE_PONG, WAITING_TO_CLOSE},
    Payload
};
use crate::{
    error::Error,
    types::{NodeId, NODE_ID_BYTES},
    util::MsgBuffer
};
use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use snow::{params::NoiseParams, Builder, HandshakeState, TransportState};
use std::{
    io::{Cursor, Read, Write},
    sync::Arc
};
use x25519_dalek::{PublicKey, StaticSecret};

pub const PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
const MAGIC: &[u8; 4] = b"NOIS";
const VERSION: u8 = 1;
const TAG_LEN: usize = 16;

pub fn is_noise_frame(msg: &[u8]) -> bool {
    msg.len() >= 4 && msg[..4] == *MAGIC
}

pub fn dh_keypair_from_seed(seed: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let secret = StaticSecret::from(*seed);
    let public = PublicKey::from(&secret);
    (secret.to_bytes(), *public.as_bytes())
}

fn noise_builder(dh_private: &[u8; 32]) -> Result<Builder<'_>, Error> {
    let params: NoiseParams = PATTERN.parse().map_err(|_| Error::InvalidConfig("Invalid Noise parameters"))?;
    Builder::new(params).local_private_key(dh_private).map_err(|_| Error::Crypto("Failed to set Noise static key"))
}

fn snow_err(_e: snow::Error) -> Error {
    Error::Crypto("Noise protocol error")
}

pub struct NoiseTransport {
    state: TransportState
}

impl NoiseTransport {
    pub fn encrypt(&mut self, buffer: &mut MsgBuffer) -> Result<(), Error> {
        let payload = buffer.message().to_vec();
        let mut out = vec![0u8; payload.len() + TAG_LEN];
        let n = self.state.write_message(&payload, &mut out).map_err(snow_err)?;
        buffer.clear();
        buffer.set_length(n);
        buffer.message_mut().copy_from_slice(&out[..n]);
        Ok(())
    }

    pub fn decrypt(&mut self, buffer: &mut MsgBuffer) -> Result<(), Error> {
        let ciphertext = buffer.message().to_vec();
        if ciphertext.len() < TAG_LEN {
            return Err(Error::Crypto("Noise ciphertext too short"));
        }
        let mut out = vec![0u8; ciphertext.len()];
        let n = self.state.read_message(&ciphertext, &mut out).map_err(snow_err)?;
        buffer.clear();
        buffer.set_length(n);
        buffer.message_mut().copy_from_slice(&out[..n]);
        Ok(())
    }
}

pub struct NoiseInit<P: Payload> {
    node_id: NodeId,
    payload: P,
    dh_private: [u8; 32],
    dh_public: [u8; 32],
    trusted_dh: Arc<[[u8; 32]]>,
    hs: Option<HandshakeState>,
    initiator: bool,
    next_stage: u8,
    last_message: Option<Vec<u8>>,
    failed_retries: usize,
    close_time: usize,
    transport: Option<NoiseTransport>
}

impl<P: Payload> NoiseInit<P> {
    pub fn new(
        node_id: NodeId, payload: P, dh_private: [u8; 32], dh_public: [u8; 32], trusted_dh: Arc<[[u8; 32]]>
    ) -> Self {
        Self {
            node_id,
            payload,
            dh_private,
            dh_public,
            trusted_dh,
            hs: None,
            initiator: true,
            next_stage: STAGE_PING,
            last_message: None,
            failed_retries: 0,
            close_time: 60,
            transport: None
        }
    }

    pub fn stage(&self) -> u8 {
        self.next_stage
    }

    pub fn take_transport(&mut self) -> Option<NoiseTransport> {
        self.transport.take()
    }

    pub fn send_ping(&mut self, out: &mut MsgBuffer) {
        let mut hs =
            noise_builder(&self.dh_private).expect("noise builder").build_initiator().expect("noise initiator");
        let mut noise_msg = vec![0u8; 128];
        let n = hs.write_message(&[], &mut noise_msg).expect("noise ping");
        noise_msg.truncate(n);
        self.hs = Some(hs);
        self.initiator = true;
        self.next_stage = STAGE_PONG;
        self.write_frame(STAGE_PING, &noise_msg, out);
    }

    pub fn every_second(&mut self, out: &mut MsgBuffer) -> Result<(), Error> {
        if self.next_stage == WAITING_TO_CLOSE {
            if self.close_time == 0 {
                self.next_stage = CLOSING;
            } else {
                self.close_time -= 1;
            }
            Ok(())
        } else if self.next_stage == CLOSING {
            Ok(())
        } else if self.failed_retries < MAX_FAILED_RETRIES {
            self.failed_retries += 1;
            if let Some(ref bytes) = self.last_message {
                debug!("Repeating last Noise init message");
                let buffer = out.buffer();
                buffer[..bytes.len()].copy_from_slice(bytes);
                out.set_length(bytes.len());
            }
            Ok(())
        } else {
            self.next_stage = CLOSING;
            Err(Error::CryptoInitFatal("Initialization timeout"))
        }
    }

    pub fn handle(&mut self, out: &mut MsgBuffer) -> Result<super::init::InitResult<P>, Error> {
        let (stage, peer_id, noise_msg) = decode_frame(out.buffer())?;
        out.clear();
        if peer_id == self.node_id {
            return Err(Error::CryptoInitFatal("Connected to self"));
        }
        if stage != self.next_stage {
            if self.next_stage == STAGE_PONG && stage == STAGE_PING {
                if peer_id > self.node_id {
                    self.hs = None;
                    self.initiator = false;
                    self.next_stage = STAGE_PING;
                    self.last_message = None;
                } else {
                    return Ok(super::init::InitResult::Continue);
                }
            } else if self.next_stage == CLOSING {
                return Ok(super::init::InitResult::Continue);
            } else if self.last_message.is_some() {
                if let Some(ref bytes) = self.last_message {
                    let buffer = out.buffer();
                    buffer[..bytes.len()].copy_from_slice(bytes);
                    out.set_length(bytes.len());
                }
                return Ok(super::init::InitResult::Continue);
            } else {
                return Err(Error::CryptoInitFatal("Received invalid stage as first message"));
            }
        }
        self.failed_retries = 0;
        match stage {
            STAGE_PING => self.handle_ping(&noise_msg, out),
            STAGE_PONG => self.handle_pong(&noise_msg, out),
            STAGE_PENG => self.handle_peng(&noise_msg, out),
            _ => Err(Error::CryptoInitFatal("Invalid stage"))
        }
    }

    fn handle_ping(&mut self, noise_msg: &[u8], out: &mut MsgBuffer) -> Result<super::init::InitResult<P>, Error> {
        let mut hs = noise_builder(&self.dh_private)?.build_responder().map_err(snow_err)?;
        let mut payload = vec![0u8; 65535];
        let _n = hs.read_message(noise_msg, &mut payload).map_err(snow_err)?;
        let mut our_payload = MsgBuffer::new(0);
        self.payload.write_to(&mut our_payload);
        let mut noise_out = vec![0u8; our_payload.len() + 128];
        let n = hs.write_message(our_payload.message(), &mut noise_out).map_err(snow_err)?;
        noise_out.truncate(n);
        self.hs = Some(hs);
        self.initiator = false;
        self.next_stage = STAGE_PENG;
        self.write_frame(STAGE_PONG, &noise_out, out);
        Ok(super::init::InitResult::Continue)
    }

    fn handle_pong(&mut self, noise_msg: &[u8], out: &mut MsgBuffer) -> Result<super::init::InitResult<P>, Error> {
        let hs = self.hs.as_mut().ok_or(Error::InvalidCryptoState("Noise handshake missing"))?;
        let mut payload = vec![0u8; 65535];
        let n = hs.read_message(noise_msg, &mut payload).map_err(snow_err)?;
        let peer_payload = P::read_from(Cursor::new(&payload[..n]))?;
        let mut our_payload = MsgBuffer::new(0);
        self.payload.write_to(&mut our_payload);
        let mut noise_out = vec![0u8; our_payload.len() + 128];
        let n = hs.write_message(our_payload.message(), &mut noise_out).map_err(snow_err)?;
        noise_out.truncate(n);
        self.write_frame(STAGE_PENG, &noise_out, out);
        self.finish_handshake()?;
        self.next_stage = WAITING_TO_CLOSE;
        self.close_time = 60;
        Ok(super::init::InitResult::Success { peer_payload, is_initiator: true })
    }

    fn handle_peng(&mut self, noise_msg: &[u8], out: &mut MsgBuffer) -> Result<super::init::InitResult<P>, Error> {
        let hs = self.hs.as_mut().ok_or(Error::InvalidCryptoState("Noise handshake missing"))?;
        let mut payload = vec![0u8; 65535];
        let n = hs.read_message(noise_msg, &mut payload).map_err(snow_err)?;
        let peer_payload = P::read_from(Cursor::new(&payload[..n]))?;
        self.finish_handshake()?;
        self.next_stage = CLOSING;
        out.clear();
        Ok(super::init::InitResult::Success { peer_payload, is_initiator: false })
    }

    fn finish_handshake(&mut self) -> Result<(), Error> {
        let hs = self.hs.take().ok_or(Error::InvalidCryptoState("Noise handshake missing"))?;
        let remote = hs.get_remote_static().ok_or(Error::CryptoInitFatal("Noise handshake missing remote static"))?;
        if !self.trusted_dh.iter().any(|k| k.as_slice() == remote) && remote != self.dh_public {
            return Err(Error::CryptoInitFatal("untrusted peer"));
        }
        let state = hs.into_transport_mode().map_err(snow_err)?;
        self.transport = Some(NoiseTransport { state });
        Ok(())
    }

    fn write_frame(&mut self, stage: u8, noise_msg: &[u8], out: &mut MsgBuffer) {
        let mut w = Cursor::new(out.buffer());
        w.write_all(MAGIC).unwrap();
        w.write_u8(VERSION).unwrap();
        w.write_u8(stage).unwrap();
        w.write_all(&self.node_id).unwrap();
        w.write_u16::<NetworkEndian>(noise_msg.len() as u16).unwrap();
        w.write_all(noise_msg).unwrap();
        let len = w.position() as usize;
        out.set_length(len);
        self.last_message = Some(out.message()[..len].to_vec());
        debug!("Sending Noise init with stage={}", stage);
    }
}

fn decode_frame(buf: &[u8]) -> Result<(u8, NodeId, Vec<u8>), Error> {
    if buf.len() < 4 + 1 + 1 + NODE_ID_BYTES + 2 {
        return Err(Error::Parse("Noise init message too short"));
    }
    let mut r = Cursor::new(buf);
    let mut magic = [0u8; 4];
    r.read_exact(&mut magic).map_err(|_| Error::Parse("Noise init message too short"))?;
    if &magic != MAGIC {
        return Err(Error::Parse("Not a Noise init message"));
    }
    let ver = r.read_u8().map_err(|_| Error::Parse("Noise init message too short"))?;
    if ver != VERSION {
        return Err(Error::CryptoInitFatal("Unsupported Noise version"));
    }
    let stage = r.read_u8().map_err(|_| Error::Parse("Noise init message too short"))?;
    let mut node_id = [0u8; NODE_ID_BYTES];
    r.read_exact(&mut node_id).map_err(|_| Error::Parse("Noise init message too short"))?;
    let n = r.read_u16::<NetworkEndian>().map_err(|_| Error::Parse("Noise init message too short"))? as usize;
    let pos = r.position() as usize;
    if buf.len() < pos + n {
        return Err(Error::Parse("Noise init message too short"));
    }
    Ok((stage, node_id, buf[pos..pos + n].to_vec()))
}
