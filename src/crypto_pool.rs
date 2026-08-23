// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! Worker pool for DATA encrypt/decrypt. Control-plane crypto stays on the wait thread.
//!
//! Jobs are per-peer batches so AEAD nonces stay in order for a given peer while
//! different peers can run in parallel.

use std::{
    net::SocketAddr,
    sync::{
        mpsc::{self, Receiver, Sender},
        Arc, Mutex
    },
    thread
};

use crate::{
    crypto::{MessageResult, PeerCrypto},
    error::Error,
    messages::NodeInfo,
    util::MsgBuffer
};

type CryptoBox = Arc<Mutex<PeerCrypto<NodeInfo>>>;

pub enum CryptoJob {
    Encrypt { crypto: CryptoBox, packets: Vec<(u8, MsgBuffer)>, addr: SocketAddr },
    Decrypt { crypto: CryptoBox, packets: Vec<MsgBuffer>, src: SocketAddr }
}

pub enum CryptoDone {
    Encrypted { addr: SocketAddr, packets: Vec<MsgBuffer> },
    Decrypted { src: SocketAddr, packets: Vec<(Result<MessageResult<NodeInfo>, Error>, MsgBuffer)> },
    Failed(Error)
}

pub struct CryptoPool {
    jobs: Option<Sender<CryptoJob>>,
    done: Mutex<Receiver<CryptoDone>>,
    done_tx: Sender<CryptoDone>
}

impl CryptoPool {
    pub fn new(workers: usize) -> Self {
        let (done_tx, done_rx) = mpsc::channel();
        if workers == 0 {
            return Self { jobs: None, done: Mutex::new(done_rx), done_tx };
        }
        let (job_tx, job_rx) = mpsc::channel::<CryptoJob>();
        let job_rx = Arc::new(Mutex::new(job_rx));
        for i in 0..workers {
            let rx = job_rx.clone();
            let done = done_tx.clone();
            thread::Builder::new()
                .name(format!("vpncloud-crypto-{i}"))
                .spawn(move || {
                    loop {
                        let job = { rx.lock().ok().and_then(|r| r.recv().ok()) };
                        let Some(job) = job else {
                            break;
                        };
                        let _ = done.send(run_job(job));
                    }
                })
                .ok();
        }
        Self { jobs: Some(job_tx), done: Mutex::new(done_rx), done_tx }
    }

    pub fn enabled(&self) -> bool {
        self.jobs.is_some()
    }

    pub fn submit(&self, job: CryptoJob) {
        if let Some(tx) = &self.jobs {
            match tx.send(job) {
                Ok(()) => return,
                Err(e) => {
                    let _ = self.done_tx.send(run_job(e.0));
                    return;
                }
            }
        }
        let _ = self.done_tx.send(run_job(job));
    }

    pub fn try_recv(&self) -> Option<CryptoDone> {
        self.done.lock().ok()?.try_recv().ok()
    }

    pub fn recv(&self) -> Option<CryptoDone> {
        self.done.lock().ok()?.recv().ok()
    }
}

fn run_job(job: CryptoJob) -> CryptoDone {
    match job {
        CryptoJob::Encrypt { crypto, packets, addr } => {
            let mut guard = match crypto.lock() {
                Ok(g) => g,
                Err(_) => return CryptoDone::Failed(Error::InvalidCryptoState("crypto lock"))
            };
            let mut out = Vec::with_capacity(packets.len());
            for (type_, mut data) in packets {
                if let Err(e) = guard.send_message(type_, &mut data) {
                    return CryptoDone::Failed(e);
                }
                out.push(data);
            }
            CryptoDone::Encrypted { addr, packets: out }
        }
        CryptoJob::Decrypt { crypto, packets, src } => {
            let mut guard = match crypto.lock() {
                Ok(g) => g,
                Err(_) => return CryptoDone::Failed(Error::InvalidCryptoState("crypto lock"))
            };
            let mut out = Vec::with_capacity(packets.len());
            for mut data in packets {
                let result = guard.handle_message(&mut data);
                out.push((result, data));
            }
            CryptoDone::Decrypted { src, packets: out }
        }
    }
}

pub type CryptoBoxHandle = CryptoBox;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_workers_is_inline() {
        assert!(!CryptoPool::new(0).enabled());
        assert!(CryptoPool::new(2).enabled());
    }
}
