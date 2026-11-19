// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use thiserror::Error;

use std::io;

/// Failure with no additional detail. Used by primitives where the caller
/// only needs success vs. failure; a named type keeps `Result` signatures
/// self-documenting instead of leaking `()` into the public API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NoDetail;

impl std::fmt::Display for NoDetail {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "operation failed")
    }
}

impl std::error::Error for NoDetail {}

#[derive(Error, Debug)]
pub enum Error {
    /// Crypto init error, this is recoverable
    #[error("Crypto initialization error: {0}")]
    CryptoInit(&'static str),

    /// Crypto init error, this is fatal and the init needs to be aborted
    #[error("Fatal crypto initialization error: {0}")]
    CryptoInitFatal(&'static str),

    /// Crypto error with this one message, no permanent error
    #[error("Crypto error: {0}")]
    Crypto(&'static str),

    #[error("Invalid crypto state: {0}")]
    InvalidCryptoState(&'static str),

    #[error("Invalid config: {0}")]
    InvalidConfig(&'static str),

    #[error("Socker error: {0}")]
    Socket(&'static str),

    #[error("Socker error: {0} ({1})")]
    SocketIo(&'static str, #[source] io::Error),

    #[error("Device error: {0}")]
    Device(&'static str),

    #[error("Device error: {0} ({1})")]
    DeviceIo(&'static str, #[source] io::Error),

    #[error("File error: {0}")]
    FileIo(&'static str, #[source] io::Error),

    #[error("Message error: {0}")]
    Message(&'static str),

    #[error("Beacon error: {0} ({1})")]
    BeaconIo(&'static str, #[source] io::Error),

    #[error("Parse error: {0}")]
    Parse(&'static str),

    #[error("Name can not be resolved: {0}")]
    NameUnresolvable(String)
}
