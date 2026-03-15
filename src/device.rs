// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021 Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::{
    cmp,
    collections::VecDeque,
    fmt,
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr},
    os::unix::io::{AsRawFd, RawFd},
    str::FromStr
};

use log::info;
use serde::{Deserialize, Serialize};
use tun::{AbstractDevice, Configuration};

use crate::error::Error;

/// The type of a tun/tap device
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
pub enum Type {
    #[serde(rename = "tun")]
    Tun,
    #[serde(rename = "tap")]
    Tap
}

impl fmt::Display for Type {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            Type::Tun => write!(formatter, "tun"),
            Type::Tap => write!(formatter, "tap")
        }
    }
}

impl FromStr for Type {
    type Err = &'static str;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Ok(match &text.to_lowercase() as &str {
            "tun" => Self::Tun,
            "tap" => Self::Tap,
            _ => return Err("Unknown device type")
        })
    }
}

/// Device abstraction used by the rest of the code.
///
/// It still extends `io::Read` and `io::Write` so existing code that uses
/// standard read/write works, but we also provide dedicated methods that
/// operate on `MsgBuffer` (the hot-path for this application).
pub trait Device: io::Read + io::Write {
    fn get_type(&self) -> Type;
    fn ifname(&self) -> &str;
    fn address(&self) -> Result<Ipv4Addr, Error>;

    /// MsgBuffer-aware helpers used on the hot path by GenericCloud.
    /// These operate directly on `MsgBuffer` (avoiding extra allocations / copies).
    fn write_msg(&mut self, data: &mut crate::util::MsgBuffer) -> Result<(), Error>;
    fn read_msg(&mut self, buffer: &mut crate::util::MsgBuffer) -> Result<(), Error>;
}

pub struct TunTapDevice {
    device: tun::Device,
    ifname: String,
    type_: Type
}

impl TunTapDevice {
    // Keep the third parameter for compatibility with callers that pass an optional device path.
    // We currently ignore `device_path` on macOS, but keep the parameter so callers don't need changes.
    pub fn new(ifname: &str, type_: Type, _device_path: Option<&str>) -> io::Result<Self> {
        let mut config = Configuration::default();
        config.tun_name(ifname);

        // Set the OSI layer based on the device type.
        match type_ {
            Type::Tun => config.layer(tun::Layer::L3),
            Type::Tap => config.layer(tun::Layer::L2)
        };

        let device: tun::Device = tun::create(&config)?;
        let ifname = device.tun_name()?.to_string();

        Ok(Self { device, ifname, type_ })
    }

    // Set MTU (delegates to tun device).
    pub fn set_mtu(&mut self, value: Option<usize>) -> io::Result<()> {
        let value = match value {
            Some(value) => value,
            None => 1500 // Placeholder
        };

        info!("Setting MTU {} on device {}", value, self.ifname);
        self.device
            .set_mtu(value as u16)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to set mtu: {}", e)))
    }

    pub fn configure(&mut self, addr: Ipv4Addr, netmask: Ipv4Addr) -> io::Result<()> {
        // enable interface and set address/netmask; convert tun errors into io::Error
        self.device.enabled(true).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Enable failed: {}", e)))?;
        self.device
            .set_address(addr.into())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Set address failed: {}", e)))?;
        self.device
            .set_netmask(netmask.into())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Set netmask failed: {}", e)))?;
        Ok(())
    }

    // Stubs for rp_filter manipulation (kept no-op on macOS / non-linux, but present for compatibility)
    pub fn fix_rp_filter(&self) -> io::Result<()> {
        // On macOS we don't change kernel rp_filter here; return Ok for compatibility
        Ok(())
    }

    pub fn get_rp_filter(&self) -> io::Result<i32> {
        // Return a conservative default (1). Callers only read this for informational purposes.
        Ok(1)
    }

    // NOTE: MsgBuffer-aware helpers are implemented as trait methods (see `impl Device for TunTapDevice`)
    // to avoid ambiguity with the std::io::Read/Write trait methods and to make them available
    // through the `Device` trait object / type parameter.
    // Inherent aliases were removed to prevent duplicate method resolution.
}

impl Device for TunTapDevice {
    fn get_type(&self) -> Type {
        self.type_
    }

    fn ifname(&self) -> &str {
        &self.ifname
    }

    fn address(&self) -> Result<Ipv4Addr, Error> {
        match self.device.address() {
            Ok(IpAddr::V4(v4)) => Ok(v4),
            Ok(IpAddr::V6(_)) => Err(Error::Device("IPv6 not supported")),
            Err(tun::Error::Io(io_err)) => Err(Error::DeviceIo("Error getting IP address", io_err)),
            _ => Err(Error::Device("Failed to query device address"))
        }
    }

    fn write_msg(&mut self, data: &mut crate::util::MsgBuffer) -> Result<(), Error> {
        let slice = data.message();
        match self.device.send(slice) {
            Ok(written) if written == slice.len() => Ok(()),
            Ok(_) => Err(Error::Socket("Sent out truncated packet")),
            Err(io_err) => Err(Error::DeviceIo("IO error when sending to device", io_err))
        }
    }

    fn read_msg(&mut self, buffer: &mut crate::util::MsgBuffer) -> Result<(), Error> {
        let buf = buffer.buffer();
        match self.device.recv(buf) {
            Ok(len) => {
                buffer.set_length(len);
                Ok(())
            }
            Err(io_err) => Err(Error::DeviceIo("IO error when reading from device", io_err))
        }
    }
}

impl io::Read for TunTapDevice {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Delegate to underlying tun device Read impl
        self.device.read(buf)
    }
}

impl io::Write for TunTapDevice {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Delegate to underlying tun device Write impl
        self.device.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.device.flush()
    }
}

// Allow the runtime to obtain the underlying raw fd for polling
impl AsRawFd for TunTapDevice {
    fn as_raw_fd(&self) -> RawFd {
        self.device.as_raw_fd()
    }
}

// MockDevice remains the same but implements the MsgBuffer read/write used by the cloud.
pub struct MockDevice {
    inbound: VecDeque<Vec<u8>>,
    outbound: VecDeque<Vec<u8>>
}

impl MockDevice {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn put_inbound(&mut self, data: Vec<u8>) {
        self.inbound.push_back(data)
    }

    pub fn pop_outbound(&mut self) -> Option<Vec<u8>> {
        self.outbound.pop_front()
    }

    pub fn has_inbound(&self) -> bool {
        !self.inbound.is_empty()
    }
}

impl Device for MockDevice {
    fn get_type(&self) -> Type {
        Type::Tun
    }

    fn ifname(&self) -> &str {
        "mock0"
    }

    fn address(&self) -> Result<Ipv4Addr, Error> {
        Err(Error::Device("Dummy devices have no IP address"))
    }

    // MsgBuffer-aware write for tests / cloud hot path (trait implementation)
    fn write_msg(&mut self, data: &mut crate::util::MsgBuffer) -> Result<(), Error> {
        let slice = data.message();
        self.outbound.push_back(slice.to_vec());
        Ok(())
    }

    // MsgBuffer-aware read for tests / cloud hot path (trait implementation)
    fn read_msg(&mut self, buffer: &mut crate::util::MsgBuffer) -> Result<(), Error> {
        if let Some(data) = self.inbound.pop_front() {
            buffer.clone_from(&data);
            Ok(())
        } else {
            Err(Error::Device("No data available"))
        }
    }
}

impl io::Read for MockDevice {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(data) = self.inbound.pop_front() {
            let len = cmp::min(buf.len(), data.len());
            buf[..len].copy_from_slice(&data[..len]);
            Ok(len)
        } else {
            Err(io::Error::new(io::ErrorKind::WouldBlock, "No data available"))
        }
    }
}

impl io::Write for MockDevice {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.outbound.push_back(buf.to_vec());
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Default for MockDevice {
    fn default() -> Self {
        Self { outbound: VecDeque::with_capacity(10), inbound: VecDeque::with_capacity(10) }
    }
}

// Provide From<Ipv4Addr> -> Address to match call sites that use Address::from(ip)
impl From<Ipv4Addr> for crate::types::Address {
    fn from(ip: Ipv4Addr) -> Self {
        crate::types::Address::from_ipv4(ip)
    }
}

// Provide From<Ipv4Addr> -> Address to match call sites that use Address::from(ip)
