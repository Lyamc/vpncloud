// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021 Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::{
    cmp,
    collections::VecDeque,
    fmt,
    io::{self},
    net::Ipv4Addr,
    str::FromStr
};

#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};

#[cfg(windows)]
use std::os::windows::io::{AsRawHandle, RawHandle};

use getifaddrs::getifaddrs;
use log::{debug, error, info, warn};
#[cfg(target_os = "linux")]
use rustix;
use serde::{Deserialize, Serialize};
use tun_rs::{DeviceBuilder, Layer, SyncDevice};

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
    device: SyncDevice,
    ifname: String,
    type_: Type
}

impl TunTapDevice {
    // Keep the third parameter for compatibility with callers that pass an optional device path.
    // We currently ignore `device_path` on macOS, but keep the parameter so callers don't need changes.
    pub fn new(ifname: &str, type_: Type, _device_path: Option<&str>) -> io::Result<Self> {
        let mut builder = DeviceBuilder::new().name(ifname);

        // Set the OSI layer based on the device type.
        match type_ {
            Type::Tun => builder = builder.layer(Layer::L3),
            Type::Tap => builder = builder.layer(Layer::L2)
        };

        let device = builder.build_sync()?;
        let actual_ifname = device.name()?.to_string();

        Ok(Self { device, ifname: actual_ifname, type_ })
    }

    // Set MTU (delegates to tun device).
    pub fn set_mtu(&mut self, value: Option<usize>) -> io::Result<()> {
        let value = match value {
            Some(value) => value,
            #[cfg(target_os = "linux")]
            None => {
                let default_device = get_default_device().unwrap_or_else(|_| "eth0".to_string());
                get_device_mtu(&default_device).unwrap_or(1500) - 100 // Subtract overhead
            }
            #[cfg(not(target_os = "linux"))]
            None => 1500 // Placeholder
        };

        info!("Setting MTU {} on device {}", value, self.ifname);
        self.device
            .set_mtu(value as u16)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to set mtu: {}", e)))
    }

    pub fn configure(&mut self, addr: Ipv4Addr, netmask: Ipv4Addr) -> io::Result<()> {
        // enable interface and set address/netmask
        self.device.enabled(true).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Enable failed: {}", e)))?;
        self.device
            .set_network_address(addr, netmask, None)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Set address failed: {}", e)))?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub fn fix_rp_filter(&self) -> io::Result<()> {
        if get_rp_filter("all")? > 1 {
            info!("Setting net.ipv4.conf.all.rp_filter=1");
            set_rp_filter("all", 1)?
        }
        if get_rp_filter(&self.ifname)? != 1 {
            info!("Setting net.ipv4.conf.{}.rp_filter=1", self.ifname);
            set_rp_filter(&self.ifname, 1)?
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn fix_rp_filter(&self) -> io::Result<()> {
        // On non-linux platforms we don't change kernel rp_filter here; return Ok for compatibility
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub fn get_rp_filter(&self) -> io::Result<i32> {
        Ok(cmp::max(get_rp_filter("all")?, get_rp_filter(&self.ifname)?) as i32)
    }

    #[cfg(not(target_os = "linux"))]
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
        // Use getifaddrs to find the IPv4 address of the interface
        let if_name = self.ifname();
        for iface in getifaddrs().map_err(|e| Error::DeviceIo("Failed to get interface addresses", e))? {
            if iface.name == if_name {
                if let Some(std::net::IpAddr::V4(v4)) = iface.address.ip_addr() {
                    return Ok(v4);
                }
            }
        }
        Err(Error::Device("No IPv4 address found for interface"))
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
        // Delegate to underlying tun device recv impl
        self.device.recv(buf)
    }
}

impl io::Write for TunTapDevice {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Delegate to underlying tun device send impl
        self.device.send(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// Allow the runtime to obtain the underlying raw fd/handle for polling
#[cfg(unix)]
impl AsRawFd for TunTapDevice {
    fn as_raw_fd(&self) -> RawFd {
        self.device.as_raw_fd()
    }
}

#[cfg(windows)]
impl AsRawHandle for TunTapDevice {
    fn as_raw_handle(&self) -> RawHandle {
        self.device.as_raw_handle()
    }
}

// MockDevice remains the same but implements the MsgBuffer read/write used by the cloud.
pub struct MockDevice {
    inbound: VecDeque<Vec<u8>>,
    outbound: VecDeque<Vec<u8>>,
    fd: std::fs::File
}

impl MockDevice {
    pub fn new() -> Self {
        // Open /dev/null to get a valid file descriptor for polling
        let fd = std::fs::File::open("/dev/null").expect("Failed to open /dev/null");
        Self { inbound: VecDeque::with_capacity(10), outbound: VecDeque::with_capacity(10), fd }
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
        Self {
            inbound: VecDeque::with_capacity(10),
            outbound: VecDeque::with_capacity(10),
            fd: std::fs::File::open("/dev/null").expect("Failed to open /dev/null")
        }
    }
}

#[cfg(unix)]
impl AsRawFd for MockDevice {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

#[cfg(windows)]
impl std::os::windows::io::AsRawHandle for MockDevice {
    fn as_raw_handle(&self) -> std::os::windows::io::RawHandle {
        use std::os::windows::io::AsRawHandle;
        self.fd.as_raw_handle()
    }
}

// Provide From<Ipv4Addr> -> Address to match call sites that use Address::from(ip)
impl From<Ipv4Addr> for crate::types::Address {
    fn from(ip: Ipv4Addr) -> Self {
        crate::types::Address::from_ipv4(ip)
    }
}

#[cfg(target_os = "linux")]
fn get_rp_filter(device: &str) -> io::Result<u8> {
    use std::io::Read;
    let mut fd = std::fs::File::open(format!("/proc/sys/net/ipv4/conf/{}/rp_filter", device))?;
    let mut contents = String::with_capacity(10);
    fd.read_to_string(&mut contents)?;
    contents.trim().parse().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid rp_filter value"))
}

#[cfg(target_os = "linux")]
fn set_rp_filter(device: &str, val: u8) -> io::Result<()> {
    use std::io::Write;
    let mut fd = std::fs::File::create(format!("/proc/sys/net/ipv4/conf/{}/rp_filter", device))?;
    writeln!(fd, "{}", val)
}

#[cfg(target_os = "linux")]
fn get_default_device() -> io::Result<String> {
    use std::io::BufRead;
    let fd = std::io::BufReader::new(std::fs::File::open("/proc/net/route")?);
    let mut best = None;
    for line in fd.lines() {
        let line = line?;
        let parts = line.split('\t').collect::<Vec<_>>();
        if parts.len() < 3 { continue; }
        if parts[1] == "00000000" {
            best = Some(parts[0].to_string());
            break
        }
        if parts[2] != "00000000" {
            best = Some(parts[0].to_string())
        }
    }
    if let Some(ifname) = best {
        Ok(ifname)
    } else {
        Err(io::Error::new(io::ErrorKind::NotFound, "No default interface found".to_string()))
    }
}

#[cfg(target_os = "linux")]
fn get_device_mtu(ifname: &str) -> io::Result<usize> {
    use rustix::net::ioctl_gifmtu;
    let sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
    ioctl_gifmtu(&sock, ifname).map(|mtu| mtu as usize).map_err(io::Error::from)
}
