// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021 Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::{
    cmp,
    collections::VecDeque,
    fmt,
    io::{self},
    net::{IpAddr, Ipv4Addr},
    str::FromStr
};

#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};

#[cfg(windows)]
use std::os::windows::io::{AsRawHandle, RawHandle};

use getifaddrs::getifaddrs;
use log::info;
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

/// Pick a tun-rs interface name for the current OS.
///
/// Linux accepts `vpncloud%d` (kernel fills in the number). macOS TUN devices are always
/// `utunN`; TAP uses `feth` pairs. Linux-style names are ignored there so the OS can assign one.
fn platform_device_name(ifname: &str, type_: Type) -> Option<String> {
    if ifname.is_empty() {
        return None;
    }
    #[cfg(target_os = "macos")]
    {
        if ifname.contains('%') || ifname.starts_with("vpncloud") {
            return None;
        }
        match type_ {
            Type::Tun if !ifname.starts_with("utun") => return None,
            Type::Tap if !ifname.starts_with("feth") => return None,
            _ => {}
        }
        Some(ifname.to_string())
    }
    #[cfg(target_os = "windows")]
    {
        let _ = type_;
        // wintun / tap-windows6 adapter names cannot contain `%d`.
        let name = ifname.replace("%d", "0");
        if name.is_empty() {
            None
        } else {
            Some(name)
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = type_;
        Some(ifname.to_string())
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
    device: std::sync::Arc<SyncDevice>,
    ifname: String,
    type_: Type,
    #[cfg(windows)]
    incoming: std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<Vec<u8>>>>
}

impl TunTapDevice {
    // Keep the third parameter for compatibility with callers that pass an optional device path.
    // Linux uses it for `/dev/net/tun`; tun-rs manages that itself, so the path is ignored.
    pub fn new(ifname: &str, type_: Type, _device_path: Option<&str>) -> io::Result<Self> {
        let mut builder = DeviceBuilder::new();

        if let Some(name) = platform_device_name(ifname, type_) {
            builder = builder.name(name);
        }

        match type_ {
            Type::Tun => builder = builder.layer(Layer::L3),
            Type::Tap => {
                builder = builder.layer(Layer::L2);
                // Kernel/tun-rs defaults can collide across nodes (#381). Assign a unique LAA.
                let mut mac = rand::random::<[u8; 6]>();
                mac[0] = (mac[0] & 0xfe) | 0x02;
                builder = builder.mac_addr(mac);
            }
        };

        // vpncloud speaks raw IP / Ethernet frames. On macOS utun, tun-rs will strip the
        // 4-byte address-family header when packet information is disabled (the default).
        #[cfg(any(
            target_os = "macos",
            target_os = "linux",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd"
        ))]
        {
            builder = builder.packet_information(false);
        }

        let device = builder.build_sync().map_err(|e| {
            if e.kind() == io::ErrorKind::PermissionDenied {
                #[cfg(windows)]
                let hint = "try running as Administrator; TUN needs wintun.dll, TAP needs tap-windows6";
                #[cfg(not(windows))]
                let hint = "try running as root/sudo";
                io::Error::new(e.kind(), format!("Permission denied creating {} device ({}): {}", type_, hint, e))
            } else {
                e
            }
        })?;
        // mio requires non-blocking file descriptors. wintun/tap-windows6 are waited separately.
        #[cfg(unix)]
        device.set_nonblocking(true)?;
        let actual_ifname = device.name()?.to_string();

        Ok(Self {
            device: std::sync::Arc::new(device),
            ifname: actual_ifname,
            type_,
            #[cfg(windows)]
            incoming: std::sync::Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new()))
        })
    }

    // Set MTU (delegates to tun device).
    pub fn set_mtu(&mut self, value: Option<usize>) -> io::Result<()> {
        let value = match value {
            Some(value) => value,
            None => {
                // Leave headroom for VpnCloud encapsulation on top of the kernel MTU.
                self.device.mtu().map(|m| (m as usize).saturating_sub(100).max(576)).unwrap_or(1400)
            }
        };

        info!("Setting MTU {} on device {}", value, self.ifname);
        self.device
            .set_mtu(value as u16)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to set mtu: {}", e)))
    }

    pub fn configure(&mut self, addr: Ipv4Addr, netmask: Ipv4Addr) -> io::Result<()> {
        self.configure_ip(IpAddr::V4(addr), Some(netmask), None)
    }

    pub fn configure_ip(&mut self, addr: IpAddr, netmask: Option<Ipv4Addr>, prefix_len: Option<u8>) -> io::Result<()> {
        self.device.enabled(true).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Enable failed: {}", e)))?;
        match addr {
            IpAddr::V4(ip) => {
                let netmask = netmask.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "IPv4 netmask required"))?;
                self.device
                    .set_network_address(ip, netmask, None)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Set address failed: {}", e)))?;
            }
            IpAddr::V6(ip) => {
                let prefix = prefix_len.unwrap_or(64);
                self.device
                    .add_address_v6(ip, prefix)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Set IPv6 address failed: {}", e)))?;
            }
        }
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
        match self.type_ {
            Type::Tap => crate::payload::fix_ethernet_ipv4_checksums(data.message_mut()),
            Type::Tun => crate::payload::fix_ipv4_checksums(data.message_mut())
        }
        let slice = data.message();
        match self.device.send(slice) {
            Ok(written) if written == slice.len() => Ok(()),
            Ok(_) => Err(Error::Socket("Sent out truncated packet")),
            Err(io_err) => Err(Error::DeviceIo("IO error when sending to device", io_err))
        }
    }

    fn read_msg(&mut self, buffer: &mut crate::util::MsgBuffer) -> Result<(), Error> {
        #[cfg(windows)]
        {
            if let Some(data) = self.incoming.lock().expect("device queue").pop_front() {
                buffer.clone_from(&data);
                match self.type_ {
                    Type::Tap => crate::payload::fix_ethernet_ipv4_checksums(buffer.message_mut()),
                    Type::Tun => crate::payload::fix_ipv4_checksums(buffer.message_mut())
                }
                return Ok(());
            }
            return Err(Error::DeviceIo(
                "IO error when reading from device",
                io::Error::new(io::ErrorKind::WouldBlock, "no TAP/TUN packet queued")
            ));
        }
        #[cfg(not(windows))]
        let buf = buffer.buffer();
        #[cfg(not(windows))]
        match self.device.recv(buf) {
            Ok(len) => {
                buffer.set_length(len);
                match self.type_ {
                    Type::Tap => crate::payload::fix_ethernet_ipv4_checksums(buffer.message_mut()),
                    Type::Tun => crate::payload::fix_ipv4_checksums(buffer.message_mut())
                }
                Ok(())
            }
            // tun-rs TAP on macOS returns UnexpectedEof when a BPF wakeup has no frames.
            Err(io_err)
                if matches!(
                    io_err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted | io::ErrorKind::UnexpectedEof
                ) =>
            {
                Err(Error::DeviceIo(
                    "IO error when reading from device",
                    io::Error::new(io::ErrorKind::WouldBlock, io_err)
                ))
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
impl crate::poll::Pollable for TunTapDevice {
    fn wait_device(&self) -> Option<crate::poll::WindowsDeviceSource> {
        let device = self.device.clone();
        Some(crate::poll::WindowsDeviceSource {
            recv: std::sync::Arc::new(move |buf| device.recv(buf)),
            queue: self.incoming.clone()
        })
    }
}

#[cfg(windows)]
impl crate::poll::Pollable for MockDevice {}

// MockDevice remains the same but implements the MsgBuffer read/write used by the cloud.
pub struct MockDevice {
    inbound: VecDeque<Vec<u8>>,
    outbound: VecDeque<Vec<u8>>,
    fd: std::fs::File
}

fn null_file() -> std::fs::File {
    #[cfg(unix)]
    {
        std::fs::File::open("/dev/null").expect("Failed to open /dev/null")
    }
    #[cfg(windows)]
    {
        std::fs::File::open("NUL").expect("Failed to open NUL")
    }
}

impl MockDevice {
    pub fn new() -> Self {
        Self { inbound: VecDeque::with_capacity(10), outbound: VecDeque::with_capacity(10), fd: null_file() }
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
        Self { inbound: VecDeque::with_capacity(10), outbound: VecDeque::with_capacity(10), fd: null_file() }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_name_empty_is_unspecified() {
        assert_eq!(platform_device_name("", Type::Tun), None);
    }

    #[test]
    fn platform_name_linux_style_percent() {
        let name = platform_device_name("vpncloud%d", Type::Tun);
        #[cfg(target_os = "macos")]
        assert_eq!(name, None);
        #[cfg(target_os = "windows")]
        assert_eq!(name.as_deref(), Some("vpncloud0"));
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        assert_eq!(name.as_deref(), Some("vpncloud%d"));
    }

    #[test]
    fn platform_name_explicit_utun() {
        let name = platform_device_name("utun8", Type::Tun);
        assert_eq!(name.as_deref(), Some("utun8"));
    }

    #[test]
    #[ignore]
    fn opens_tun_device() {
        let mut dev = TunTapDevice::new("vpncloud%d", Type::Tun, None).expect("open tun");
        #[cfg(target_os = "macos")]
        assert!(dev.ifname().starts_with("utun"), "unexpected ifname {}", dev.ifname());
        dev.set_mtu(None).expect("set mtu");
        dev.configure(Ipv4Addr::new(10, 250, 0, 1), Ipv4Addr::new(255, 255, 255, 0)).expect("configure");
        assert_eq!(dev.address().unwrap(), Ipv4Addr::new(10, 250, 0, 1));
    }
}
