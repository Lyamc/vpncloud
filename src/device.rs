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

#[cfg(target_os = "android")]
use std::process::Command;

#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};


use getifaddrs::getifaddrs;
use log::info;
use serde::{Deserialize, Serialize};
use tun_rs::SyncDevice;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use tun_rs::{DeviceBuilder, Layer};
#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
use tun_rs::{GROTable, VIRTIO_NET_HDR_LEN};

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
/// `utunN`; TAP uses `feth` pairs. FreeBSD/other BSD TUN/TAP units are `tunN` / `tapN`;
/// Linux-style names are ignored there so the OS can clone a free unit.
#[cfg_attr(target_os = "ios", allow(dead_code))]
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
    #[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd", target_os = "dragonfly"))]
    {
        if ifname.contains('%') || ifname.starts_with("vpncloud") {
            return None;
        }
        match type_ {
            Type::Tun if !ifname.starts_with("tun") => return None,
            Type::Tap if !ifname.starts_with("tap") => return None,
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
    #[cfg(not(any(
        target_os = "macos",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    )))]
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

    /// Fill `bufs` with packets until WouldBlock or `bufs` is full.
    fn read_batch(&mut self, bufs: &mut [crate::util::MsgBuffer]) -> Result<usize, Error> {
        let mut n = 0;
        for b in bufs.iter_mut() {
            match self.read_msg(b) {
                Ok(()) => n += 1,
                Err(Error::DeviceIo(_, ref e)) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) if n > 0 => break,
                Err(e) => return Err(e)
            }
        }
        Ok(n)
    }

    /// Write `bufs` to the overlay device. Linux TUN with offload uses `send_multiple`.
    fn write_batch(&mut self, bufs: &mut [crate::util::MsgBuffer]) -> Result<usize, Error> {
        if bufs.is_empty() {
            return Ok(0);
        }
        for b in bufs.iter_mut() {
            self.write_msg(b)?;
        }
        Ok(bufs.len())
    }
}

pub struct TunTapDevice {
    device: std::sync::Arc<SyncDevice>,
    ifname: String,
    type_: Type,
    #[cfg(windows)]
    incoming: std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<Vec<u8>>>>,
    #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
    tun_offload: bool,
    #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
    tun_scratch: Vec<u8>,
    #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
    tun_batch: Vec<Vec<u8>>,
    #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
    tun_sizes: Vec<usize>,
    #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
    gro_table: GROTable
}

/// Shown in `--help` and in the error when TAP is requested without root.
pub const ANDROID_TAP_HELP: &str = "\
TAP/L2 on Android is only supported on rooted devices (needs /dev/net/tun). \
Unrooted devices can only use TUN via VpnService. See --help.";

/// Shown in `--help` and in the error when TAP is requested on iOS.
pub const IOS_TAP_HELP: &str = "\
TAP/L2 is not available on iOS. Packet Tunnel Provider is TUN-only (IP packets). \
There is no /dev/net/tun or Ethernet bridging on iOS. See --help.";

pub fn android_tap_needs_root() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, ANDROID_TAP_HELP)
}

/// True if this process can open `/dev/net/tun` (uid 0, or chmod via `su`).
#[cfg(target_os = "android")]
pub fn android_has_tuntap_access() -> bool {
    android_tun::has_access()
}

#[cfg(not(target_os = "android"))]
pub fn android_has_tuntap_access() -> bool {
    false
}

#[cfg(target_os = "android")]
mod android_tun {
    use super::*;
    use std::{
        ffi::CString,
        io::{Error, ErrorKind},
        mem,
        os::unix::io::RawFd
    };

    const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
    const IFF_TUN: libc::c_short = 0x0001;
    const IFF_TAP: libc::c_short = 0x0002;
    const IFF_NO_PI: libc::c_short = 0x1000;
    const IFNAMSIZ: usize = 16;

    pub fn has_access() -> bool {
        if unsafe { libc::geteuid() } == 0 {
            return true;
        }
        if open_dev().is_ok() {
            return true;
        }
        let _ = Command::new("su").args(["-c", "chmod 666 /dev/net/tun"]).status();
        open_dev().is_ok()
    }

    fn open_dev() -> io::Result<std::fs::File> {
        std::fs::OpenOptions::new().read(true).write(true).open("/dev/net/tun")
    }

    pub fn create(ifname: &str, tap: bool, device_path: Option<&str>) -> io::Result<(SyncDevice, String)> {
        if tap && !has_access() {
            return Err(android_tap_needs_root());
        }
        if !tap && !has_access() {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                "cannot open /dev/net/tun; pass a VpnService TUN fd with --tun-fd, or run as root"
            ));
        }
        let path = device_path.unwrap_or("/dev/net/tun");
        let c_path = CString::new(path).map_err(|_| Error::new(ErrorKind::InvalidInput, "device path"))?;
        let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            let err = Error::last_os_error();
            if tap {
                return Err(Error::new(err.kind(), format!("{} ({})", ANDROID_TAP_HELP, err)));
            }
            return Err(err);
        }
        let mut req: libc::ifreq = unsafe { mem::zeroed() };
        let flags = (if tap { IFF_TAP } else { IFF_TUN }) | IFF_NO_PI;
        req.ifr_ifru.ifru_flags = flags;
        let want = if ifname.is_empty() || ifname.contains('%') { String::new() } else { ifname.to_string() };
        if !want.is_empty() {
            let bytes = want.as_bytes();
            let n = bytes.len().min(IFNAMSIZ - 1);
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const libc::c_char, req.ifr_name.as_mut_ptr(), n);
            }
        }
        let rc = unsafe { libc::ioctl(fd, TUNSETIFF as _, &mut req as *mut _) };
        if rc < 0 {
            let err = Error::last_os_error();
            unsafe { libc::close(fd) };
            if tap {
                return Err(Error::new(err.kind(), format!("TAP ioctl failed: {} ({})", err, ANDROID_TAP_HELP)));
            }
            return Err(err);
        }
        let actual = unsafe { std::ffi::CStr::from_ptr(req.ifr_name.as_ptr()) }.to_string_lossy().into_owned();
        if tap {
            let mut mac = rand::random::<[u8; 6]>();
            mac[0] = (mac[0] & 0xfe) | 0x02;
            let _ = set_mac(&actual, mac);
        }
        let device = unsafe { SyncDevice::from_fd(fd as RawFd) }?;
        device.set_nonblocking(true)?;
        Ok((device, actual))
    }

    fn set_mac(ifname: &str, mac: [u8; 6]) -> io::Result<()> {
        // SIOCSIFHWADDR
        const SIOCSIFHWADDR: libc::c_ulong = 0x8924;
        const ARPHRD_ETHER: libc::c_ushort = 1;
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if sock < 0 {
            return Err(Error::last_os_error());
        }
        let mut req: libc::ifreq = unsafe { mem::zeroed() };
        let bytes = ifname.as_bytes();
        let n = bytes.len().min(IFNAMSIZ - 1);
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const libc::c_char, req.ifr_name.as_mut_ptr(), n);
            req.ifr_ifru.ifru_hwaddr.sa_family = ARPHRD_ETHER;
            std::ptr::copy_nonoverlapping(mac.as_ptr(), req.ifr_ifru.ifru_hwaddr.sa_data.as_mut_ptr() as *mut u8, 6);
        }
        let rc = unsafe { libc::ioctl(sock, SIOCSIFHWADDR as _, &mut req as *mut _) };
        unsafe { libc::close(sock) };
        if rc < 0 {
            Err(Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub fn run_ip(args: &[&str]) -> io::Result<()> {
        let joined = args.join(" ");
        let try_ip = Command::new("ip").args(args).status();
        match try_ip {
            Ok(s) if s.success() => return Ok(()),
            _ => {}
        }
        let status = Command::new("su").args(["-c", &format!("ip {}", joined)]).status();
        match status {
            Ok(s) if s.success() => Ok(()),
            Ok(s) => Err(Error::new(ErrorKind::Other, format!("ip {} failed: {:?}", joined, s.code()))),
            Err(e) => Err(e)
        }
    }
}

impl TunTapDevice {
    /// Adopt a TUN file descriptor from Android `VpnService` or iOS Packet Tunnel.
    ///
    /// The fd is owned by this device afterwards. TAP cannot come from those APIs.
    #[cfg(unix)]
    pub fn from_tun_fd(fd: i32, type_: Type) -> io::Result<Self> {
        if type_ == Type::Tap {
            #[cfg(target_os = "ios")]
            {
                return Err(io::Error::new(io::ErrorKind::Unsupported, IOS_TAP_HELP));
            }
            #[cfg(not(target_os = "ios"))]
            {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "TAP cannot use a TUN file descriptor (VpnService / Packet Tunnel are TUN-only). See --help."
                ));
            }
        }
        let device = unsafe { SyncDevice::from_fd(fd) }?;
        device.set_nonblocking(true)?;
        Ok(Self {
            device: std::sync::Arc::new(device),
            ifname: format!("tun{}", fd),
            type_,
            #[cfg(windows)]
            incoming: std::sync::Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new())),
            #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
            tun_offload: false,
            #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
            tun_scratch: Vec::new(),
            #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
            tun_batch: Vec::new(),
            #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
            tun_sizes: Vec::new(),
            #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
            gro_table: GROTable::default()
        })
    }

    #[cfg(not(unix))]
    pub fn from_tun_fd(_fd: i32, _type_: Type) -> io::Result<Self> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "TUN file descriptors are only supported on Unix"))
    }

    // Keep the third parameter for compatibility with callers that pass an optional device path.
    // Linux uses it for `/dev/net/tun`; tun-rs manages that itself, so the path is ignored.
    pub fn new(ifname: &str, type_: Type, _device_path: Option<&str>) -> io::Result<Self> {
        #[cfg(target_os = "android")]
        {
            if type_ == Type::Tap && !android_tun::has_access() {
                return Err(android_tap_needs_root());
            }
            let (device, actual) = android_tun::create(ifname, type_ == Type::Tap, _device_path)?;
            return Ok(Self {
                device: std::sync::Arc::new(device),
                ifname: actual,
                type_,
                #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
                tun_offload: false,
                #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
                tun_scratch: Vec::new(),
                #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
                tun_batch: Vec::new(),
                #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
                tun_sizes: Vec::new(),
                #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
                gro_table: GROTable::default()
            });
        }
        #[cfg(target_os = "ios")]
        {
            let _ = (ifname, _device_path);
            if type_ == Type::Tap {
                return Err(io::Error::new(io::ErrorKind::Unsupported, IOS_TAP_HELP));
            }
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "On iOS, TUN must come from a Packet Tunnel Provider (--tun-fd). Direct utun creation is not allowed."
            ));
        }
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            let mut builder = DeviceBuilder::new();

            if let Some(name) = platform_device_name(ifname, type_) {
                builder = builder.name(name);
            }

            match type_ {
                Type::Tun => {
                    builder = builder.layer(Layer::L3);
                    #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
                    {
                        builder = builder.offload(true);
                    }
                }
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
                incoming: std::sync::Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new())),
                #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
                tun_offload: type_ == Type::Tun,
                #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
                tun_scratch: if type_ == Type::Tun { vec![0u8; VIRTIO_NET_HDR_LEN + 65535] } else { Vec::new() },
                #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
                tun_batch: if type_ == Type::Tun { vec![vec![0u8; 2048]; 64] } else { Vec::new() },
                #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
                tun_sizes: if type_ == Type::Tun { vec![0usize; 64] } else { Vec::new() },
                #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
                gro_table: GROTable::default()
            })
        }
    }

    // Set MTU (delegates to tun device).
    pub fn set_mtu(&mut self, value: Option<usize>) -> io::Result<()> {
        let value = match value {
            Some(value) => value,
            None => {
                #[cfg(any(target_os = "android", target_os = "ios"))]
                {
                    1400
                }
                #[cfg(not(any(target_os = "android", target_os = "ios")))]
                {
                    // Leave headroom for VpnCloud encapsulation on top of the kernel MTU.
                    self.device.mtu().map(|m| (m as usize).saturating_sub(100).max(576)).unwrap_or(1400)
                }
            }
        };

        info!("Setting MTU {} on device {}", value, self.ifname);
        #[cfg(target_os = "android")]
        {
            android_tun::run_ip(&["link", "set", "dev", &self.ifname, "mtu", &value.to_string()])
        }
        #[cfg(target_os = "ios")]
        {
            // Packet Tunnel Provider sets MTU via NEPacketTunnelNetworkSettings.
            Ok(())
        }
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            self.device
                .set_mtu(value as u16)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to set mtu: {}", e)))
        }
    }

    pub fn configure(&mut self, addr: Ipv4Addr, netmask: Ipv4Addr) -> io::Result<()> {
        self.configure_ip(IpAddr::V4(addr), Some(netmask), None)
    }

    pub fn configure_ip(&mut self, addr: IpAddr, netmask: Option<Ipv4Addr>, prefix_len: Option<u8>) -> io::Result<()> {
        #[cfg(target_os = "android")]
        {
            android_tun::run_ip(&["link", "set", "dev", &self.ifname, "up"])?;
            match addr {
                IpAddr::V4(ip) => {
                    let prefix = prefix_len.unwrap_or_else(|| {
                        netmask.map(|m| m.octets().iter().fold(0u8, |a, b| a + b.count_ones() as u8)).unwrap_or(24)
                    });
                    android_tun::run_ip(&["addr", "add", &format!("{}/{}", ip, prefix), "dev", &self.ifname])
                }
                IpAddr::V6(ip) => {
                    let prefix = prefix_len.unwrap_or(64);
                    android_tun::run_ip(&["addr", "add", &format!("{}/{}", ip, prefix), "dev", &self.ifname])
                }
            }
        }
        #[cfg(target_os = "ios")]
        {
            let _ = (addr, netmask, prefix_len);
            Ok(())
        }
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            self.device
                .enabled(true)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Enable failed: {}", e)))?;
            match addr {
                IpAddr::V4(ip) => {
                    let netmask =
                        netmask.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "IPv4 netmask required"))?;
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
        #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
        if self.tun_offload && self.type_ == Type::Tun {
            let msg = data.message();
            let mut pkt = vec![0u8; VIRTIO_NET_HDR_LEN + msg.len()];
            pkt[VIRTIO_NET_HDR_LEN..].copy_from_slice(msg);
            match self.device.send_multiple(&mut self.gro_table, std::slice::from_mut(&mut pkt), VIRTIO_NET_HDR_LEN) {
                Ok(_) => return Ok(()),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    return Err(Error::DeviceIo("IO error when sending to device", e));
                }
                Err(_) => {}
            }
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

    #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
    fn read_batch(&mut self, bufs: &mut [crate::util::MsgBuffer]) -> Result<usize, Error> {
        if !self.tun_offload || bufs.is_empty() {
            let mut n = 0;
            for b in bufs.iter_mut() {
                match self.read_msg(b) {
                    Ok(()) => n += 1,
                    Err(Error::DeviceIo(_, ref e)) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(_) if n > 0 => break,
                    Err(e) => return Err(e)
                }
            }
            return Ok(n);
        }
        let nbufs = bufs.len().min(self.tun_batch.len());
        match self.device.recv_multiple(
            &mut self.tun_scratch,
            &mut self.tun_batch[..nbufs],
            &mut self.tun_sizes[..nbufs],
            0
        ) {
            Ok(n) => {
                for i in 0..n {
                    bufs[i].clear();
                    bufs[i].clone_from(&self.tun_batch[i][..self.tun_sizes[i]]);
                    crate::payload::fix_ipv4_checksums(bufs[i].message_mut());
                }
                Ok(n)
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::Interrupted => Ok(0),
            Err(e) => Err(Error::DeviceIo("IO error when reading from device", e))
        }
    }

    #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
    fn write_batch(&mut self, bufs: &mut [crate::util::MsgBuffer]) -> Result<usize, Error> {
        if bufs.is_empty() {
            return Ok(0);
        }
        if !self.tun_offload || self.type_ != Type::Tun {
            for b in bufs.iter_mut() {
                self.write_msg(b)?;
            }
            return Ok(bufs.len());
        }
        while self.tun_batch.len() < bufs.len() {
            self.tun_batch.push(vec![0u8; VIRTIO_NET_HDR_LEN + 2048]);
        }
        for (i, b) in bufs.iter_mut().enumerate() {
            crate::payload::fix_ipv4_checksums(b.message_mut());
            let msg = b.message();
            let need = VIRTIO_NET_HDR_LEN + msg.len();
            self.tun_batch[i].clear();
            self.tun_batch[i].resize(need, 0);
            self.tun_batch[i][VIRTIO_NET_HDR_LEN..].copy_from_slice(msg);
        }
        match self.device.send_multiple(&mut self.gro_table, &mut self.tun_batch[..bufs.len()], VIRTIO_NET_HDR_LEN) {
            Ok(_) => Ok(bufs.len()),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                Err(Error::DeviceIo("IO error when sending to device", e))
            }
            Err(_) => {
                for b in bufs.iter_mut() {
                    let slice = b.message();
                    match self.device.send(slice) {
                        Ok(written) if written == slice.len() => {}
                        Ok(_) => return Err(Error::Socket("Sent out truncated packet")),
                        Err(io_err) => return Err(Error::DeviceIo("IO error when sending to device", io_err))
                    }
                }
                Ok(bufs.len())
            }
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
        std::os::windows::io::AsRawHandle::as_raw_handle(&self.fd)
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
        #[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd", target_os = "dragonfly"))]
        assert_eq!(name, None);
        #[cfg(not(any(
            target_os = "macos",
            target_os = "windows",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly"
        )))]
        assert_eq!(name.as_deref(), Some("vpncloud%d"));
    }

    #[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd", target_os = "dragonfly"))]
    #[test]
    fn platform_name_bsd_uses_tun_tap_units() {
        assert_eq!(platform_device_name("tun0", Type::Tun).as_deref(), Some("tun0"));
        assert_eq!(platform_device_name("tap1", Type::Tap).as_deref(), Some("tap1"));
        assert_eq!(platform_device_name("feth0", Type::Tap), None);
    }

    #[test]
    fn platform_name_explicit_utun() {
        let name = platform_device_name("utun8", Type::Tun);
        assert_eq!(name.as_deref(), Some("utun8"));
    }

    #[test]
    fn android_tap_error_tells_user_to_use_root_and_help() {
        let err = android_tap_needs_root();
        let msg = err.to_string();
        assert!(msg.contains("rooted"), "{}", msg);
        assert!(msg.contains("--help"), "{}", msg);
        assert!(msg.contains("TUN") || msg.contains("tun"), "{}", msg);
    }

    #[test]
    fn ios_tap_error_says_unavailable() {
        let msg = IOS_TAP_HELP;
        assert!(msg.contains("iOS"), "{}", msg);
        assert!(msg.contains("TAP") || msg.contains("tap"), "{}", msg);
        assert!(msg.contains("TUN") || msg.contains("tun") || msg.contains("Packet Tunnel"), "{}", msg);
        assert!(msg.contains("--help"), "{}", msg);
    }

    #[cfg(unix)]
    #[test]
    fn from_tun_fd_rejects_tap_without_touching_fd() {
        let err = match TunTapDevice::from_tun_fd(-1, Type::Tap) {
            Err(e) => e,
            Ok(_) => panic!("TAP fd adopt must fail")
        };
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    #[ignore]
    fn opens_tun_device() {
        let mut dev = TunTapDevice::new("vpncloud%d", Type::Tun, None).expect("open tun");
        #[cfg(target_os = "macos")]
        assert!(dev.ifname().starts_with("utun"), "unexpected ifname {}", dev.ifname());
        #[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd", target_os = "dragonfly"))]
        assert!(dev.ifname().starts_with("tun"), "unexpected ifname {}", dev.ifname());
        dev.set_mtu(None).expect("set mtu");
        dev.configure(Ipv4Addr::new(10, 250, 0, 1), Ipv4Addr::new(255, 255, 255, 0)).expect("configure");
        assert_eq!(dev.address().unwrap(), Ipv4Addr::new(10, 250, 0, 1));
    }
}
