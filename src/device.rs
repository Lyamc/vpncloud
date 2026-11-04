// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021 Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::{
    cmp,
    collections::VecDeque,
    fmt,
    io::{self},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
    sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering}
};

#[cfg(target_os = "android")]
use std::process::Command;

#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
use std::cell::{Cell, RefCell};
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};


use getifaddrs::getifaddrs;
use log::info;
use serde::{Deserialize, Serialize};
use tun_rs::SyncDevice;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use tun_rs::{DeviceBuilder, Layer};
#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
use tun_rs::{ExpandBuffer, GROTable, VIRTIO_NET_HDR_LEN};

use crate::{error::Error, gso::GsoMeta};

/// What [`Device::read_offload`] produced.
pub enum OffloadRead {
    /// This device has no GSO reader. Use [`Device::read_batch`].
    Unsupported,
    /// No packet is waiting.
    Blocked,
    /// One IP packet is in the buffer.
    ///
    /// `Some((csum_start, csum_offset))` means the virtio header had `NEEDS_CSUM`
    /// and the L4 checksum field is still the partial sum. `None` means the
    /// packet is already safe to forward.
    Plain(Option<(u16, u16)>),
    /// One GSO/USO aggregate is in the buffer (IP bytes only; metadata alongside).
    Gso(GsoMeta)
}

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

/// Which host `platform_device_name` is naming a TUN/TAP device for.
///
/// Linux release builds only construct `Other`. The other variants are the
/// rules `TunTapDevice::new` uses on those hosts, and the lib test constructs them.
#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum HostOs {
    Macos,
    Bsd,
    Windows,
    Other
}

fn current_host_os() -> HostOs {
    #[cfg(target_os = "macos")]
    {
        HostOs::Macos
    }
    #[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd", target_os = "dragonfly"))]
    {
        HostOs::Bsd
    }
    #[cfg(target_os = "windows")]
    {
        HostOs::Windows
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
        HostOs::Other
    }
}

/// Pick a tun-rs interface name for the current OS.
///
/// Linux accepts `vpncloud%d` (kernel fills in the number). macOS TUN devices are always
/// `utunN`; TAP uses `feth` pairs. FreeBSD/other BSD TUN/TAP units are `tunN` / `tapN`;
/// Linux-style names are ignored there so the OS can clone a free unit.
#[cfg_attr(target_os = "ios", allow(dead_code))]
fn platform_device_name(ifname: &str, type_: Type) -> Option<String> {
    platform_device_name_for(current_host_os(), ifname, type_)
}

fn platform_device_name_for(host: HostOs, ifname: &str, type_: Type) -> Option<String> {
    if ifname.is_empty() {
        return None;
    }
    match host {
        HostOs::Macos => {
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
        HostOs::Bsd => {
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
        HostOs::Windows => {
            let _ = type_;
            // wintun / tap-windows6 adapter names cannot contain `%d`.
            let name = ifname.replace("%d", "0");
            if name.is_empty() { None } else { Some(name) }
        }
        HostOs::Other => {
            let _ = type_;
            Some(ifname.to_string())
        }
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

    /// Read one TUN packet, keeping a GSO aggregate intact when it fits in `buf`.
    fn read_offload(&mut self, _buf: &mut crate::util::MsgBuffer) -> Result<OffloadRead, Error> {
        Ok(OffloadRead::Unsupported)
    }

    /// Write one GSO aggregate. `data` is the unmodified IP super-packet.
    fn write_offload(&mut self, data: &mut crate::util::MsgBuffer, _meta: &GsoMeta) -> Result<(), Error> {
        self.write_msg(data)
    }

    /// Largest inner IP super-packet that fits in one outer datagram.
    ///
    /// The default is a 1500-byte IPv4 underlay. Devices that probed a path
    /// override this. Callers must not substitute 60KB: that size only fits
    /// when the underlay reassembles IP fragments.
    fn max_gso_payload(&self) -> usize {
        crate::mtu::max_gso(1500, crate::mtu::Underlay::V4)
    }

    /// Largest single inner packet (IP packet, or a TAP frame's payload MTU
    /// is separate). Default matches a 1500-byte IPv4 underlay.
    fn max_plain_payload(&self) -> usize {
        crate::mtu::max_plain(1500, crate::mtu::Underlay::V4)
    }

    /// Pull the next TUN batch on a side thread. The caller must not read the
    /// TUN until [`join_tun_prefetch`]. Default devices have nothing to prefetch.
    fn kick_tun_prefetch(&mut self) {}

    /// Block until the side read has stopped, so the caller's next read is the
    /// only reader of the TUN.
    fn join_tun_prefetch(&mut self) {}

    /// `true` when a side read already took packets the caller has not parsed.
    fn tun_prefetch_pending(&self) -> bool {
        false
    }

    /// Apply [`crate::mtu::path_fit`] for `l2_mtu`. The default keeps tests
    /// that never learn a path on the 1500-byte IPv4 cap.
    fn set_path_budget(&mut self, requested: Option<usize>, l2_mtu: usize, ipv6: bool) -> Result<(), Error> {
        let _ = (requested, l2_mtu, ipv6);
        Ok(())
    }
}

/// Packets one side read may pull off the TUN while the datapath thread is
/// in the UDP socket. Matches the device-handler batch cap so the next turn
/// does not fall back to a per-packet `read`.
#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
const TUN_PREFETCH_BATCH: usize = 64;
#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
const TUN_PREFETCH_BYTES: usize = 16384;

#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
struct PrefetchRun {
    want: bool,
    running: bool
}

/// Owns a `dup` of the TUN fd. Only this thread reads that dup, and only
/// while the datapath thread has promised not to read the original.
#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
struct TunPrefetch {
    fd: std::sync::atomic::AtomicI32,
    queue: std::sync::Mutex<VecDeque<Vec<u8>>>,
    state: std::sync::Mutex<PrefetchRun>,
    kick: std::sync::Condvar,
    stop: AtomicBool,
    thread: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>
}

#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
impl TunPrefetch {
    fn start(tun_fd: RawFd) -> Option<std::sync::Arc<Self>> {
        let fd = unsafe { libc::dup(tun_fd) };
        if fd < 0 {
            return None;
        }
        let prefetch = std::sync::Arc::new(Self {
            fd: std::sync::atomic::AtomicI32::new(fd),
            queue: std::sync::Mutex::new(VecDeque::new()),
            state: std::sync::Mutex::new(PrefetchRun { want: false, running: false }),
            kick: std::sync::Condvar::new(),
            stop: AtomicBool::new(false),
            thread: std::sync::Mutex::new(None)
        });
        let worker = std::sync::Arc::clone(&prefetch);
        let handle = match std::thread::Builder::new().name("tun-prefetch".to_string()).spawn(move || worker.run()) {
            Ok(handle) => handle,
            Err(_) => {
                let fd = prefetch.fd.swap(-1, Ordering::AcqRel);
                if fd >= 0 {
                    unsafe { libc::close(fd) };
                }
                return None;
            }
        };
        if let Ok(mut slot) = prefetch.thread.lock() {
            *slot = Some(handle);
        }
        Some(prefetch)
    }

    fn run(self: std::sync::Arc<Self>) {
        crate::cloud::pin_reader_thread();
        loop {
            if self.stop.load(Ordering::Acquire) {
                break;
            }
            let mut state = match self.state.lock() {
                Ok(state) => state,
                Err(poisoned) => poisoned.into_inner()
            };
            while !state.want && !self.stop.load(Ordering::Acquire) {
                state = match self.kick.wait(state) {
                    Ok(state) => state,
                    Err(poisoned) => poisoned.into_inner()
                };
            }
            if self.stop.load(Ordering::Acquire) {
                break;
            }
            state.want = false;
            state.running = true;
            drop(state);

            let fd = self.fd.load(Ordering::Acquire);
            let mut batch = Vec::new();
            if fd >= 0 {
                while batch.len() < TUN_PREFETCH_BATCH && !self.stop.load(Ordering::Acquire) {
                    let mut buf = vec![0u8; TUN_PREFETCH_BYTES];
                    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                    if n > 0 {
                        buf.truncate(n as usize);
                        batch.push(buf);
                        continue;
                    }
                    if n < 0 {
                        let err = io::Error::last_os_error();
                        if err.kind() == io::ErrorKind::Interrupted {
                            continue;
                        }
                    }
                    break;
                }
            }
            if !batch.is_empty() {
                let mut queue = match self.queue.lock() {
                    Ok(queue) => queue,
                    Err(poisoned) => poisoned.into_inner()
                };
                queue.extend(batch);
            }
            let mut state = match self.state.lock() {
                Ok(state) => state,
                Err(poisoned) => poisoned.into_inner()
            };
            state.running = false;
            self.kick.notify_all();
        }
    }

    fn kick(&self) {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner()
        };
        if state.running || state.want || self.stop.load(Ordering::Acquire) {
            return;
        }
        state.want = true;
        self.kick.notify_one();
    }

    fn join(&self) {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner()
        };
        while state.running || state.want {
            state = match self.kick.wait(state) {
                Ok(state) => state,
                Err(poisoned) => poisoned.into_inner()
            };
            if self.stop.load(Ordering::Acquire) && !state.running {
                break;
            }
        }
    }

    fn pending(&self) -> bool {
        self.queue.lock().map(|queue| !queue.is_empty()).unwrap_or(false)
    }

    fn pop(&self) -> Option<Vec<u8>> {
        self.queue.lock().ok().and_then(|mut queue| queue.pop_front())
    }

    fn shutdown(&self) {
        self.stop.store(true, Ordering::Release);
        self.kick.notify_all();
        if let Some(handle) = self.thread.lock().ok().and_then(|mut slot| slot.take()) {
            let _ = handle.join();
        }
        let fd = self.fd.swap(-1, Ordering::AcqRel);
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
    }
}

pub struct TunTapDevice {
    device: std::sync::Arc<SyncDevice>,
    ifname: String,
    type_: Type,
    /// Largest inner IP super-packet that fits in one outer datagram.
    max_gso: usize,
    /// Largest single inner packet that fits in one outer datagram.
    max_plain: usize,
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
    gro_table: GROTable,
    /// Segments produced by splitting one aggregate that did not fit in a UDP datagram.
    #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
    split_len: usize,
    #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
    split_pos: usize,
    /// TUN reads overlapped with UDP-socket work. `None` until the first kick.
    #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
    prefetch: Option<std::sync::Arc<TunPrefetch>>
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
            max_gso: crate::mtu::max_gso(1500, crate::mtu::Underlay::V4),
            max_plain: crate::mtu::max_plain(1500, crate::mtu::Underlay::V4),
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
            gro_table: GROTable::default(),
            #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
            split_len: 0,
            #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
            split_pos: 0,
            #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
            prefetch: None
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
                max_gso: crate::mtu::max_gso(1500, crate::mtu::Underlay::V4),
                max_plain: crate::mtu::max_plain(1500, crate::mtu::Underlay::V4),
                #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
                tun_offload: false,
                #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
                tun_scratch: Vec::new(),
                #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
                tun_batch: Vec::new(),
                #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
                tun_sizes: Vec::new(),
                #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
                gro_table: GROTable::default(),
                #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
                split_len: 0,
                #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
                split_pos: 0,
                #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
                prefetch: None
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
            // The default ring is 500 packets. A scheduling stall then drops
            // datagrams after the qdisc has already counted them as sent.
            #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
            widen_tx_queue(&actual_ifname);

            Ok(Self {
                device: std::sync::Arc::new(device),
                ifname: actual_ifname,
                type_,
                max_gso: crate::mtu::max_gso(1500, crate::mtu::Underlay::V4),
                max_plain: crate::mtu::max_plain(1500, crate::mtu::Underlay::V4),
                #[cfg(windows)]
                incoming: std::sync::Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new())),
                #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
                tun_offload: type_ == Type::Tun,
                #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
                tun_scratch: if type_ == Type::Tun { vec![0u8; VIRTIO_NET_HDR_LEN + 65535] } else { Vec::new() },
                #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
                tun_batch: if type_ == Type::Tun { vec![vec![0u8; 2048]; 128] } else { Vec::new() },
                #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
                tun_sizes: if type_ == Type::Tun { vec![0usize; 128] } else { Vec::new() },
                #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
                gro_table: GROTable::default(),
                #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
                split_len: 0,
                #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
                split_pos: 0,
                #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
                prefetch: None
            })
        }
    }

    /// Set the tunnel MTU. `None` sizes it for a 1500-byte IPv4 underlay.
    pub fn set_mtu(&mut self, value: Option<usize>) -> io::Result<()> {
        self.set_mtu_capped(value, 1500, false)
    }

    /// Size the tunnel so one inner packet fits in one outer datagram.
    ///
    /// `l2_mtu` is the underlay interface MTU (maximum IP packet). `ipv6`
    /// selects the IPv6 header budget. Callers pass true when the underlay
    /// may be IPv6. A requested MTU above that budget is lowered. It is
    /// never raised to 576 or 1280 when that would exceed the path.
    pub fn set_mtu_capped(&mut self, requested: Option<usize>, l2_mtu: usize, ipv6: bool) -> io::Result<()> {
        let l2 = if l2_mtu == 0 { 1500 } else { l2_mtu };
        let sized = crate::mtu::path_fit(l2, None, ipv6, self.type_ == Type::Tap, requested);
        if let Some(req) = requested {
            if req > sized.device_mtu {
                info!(
                    "MTU {} is larger than the underlay allows ({}); using {}",
                    req, sized.device_mtu, sized.device_mtu
                );
            }
        }
        let value = sized.device_mtu;
        // GSO adds a 10-byte prefix, so the super-packet is slightly smaller
        // than a plain packet. Never raise this to the old 60000 cap: that
        // only fits when the underlay reassembles IP fragments.
        self.max_gso = sized.max_gso;
        self.max_plain = value;

        info!("Setting MTU {} on device {} (underlay {}, gso {})", value, self.ifname, sized.l2_mtu, self.max_gso);
        // TCP GSO is still one AEAD message per aggregate, but the aggregate
        // has to fit in a single underlay frame. iperf UDP datagrams are not
        // merged by TUN_F_USO; userspace coalesce uses the same cap.
        #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
        if self.tun_offload {
            let offloads = libc::TUN_F_CSUM
                | libc::TUN_F_TSO4
                | libc::TUN_F_TSO6
                | libc::TUN_F_TSO_ECN
                | libc::TUN_F_USO4
                | libc::TUN_F_USO6;
            let rc = unsafe { libc::ioctl(self.as_raw_fd(), libc::TUNSETOFFLOAD, offloads) };
            if rc == 0 {
                info!("TUN offload includes UDP segmentation");
            } else {
                let err = io::Error::last_os_error();
                info!("UDP segmentation offload unavailable ({}), TCP GSO only", err);
            }
            let gso = self.max_gso.to_string();
            for key in ["gso_max_size", "gso_ipv4_max_size"] {
                let status =
                    std::process::Command::new("ip").args(["link", "set", "dev", &self.ifname, key, &gso]).status();
                match status {
                    Ok(s) if s.success() => info!("Set {} {} on {}", key, gso, self.ifname),
                    Ok(s) => info!("Could not set {} on {} ({})", key, self.ifname, s),
                    Err(e) => info!("Could not set {} on {}: {}", key, self.ifname, e)
                }
            }
        }
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

    #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
    fn write_batch_copy(&mut self, bufs: &mut [crate::util::MsgBuffer]) -> Result<usize, Error> {
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

    #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
    fn write_tcp_train(&mut self, bufs: &mut [crate::util::MsgBuffer]) -> Result<usize, Error> {
        for b in bufs.iter_mut() {
            crate::payload::fix_ipv4_checksums(b.message_mut());
            b.prepend_zero(VIRTIO_NET_HDR_LEN);
        }
        let nbufs = bufs.len();
        let mut wraps: Vec<MsgVirtio<'_>> = bufs.iter_mut().map(MsgVirtio).collect();
        let mut last_block = io::Error::new(io::ErrorKind::WouldBlock, "tun tx queue full");
        for attempt in 0..3 {
            match self.device.send_multiple(&mut self.gro_table, &mut wraps, VIRTIO_NET_HDR_LEN) {
                Ok(_) => {
                    drop(wraps);
                    note_gro_batch(bufs);
                    return Ok(nbufs);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    last_block = e;
                    if attempt == 2 || !tun_tx_ready(self.as_raw_fd()) {
                        break;
                    }
                }
                Err(_) => {
                    drop(wraps);
                    for b in bufs.iter_mut() {
                        b.skip(VIRTIO_NET_HDR_LEN);
                    }
                    for b in bufs.iter_mut() {
                        let slice = b.message();
                        match self.device.send(slice) {
                            Ok(written) if written == slice.len() => {}
                            Ok(_) => return Err(Error::Socket("Sent out truncated packet")),
                            Err(io_err) => return Err(Error::DeviceIo("IO error when sending to device", io_err))
                        }
                    }
                    return Ok(bufs.len());
                }
            }
        }
        drop(wraps);
        for b in bufs.iter_mut() {
            b.skip(VIRTIO_NET_HDR_LEN);
        }
        Err(Error::DeviceIo("IO error when sending to device", last_block))
    }

    /// Write each datagram as its own packet. `sendmmsg` is one syscall for
    /// the batch; a failure falls back to one write per packet.
    #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
    fn write_datagrams(&mut self, bufs: &mut [crate::util::MsgBuffer]) -> Result<usize, Error> {
        if bufs.is_empty() {
            return Ok(0);
        }
        // One chunk per call. The event loop holds the airtime gap and reads
        // one matching underlay batch before the next chunk. Sleeping in here
        // left that socket unread. Writing the whole queue overflowed iperf.
        let bufs = if bufs.len() > UDP_INJECT_CHUNK { &mut bufs[..UDP_INJECT_CHUNK] } else { bufs };
        let offload = self.tun_offload && self.type_ == Type::Tun;
        for b in bufs.iter_mut() {
            match self.type_ {
                Type::Tap => crate::payload::fix_ethernet_ipv4_checksums(b.message_mut()),
                Type::Tun => crate::payload::fix_ipv4_checksums(b.message_mut())
            }
            if offload {
                b.prepend_zero(VIRTIO_NET_HDR_LEN);
            }
        }
        let fd = self.as_raw_fd();
        let sent = tun_sendmmsg(fd, bufs);
        let unsent_from = match sent {
            Ok(n) => n,
            Err(_) => 0
        };
        if offload {
            for b in bufs.iter_mut().skip(unsent_from) {
                b.skip(VIRTIO_NET_HDR_LEN);
            }
        }
        match sent {
            Ok(0) => Err(Error::DeviceIo(
                "IO error when sending to device",
                io::Error::new(io::ErrorKind::WouldBlock, "tun tx queue full")
            )),
            Ok(n) => Ok(n),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::Interrupted => {
                Err(Error::DeviceIo("IO error when sending to device", e))
            }
            Err(_) => {
                let mut wrote = 0usize;
                for b in bufs.iter_mut() {
                    match self.write_one_datagram(b) {
                        Ok(()) => {
                            wrote += 1;
                        }
                        Err(Error::DeviceIo(_, ref err))
                            if wrote > 0 && err.kind() == io::ErrorKind::WouldBlock =>
                        {
                            return Ok(wrote);
                        }
                        Err(err) => return Err(err)
                    }
                }
                Ok(wrote)
            }
        }
    }

    /// One packet, one write, no userspace coalesce. Used when `sendmmsg` is
    /// unavailable so a batch cannot become a single USO aggregate.
    #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
    fn write_one_datagram(&mut self, data: &mut crate::util::MsgBuffer) -> Result<(), Error> {
        match self.type_ {
            Type::Tap => crate::payload::fix_ethernet_ipv4_checksums(data.message_mut()),
            Type::Tun => crate::payload::fix_ipv4_checksums(data.message_mut())
        }
        if self.tun_offload && self.type_ == Type::Tun && data.get_start() >= VIRTIO_NET_HDR_LEN {
            let old = data.get_start();
            data.prepend_zero(VIRTIO_NET_HDR_LEN);
            let expect = data.len();
            let sent = self.device.send(data.message());
            data.set_start(old);
            return match sent {
                Ok(n) if n == expect => Ok(()),
                Ok(_) => Err(Error::Socket("Sent out truncated packet")),
                Err(io_err) => Err(Error::DeviceIo("IO error when sending to device", io_err))
            };
        }
        let slice = data.message();
        match self.device.send(slice) {
            Ok(written) if written == slice.len() => Ok(()),
            Ok(_) => Err(Error::Socket("Sent out truncated packet")),
            Err(io_err) => Err(Error::DeviceIo("IO error when sending to device", io_err))
        }
    }

    // NOTE: MsgBuffer-aware helpers are implemented as trait methods (see `impl Device for TunTapDevice`)
    // to avoid ambiguity with the std::io::Read/Write trait methods and to make them available
    // through the `Device` trait object / type parameter.
    // Inherent aliases were removed to prevent duplicate method resolution.
}

#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
impl TunTapDevice {
    /// Take one virtio frame the side thread already read. `None` means the
    /// queue is empty and the caller should read the TUN itself.
    fn copy_prefetch(&mut self, buf: &mut crate::util::MsgBuffer) -> Option<usize> {
        let raw = self.prefetch.as_ref().and_then(|prefetch| prefetch.pop())?;
        buf.clear();
        let n = raw.len();
        {
            let dst = buf.buffer();
            if n <= VIRTIO_NET_HDR_LEN || n > dst.len() {
                return Some(0);
            }
            dst[..n].copy_from_slice(&raw);
        }
        buf.set_length(n);
        Some(n)
    }
}

impl Device for TunTapDevice {
    fn get_type(&self) -> Type {
        self.type_
    }

    fn ifname(&self) -> &str {
        &self.ifname
    }

    fn max_gso_payload(&self) -> usize {
        self.max_gso
    }

    fn max_plain_payload(&self) -> usize {
        self.max_plain
    }

    fn set_path_budget(&mut self, requested: Option<usize>, l2_mtu: usize, ipv6: bool) -> Result<(), Error> {
        self.set_mtu_capped(requested, l2_mtu, ipv6).map_err(|e| Error::DeviceIo("setting path mtu", e))
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
        if self.tun_offload && self.type_ == Type::Tun && data.get_start() >= VIRTIO_NET_HDR_LEN {
            let old = data.get_start();
            data.prepend_zero(VIRTIO_NET_HDR_LEN);
            let send = {
                let mut wrap = MsgVirtio(data);
                self.device.send_multiple(&mut self.gro_table, std::slice::from_mut(&mut wrap), VIRTIO_NET_HDR_LEN)
            };
            data.set_start(old);
            match send {
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
        // One TCP header per flow, so a segment train can merge.
        crate::payload::share_tcp_timestamps_for_gro(bufs);
        if !self.tun_offload || self.type_ != Type::Tun {
            for b in bufs.iter_mut() {
                self.write_msg(b)?;
            }
            return Ok(bufs.len());
        }
        // UDP GRO of a multi-packet batch stalled the tunnel. One datagram
        // per message keeps each UDP payload intact, and one sendmmsg keeps
        // the reader from falling behind a flood of writes.
        let tcp_train = bufs.iter().all(|b| crate::payload::ipv4_tcp_segment(b.message()));
        if !tcp_train {
            return self.write_datagrams(bufs);
        }
        if bufs.iter().any(|b| b.get_start() < VIRTIO_NET_HDR_LEN) {
            return self.write_batch_copy(bufs);
        }
        self.write_tcp_train(bufs)
    }

    fn kick_tun_prefetch(&mut self) {
        #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
        if self.tun_offload {
            if self.prefetch.is_none() {
                self.prefetch = TunPrefetch::start(self.as_raw_fd());
            }
            if let Some(prefetch) = &self.prefetch {
                prefetch.kick();
            }
        }
    }

    fn join_tun_prefetch(&mut self) {
        #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
        if let Some(prefetch) = &self.prefetch {
            prefetch.join();
        }
    }

    fn tun_prefetch_pending(&self) -> bool {
        #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
        {
            return self.prefetch.as_ref().is_some_and(|prefetch| prefetch.pending());
        }
        #[cfg(not(all(target_os = "linux", not(target_env = "ohos"))))]
        false
    }

    #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
    fn read_offload(&mut self, buf: &mut crate::util::MsgBuffer) -> Result<OffloadRead, Error> {
        if !self.tun_offload {
            return Ok(OffloadRead::Unsupported);
        }
        if self.split_pos < self.split_len {
            let i = self.split_pos;
            self.split_pos += 1;
            let n = self.tun_sizes[i];
            buf.clear();
            buf.clone_from(&self.tun_batch[i][..n]);
            crate::payload::fix_ipv4_checksums(buf.message_mut());
            return Ok(OffloadRead::Plain(None));
        }
        self.split_len = 0;
        self.split_pos = 0;
        // A side thread may already have drained the TUN while this thread was
        // on the UDP socket. Those bytes are the same virtio frames `recv` returns.
        let len = if let Some(n) = self.copy_prefetch(buf) {
            n
        } else {
            // Read straight into the message buffer. The previous scratch copy was a
            // full extra pass over every packet on the forward path.
            buf.clear();
            let len = loop {
                match self.device.recv(buf.buffer()) {
                    Ok(len) => break len,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(OffloadRead::Blocked),
                    Err(e) => return Err(Error::DeviceIo("IO error when reading from device", e))
                }
            };
            if len <= VIRTIO_NET_HDR_LEN || len > buf.remaining_capacity() {
                return Ok(OffloadRead::Blocked);
            }
            buf.set_length(len);
            len
        };
        if len <= VIRTIO_NET_HDR_LEN {
            return Ok(OffloadRead::Blocked);
        }
        let Some(mut meta) = GsoMeta::read(buf.message()) else {
            return Ok(OffloadRead::Blocked);
        };
        let payload_len = len - VIRTIO_NET_HDR_LEN;
        // Keep the super-packet inside one outer datagram. A larger aggregate
        // is split into plain segments below; those are forwarded individually
        // instead of being IP-fragmented on the underlay.
        let max_ip = buf.remaining_capacity().saturating_sub(16).min(self.max_gso);
        if meta.segmented() && payload_len <= max_ip {
            buf.skip(VIRTIO_NET_HDR_LEN);
            return Ok(OffloadRead::Gso(meta));
        }
        if meta.segmented() {
            self.tun_scratch[..len].copy_from_slice(&buf.message()[..len]);
            tune_gso_hdr(&mut meta, &self.tun_scratch[VIRTIO_NET_HDR_LEN..len]);
            let is_v6 = self.tun_scratch[VIRTIO_NET_HDR_LEN] >> 4 == 6;
            let hdr = tun_rs::VirtioNetHdr {
                flags: meta.flags,
                gso_type: meta.gso_type,
                hdr_len: meta.hdr_len,
                gso_size: meta.gso_size,
                csum_start: meta.csum_start,
                csum_offset: meta.csum_offset
            };
            let nbufs = self.tun_batch.len().min(self.tun_sizes.len());
            let split = {
                let (_head, tail) = self.tun_scratch.split_at_mut(VIRTIO_NET_HDR_LEN);
                tun_rs::gso_split(
                    &mut tail[..payload_len],
                    hdr,
                    &mut self.tun_batch[..nbufs],
                    &mut self.tun_sizes[..nbufs],
                    0,
                    is_v6
                )
            };
            match split {
                Ok(n) if n > 0 => {
                    self.split_len = n;
                    self.split_pos = 1;
                    let seg = self.tun_sizes[0];
                    buf.clear();
                    buf.clone_from(&self.tun_batch[0][..seg]);
                    crate::payload::fix_ipv4_checksums(buf.message_mut());
                    return Ok(OffloadRead::Plain(None));
                }
                Ok(_) => return Ok(OffloadRead::Blocked),
                Err(e) => {
                    debug!("GSO split failed, dropping aggregate: {}", e);
                    return Ok(OffloadRead::Blocked);
                }
            }
        }
        let partial = if meta.flags & crate::gso::VIRTIO_F_NEEDS_CSUM != 0 {
            Some((meta.csum_start, meta.csum_offset))
        } else {
            None
        };
        buf.skip(VIRTIO_NET_HDR_LEN);
        Ok(OffloadRead::Plain(partial))
    }

    #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
    fn write_offload(&mut self, data: &mut crate::util::MsgBuffer, meta: &GsoMeta) -> Result<(), Error> {
        if !self.tun_offload {
            return self.write_msg(data);
        }
        let total = VIRTIO_NET_HDR_LEN + data.len();
        if total > self.tun_scratch.len() {
            return Err(Error::Device("GSO packet exceeds TUN buffer"));
        }
        self.tun_scratch[..VIRTIO_NET_HDR_LEN].fill(0);
        meta.write(&mut self.tun_scratch);
        self.tun_scratch[VIRTIO_NET_HDR_LEN..total].copy_from_slice(data.message());
        let mut last = io::Error::new(io::ErrorKind::WouldBlock, "tun tx queue full");
        for attempt in 0..3 {
            match self.device.send(&self.tun_scratch[..total]) {
                Ok(n) if n == total => return Ok(()),
                Ok(_) => return Err(Error::Socket("Sent out truncated packet")),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    last = e;
                    if attempt == 2 || !tun_tx_ready(self.as_raw_fd()) {
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(Error::DeviceIo("IO error when sending to device", e))
            }
        }
        Err(Error::DeviceIo("IO error when sending to device", last))
    }
}

/// Fill `hdr_len` from the transport header. The kernel sometimes reports the
/// first segment's full length here, which makes `gso_split` emit one giant packet.
#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
fn tune_gso_hdr(meta: &mut GsoMeta, pkt: &[u8]) {
    let kind = meta.gso_type & !0x80;
    if kind == crate::gso::GSO_UDP_L4 {
        meta.hdr_len = meta.csum_start.saturating_add(8);
        return;
    }
    let cs = meta.csum_start as usize;
    if pkt.len() <= cs + 12 {
        return;
    }
    let tcp_hlen = ((pkt[cs + 12] as u16) >> 4) * 4;
    if (20..=60).contains(&tcp_hlen) {
        meta.hdr_len = meta.csum_start.saturating_add(tcp_hlen);
    }
}

#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
fn tun_tx_ready(fd: RawFd) -> bool {
    let mut pfd = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };
    unsafe { libc::poll(&mut pfd, 1, 0) > 0 }
}

#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
struct TunSendScratch {
    iov: Vec<libc::iovec>,
    hdrs: Vec<libc::mmsghdr>
}

#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
thread_local! {
    static TUN_SEND: RefCell<TunSendScratch> =
        RefCell::new(TunSendScratch { iov: Vec::new(), hdrs: Vec::new() });
}

/// Driver queue in front of the TUN reader. The kernel default of 500 packets
/// is about 6 ms, and a stall longer than that is dropped after the qdisc has
/// counted the datagrams as sent. 2048 still dropped on the order of a
/// thousand datagrams in one 30s run. 16384 absorbs that stall.
#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
pub(crate) const TUN_TXQUEUELEN: u32 = 16_384;

/// Raise the TUN transmit ring. Failure leaves the kernel default in place.
#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
pub(crate) fn widen_tx_queue(ifname: &str) {
    let qlen = TUN_TXQUEUELEN.to_string();
    match std::process::Command::new("ip").args(["link", "set", "dev", ifname, "txqueuelen", &qlen]).status() {
        Ok(status) if status.success() => info!("Set txqueuelen {qlen} on {ifname}"),
        Ok(status) => info!("Could not set txqueuelen on {ifname} ({status})"),
        Err(err) => info!("Could not set txqueuelen on {ifname}: {err}")
    }
}

/// Datagrams per TUN inject. Eight inner packets are about 11 KiB. A
/// sixteen-packet chunk still left 0.03–0.1% of a 30s run on the floor.
#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
pub(crate) const UDP_INJECT_CHUNK: usize = 8;

/// Airtime of one inner UDP packet at the shaped underlay rate (~995 Mbit/s
/// of a 1500-byte frame). Short batches are this long per datagram. A fixed
/// chunk gap never ran: most injects are shorter than a chunk, and an empty
/// queue used to cancel the wait.
#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
pub(crate) const UDP_INJECT_PACKET_NS: u64 = 12_000;

/// Upper bound on one inject wait. One chunk of packets.
#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
pub(crate) const UDP_INJECT_GAP_NS: u64 = UDP_INJECT_PACKET_NS * UDP_INJECT_CHUNK as u64;

#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
fn sleep_ns(ns: u64) {
    let ts = libc::timespec { tv_sec: 0, tv_nsec: ns as libc::c_long };
    while unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) } == -1
        && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
    {}
}

/// Burn the rest of an inject gap. A readable underlay socket must not cut
/// this short: the caller reads at most one chunk, then holds the remainder.
///
/// A relative `nanosleep` wakes up to the thread's timer slack (50 µs) late
/// and that extra wait filled the underlay socket. Spinning the whole gap
/// kept the deadline but held a core, so iperf's socket overflowed. Sleep
/// until just before the deadline, then spin the rest: the sleep yields, and
/// the spin absorbs the few microseconds `clock_nanosleep` runs long.
#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
pub(crate) fn hold_udp_inject_gap(ns: u64) {
    if ns == 0 {
        return;
    }
    let ns = ns.min(UDP_INJECT_GAP_NS);
    let Some(start) = crate::net::mono_now() else {
        sleep_ns(ns);
        return;
    };
    let end = start.saturating_add(ns);
    // Measured overshoot of an absolute sleep here is about 2 µs. Leave
    // 20 µs so a late wake still finishes on the deadline.
    const SPIN_TAIL_NS: u64 = 20_000;
    let sleep_at = end.saturating_sub(SPIN_TAIL_NS);
    if crate::net::mono_now().unwrap_or(end) < sleep_at {
        precise_timer_slack();
        let ts = libc::timespec {
            tv_sec: (sleep_at / 1_000_000_000) as libc::time_t,
            tv_nsec: (sleep_at % 1_000_000_000) as libc::c_long
        };
        loop {
            let rc =
                unsafe { libc::clock_nanosleep(libc::CLOCK_MONOTONIC, libc::TIMER_ABSTIME, &ts, std::ptr::null_mut()) };
            if rc != libc::EINTR {
                break;
            }
        }
    }
    while crate::net::mono_now().unwrap_or(end) < end {
        std::hint::spin_loop();
    }
}

#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
fn precise_timer_slack() {
    thread_local! {
        static SET: Cell<bool> = const { Cell::new(false) };
    }
    SET.with(|set| {
        if set.get() {
            return;
        }
        set.set(true);
        unsafe {
            libc::prctl(libc::PR_SET_TIMERSLACK, 1, 0, 0, 0);
        }
    });
}

/// A TUN fd is a character device. `sendmmsg` returns `ENOTSOCK` every time,
/// so remember that and skip the syscall. The caller writes one datagram each.
#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
static TUN_SENDMMSG: AtomicBool = AtomicBool::new(true);

/// One TUN message per datagram. The virtio header, when present, is already
/// in the buffer. `sendmmsg` stops at the first packet the queue will not take.
#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
fn tun_sendmmsg(fd: RawFd, bufs: &mut [crate::util::MsgBuffer]) -> io::Result<usize> {
    if !TUN_SENDMMSG.load(Ordering::Relaxed) {
        return Err(io::Error::new(io::ErrorKind::Unsupported, "tun is not a socket"));
    }
    TUN_SEND.with(|cell| {
        let scratch = &mut *cell.borrow_mut();
        let n = bufs.len();
        scratch.iov.resize(n, libc::iovec { iov_base: std::ptr::null_mut(), iov_len: 0 });
        scratch.hdrs.resize_with(n, || unsafe { std::mem::zeroed() });
        let iov = scratch.iov.as_mut_ptr();
        let hdrs = scratch.hdrs.as_mut_ptr();
        for i in 0..n {
            let msg = bufs[i].message();
            unsafe {
                *iov.add(i) = libc::iovec { iov_base: msg.as_ptr() as *mut _, iov_len: msg.len() };
                let mut msg_hdr: libc::msghdr = std::mem::zeroed();
                msg_hdr.msg_iov = iov.add(i);
                msg_hdr.msg_iovlen = 1;
                let mut packed: libc::mmsghdr = std::mem::zeroed();
                packed.msg_hdr = msg_hdr;
                *hdrs.add(i) = packed;
            }
        }
        let got = unsafe { libc::sendmmsg(fd, hdrs, n as u32, libc::MSG_DONTWAIT as _) };
        if got < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOTSOCK) {
                TUN_SENDMMSG.store(false, Ordering::Relaxed);
            }
            Err(err)
        } else {
            Ok(got as usize)
        }
    })
}

/// Count virtio GSO trains. `gso_type` is set only when segments were merged.
#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
fn note_gro_batch(bufs: &[crate::util::MsgBuffer]) {
    static FLUSHES: AtomicU64 = AtomicU64::new(0);
    static MERGED: AtomicU64 = AtomicU64::new(0);
    static SUM_SEGS: AtomicU64 = AtomicU64::new(0);
    static MAX_SEGS: AtomicUsize = AtomicUsize::new(0);
    let flush = FLUSHES.fetch_add(1, Ordering::Relaxed) + 1;
    // Walking every virtio header on every train showed up on the TCP path.
    // Sample one train in 4000; the log line is the only consumer.
    if flush % 4000 != 0 {
        return;
    }
    let mut merged_here = 0u64;
    let mut segs_here = 0u64;
    let mut max_here = 0usize;
    for b in bufs {
        let msg = b.message();
        if msg.len() < VIRTIO_NET_HDR_LEN || msg[1] == 0 {
            continue;
        }
        let hdr_len = u16::from_le_bytes([msg[2], msg[3]]) as usize;
        let gso_size = u16::from_le_bytes([msg[4], msg[5]]) as usize;
        if gso_size == 0 {
            continue;
        }
        let payload = msg.len().saturating_sub(VIRTIO_NET_HDR_LEN).saturating_sub(hdr_len);
        let segs = payload / gso_size + usize::from(payload % gso_size != 0);
        if segs >= 2 {
            merged_here += 1;
            segs_here += segs as u64;
            max_here = max_here.max(segs);
        }
    }
    let merged = MERGED.fetch_add(merged_here, Ordering::Relaxed) + merged_here;
    let segs_sum = SUM_SEGS.fetch_add(segs_here, Ordering::Relaxed) + segs_here;
    let mut max_segs = MAX_SEGS.load(Ordering::Relaxed);
    while max_here > max_segs {
        match MAX_SEGS.compare_exchange_weak(max_segs, max_here, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => {
                max_segs = max_here;
                break;
            }
            Err(cur) => max_segs = cur
        }
    }
    if flush % 4000 == 0 {
        info!("TUN gso flushes={flush} merged={merged} segs={segs_sum} max_segs={max_segs}");
    }
}

#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
struct MsgVirtio<'a>(&'a mut crate::util::MsgBuffer);

#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
impl AsRef<[u8]> for MsgVirtio<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0.message()
    }
}

#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
impl AsMut<[u8]> for MsgVirtio<'_> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.message_mut()
    }
}

#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
impl ExpandBuffer for MsgVirtio<'_> {
    fn buf_capacity(&self) -> usize {
        self.0.remaining_capacity()
    }

    fn buf_resize(&mut self, new_len: usize, value: u8) {
        let old = self.0.len();
        self.0.set_length(new_len.min(self.0.remaining_capacity()));
        if self.0.len() > old {
            self.0.message_mut()[old..].fill(value);
        }
    }

    fn buf_extend_from_slice(&mut self, src: &[u8]) {
        let old = self.0.len();
        let add = src.len().min(self.0.remaining_capacity().saturating_sub(old));
        self.0.set_length(old + add);
        self.0.message_mut()[old..].copy_from_slice(&src[..add]);
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

#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
impl Drop for TunTapDevice {
    fn drop(&mut self) {
        if let Some(prefetch) = self.prefetch.take() {
            prefetch.shutdown();
        }
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
    gso_in: VecDeque<(GsoMeta, Vec<u8>)>,
    gso_out: VecDeque<GsoMeta>,
    /// Plain packets produced by [`MockDevice::read_offload`], with an optional
    /// virtio partial checksum `(csum_start, csum_offset)`.
    plain_in: VecDeque<(Option<(u16, u16)>, Vec<u8>)>,
    /// Set when this call already returned a packet, so the next empty read is
    /// [`OffloadRead::Blocked`] rather than falling through into `read_batch`.
    offload_yielded: bool,
    fd: std::fs::File,
    max_gso: usize,
    max_plain: usize
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
        Self {
            inbound: VecDeque::with_capacity(10),
            outbound: VecDeque::with_capacity(10),
            gso_in: VecDeque::new(),
            gso_out: VecDeque::new(),
            plain_in: VecDeque::new(),
            offload_yielded: false,
            fd: null_file(),
            max_gso: crate::mtu::max_gso(1500, crate::mtu::Underlay::V4),
            max_plain: crate::mtu::max_plain(1500, crate::mtu::Underlay::V4)
        }
    }

    pub fn gso_limit(&self) -> usize {
        self.max_gso
    }

    pub fn plain_limit(&self) -> usize {
        self.max_plain
    }

    pub fn put_plain_inbound(&mut self, partial_csum: Option<(u16, u16)>, data: Vec<u8>) {
        self.plain_in.push_back((partial_csum, data))
    }

    pub fn put_inbound(&mut self, data: Vec<u8>) {
        self.inbound.push_back(data)
    }

    pub fn put_gso_inbound(&mut self, meta: GsoMeta, data: Vec<u8>) {
        self.gso_in.push_back((meta, data))
    }

    pub fn pop_outbound(&mut self) -> Option<Vec<u8>> {
        self.outbound.pop_front()
    }

    pub fn pop_gso_meta(&mut self) -> Option<GsoMeta> {
        self.gso_out.pop_front()
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

    fn max_gso_payload(&self) -> usize {
        self.max_gso
    }

    fn max_plain_payload(&self) -> usize {
        self.max_plain
    }

    fn set_path_budget(&mut self, requested: Option<usize>, l2_mtu: usize, ipv6: bool) -> Result<(), Error> {
        let fit = crate::mtu::path_fit(l2_mtu, None, ipv6, self.get_type() == Type::Tap, requested);
        self.max_gso = fit.max_gso;
        self.max_plain = fit.device_mtu;
        Ok(())
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

    fn read_offload(&mut self, buf: &mut crate::util::MsgBuffer) -> Result<OffloadRead, Error> {
        if let Some((meta, data)) = self.gso_in.pop_front() {
            self.offload_yielded = true;
            buf.clear();
            buf.clone_from(&data);
            return Ok(OffloadRead::Gso(meta));
        }
        if let Some((partial, data)) = self.plain_in.pop_front() {
            self.offload_yielded = true;
            buf.clear();
            buf.clone_from(&data);
            return Ok(OffloadRead::Plain(partial));
        }
        if self.offload_yielded {
            self.offload_yielded = false;
            return Ok(OffloadRead::Blocked);
        }
        Ok(OffloadRead::Unsupported)
    }

    fn write_offload(&mut self, data: &mut crate::util::MsgBuffer, meta: &GsoMeta) -> Result<(), Error> {
        self.gso_out.push_back(*meta);
        self.outbound.push_back(data.message().to_vec());
        Ok(())
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
        Self::new()
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

impl From<Ipv6Addr> for crate::types::Address {
    fn from(ip: Ipv6Addr) -> Self {
        crate::types::Address::from_ipv6(ip)
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

    /// macOS utun/feth, Windows wintun names, and BSD tun/tap units are the names
    /// `TunTapDevice::new` passes to tun-rs on those hosts.
    #[test]
    fn each_os_tun_name_follows_that_platforms_entry_rule() {
        assert_eq!(platform_device_name_for(HostOs::Macos, "utun3", Type::Tun).as_deref(), Some("utun3"));
        assert_eq!(platform_device_name_for(HostOs::Macos, "feth0", Type::Tap).as_deref(), Some("feth0"));
        assert_eq!(platform_device_name_for(HostOs::Macos, "vpncloud%d", Type::Tun), None);
        assert_eq!(platform_device_name_for(HostOs::Windows, "vpncloud%d", Type::Tun).as_deref(), Some("vpncloud0"));
        assert_eq!(platform_device_name_for(HostOs::Bsd, "tun0", Type::Tun).as_deref(), Some("tun0"));
        assert_eq!(platform_device_name_for(HostOs::Bsd, "tap1", Type::Tap).as_deref(), Some("tap1"));
        assert_eq!(platform_device_name_for(HostOs::Bsd, "vpncloud%d", Type::Tun), None);
        assert_eq!(platform_device_name_for(HostOs::Other, "vpncloud%d", Type::Tun).as_deref(), Some("vpncloud%d"));
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

    /// A larger kernel GSO train is one read, then a userspace split, but cake
    /// under-charges it and the hairpin retransmits. Keep the cap at one frame.
    #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
    #[test]
    fn tun_gso_max_stays_one_underlay_frame() {
        if std::env::var_os("VPNCLOUD_GSO_CAP").is_none() {
            let exe = std::env::current_exe().expect("current_exe");
            let unshare = tool_on_path("unshare");
            let out = std::process::Command::new(unshare)
                .args(["-Urn", "--"])
                .arg(&exe)
                .arg("--exact")
                .arg("device::tests::tun_gso_max_stays_one_underlay_frame")
                .arg("--test-threads=1")
                .env("VPNCLOUD_GSO_CAP", "1")
                .output()
                .expect("spawn unshare");
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(out.status.success(), "gso cap child failed: {}\n{stdout}\n{stderr}", out.status);
            assert!(
                stdout.contains("tun_gso_max_stays_one_underlay_frame") && stdout.contains("ok"),
                "child did not run the gso cap: {stdout}\n{stderr}"
            );
            return;
        }
        let mut dev = TunTapDevice::new("gro%d", Type::Tun, None).expect("tun");
        dev.set_mtu(None).expect("mtu");
        let name = dev.ifname().to_string();
        let show = std::process::Command::new(tool_on_path("ip"))
            .args(["-d", "link", "show", "dev", &name])
            .output()
            .expect("ip link");
        let text = String::from_utf8_lossy(&show.stdout);
        assert!(show.status.success(), "{text} {}", String::from_utf8_lossy(&show.stderr));
        let mtu = link_detail_u64(&text, "mtu");
        let gso = link_detail_u64(&text, "gso_max_size");
        let cap = dev.max_gso_payload() as u64;
        assert_eq!(gso, cap, "{text}");
        assert!(gso < mtu, "gso {gso} mtu {mtu}");
        assert_eq!(cap, crate::mtu::max_gso(1500, crate::mtu::Underlay::V4) as u64);
    }

    /// The constructor sets the transmit ring. Read it back from the device.
    #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
    #[test]
    fn tun_tx_queue_absorbs_a_scheduling_stall() {
        if std::env::var_os("VPNCLOUD_TXQLEN").is_none() {
            let exe = std::env::current_exe().expect("current_exe");
            let unshare = tool_on_path("unshare");
            let out = std::process::Command::new(unshare)
                .args(["-Urn", "--"])
                .arg(&exe)
                .arg("--exact")
                .arg("device::tests::tun_tx_queue_absorbs_a_scheduling_stall")
                .arg("--test-threads=1")
                .env("VPNCLOUD_TXQLEN", "1")
                .output()
                .expect("spawn unshare");
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(out.status.success(), "txqlen child failed: {}\n{stdout}\n{stderr}", out.status);
            assert!(
                stdout.contains("tun_tx_queue_absorbs_a_scheduling_stall") && stdout.contains("ok"),
                "child did not run the txqlen check: {stdout}\n{stderr}"
            );
            return;
        }
        let dev = TunTapDevice::new("gro%d", Type::Tun, None).expect("tun");
        let show = std::process::Command::new(tool_on_path("ip"))
            .args(["link", "show", "dev", dev.ifname()])
            .output()
            .expect("ip link");
        let text = String::from_utf8_lossy(&show.stdout);
        assert!(show.status.success(), "{text} {}", String::from_utf8_lossy(&show.stderr));
        let qlen = text
            .split_whitespace()
            .skip_while(|word| *word != "qlen")
            .nth(1)
            .unwrap_or_else(|| panic!("no qlen in {text}"))
            .parse::<u32>()
            .unwrap_or_else(|e| panic!("qlen in {text}: {e}"));
        assert_eq!(qlen, super::TUN_TXQUEUELEN, "{text}");
    }

    /// Two in-order TCP segments must become one TUN write. Separate writes
    /// make the peer ACK each segment, and those ACKs take the reverse shaper.
    #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
    #[test]
    fn tcp_payloads_coalesce_into_one_tun_write() {
        if std::env::var_os("VPNCLOUD_GRO_COALESCE").is_none() {
            let exe = std::env::current_exe().expect("current_exe");
            let unshare = tool_on_path("unshare");
            let out = std::process::Command::new(unshare)
                .args(["-Urn", "--"])
                .arg(&exe)
                .arg("--exact")
                .arg("device::tests::tcp_payloads_coalesce_into_one_tun_write")
                .arg("--test-threads=1")
                .env("VPNCLOUD_GRO_COALESCE", "1")
                .output()
                .expect("spawn unshare");
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(out.status.success(), "coalesce child failed: {}\n{stdout}\n{stderr}", out.status);
            assert!(
                stdout.contains("tcp_payloads_coalesce_into_one_tun_write") && stdout.contains("ok"),
                "child did not run the coalesce: {stdout}\n{stderr}"
            );
            return;
        }
        let mut dev = TunTapDevice::new("gro%d", Type::Tun, None).expect("tun");
        let ip = tool_on_path("ip");
        let up = std::process::Command::new(ip).args(["link", "set", "dev", dev.ifname(), "up"]).status().expect("ip");
        assert!(up.success(), "link up");
        let first = tcp_segment(1, b"abcd");
        let second = tcp_segment(5, b"efgh");
        let mut ba = crate::util::MsgBuffer::new(100);
        let mut bb = crate::util::MsgBuffer::new(100);
        ba.clone_from(&first);
        bb.clone_from(&second);
        crate::payload::fix_ipv4_checksums(ba.message_mut());
        crate::payload::fix_ipv4_checksums(bb.message_mut());
        ba.prepend_zero(VIRTIO_NET_HDR_LEN);
        bb.prepend_zero(VIRTIO_NET_HDR_LEN);
        let separate = ba.len() + bb.len();
        let device = std::sync::Arc::clone(&dev.device);
        let sent = {
            let mut wraps = [MsgVirtio(&mut ba), MsgVirtio(&mut bb)];
            device.send_multiple(&mut dev.gro_table, &mut wraps, VIRTIO_NET_HDR_LEN).expect("send_multiple")
        };
        let merged = VIRTIO_NET_HDR_LEN + first.len() + 4;
        assert_eq!(sent, merged, "separate writes would be {separate} bytes");

        // Timestamps differ per segment. The coalescer treats that as a different header.
        let ts1 = tcp_segment_ts(1, b"abcd", 100);
        let ts2 = tcp_segment_ts(5, b"efgh", 180);
        let mut ta = crate::util::MsgBuffer::new(100);
        let mut tb = crate::util::MsgBuffer::new(100);
        ta.clone_from(&ts1);
        tb.clone_from(&ts2);
        let mut held = [ta, tb];
        crate::payload::share_tcp_timestamps_for_gro(&mut held);
        crate::payload::fix_ipv4_checksums(held[0].message_mut());
        crate::payload::fix_ipv4_checksums(held[1].message_mut());
        held[0].prepend_zero(VIRTIO_NET_HDR_LEN);
        held[1].prepend_zero(VIRTIO_NET_HDR_LEN);
        let sent_ts = {
            let (left, right) = held.split_at_mut(1);
            let mut wraps = [MsgVirtio(&mut left[0]), MsgVirtio(&mut right[0])];
            device.send_multiple(&mut dev.gro_table, &mut wraps, VIRTIO_NET_HDR_LEN).expect("send_multiple ts")
        };
        let merged_ts = VIRTIO_NET_HDR_LEN + ts1.len() + 4;
        assert_eq!(sent_ts, merged_ts, "timestamped segments stayed separate");

        // Different piggybacked ACKs are different tun-rs flows until the
        // shipped share stamps the newer ACK onto the head buffer.
        let mut ack_lo = tcp_segment_ts(1, b"abcd", 100);
        let mut ack_hi = tcp_segment_ts(5, b"efgh", 180);
        ack_lo[28..32].copy_from_slice(&50u32.to_be_bytes());
        ack_hi[28..32].copy_from_slice(&80u32.to_be_bytes());
        ack_hi[34..36].copy_from_slice(&4000u16.to_be_bytes());
        let mut ha = crate::util::MsgBuffer::new(100);
        let mut hb = crate::util::MsgBuffer::new(100);
        ha.clone_from(&ack_lo);
        hb.clone_from(&ack_hi);
        let mut differed = [ha, hb];
        crate::payload::share_tcp_timestamps_for_gro(&mut differed);
        assert_eq!(&differed[0].message()[28..32], &80u32.to_be_bytes());
        assert_eq!(&differed[1].message()[28..32], &80u32.to_be_bytes());
        assert_eq!(&differed[0].message()[34..36], &4000u16.to_be_bytes());
        crate::payload::fix_ipv4_checksums(differed[0].message_mut());
        crate::payload::fix_ipv4_checksums(differed[1].message_mut());
        differed[0].prepend_zero(VIRTIO_NET_HDR_LEN);
        differed[1].prepend_zero(VIRTIO_NET_HDR_LEN);
        let sent_ack = {
            let (left, right) = differed.split_at_mut(1);
            let mut wraps = [MsgVirtio(&mut left[0]), MsgVirtio(&mut right[0])];
            device.send_multiple(&mut dev.gro_table, &mut wraps, VIRTIO_NET_HDR_LEN).expect("send_multiple ack")
        };
        let merged_ack = VIRTIO_NET_HDR_LEN + ack_lo.len() + 4;
        assert_eq!(sent_ack, merged_ack, "different ACKs stayed separate");
    }

    /// UDP must arrive as separate datagrams. A GRO/USO merge of the batch
    /// delivers one payload and the iperf control connection dies.
    #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
    #[test]
    fn udp_datagrams_are_delivered_separately() {
        if std::env::var_os("VPNCLOUD_UDP_WRITE").is_none() {
            let exe = std::env::current_exe().expect("current_exe");
            let unshare = tool_on_path("unshare");
            let out = std::process::Command::new(unshare)
                .args(["-Urn", "--"])
                .arg(&exe)
                .arg("--exact")
                .arg("device::tests::udp_datagrams_are_delivered_separately")
                .arg("--test-threads=1")
                .env("VPNCLOUD_UDP_WRITE", "1")
                .output()
                .expect("spawn unshare");
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(out.status.success(), "udp write child failed: {}\n{stdout}\n{stderr}", out.status);
            assert!(
                stdout.contains("udp_datagrams_are_delivered_separately") && stdout.contains("ok"),
                "child did not run the udp write: {stdout}\n{stderr}"
            );
            return;
        }
        let mut dev = TunTapDevice::new("gro%d", Type::Tun, None).expect("tun");
        let ip = tool_on_path("ip");
        let name = dev.ifname().to_string();
        let addr = std::process::Command::new(&ip)
            .args(["addr", "add", "10.250.0.1/24", "dev", &name])
            .status()
            .expect("addr");
        assert!(addr.success(), "addr add");
        let up = std::process::Command::new(&ip).args(["link", "set", "dev", &name, "up"]).status().expect("ip");
        assert!(up.success(), "link up");
        let _ = std::fs::write("/proc/sys/net/ipv4/conf/all/rp_filter", "0");
        let _ = std::fs::write(format!("/proc/sys/net/ipv4/conf/{name}/rp_filter"), "0");
        let sock = std::net::UdpSocket::bind("10.250.0.1:9").expect("bind");
        sock.set_nonblocking(true).expect("nonblocking");
        let mut batch = [crate::util::MsgBuffer::new(100), crate::util::MsgBuffer::new(100)];
        batch[0].clone_from(&udp_packet(b"one-datagram"));
        batch[1].clone_from(&udp_packet(b"two-datagram"));
        let n = dev.write_batch(&mut batch).expect("write_batch");
        assert_eq!(n, 2, "both datagrams must be accepted");
        let mut got = Vec::new();
        for _ in 0..40 {
            let mut buf = [0u8; 64];
            match sock.recv(&mut buf) {
                Ok(len) => got.push(buf[..len].to_vec()),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(e) => panic!("recv: {e}")
            }
            if got.len() == 2 {
                break;
            }
        }
        assert_eq!(got, vec![b"one-datagram".to_vec(), b"two-datagram".to_vec()]);
    }

    /// A burst larger than one inject chunk must stay one datagram per payload.
    /// The shipped hold runs between chunks.
    #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
    #[test]
    fn udp_burst_is_paced_and_separate() {
        if std::env::var_os("VPNCLOUD_UDP_PACE").is_none() {
            let exe = std::env::current_exe().expect("current_exe");
            let unshare = tool_on_path("unshare");
            let out = std::process::Command::new(unshare)
                .args(["-Urn", "--"])
                .arg(&exe)
                .arg("--exact")
                .arg("device::tests::udp_burst_is_paced_and_separate")
                .arg("--test-threads=1")
                .env("VPNCLOUD_UDP_PACE", "1")
                .output()
                .expect("spawn unshare");
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(out.status.success(), "udp pace child failed: {}\n{stdout}\n{stderr}", out.status);
            assert!(
                stdout.contains("udp_burst_is_paced_and_separate") && stdout.contains("ok"),
                "child did not run the udp pace test: {stdout}\n{stderr}"
            );
            return;
        }
        let mut dev = TunTapDevice::new("gro%d", Type::Tun, None).expect("tun");
        let ip = tool_on_path("ip");
        let name = dev.ifname().to_string();
        let addr = std::process::Command::new(&ip)
            .args(["addr", "add", "10.250.0.1/24", "dev", &name])
            .status()
            .expect("addr");
        assert!(addr.success(), "addr add");
        let up = std::process::Command::new(&ip).args(["link", "set", "dev", &name, "up"]).status().expect("ip");
        assert!(up.success(), "link up");
        let _ = std::fs::write("/proc/sys/net/ipv4/conf/all/rp_filter", "0");
        let _ = std::fs::write(format!("/proc/sys/net/ipv4/conf/{name}/rp_filter"), "0");
        let sock = std::net::UdpSocket::bind("10.250.0.1:9").expect("bind");
        sock.set_nonblocking(true).expect("nonblocking");
        // The pause test checks that every datagram is still its own payload.
        // A default receive buffer can drop the burst before this assertion.
        let rcv: libc::c_int = 4 * 1024 * 1024;
        let fd = std::os::unix::io::AsRawFd::as_raw_fd(&sock);
        assert_eq!(
            unsafe {
                libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, &rcv as *const _ as *const libc::c_void, 4)
            },
            0,
            "rcvbuf"
        );
        let nseg = 96usize;
        let mut batch: Vec<crate::util::MsgBuffer> = (0..nseg)
            .map(|i| {
                let mut payload = vec![0u8; 1200];
                payload[0] = i as u8;
                let mut buf = crate::util::MsgBuffer::new(100);
                buf.clone_from(&udp_packet(&payload));
                buf
            })
            .collect();
        let started = std::time::Instant::now();
        let mut off = 0usize;
        let mut calls = 0usize;
        while off < nseg {
            let n = dev.write_batch(&mut batch[off..]).expect("write_batch");
            calls += 1;
            assert!(n > 0 && n <= super::UDP_INJECT_CHUNK, "chunk {n}");
            if off + n < nseg {
                assert_eq!(n, super::UDP_INJECT_CHUNK, "full chunks until the tail");
                super::hold_udp_inject_gap(super::UDP_INJECT_GAP_NS);
            }
            off += n;
        }
        let elapsed = started.elapsed();
        assert_eq!(off, nseg, "every datagram must be accepted");
        let gaps = calls.saturating_sub(1) as u64;
        let min_ns = super::UDP_INJECT_GAP_NS.saturating_mul(gaps) * 4 / 5;
        assert!(
            elapsed >= std::time::Duration::from_nanos(min_ns),
            "burst of {nseg} datagrams wrote in {elapsed:?}, gaps took under {min_ns}ns"
        );
        let mut got = vec![None; nseg];
        let mut count = 0usize;
        for _ in 0..400 {
            let mut buf = [0u8; 1600];
            match sock.recv(&mut buf) {
                Ok(len) => {
                    assert_eq!(len, 1200, "datagram len {len}");
                    let id = buf[0] as usize;
                    assert!(id < nseg, "payload id {id}");
                    assert!(got[id].is_none(), "duplicate {id}");
                    assert!(buf[..len].iter().skip(1).all(|b| *b == 0), "payload {id} changed");
                    got[id] = Some(());
                    count += 1;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if count == nseg {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                Err(e) => panic!("recv: {e}")
            }
        }
        assert_eq!(count, nseg, "missing datagrams");
    }

    /// Datagrams queued on the TUN before the side read must come back through
    /// `read_offload` unmodified, and only after the prefetch queue actually
    /// held them. A direct `recv` would also return the bytes, so the pending
    /// check is what proves this path was used.
    #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
    #[test]
    fn tun_prefetch_returns_every_datagram_unmodified() {
        if std::env::var_os("VPNCLOUD_TUN_PREFETCH").is_none() {
            let exe = std::env::current_exe().expect("current_exe");
            let unshare = tool_on_path("unshare");
            let out = std::process::Command::new(unshare)
                .args(["-Urn", "--"])
                .arg(&exe)
                .arg("--exact")
                .arg("device::tests::tun_prefetch_returns_every_datagram_unmodified")
                .arg("--test-threads=1")
                .env("VPNCLOUD_TUN_PREFETCH", "1")
                .output()
                .expect("spawn unshare");
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(out.status.success(), "prefetch child failed: {}\n{stdout}\n{stderr}", out.status);
            assert!(
                stdout.contains("tun_prefetch_returns_every_datagram_unmodified") && stdout.contains("ok"),
                "child did not run the prefetch test: {stdout}\n{stderr}"
            );
            return;
        }
        let mut dev = TunTapDevice::new("gro%d", Type::Tun, None).expect("tun");
        dev.set_mtu(None).expect("mtu");
        let ip = tool_on_path("ip");
        let name = dev.ifname().to_string();
        let addr = std::process::Command::new(&ip)
            .args(["addr", "add", "10.250.0.1/24", "dev", &name])
            .status()
            .expect("addr");
        assert!(addr.success(), "addr add");
        let up = std::process::Command::new(&ip).args(["link", "set", "dev", &name, "up"]).status().expect("ip");
        assert!(up.success(), "link up");
        let _ = std::fs::write("/proc/sys/net/ipv4/conf/all/rp_filter", "0");
        let _ = std::fs::write(format!("/proc/sys/net/ipv4/conf/{name}/rp_filter"), "0");
        let payloads: Vec<Vec<u8>> = (0..5)
            .map(|i| format!("prefetch-datagram-{i:02}-{}", "0123456789abcdef".repeat(3)).into_bytes())
            .collect();
        let sock = std::net::UdpSocket::bind("10.250.0.1:9").expect("bind");
        for payload in &payloads {
            let sent = sock.send_to(payload, "10.250.0.2:9").expect("send_to");
            assert_eq!(sent, payload.len());
        }
        // The kernel has the frames. Kick only now, so a later direct recv
        // cannot satisfy the test without the side thread having read them.
        dev.kick_tun_prefetch();
        dev.join_tun_prefetch();
        assert!(dev.tun_prefetch_pending(), "side read left the queue empty");
        let plain_cap = dev.max_plain_payload();
        let gso_cap = dev.max_gso_payload();
        let mut frames = Vec::new();
        let mut buf = crate::util::MsgBuffer::new(100);
        // Stop when the queue is empty. A further read_offload would recv()
        // from the TUN and could hide a side thread that never took the datagrams.
        for _ in 0..128 {
            if !dev.tun_prefetch_pending() {
                break;
            }
            match dev.read_offload(&mut buf) {
                Ok(OffloadRead::Plain(_)) => {
                    let msg = buf.message();
                    assert!(msg.len() <= plain_cap, "plain {} exceeds max_plain {plain_cap}", msg.len());
                    frames.push(msg.to_vec());
                }
                Ok(OffloadRead::Gso(_)) => {
                    let msg = buf.message();
                    assert!(msg.len() <= gso_cap, "aggregate {} exceeds max_gso {gso_cap}", msg.len());
                    frames.push(msg.to_vec());
                }
                Ok(OffloadRead::Blocked) | Ok(OffloadRead::Unsupported) => {
                    panic!("prefetch queue was pending but read_offload returned no packet");
                }
                Err(e) => panic!("read_offload: {e}")
            }
        }
        assert!(!dev.tun_prefetch_pending(), "queue still held a frame after the drain");
        for payload in &payloads {
            let hits = frames.iter().filter(|msg| msg.windows(payload.len()).any(|w| w == payload.as_slice())).count();
            assert_eq!(
                hits,
                1,
                "payload of {} bytes was dropped or duplicated among {} frames",
                payload.len(),
                frames.len()
            );
        }
    }
}

#[cfg(all(test, target_os = "linux", not(target_env = "ohos")))]
fn udp_packet(payload: &[u8]) -> Vec<u8> {
    let total = 28 + payload.len();
    let mut pkt = vec![0u8; total];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 17;
    pkt[12..16].copy_from_slice(&[10, 250, 0, 2]);
    pkt[16..20].copy_from_slice(&[10, 250, 0, 1]);
    pkt[20..22].copy_from_slice(&4000u16.to_be_bytes());
    pkt[22..24].copy_from_slice(&9u16.to_be_bytes());
    pkt[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    pkt[28..].copy_from_slice(payload);
    pkt
}

#[cfg(all(test, target_os = "linux", not(target_env = "ohos")))]
fn tcp_segment_ts(seq: u32, payload: &[u8], tsval: u32) -> Vec<u8> {
    let total = 52 + payload.len();
    let mut pkt = vec![0u8; total];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 6;
    pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
    pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);
    pkt[20..22].copy_from_slice(&4000u16.to_be_bytes());
    pkt[22..24].copy_from_slice(&5201u16.to_be_bytes());
    pkt[24..28].copy_from_slice(&seq.to_be_bytes());
    pkt[28..32].copy_from_slice(&1u32.to_be_bytes());
    pkt[32] = 0x80;
    pkt[33] = 0x10;
    pkt[34..36].copy_from_slice(&65535u16.to_be_bytes());
    pkt[40] = 1;
    pkt[41] = 1;
    pkt[42] = 8;
    pkt[43] = 10;
    pkt[44..48].copy_from_slice(&tsval.to_be_bytes());
    pkt[48..52].copy_from_slice(&7u32.to_be_bytes());
    pkt[52..].copy_from_slice(payload);
    pkt
}

#[cfg(all(test, target_os = "linux", not(target_env = "ohos")))]
fn link_detail_u64(text: &str, key: &str) -> u64 {
    let needle = format!("{key} ");
    let rest = text.split(&needle).nth(1).unwrap_or_else(|| panic!("{key} missing in {text}"));
    rest.split_whitespace().next().unwrap_or_else(|| panic!("{key} value missing in {text}")).parse().expect(key)
}

#[cfg(all(test, target_os = "linux", not(target_env = "ohos")))]
fn tool_on_path(name: &str) -> String {
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return candidate.to_string_lossy().into_owned();
            }
        }
    }
    format!("/run/current-system/sw/bin/{name}")
}

#[cfg(all(test, target_os = "linux", not(target_env = "ohos")))]
fn tcp_segment(seq: u32, payload: &[u8]) -> Vec<u8> {
    let total = 40 + payload.len();
    let mut pkt = vec![0u8; total];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 6;
    pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
    pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);
    pkt[20..22].copy_from_slice(&4000u16.to_be_bytes());
    pkt[22..24].copy_from_slice(&5201u16.to_be_bytes());
    pkt[24..28].copy_from_slice(&seq.to_be_bytes());
    pkt[28..32].copy_from_slice(&1u32.to_be_bytes());
    pkt[32] = 0x50;
    pkt[33] = 0x10;
    pkt[34..36].copy_from_slice(&65535u16.to_be_bytes());
    pkt[40..].copy_from_slice(payload);
    pkt
}
