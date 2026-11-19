// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

#[cfg(unix)] use std::thread;
use std::{
    fmt,
    net::{Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket},
    path::PathBuf,
    process::{self, Command},
    sync::{
        atomic::{AtomicBool, AtomicIsize, Ordering},
        Arc, Mutex
    },
    time::Instant
};

use crate::error::Error;

#[cfg(unix)]
use signal_hook::consts::{SIGQUIT, SIGTERM};
use signal_hook::{consts::SIGINT, flag};
use smallvec::SmallVec;
#[cfg(unix)] use std::io;

pub type Duration = u32;
pub type Time = i64;

pub struct MsgBuffer {
    space_before: usize,
    // Heap buffer so moving a packet between the TUN queue, crypto workers, and the
    // UDP outbox is a pointer swap. An inline 64KB array made every `mem::swap` copy
    // the whole allocation and capped forwarding well below line rate.
    //
    // 65535 is one UDP datagram. A 44-segment UDP_GRO train (44 * 1472 = 64768)
    // still fits after the 100-byte headroom. A larger box pushed TCP retransmits
    // up without raising the line rate. `mem::swap` still moves only the Box pointer.
    buffer: Box<[u8]>,
    start: usize,
    end: usize
}

impl MsgBuffer {
    pub fn new(space_before: usize) -> Self {
        Self { buffer: vec![0u8; 65535].into_boxed_slice(), space_before, start: space_before, end: space_before }
    }

    pub fn get_start(&self) -> usize {
        self.start
    }

    pub fn set_start(&mut self, start: usize) {
        self.start = start
    }

    pub fn prepend_byte(&mut self, byte: u8) {
        self.start -= 1;
        self.buffer[self.start] = byte
    }

    pub fn take_prefix(&mut self) -> u8 {
        let byte = self.buffer[self.start];
        self.start += 1;
        byte
    }

    pub fn buffer(&mut self) -> &mut [u8] {
        &mut self.buffer[self.start..]
    }

    pub fn message(&self) -> &[u8] {
        &self.buffer[self.start..self.end]
    }

    pub fn take(&mut self) -> Option<&[u8]> {
        if self.start != self.end {
            let end = self.end;
            self.end = self.start;
            Some(&self.buffer[self.start..end])
        } else {
            None
        }
    }

    pub fn message_mut(&mut self) -> &mut [u8] {
        &mut self.buffer[self.start..self.end]
    }

    pub fn set_length(&mut self, length: usize) {
        self.end = self.start + length
    }

    pub fn clone_from(&mut self, other: &[u8]) {
        self.set_length(other.len());
        self.message_mut().clone_from_slice(other);
    }

    /// Insert `n` zero bytes before the current payload. Panics if `start < n`.
    pub fn prepend_zero(&mut self, n: usize) {
        self.start = self.start.checked_sub(n).expect("MsgBuffer prepend");
        self.buffer[self.start..self.start + n].fill(0);
    }

    pub fn skip(&mut self, n: usize) {
        self.start += n;
    }

    pub fn remaining_capacity(&self) -> usize {
        self.buffer.len().saturating_sub(self.start)
    }

    pub fn len(&self) -> usize {
        self.end - self.start
    }

    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }

    pub fn clear(&mut self) {
        self.set_start(self.space_before);
        self.set_length(0)
    }
}

impl Clone for MsgBuffer {
    fn clone(&self) -> Self {
        let mut n = MsgBuffer::new(self.space_before);
        n.start = self.start;
        n.end = self.end;
        n.buffer[self.start..self.end].copy_from_slice(&self.buffer[self.start..self.end]);
        n
    }
}

const HEX_CHARS: &[u8] = b"0123456789abcdef";

/// Decode a hex string into bytes (used for node ids in config).
pub fn from_hex(text: &str) -> Result<Vec<u8>, crate::error::NoDetail> {
    if !text.len().is_multiple_of(2) {
        return Err(crate::error::NoDetail);
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|_| crate::error::NoDetail))
        .collect()
}

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        s.push(HEX_CHARS[(byte >> 4) as usize] as char);
        s.push(HEX_CHARS[(byte & 0xf) as usize] as char);
    }
    s
}

pub fn addr_nice(addr: SocketAddr) -> SocketAddr {
    if let SocketAddr::V6(v6addr) = addr {
        if let Some(ip) = v6addr.ip().to_ipv4_mapped().or_else(|| v6addr.ip().to_ipv4()) {
            return (ip, addr.port()).into();
        }
    }
    addr
}

pub struct Encoder;

impl Encoder {
    #[inline]
    pub fn read_u16(data: &[u8]) -> u16 {
        (u16::from(data[0]) << 8) | u16::from(data[1])
    }

    #[inline]
    pub fn write_u16(val: u16, data: &mut [u8]) {
        data[0] = ((val >> 8) & 0xff) as u8;
        data[1] = (val & 0xff) as u8;
    }

    #[inline]
    pub fn read_u32(data: &[u8]) -> u32 {
        (u32::from(data[0]) << 24) | (u32::from(data[1]) << 16) | (u32::from(data[2]) << 8) | u32::from(data[3])
    }

    #[inline]
    pub fn write_u32(val: u32, data: &mut [u8]) {
        data[0] = ((val >> 24) & 0xff) as u8;
        data[1] = ((val >> 16) & 0xff) as u8;
        data[2] = ((val >> 8) & 0xff) as u8;
        data[3] = (val & 0xff) as u8;
    }

    #[inline]
    pub fn read_u64(data: &[u8]) -> u64 {
        (u64::from(data[0]) << 56)
            | (u64::from(data[1]) << 48)
            | (u64::from(data[2]) << 40)
            | (u64::from(data[3]) << 32)
            | (u64::from(data[4]) << 24)
            | (u64::from(data[5]) << 16)
            | (u64::from(data[6]) << 8)
            | u64::from(data[7])
    }

    #[inline]
    pub fn write_u64(val: u64, data: &mut [u8]) {
        data[0] = ((val >> 56) & 0xff) as u8;
        data[1] = ((val >> 48) & 0xff) as u8;
        data[2] = ((val >> 40) & 0xff) as u8;
        data[3] = ((val >> 32) & 0xff) as u8;
        data[4] = ((val >> 24) & 0xff) as u8;
        data[5] = ((val >> 16) & 0xff) as u8;
        data[6] = ((val >> 8) & 0xff) as u8;
        data[7] = (val & 0xff) as u8;
    }
}

macro_rules! fail {
    ($format:expr) => ( {
        crate::util::fatal_stop($format);
    } );
    ($format:expr, $( $arg:expr ),+) => ( {
        crate::util::fatal_stop(&format!($format, $( $arg ),+));
    } );
}

macro_rules! try_fail {
    ($val:expr, $format:expr) => ( {
        match $val {
            Ok(val) => val,
            Err(err) => fail!($format, err)
        }
    } );
    ($val:expr, $format:expr, $( $arg:expr ),+) => ( {
        match $val {
            Ok(val) => val,
            Err(err) => fail!($format, $( $arg ),+, err)
        }
    } );
}

pub fn get_internal_ip() -> Ipv4Addr {
    // UDP connect trick: the kernel fills in the source address for that route.
    if let Ok(dummy_sock) = UdpSocket::bind("0.0.0.0:0") {
        if dummy_sock.connect("8.8.8.8:53").is_ok() {
            if let Ok(SocketAddr::V4(addr)) = dummy_sock.local_addr() {
                return *addr.ip();
            }
        }
    }
    Ipv4Addr::UNSPECIFIED
}

/// Detach from the controlling terminal (Unix `--daemon`).
///
/// Implemented with fork/setsid rather than `daemon(3)`: the latter is
/// deprecated and was removed from newer `libc` releases on macOS.
#[cfg(unix)]
pub fn unix_daemonize() -> io::Result<()> {
    unsafe {
        match libc::fork() {
            -1 => return Err(io::Error::last_os_error()),
            0 => {}
            _ => process::exit(0) // parent exits, child continues
        }
        if libc::setsid() == -1 {
            return Err(io::Error::last_os_error());
        }
        if libc::chdir(c"/".as_ptr()) == -1 {
            return Err(io::Error::last_os_error());
        }
        let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if devnull >= 0 {
            for fd in [0, 1, 2] {
                libc::dup2(devnull, fd);
            }
            if devnull > 2 {
                libc::close(devnull);
            }
        }
    }
    Ok(())
}

#[allow(unknown_lints, clippy::needless_pass_by_value)]
pub fn resolve<Addr: ToSocketAddrs + fmt::Debug>(addr: Addr) -> Result<SmallVec<[SocketAddr; 4]>, Error> {
    let mut addrs =
        addr.to_socket_addrs().map_err(|_| Error::NameUnresolvable(format!("{:?}", addr)))?.collect::<SmallVec<_>>();
    // Try IPv4 first as it usually is faster
    addrs.sort_by_key(|addr| {
        match *addr {
            SocketAddr::V4(_) => 4,
            SocketAddr::V6(_) => 6
        }
    });
    // Remove duplicates in addrs (why are there duplicates???)
    addrs.dedup();
    Ok(addrs)
}

#[allow(unused_macros)]
macro_rules! addr {
    ($addr: expr) => {{
        std::net::ToSocketAddrs::to_socket_addrs($addr).unwrap().next().unwrap()
    }};
}

pub struct Bytes(pub u64);

impl fmt::Display for Bytes {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let mut size = self.0 as f32;
        if size >= 512.0 {
            size /= 1024.0;
        } else {
            return write!(formatter, "{:.0} B", size);
        }
        if size >= 512.0 {
            size /= 1024.0;
        } else {
            return write!(formatter, "{:.1} KiB", size);
        }
        if size >= 512.0 {
            size /= 1024.0;
        } else {
            return write!(formatter, "{:.1} MiB", size);
        }
        if size >= 512.0 {
            size /= 1024.0;
        } else {
            return write!(formatter, "{:.1} GiB", size);
        }
        write!(formatter, "{:.1} TiB", size)
    }
}

static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
static PAUSED: AtomicBool = AtomicBool::new(false);
static RELOAD_REQUESTED: AtomicBool = AtomicBool::new(false);
static RELOAD_PATH: Mutex<Option<PathBuf>> = Mutex::new(None);
static FAIL_PANICS: AtomicBool = AtomicBool::new(false);
/// Opt-in hex dump of wire messages (set by `--wire-log`).
static WIRE_LOG: AtomicBool = AtomicBool::new(false);

/// Enable/disable the wire hex dump. Off by default: dumps can expose payload
/// contents and are written to the log file.
pub fn set_wire_log(enabled: bool) {
    WIRE_LOG.store(enabled, Ordering::Relaxed);
}

pub fn wire_log_enabled() -> bool {
    WIRE_LOG.load(Ordering::Relaxed)
}

/// Emit a bounded hex dump of a wire message when `--wire-log` is enabled.
/// `data` is the decrypted payload (or the plaintext before encryption).
pub fn wire_log(direction: &str, peer: crate::util::SocketAddr, type_: u8, data: &[u8]) {
    if !wire_log_enabled() {
        return;
    }
    const MAX_DUMP: usize = 64;
    let end = data.len().min(MAX_DUMP);
    log::trace!(
        "WIRE {} {} type={} len={} {}",
        direction,
        addr_nice(peer),
        type_,
        data.len(),
        bytes_to_hex(&data[..end])
    );
}

/// When true, `fail!` panics the current thread instead of exiting the process.
/// Used by the GUI worker so a TUN error does not kill the window.
pub fn set_fail_panics(v: bool) {
    FAIL_PANICS.store(v, Ordering::Relaxed);
}

pub fn fatal_stop(msg: &str) -> ! {
    error!("{}", msg);
    log::logger().flush();
    if FAIL_PANICS.load(Ordering::Relaxed) {
        panic!("{}", msg);
    }
    process::exit(-1);
}

pub struct CtrlC {
    flag: Arc<AtomicBool>
}

impl CtrlC {
    pub fn new() -> Self {
        Default::default()
    }

    /// Request the run loop to exit (Android JNI / iOS FFI stop, tests).
    pub fn request_stop() {
        STOP_REQUESTED.store(true, Ordering::Relaxed);
    }

    pub fn clear_stop() {
        STOP_REQUESTED.store(false, Ordering::Relaxed);
        PAUSED.store(false, Ordering::Relaxed);
    }

    pub fn set_paused(paused: bool) {
        PAUSED.store(paused, Ordering::Relaxed);
    }

    pub fn is_paused() -> bool {
        PAUSED.load(Ordering::Relaxed)
    }

    /// Ask the datapath to reload policy config (used by tray menus on
    /// platforms without SIGHUP).
    pub fn request_reload() {
        RELOAD_REQUESTED.store(true, Ordering::Relaxed);
    }

    /// True once if SIGHUP was received (clears the flag).
    pub fn reload_requested() -> bool {
        RELOAD_REQUESTED.swap(false, Ordering::Relaxed)
    }

    /// Remember the config path so the datapath can reload it on SIGHUP.
    pub fn set_reload_path(path: PathBuf) {
        if let Ok(mut guard) = RELOAD_PATH.lock() {
            *guard = Some(path);
        }
    }

    pub fn reload_path() -> Option<PathBuf> {
        RELOAD_PATH.lock().ok().and_then(|guard| guard.clone())
    }

    pub fn was_pressed(&mut self) -> bool {
        self.flag.swap(false, Ordering::Relaxed) || STOP_REQUESTED.swap(false, Ordering::Relaxed)
    }
}

impl Default for CtrlC {
    fn default() -> Self {
        let flag = Arc::new(AtomicBool::new(false));
        let _ = flag::register(SIGINT, Arc::clone(&flag));
        #[cfg(unix)]
        {
            let _ = flag::register(SIGTERM, Arc::clone(&flag));
            let _ = flag::register(SIGQUIT, Arc::clone(&flag));
            // SIGHUP asks for a config reload (peers, ACL, grants, routes).
            let reload = Arc::new(AtomicBool::new(false));
            if flag::register(libc::SIGHUP, Arc::clone(&reload)).is_ok() {
                thread::spawn(move || {
                    while !STOP_REQUESTED.load(Ordering::Relaxed) {
                        thread::sleep(std::time::Duration::from_millis(200));
                        if reload.swap(false, Ordering::Relaxed) {
                            RELOAD_REQUESTED.store(true, Ordering::Relaxed);
                        }
                    }
                });
            }
        }
        Self { flag }
    }
}

pub trait TimeSource: Sync + Copy + Send + 'static {
    fn now() -> Time;
}

#[derive(Clone, Copy)]
pub struct SystemTimeSource;

impl TimeSource for SystemTimeSource {
    fn now() -> Time {
        lazy_static::lazy_static! {
            static ref BOOT_INSTANT: Instant = Instant::now();
        }
        BOOT_INSTANT.elapsed().as_secs() as Time
    }
}

thread_local! {
    static MOCK_TIME: AtomicIsize = const { AtomicIsize::new(0) };
}

#[derive(Clone, Copy)]
pub struct MockTimeSource;

impl MockTimeSource {
    pub fn set_time(time: Time) {
        MOCK_TIME.with(|t| t.store(time as isize, Ordering::SeqCst))
    }
}

impl TimeSource for MockTimeSource {
    fn now() -> Time {
        MOCK_TIME.with(|t| t.load(Ordering::SeqCst) as Time)
    }
}

/// Helper function that multiplies the base62 data in buf[0..buflen] by 16 and adds m to it
fn base62_add_mult_16(buf: &mut [u8], mut buflen: usize, m: u8) -> usize {
    let mut d: usize = m as usize;
    for item in buf.iter_mut().take(buflen) {
        d += *item as usize * 16;
        *item = (d % 62) as u8;
        d /= 62;
    }
    assert!(d < 62);
    if d > 0 {
        buf[buflen] = d as u8;
        buflen += 1;
    }
    buflen
}

const BASE62: [char; 62] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
    'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
];

pub fn to_base62(data: &[u8]) -> String {
    let l = data.len();
    let mut buf = vec![0; l * 2];
    let mut buflen = 0;
    for b in data {
        buflen = base62_add_mult_16(&mut buf, buflen, b / 16);
        buflen = base62_add_mult_16(&mut buf, buflen, b % 16);
    }
    buf[0..buflen].reverse();
    let mut result = String::with_capacity(buflen);
    for b in &buf[0..buflen] {
        result.push(BASE62[*b as usize]);
    }
    result
}

/// Decode a fixed-size value from base62, restoring leading zero bytes that
/// `to_base62` omits. Without this, roughly 1 in 256 generated keys (and 1 in
/// 256 signatures) round-trips to the wrong length and is rejected.
pub fn from_base62_fixed<const N: usize>(data: &str) -> Result<[u8; N], char> {
    let bytes = from_base62(data)?;
    if bytes.len() > N {
        return Err('\0');
    }
    let mut out = [0u8; N];
    out[N - bytes.len()..].copy_from_slice(&bytes);
    Ok(out)
}

pub fn from_base62(data: &str) -> Result<Vec<u8>, char> {
    let mut buf = Vec::with_capacity(data.len() / 2 + data.len() / 4);
    for c in data.chars() {
        let mut val = match c {
            '0'..='9' => (c as usize) % ('0' as usize),
            'A'..='Z' => ((c as usize) % ('A' as usize)) + 10,
            'a'..='z' => ((c as usize) % ('a' as usize)) + 36,
            _ => return Err(c)
        };
        for item in &mut buf {
            val += *item as usize * 62;
            *item = (val % 256) as u8;
            val /= 256;
        }
        if val > 0 {
            buf.push(val as u8);
        }
    }
    buf.reverse();
    Ok(buf)
}

#[derive(Default)]
pub struct StatsdMsg {
    entries: Vec<String>,
    key: Vec<String>
}

impl StatsdMsg {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn add<T: fmt::Display>(&mut self, key: &str, val: T, type_: &str) -> &mut Self {
        self.entries.push(format!("{}.{}:{}|{}", self.key.join("."), key, val, type_));
        self
    }

    pub fn with_ns<F: FnOnce(&mut Self)>(&mut self, ns: &str, f: F) -> &mut Self {
        self.key.push(ns.to_string());
        f(self);
        self.key.pop();
        self
    }

    pub fn build(&self) -> String {
        self.entries.join("\n")
    }
}

pub fn run_cmd(mut cmd: Command) {
    match cmd.status() {
        Ok(status) => {
            if !status.success() {
                error!("Command returned error: {:?}", status.code())
            }
        }
        Err(e) => error!("Failed to execute command {:?}: {}", cmd, e)
    }
}

#[test]
fn msgbuffer_prepend_zero() {
    let mut b = MsgBuffer::new(20);
    b.clone_from(&[1, 2, 3]);
    b.prepend_zero(4);
    assert_eq!(b.message(), &[0, 0, 0, 0, 1, 2, 3]);
    b.skip(4);
    assert_eq!(b.message(), &[1, 2, 3]);
}

#[test]
fn base62() {
    assert_eq!("", to_base62(&[0]));
    assert_eq!("z", to_base62(&[61]));
    assert_eq!("10", to_base62(&[62]));
    assert_eq!("48", to_base62(&[1, 0]));
    assert_eq!("1Xp7Ke", to_base62(b"Test"));
    assert!(from_base62("").unwrap().is_empty());
    assert_eq!(vec![61], from_base62("z").unwrap());
    assert_eq!(vec![62], from_base62("10").unwrap());
    assert_eq!(vec![1, 0], from_base62("48").unwrap());
    assert_eq!(b"Test".to_vec(), from_base62("1Xp7Ke").unwrap());
}

#[test]
fn base62_fixed_roundtrips_leading_zeroes() {
    // to_base62 drops leading zero bytes, so a naive from_base62 roundtrip of a
    // 32-byte key with leading zeroes yields the wrong length. The fixed-size
    // decoder must restore them.
    assert_eq!(from_base62_fixed::<32>(&to_base62(&[0u8; 32])), Ok([0u8; 32]));
    assert_eq!(from_base62_fixed::<32>(&to_base62(&[0u8; 31])), Ok([0u8; 32]));
    let mut one = [0u8; 32];
    one[31] = 1;
    assert_eq!(from_base62_fixed::<32>(&to_base62(&one)), Ok(one));

    // Exercise many random values, including ones with leading zeroes.
    for _ in 0..5000 {
        let value: [u8; 32] = rand::random();
        let encoded = to_base62(&value);
        assert_eq!(from_base62_fixed::<32>(&encoded), Ok(value), "roundtrip failed for {encoded}");
    }
}
