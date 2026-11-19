// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! Rooted-Android `/dev/net/tun` creation and `ip` invocation helpers.
//! Extracted from `device.rs`; compiled only on Android.

#![cfg(target_os = "android")]

use std::{
    ffi::CString,
    io::{self, Error, ErrorKind},
    mem,
    os::unix::io::RawFd,
    process::Command
};

use tun_rs::SyncDevice;

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
    // Grant access only to this app's uid, not the whole world.
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    let cmd = format!("chown {}:{} /dev/net/tun && chmod 600 /dev/net/tun", uid, gid);
    let _ = Command::new("su").args(["-c", &cmd]).status();
    open_dev().is_ok()
}

fn open_dev() -> io::Result<std::fs::File> {
    std::fs::OpenOptions::new().read(true).write(true).open("/dev/net/tun")
}

pub fn create(ifname: &str, tap: bool, device_path: Option<&str>) -> io::Result<(SyncDevice, String)> {
    if tap && !has_access() {
        return Err(crate::device::android_tap_needs_root());
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
            return Err(Error::new(err.kind(), format!("{} ({})", crate::device::ANDROID_TAP_HELP, err)));
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
            return Err(Error::new(
                err.kind(),
                format!("TAP ioctl failed: {} ({})", err, crate::device::ANDROID_TAP_HELP)
            ));
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
        std::ptr::copy_nonoverlapping(mac.as_ptr(), req.ifr_ifru.ifru_hwaddr.sa_data.as_mut_ptr(), 6);
    }
    let rc = unsafe { libc::ioctl(sock, SIOCSIFHWADDR as _, &mut req as *mut _) };
    unsafe { libc::close(sock) };
    if rc < 0 {
        Err(Error::last_os_error())
    } else {
        Ok(())
    }
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

pub fn run_ip(args: &[&str]) -> io::Result<()> {
    let try_ip = Command::new("ip").args(args).status();
    if let Ok(status) = try_ip {
        if status.success() {
            return Ok(());
        }
    }
    let quoted: Vec<String> = args.iter().map(|a| shell_quote(a)).collect();
    let script = format!("ip {}", quoted.join(" "));
    let status = Command::new("su").args(["-c", &script]).status();
    match status {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => Err(Error::other(format!("ip {} failed: {:?}", script, s.code()))),
        Err(e) => Err(e)
    }
}
