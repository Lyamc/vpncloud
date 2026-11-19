// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! C ABI for the iOS Packet Tunnel Provider.
//!
//! TUN uses `NEPacketTunnelProvider` (utun). TAP is not available on iOS.

use std::{
    ffi::{CStr, CString},
    os::raw::{c_char, c_int},
    sync::Mutex
};

use crate::{config::Config, device::Type, engine::run_vpn, util::CtrlC};

static LAST_ERROR: Mutex<Option<CString>> = Mutex::new(None);

struct IosLogger;

impl log::Log for IosLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            eprintln!("vpncloud {} - {}", record.level(), record.args());
        }
    }

    fn flush(&self) {}
}

fn init_log() {
    let _ = log::set_boxed_logger(Box::new(IosLogger));
    log::set_max_level(log::LevelFilter::Info);
}

fn set_error(msg: &str) -> c_int {
    error!("{}", msg);
    if let Ok(mut guard) = LAST_ERROR.lock() {
        *guard = CString::new(msg.replace('\0', "")).ok();
    }
    -1
}

/// Last error from `vpncloud_start`, or null. The returned string is a heap
/// copy that stays valid across later calls; release it with
/// `vpncloud_free_error` when done. This avoids a dangling pointer if another
/// error replaces the stored message.
#[no_mangle]
pub extern "C" fn vpncloud_last_error() -> *const c_char {
    let copy = match LAST_ERROR.lock() {
        Ok(guard) => {
            match guard.as_ref() {
                Some(s) => {
                    let bytes = s.as_bytes_with_nul();
                    let ptr = unsafe { libc::malloc(bytes.len()) } as *mut u8;
                    if ptr.is_null() {
                        std::ptr::null()
                    } else {
                        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len()) };
                        ptr as *const c_char
                    }
                }
                None => std::ptr::null()
            }
        }
        Err(_) => std::ptr::null()
    };
    copy
}

/// Free a string returned by `vpncloud_last_error`.
#[no_mangle]
pub extern "C" fn vpncloud_free_error(ptr: *const c_char) {
    if !ptr.is_null() {
        unsafe { libc::free(ptr as *mut _) };
    }
}

/// Start VpnCloud with YAML config and a Packet Tunnel utun fd. Blocks until `vpncloud_stop`.
///
/// Returns 0 on clean shutdown, -1 on setup error (see `vpncloud_last_error`).
#[no_mangle]
pub extern "C" fn vpncloud_start(yaml: *const c_char, tun_fd: c_int) -> c_int {
    init_log();
    if yaml.is_null() {
        return set_error("null config YAML");
    }
    let yaml = unsafe { CStr::from_ptr(yaml) }.to_string_lossy();
    let file: crate::config::ConfigFile = match crate::config::parse_config_auto(&yaml) {
        Ok(f) => f,
        Err(e) => return set_error(&format!("config YAML/TOML: {}", e))
    };
    let mut config = Config::default();
    config.merge_file(file);

    if config.device_type == Type::Tap {
        return set_error(crate::device::IOS_TAP_HELP);
    }
    if tun_fd < 0 {
        return set_error("invalid TUN fd");
    }
    if config.crypto.password.is_none() && config.crypto.private_key.is_none() {
        return set_error("password or private-key is required");
    }
    if config.listen.starts_with("ws://") || config.listen.starts_with("ws-listen://") {
        return set_error("Websocket listen is not supported on iOS; use UDP (--listen PORT).");
    }

    config.port_forwarding = false;
    config.daemonize = false;
    config.device_type = Type::Tun;
    config.tun_fd = Some(tun_fd);
    info!("Starting VpnCloud on iOS TUN fd {}", tun_fd);

    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_vpn(config);
    }))
    .is_err();
    if panicked {
        return set_error("VpnCloud panicked");
    }
    info!("VpnCloud stopped");
    0
}

/// Signal the worker started by `vpncloud_start` to exit.
#[no_mangle]
pub extern "C" fn vpncloud_stop() {
    init_log();
    info!("iOS vpncloud_stop");
    CtrlC::request_stop();
}
