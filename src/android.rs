// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! JNI entry points for the Android host.
//!
//! TUN uses VpnService. TAP opens `/dev/net/tun` and requires root.

use std::{
    io,
    os::unix::io::RawFd,
    sync::Mutex
};

use jni::{
    objects::{GlobalRef, JClass, JObject, JString, JValue},
    sys::{jboolean, jint, JNI_FALSE, JNI_TRUE},
    JNIEnv, JavaVM
};

use crate::{
    config::Config,
    device::Type,
    engine::run_vpn,
    net::set_socket_protect,
    util::CtrlC
};

struct AndroidVpn {
    vm: JavaVM,
    service: GlobalRef
}

static ANDROID_VPN: Mutex<Option<AndroidVpn>> = Mutex::new(None);

fn protect_fd(fd: RawFd) -> io::Result<()> {
    let guard = ANDROID_VPN.lock().map_err(|_| io::Error::new(io::ErrorKind::Other, "android vpn lock"))?;
    let ctx = guard.as_ref().ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "VpnService not attached"))?;
    let mut env = ctx.vm.attach_current_thread().map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    let ok = env
        .call_method(&ctx.service, "protect", "(I)Z", &[JValue::Int(fd)])
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    match ok.z() {
        Ok(true) => {
            info!("Protected UDP fd {} from the VPN routing table", fd);
            Ok(())
        }
        Ok(false) => Err(io::Error::new(io::ErrorKind::Other, "VpnService.protect returned false")),
        Err(e) => Err(io::Error::new(io::ErrorKind::Other, e.to_string()))
    }
}

fn throw(env: &mut JNIEnv, msg: &str) {
    let _ = env.throw_new("java/lang/IllegalArgumentException", msg);
}

/// `NativeEngine.nativeStart(configYaml, tunFd, vpnService)` — blocks until stop.
#[no_mangle]
pub extern "system" fn Java_ca_witherow_vpncloud_NativeEngine_nativeStart(
    mut env: JNIEnv, _class: JClass, yaml: JString, tun_fd: jint, service: JObject
) {
    let _ = android_logger::init_once(
        android_logger::Config::default().with_max_level(log::LevelFilter::Info).with_tag("vpncloud")
    );

    let yaml: String = match env.get_string(&yaml) {
        Ok(s) => s.into(),
        Err(_) => {
            throw(&mut env, "invalid config YAML");
            return;
        }
    };
    let file: crate::config::ConfigFile = match crate::config::parse_config_auto(&yaml) {
        Ok(f) => f,
        Err(e) => {
            throw(&mut env, &format!("config YAML/TOML: {}", e));
            return;
        }
    };
    let mut config = Config::default();
    config.merge_file(file);
    let tap = config.device_type == Type::Tap;

    if tap && tun_fd >= 0 {
        throw(
            &mut env,
            "TAP cannot use a VpnService TUN fd. TAP on Android requires a rooted device. See --help."
        );
        return;
    }
    if tap && !crate::device::android_has_tuntap_access() {
        throw(&mut env, crate::device::ANDROID_TAP_HELP);
        return;
    }
    if !tap && tun_fd < 0 {
        throw(&mut env, "invalid TUN fd");
        return;
    }

    if config.crypto.password.is_none() && config.crypto.private_key.is_none() {
        throw(&mut env, "password or private-key is required");
        return;
    }
    config.port_forwarding = false;
    config.daemonize = false;

    if tap {
        config.tun_fd = None;
        set_socket_protect(None);
        info!("Starting VpnCloud TAP on rooted Android (/dev/net/tun)");
    } else {
        let vm = match env.get_java_vm() {
            Ok(vm) => vm,
            Err(e) => {
                throw(&mut env, &format!("JavaVM: {}", e));
                return;
            }
        };
        let service = match env.new_global_ref(&service) {
            Ok(r) => r,
            Err(e) => {
                throw(&mut env, &format!("VpnService ref: {}", e));
                return;
            }
        };
        *ANDROID_VPN.lock().expect("android vpn lock") = Some(AndroidVpn { vm, service });
        set_socket_protect(Some(protect_fd));
        config.device_type = Type::Tun;
        config.tun_fd = Some(tun_fd);
        info!("Starting VpnCloud on Android TUN fd {}", tun_fd);
    }

    run_vpn(config);
    info!("VpnCloud stopped");
    set_socket_protect(None);
    *ANDROID_VPN.lock().expect("android vpn lock") = None;
}

/// `NativeEngine.nativeIsRooted()`
#[no_mangle]
pub extern "system" fn Java_ca_witherow_vpncloud_NativeEngine_nativeIsRooted(
    _env: JNIEnv, _class: JClass
) -> jboolean {
    if crate::device::android_has_tuntap_access() {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

/// `NativeEngine.nativeStop()`
#[no_mangle]
pub extern "system" fn Java_ca_witherow_vpncloud_NativeEngine_nativeStop(_env: JNIEnv, _class: JClass) {
    info!("Android nativeStop");
    CtrlC::request_stop();
}
