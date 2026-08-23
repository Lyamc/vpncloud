// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! JNI entry points for the Android VpnService host.
//!
//! TAP/L2 is not available: `VpnService` only hands out a TUN fd.

use std::{
    io,
    os::unix::io::RawFd,
    sync::Mutex
};

use jni::{
    objects::{GlobalRef, JClass, JObject, JString, JValue},
    sys::jint,
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
    if tun_fd < 0 {
        throw(&mut env, "invalid TUN fd");
        return;
    }

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

    let file: crate::config::ConfigFile = match serde_norway::from_str(&yaml) {
        Ok(f) => f,
        Err(e) => {
            throw(&mut env, &format!("config YAML: {}", e));
            return;
        }
    };
    let mut config = Config::default();
    config.merge_file(file);
    if config.device_type == Type::Tap {
        throw(
            &mut env,
            "TAP/L2 is not supported on Android. VpnService only provides a TUN (layer-3) interface."
        );
        return;
    }
    config.device_type = Type::Tun;
    config.tun_fd = Some(tun_fd);
    config.port_forwarding = false;
    config.daemonize = false;

    if config.crypto.password.is_none() && config.crypto.private_key.is_none() {
        throw(&mut env, "password or private-key is required");
        return;
    }

    info!("Starting VpnCloud on Android TUN fd {}", tun_fd);
    run_vpn(config);
    info!("VpnCloud stopped");
    set_socket_protect(None);
    *ANDROID_VPN.lock().expect("android vpn lock") = None;
}

/// `NativeEngine.nativeStop()`
#[no_mangle]
pub extern "system" fn Java_ca_witherow_vpncloud_NativeEngine_nativeStop(_env: JNIEnv, _class: JClass) {
    info!("Android nativeStop");
    CtrlC::request_stop();
}
