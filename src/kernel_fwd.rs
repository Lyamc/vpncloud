// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! The cargo test drives `kernel/vpncloud_forward.c` through the userspace
//! driver. The same function is what `vpncloud_mod.c` calls at init.

use std::{path::PathBuf, process::Command};

pub fn forward_driver() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/vpncloud-fwd-user")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_mode_datapath() {
        println!("row: kernel-mode datapath");
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let bin = forward_driver();
        if let Some(parent) = bin.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let status = Command::new("clang")
            .args(["-O2", "-DVPNCLOUD_USERSPACE", "-o"])
            .arg(&bin)
            .arg(root.join("kernel/fwd_user.c"))
            .arg(root.join("kernel/vpncloud_forward.c"))
            .status()
            .expect("clang");
        assert!(status.success());
        let packet = "4500001400000000400000007f0000017f000001";
        let fwd = Command::new(&bin).arg(packet).output().expect("run forward");
        assert!(fwd.status.success(), "{}", String::from_utf8_lossy(&fwd.stderr));
        let text = String::from_utf8(fwd.stdout).unwrap();
        assert!(text.starts_with("FORWARD "), "{text}");
        assert!(text.contains(packet));
        let dropped = Command::new(&bin).arg("0000").output().expect("run drop");
        assert!(dropped.status.success());
        let drop_text = String::from_utf8(dropped.stdout).unwrap();
        assert!(drop_text.contains("DROP"), "{drop_text}");
    }
}
