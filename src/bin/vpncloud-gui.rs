// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

fn main() {
    vpncloud::gui::init_log();
    if let Err(e) = vpncloud::gui::run() {
        eprintln!("VpnCloud GUI: {}", e);
        std::process::exit(1);
    }
}
