// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

pub mod impl_;
pub mod types;

pub use impl_::STATS_INTERVAL;
pub use types::{GenericCloud, Hash, ReconnectEntry};
