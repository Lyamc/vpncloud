#![no_main]
use libfuzzer_sys::fuzz_target;
use vpncloud::payload::{Frame, Packet, Protocol};

fuzz_target!(|data: &[u8]| {
    let _ = Frame::parse(data);
    let _ = Packet::parse(data);
});
