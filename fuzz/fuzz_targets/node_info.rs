#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use vpncloud::messages::NodeInfo;

fuzz_target!(|data: &[u8]| {
    // Must never panic or allocate based on an untrusted length.
    let _ = NodeInfo::decode(Cursor::new(data));
});
