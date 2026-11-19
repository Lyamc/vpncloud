#![no_main]
use libfuzzer_sys::fuzz_target;
use vpncloud::gso::GsoMeta;

fuzz_target!(|data: &[u8]| {
    if let Some(meta) = GsoMeta::read(data) {
        let _ = meta.sane(data.len());
        let _ = meta.segmented();
    }
});
