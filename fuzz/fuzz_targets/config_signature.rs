#![no_main]
use libfuzzer_sys::fuzz_target;
use vpncloud::sign;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    // Must never panic on malformed signatures or canonicalization input.
    let _ = sign::find_signature(text);
    let _ = sign::canonical_body(text);
    let _ = sign::extract_signature(text);
    let keys = vec!["AAAA".to_string()];
    let _ = sign::verify_config(text, &keys);
});
