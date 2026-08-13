#![no_main]

use agent_trust_action_ir::{ParseLimits, parse_draft};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = ParseLimits {
        max_body_bytes: 64 * 1024,
        max_depth: 32,
        max_array_items: 1024,
        max_string_bytes: 16 * 1024,
        max_object_keys: 256,
        max_number_chars: 128,
    };
    let _ = parse_draft(data, &limits);
});
