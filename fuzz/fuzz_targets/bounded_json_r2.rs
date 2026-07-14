#![no_main]

use fenrua_c14n::canonical_document;
use fenrua_protocol::{ParseLimits, R2DocumentKind, parse_json, parse_r2_document};
use libfuzzer_sys::fuzz_target;

const DIRECT_DOCUMENT_KINDS: [R2DocumentKind; 4] = [
    R2DocumentKind::EntityManifest,
    R2DocumentKind::AuthorityPolicy,
    R2DocumentKind::ToolCallRequest,
    R2DocumentKind::RevocationSet,
];

fuzz_target!(|data: &[u8]| {
    for kind in DIRECT_DOCUMENT_KINDS {
        let _ = parse_r2_document(data, kind);
    }

    let parsed = match parse_json(data, ParseLimits::R1_FOUNDATION) {
        Ok(value) => value,
        Err(_) => return,
    };
    let canonical = match canonical_document(&parsed) {
        Ok(document) => document,
        Err(_) => return,
    };
    let reparsed = match parse_json(canonical.bytes(), ParseLimits::R1_FOUNDATION) {
        Ok(value) => value,
        Err(error) => panic!("canonical bytes must parse: {error}"),
    };
    let round_trip = match canonical_document(&reparsed) {
        Ok(document) => document,
        Err(error) => panic!("canonical bytes must re-canonicalize: {error}"),
    };

    assert_eq!(round_trip.bytes(), canonical.bytes());
    assert_eq!(round_trip.digest(), canonical.digest());
});
