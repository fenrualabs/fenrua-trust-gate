use fenrua_c14n::canonical_document;
use fenrua_protocol::{ParseLimits, parse_json};

fn parse(input: &[u8]) -> fenrua_protocol::JsonValue {
    match parse_json(input, ParseLimits::R1_FOUNDATION) {
        Ok(value) => value,
        Err(error) => panic!("valid fixture must parse: {error}"),
    }
}

#[test]
fn golden_fixture_has_stable_canonical_bytes_and_digest() {
    let first = parse(include_bytes!(
        "../../../fixtures/v1/valid/canonical-order-a.json"
    ));
    let second = parse(include_bytes!(
        "../../../fixtures/v1/valid/canonical-order-b.json"
    ));
    let first = match canonical_document(&first) {
        Ok(document) => document,
        Err(error) => panic!("first fixture must canonicalize: {error}"),
    };
    let second = match canonical_document(&second) {
        Ok(document) => document,
        Err(error) => panic!("second fixture must canonicalize: {error}"),
    };

    assert_eq!(first.bytes(), br#"{"a":"text","z":1}"#);
    assert_eq!(first, second);
    assert_eq!(
        first.digest().to_prefixed_hex(),
        "sha256:aa37f2d20a68a5d9f5579d08d2e07ca74ef8fc99555fe19bd901f3fc2b02e5bb"
    );
}
