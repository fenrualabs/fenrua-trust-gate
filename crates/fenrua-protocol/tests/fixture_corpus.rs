use fenrua_protocol::{ParseLimits, ProblemCode, parse_json};

#[test]
fn duplicate_key_fixture_is_rejected_before_schema_handling() {
    let input = include_bytes!("../../../fixtures/v1/invalid/duplicate-key.json");
    let error = match parse_json(input, ParseLimits::R1_FOUNDATION) {
        Ok(_) => panic!("duplicate-key fixture must fail"),
        Err(error) => error,
    };
    assert_eq!(error.code(), ProblemCode::DuplicateKey);
}
