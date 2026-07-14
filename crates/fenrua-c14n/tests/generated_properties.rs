use fenrua_c14n::{CanonicalDocument, canonical_document};
use fenrua_protocol::{JsonValue, ParseLimits, ProblemCode, parse_json};

fn parse(input: &[u8]) -> JsonValue {
    match parse_json(input, ParseLimits::R1_FOUNDATION) {
        Ok(value) => value,
        Err(error) => panic!("generated valid input must parse: {error}"),
    }
}

fn canonical(input: &[u8]) -> CanonicalDocument {
    match canonical_document(&parse(input)) {
        Ok(document) => document,
        Err(error) => panic!("generated valid input must canonicalize: {error}"),
    }
}

#[test]
fn generated_semantic_equivalents_have_one_idempotent_canonical_document() {
    const MEMBER_ORDERS: [[usize; 3]; 6] = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    const NUMBER_SPELLINGS: [&str; 5] = ["1", "1.0", "1e0", "10e-1", "1000e-3"];
    const STRING_SPELLINGS: [&str; 2] = [r#""A""#, r#""\u0041""#];
    const WHITESPACE: [&str; 3] = ["", " ", "\n\t"];
    const EXPECTED: &[u8] = br#"{"a":"A","m":[true,false,null],"z":1}"#;

    let mut cases = 0_usize;
    for order in MEMBER_ORDERS {
        for number in NUMBER_SPELLINGS {
            for string in STRING_SPELLINGS {
                for whitespace in WHITESPACE {
                    let members = [
                        format!(r#""z":{number}"#),
                        format!(r#""a":{string}"#),
                        String::from(r#""m":[true,false,null]"#),
                    ];
                    let input = format!(
                        "{{{whitespace}{}{whitespace},{whitespace}{}{whitespace},{whitespace}{}{whitespace}}}",
                        members[order[0]], members[order[1]], members[order[2]],
                    );
                    let document = canonical(input.as_bytes());
                    assert_eq!(document.bytes(), EXPECTED);

                    let reparsed = canonical(document.bytes());
                    assert_eq!(reparsed, document);
                    cases = cases.saturating_add(1);
                }
            }
        }
    }

    assert_eq!(
        cases,
        MEMBER_ORDERS.len() * NUMBER_SPELLINGS.len() * STRING_SPELLINGS.len() * WHITESPACE.len()
    );
}

#[test]
fn generated_duplicate_key_variants_fail_closed_before_canonicalization() {
    const NUMBER_SPELLINGS: [&str; 5] = ["0", "1", "1.0", "1e0", "10e-1"];

    for first in NUMBER_SPELLINGS {
        for second in NUMBER_SPELLINGS {
            let input = format!(r#"{{"a":{first},"a":{second}}}"#);
            let error = match parse_json(input.as_bytes(), ParseLimits::R1_FOUNDATION) {
                Ok(_) => panic!("generated duplicate key must fail closed"),
                Err(error) => error,
            };
            assert_eq!(error.code(), ProblemCode::DuplicateKey);
        }
    }
}
