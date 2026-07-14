//! Independent package boundary for future verification work.
//!
//! The R1 crate can only compare a generic canonical JSON digest. It is not an
//! evidence-bundle verifier and does not depend on `fenrua-gate`; those remain
//! later-train work requiring released schemas and independently reviewed
//! verification behavior.

use fenrua_c14n::{Digest, canonical_document};
use fenrua_protocol::{JsonValue, Problem};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntegrityVerification {
    Match,
    Mismatch,
}

/// Compares a canonical JSON digest without interpreting a Trust Gate schema.
pub fn verify_canonical_digest(
    value: &JsonValue,
    expected: Digest,
) -> Result<IntegrityVerification, Problem> {
    let actual = canonical_document(value)?.digest();
    Ok(if actual == expected {
        IntegrityVerification::Match
    } else {
        IntegrityVerification::Mismatch
    })
}

#[cfg(test)]
mod tests {
    use fenrua_c14n::canonical_document;
    use fenrua_protocol::{ParseLimits, parse_json};

    use super::{IntegrityVerification, verify_canonical_digest};

    #[test]
    fn generic_integrity_check_detects_a_changed_document() {
        let original = match parse_json(br#"{"a":1}"#, ParseLimits::R1_FOUNDATION) {
            Ok(value) => value,
            Err(error) => panic!("original fixture must parse: {error}"),
        };
        let changed = match parse_json(br#"{"a":2}"#, ParseLimits::R1_FOUNDATION) {
            Ok(value) => value,
            Err(error) => panic!("changed fixture must parse: {error}"),
        };
        let digest = match canonical_document(&original) {
            Ok(document) => document.digest(),
            Err(error) => panic!("original fixture must canonicalize: {error}"),
        };
        let result = match verify_canonical_digest(&changed, digest) {
            Ok(result) => result,
            Err(error) => panic!("changed fixture must canonicalize: {error}"),
        };
        assert_eq!(result, IntegrityVerification::Mismatch);
    }
}
