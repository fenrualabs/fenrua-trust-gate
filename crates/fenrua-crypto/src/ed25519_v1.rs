//! Source-only Ed25519 primitive for a later signing-profile review.
//!
//! This module is deliberately not connected to the R2 evaluator, CLI,
//! profile registry, key resolver, key storage, revocation state, release
//! artifact, or network boundary. It accepts a caller-owned in-memory signing
//! key by reference and never serializes, stores, logs, or exports private-key
//! material.

use std::collections::BTreeMap;

use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use fenrua_c14n::{
    Digest, DigestDomain, canonical_document_in_domain, canonical_document_without_top_level_member,
};
use fenrua_protocol::{JsonValue, Problem, ProblemCode, object_fields, string_value};

pub const ED25519_V1_PROFILE: &str = "ed25519-v1";
pub const ED25519_V1_CANONICALIZATION_PROFILE: &str = "fenrua.c14n.ed25519-v1-r3-source-json";
pub const ED25519_V1_DIGEST_ALGORITHM: &str = "sha-256";

const SIGNATURE_MEMBER: &str = "signature";
const KEY_ID_PREFIX: &str = "urn:fenrua:key:";
const KEY_ID_MIN_LENGTH: usize = 16;
const KEY_ID_MAX_LENGTH: usize = 113;
const KEY_ID_SUFFIX_MAX_LENGTH: usize = 96;
const PUBLIC_KEY_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;
const BASE64URL_SIGNATURE_LENGTH: usize = 86;

/// Public verification material bound to one stable Fenrua key identifier.
///
/// The caller supplies this object directly. This source prerequisite does not
/// resolve identifiers, persist public keys, rotate keys, or check revocation.
#[derive(Clone)]
pub struct Ed25519V1VerificationKey {
    key_id: String,
    verifying_key: VerifyingKey,
}

impl Ed25519V1VerificationKey {
    pub fn from_bytes(key_id: &str, bytes: [u8; PUBLIC_KEY_BYTES]) -> Result<Self, Problem> {
        validate_key_id(key_id)?;
        let verifying_key = VerifyingKey::from_bytes(&bytes)
            .map_err(|_| Problem::new(ProblemCode::InvalidArgument))?;
        Ok(Self {
            key_id: key_id.to_owned(),
            verifying_key,
        })
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

/// A strict, serializable non-local signature record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ed25519V1Signature {
    key_id: String,
    payload_digest: Digest,
    value: String,
}

impl Ed25519V1Signature {
    pub const fn profile(&self) -> &'static str {
        ED25519_V1_PROFILE
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub const fn payload_digest(&self) -> Digest {
        self.payload_digest
    }

    pub fn value(&self) -> &str {
        &self.value
    }

    pub fn to_json_value(&self) -> JsonValue {
        signature_json(&self.key_id, self.payload_digest, &self.value)
    }
}

/// Signs an unsigned canonical JSON document with caller-owned in-memory key
/// material. The returned record must be attached as the document's top-level
/// `signature` member before verification.
pub fn sign_ed25519_v1(
    unsigned_document: &JsonValue,
    key_id: &str,
    signing_key: &SigningKey,
) -> Result<Ed25519V1Signature, Problem> {
    validate_key_id(key_id)?;
    require_unsigned_document(unsigned_document)?;
    let canonical =
        canonical_document_in_domain(unsigned_document, DigestDomain::Ed25519PayloadR3Source)?;
    let message = signing_message(key_id, canonical.bytes());
    let signature = signing_key.sign(&message);
    let value = Base64UrlUnpadded::encode_string(&signature.to_bytes());
    Ok(Ed25519V1Signature {
        key_id: key_id.to_owned(),
        payload_digest: canonical.digest(),
        value,
    })
}

/// Verifies an `ed25519-v1` record against a caller-selected public key.
///
/// The profile, canonicalization label, key ID, declared digest, and canonical
/// payload bytes are all covered by the verification path. Unknown profiles,
/// malformed records, mismatched key IDs, and changed payloads fail closed.
pub fn verify_ed25519_v1(
    signed_document: &JsonValue,
    verification_key: &Ed25519V1VerificationKey,
) -> Result<(), Problem> {
    let record = parse_signature_record(signed_document)?;
    if record.key_id != verification_key.key_id {
        return Err(integrity_mismatch());
    }

    let canonical = canonical_document_without_top_level_member(
        signed_document,
        SIGNATURE_MEMBER,
        DigestDomain::Ed25519PayloadR3Source,
    )?;
    if canonical.digest() != record.payload_digest {
        return Err(integrity_mismatch());
    }

    let message = signing_message(&record.key_id, canonical.bytes());
    verification_key
        .verifying_key
        .verify_strict(&message, &record.signature)
        .map_err(|_| integrity_mismatch())
}

struct ParsedSignatureRecord {
    key_id: String,
    payload_digest: Digest,
    signature: Signature,
}

fn parse_signature_record(value: &JsonValue) -> Result<ParsedSignatureRecord, Problem> {
    let document = object_fields(value).map_err(|_| integrity_mismatch())?;
    let signature_value = document
        .get(SIGNATURE_MEMBER)
        .ok_or_else(integrity_mismatch)?;
    let signature = object_fields(signature_value).map_err(|_| integrity_mismatch())?;
    require_exact_fields(signature, &["profile", "keyId", "payloadDigest", "value"])?;

    if record_string(signature, "profile")? != ED25519_V1_PROFILE {
        return Err(Problem::new(ProblemCode::UnsupportedProfile));
    }
    let key_id = record_string(signature, "keyId")?;
    validate_key_id(key_id).map_err(|_| integrity_mismatch())?;
    let payload_digest = parse_digest(
        signature
            .get("payloadDigest")
            .ok_or_else(integrity_mismatch)?,
    )?;
    let signature = decode_signature(record_string(signature, "value")?)?;

    Ok(ParsedSignatureRecord {
        key_id: key_id.to_owned(),
        payload_digest,
        signature,
    })
}

fn require_unsigned_document(value: &JsonValue) -> Result<(), Problem> {
    let fields = object_fields(value).map_err(|_| Problem::new(ProblemCode::InvalidArgument))?;
    if fields.contains_key(SIGNATURE_MEMBER) {
        return Err(Problem::new(ProblemCode::InvalidArgument));
    }
    Ok(())
}

fn validate_key_id(key_id: &str) -> Result<(), Problem> {
    if !(KEY_ID_MIN_LENGTH..=KEY_ID_MAX_LENGTH).contains(&key_id.len()) {
        return Err(Problem::new(ProblemCode::InvalidArgument));
    }
    let suffix = key_id
        .strip_prefix(KEY_ID_PREFIX)
        .ok_or_else(|| Problem::new(ProblemCode::InvalidArgument))?;
    let bytes = suffix.as_bytes();
    if bytes.is_empty() || bytes.len() > KEY_ID_SUFFIX_MAX_LENGTH {
        return Err(Problem::new(ProblemCode::InvalidArgument));
    }
    let Some(first) = bytes.first() else {
        return Err(Problem::new(ProblemCode::InvalidArgument));
    };
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return Err(Problem::new(ProblemCode::InvalidArgument));
    }
    if bytes
        .iter()
        .any(|byte| !byte.is_ascii_lowercase() && !byte.is_ascii_digit() && *byte != b'-')
    {
        return Err(Problem::new(ProblemCode::InvalidArgument));
    }
    Ok(())
}

fn parse_digest(value: &JsonValue) -> Result<Digest, Problem> {
    let fields = object_fields(value).map_err(|_| integrity_mismatch())?;
    require_exact_fields(fields, &["algorithm", "value"])?;
    if record_string(fields, "algorithm")? != ED25519_V1_DIGEST_ALGORITHM {
        return Err(integrity_mismatch());
    }
    Digest::from_hex(record_string(fields, "value")?).map_err(|_| integrity_mismatch())
}

fn decode_signature(value: &str) -> Result<Signature, Problem> {
    if value.len() != BASE64URL_SIGNATURE_LENGTH
        || value.bytes().any(|byte| {
            !byte.is_ascii_uppercase()
                && !byte.is_ascii_lowercase()
                && !byte.is_ascii_digit()
                && byte != b'-'
                && byte != b'_'
        })
    {
        return Err(integrity_mismatch());
    }
    let decoded = Base64UrlUnpadded::decode_vec(value).map_err(|_| integrity_mismatch())?;
    let bytes: [u8; SIGNATURE_BYTES] = decoded.try_into().map_err(|_| integrity_mismatch())?;
    Ok(Signature::from_bytes(&bytes))
}

fn record_string<'a>(
    fields: &'a BTreeMap<String, JsonValue>,
    name: &str,
) -> Result<&'a str, Problem> {
    let value = fields.get(name).ok_or_else(integrity_mismatch)?;
    string_value(value).map_err(|_| integrity_mismatch())
}

fn require_exact_fields(
    fields: &BTreeMap<String, JsonValue>,
    expected: &[&str],
) -> Result<(), Problem> {
    if fields.len() != expected.len() || expected.iter().any(|name| !fields.contains_key(*name)) {
        return Err(integrity_mismatch());
    }
    Ok(())
}

fn signing_message(key_id: &str, canonical_payload: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        20_usize
            .saturating_add(ED25519_V1_PROFILE.len())
            .saturating_add(ED25519_V1_CANONICALIZATION_PROFILE.len())
            .saturating_add(key_id.len())
            .saturating_add(canonical_payload.len()),
    );
    message.extend_from_slice(b"fenrua-trust-gate\0");
    message.extend_from_slice(ED25519_V1_PROFILE.as_bytes());
    message.push(0);
    message.extend_from_slice(ED25519_V1_CANONICALIZATION_PROFILE.as_bytes());
    message.push(0);
    message.extend_from_slice(key_id.as_bytes());
    message.push(0);
    message.extend_from_slice(canonical_payload);
    message
}

fn signature_json(key_id: &str, payload_digest: Digest, value: &str) -> JsonValue {
    JsonValue::Object(BTreeMap::from([
        (
            "profile".to_owned(),
            JsonValue::String(ED25519_V1_PROFILE.to_owned()),
        ),
        ("keyId".to_owned(), JsonValue::String(key_id.to_owned())),
        (
            "payloadDigest".to_owned(),
            JsonValue::Object(BTreeMap::from([
                (
                    "algorithm".to_owned(),
                    JsonValue::String(ED25519_V1_DIGEST_ALGORITHM.to_owned()),
                ),
                (
                    "value".to_owned(),
                    JsonValue::String(payload_digest.to_hex()),
                ),
            ])),
        ),
        ("value".to_owned(), JsonValue::String(value.to_owned())),
    ]))
}

fn integrity_mismatch() -> Problem {
    Problem::new(ProblemCode::IntegrityMismatch)
}

#[cfg(test)]
mod tests {
    use super::{ED25519_V1_PROFILE, Ed25519V1VerificationKey, sign_ed25519_v1, verify_ed25519_v1};
    use ed25519_dalek::SigningKey;
    use fenrua_protocol::{JsonValue, ParseLimits, ProblemCode, parse_json};

    const KEY_ID: &str = "urn:fenrua:key:source-ed25519-primary";
    const SECONDARY_KEY_ID: &str = "urn:fenrua:key:source-ed25519-secondary";

    #[test]
    fn signs_and_verifies_a_canonical_document() {
        let document = parse_document(
            "{\"subject\":\"fenrua\",\"nested\":{\"enabled\":true},\"sequence\":[3,2,1]}",
        );
        let (signing_key, verification_key) = signing_material(KEY_ID);
        let signed = signed_document(document, KEY_ID, &signing_key);

        assert_eq!(verify_ed25519_v1(&signed, &verification_key), Ok(()));
    }

    #[test]
    fn canonical_equivalents_produce_the_same_signature_record() {
        let first = parse_document(
            "{\"subject\":\"fenrua\",\"nested\":{\"enabled\":true},\"sequence\":[3,2,1]}",
        );
        let second = parse_document(
            " { \"sequence\" : [3, 2, 1], \"nested\" : { \"enabled\" : true }, \"subject\" : \"fenrua\" } ",
        );
        let (signing_key, _) = signing_material(KEY_ID);
        let first_signature = signed_signature(&first, KEY_ID, &signing_key);
        let second_signature = signed_signature(&second, KEY_ID, &signing_key);

        assert_eq!(
            first_signature.payload_digest(),
            second_signature.payload_digest()
        );
        assert_eq!(first_signature.value(), second_signature.value());
    }

    #[test]
    fn rejects_payload_and_declared_digest_tampering() {
        let document = parse_document("{\"subject\":\"fenrua\",\"nested\":{\"enabled\":true}}");
        let (signing_key, verification_key) = signing_material(KEY_ID);
        let mut payload_tampered = signed_document(document.clone(), KEY_ID, &signing_key);
        let JsonValue::Object(fields) = &mut payload_tampered else {
            panic!("signed test document must be an object");
        };
        fields.insert(
            "subject".to_owned(),
            JsonValue::String("changed".to_owned()),
        );
        let payload_error = verify_ed25519_v1(&payload_tampered, &verification_key);
        assert_eq!(
            payload_error.map_err(|error| error.code()),
            Err(ProblemCode::IntegrityMismatch)
        );

        let mut digest_tampered = signed_document(document, KEY_ID, &signing_key);
        signature_fields_mut(&mut digest_tampered).insert(
            "payloadDigest".to_owned(),
            JsonValue::Object(std::collections::BTreeMap::from([
                (
                    "algorithm".to_owned(),
                    JsonValue::String("sha-256".to_owned()),
                ),
                ("value".to_owned(), JsonValue::String("0".repeat(64))),
            ])),
        );
        let digest_error = verify_ed25519_v1(&digest_tampered, &verification_key);
        assert_eq!(
            digest_error.map_err(|error| error.code()),
            Err(ProblemCode::IntegrityMismatch)
        );
    }

    #[test]
    fn rejects_key_id_relabel_profile_downgrade_and_malformed_signature() {
        let document = parse_document("{\"subject\":\"fenrua\",\"nested\":{\"enabled\":true}}");
        let (signing_key, primary_key) = signing_material(KEY_ID);

        let mut relabeled = signed_document(document.clone(), KEY_ID, &signing_key);
        signature_fields_mut(&mut relabeled).insert(
            "keyId".to_owned(),
            JsonValue::String(SECONDARY_KEY_ID.to_owned()),
        );
        let secondary_key = verification_key(&signing_key, SECONDARY_KEY_ID);
        let relabel_error = verify_ed25519_v1(&relabeled, &secondary_key);
        assert_eq!(
            relabel_error.map_err(|error| error.code()),
            Err(ProblemCode::IntegrityMismatch)
        );

        let mut downgraded = signed_document(document.clone(), KEY_ID, &signing_key);
        signature_fields_mut(&mut downgraded).insert(
            "profile".to_owned(),
            JsonValue::String("local-unsigned-development".to_owned()),
        );
        let downgrade_error = verify_ed25519_v1(&downgraded, &primary_key);
        assert_eq!(
            downgrade_error.map_err(|error| error.code()),
            Err(ProblemCode::UnsupportedProfile)
        );

        let mut malformed = signed_document(document, KEY_ID, &signing_key);
        signature_fields_mut(&mut malformed).insert(
            "value".to_owned(),
            JsonValue::String("not+base64url".to_owned()),
        );
        let malformed_error = verify_ed25519_v1(&malformed, &primary_key);
        assert_eq!(
            malformed_error.map_err(|error| error.code()),
            Err(ProblemCode::IntegrityMismatch)
        );

        let mut extra_field = signed_document(
            parse_document("{\"subject\":\"fenrua\"}"),
            KEY_ID,
            &signing_key,
        );
        signature_fields_mut(&mut extra_field).insert(
            "unexpected".to_owned(),
            JsonValue::String("field".to_owned()),
        );
        let extra_field_error = verify_ed25519_v1(&extra_field, &primary_key);
        assert_eq!(
            extra_field_error.map_err(|error| error.code()),
            Err(ProblemCode::IntegrityMismatch)
        );
    }

    #[test]
    fn signing_rejects_existing_signature_and_invalid_key_id() {
        let existing_signature = parse_document("{\"signature\":{}}");
        let (signing_key, _) = signing_material(KEY_ID);
        let existing_error = sign_ed25519_v1(&existing_signature, KEY_ID, &signing_key);
        assert_eq!(
            existing_error.map_err(|error| error.code()),
            Err(ProblemCode::InvalidArgument)
        );

        let unsigned = parse_document("{\"subject\":\"fenrua\"}");
        let invalid_key_error =
            sign_ed25519_v1(&unsigned, "urn:fenrua:key:UPPERCASE", &signing_key);
        assert_eq!(
            invalid_key_error.map_err(|error| error.code()),
            Err(ProblemCode::InvalidArgument)
        );
    }

    fn parse_document(source: &str) -> JsonValue {
        match parse_json(source.as_bytes(), ParseLimits::R1_FOUNDATION) {
            Ok(value) => value,
            Err(error) => panic!("test JSON must parse: {error}"),
        }
    }

    fn signing_material(key_id: &str) -> (SigningKey, Ed25519V1VerificationKey) {
        let mut seed = [0_u8; 32];
        if let Err(error) = getrandom::fill(&mut seed) {
            panic!("test requires local OS entropy: {error}");
        }
        let signing_key = SigningKey::from_bytes(&seed);
        let verification_key = verification_key(&signing_key, key_id);
        (signing_key, verification_key)
    }

    fn verification_key(signing_key: &SigningKey, key_id: &str) -> Ed25519V1VerificationKey {
        match Ed25519V1VerificationKey::from_bytes(key_id, signing_key.verifying_key().to_bytes()) {
            Ok(key) => key,
            Err(error) => panic!("generated test key must be valid: {error}"),
        }
    }

    fn signed_signature(
        document: &JsonValue,
        key_id: &str,
        signing_key: &SigningKey,
    ) -> super::Ed25519V1Signature {
        match sign_ed25519_v1(document, key_id, signing_key) {
            Ok(signature) => signature,
            Err(error) => panic!("test document must sign: {error}"),
        }
    }

    fn signed_document(document: JsonValue, key_id: &str, signing_key: &SigningKey) -> JsonValue {
        let signature = signed_signature(&document, key_id, signing_key);
        let JsonValue::Object(mut fields) = document else {
            panic!("test document must be an object");
        };
        fields.insert("signature".to_owned(), signature.to_json_value());
        JsonValue::Object(fields)
    }

    fn signature_fields_mut(
        value: &mut JsonValue,
    ) -> &mut std::collections::BTreeMap<String, JsonValue> {
        let JsonValue::Object(fields) = value else {
            panic!("signed test document must be an object");
        };
        let Some(JsonValue::Object(signature)) = fields.get_mut("signature") else {
            panic!("signed test document must contain a signature object");
        };
        signature
    }

    #[test]
    fn retains_the_exact_profile_label() {
        assert_eq!(ED25519_V1_PROFILE, "ed25519-v1");
    }
}
