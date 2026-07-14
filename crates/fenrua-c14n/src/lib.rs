//! Deterministic R1 foundation and R2 local-prototype canonical JSON primitives.
//!
//! This is deliberately not a released canonicalisation profile. It is bounded,
//! fully local, and suitable for developing immutable test vectors before a
//! profile specification receives its separate review and release gate.

use fenrua_protocol::{JsonNumber, JsonValue, Problem, ProblemCode};
use sha2::{Digest as _, Sha256};

pub const R1_DRAFT_CANONICALIZATION_PROFILE: &str = "fenrua.c14n.r1-draft-json";

/// Bounds canonicalisation even when a caller constructs a `JsonValue` without
/// using the strict parser first.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalizationLimits {
    pub max_depth: usize,
    pub max_collection_items: usize,
    pub max_output_bytes: usize,
    pub max_exponent_abs: u32,
}

impl CanonicalizationLimits {
    pub const R1_FOUNDATION: Self = Self {
        max_depth: 32,
        max_collection_items: 1_024,
        max_output_bytes: 1_048_576,
        max_exponent_abs: 10_000,
    };
}

impl Default for CanonicalizationLimits {
    fn default() -> Self {
        Self::R1_FOUNDATION
    }
}

/// Fixed digest domains avoid reusing an identical digest as a different kind
/// of artifact later in the product workflow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DigestDomain {
    CanonicalJsonR1Draft,
    CanonicalJsonR2Prototype,
    EvidenceBundleR1Draft,
    VerificationResultR1Draft,
    LocalUnsignedPayloadR2Prototype,
    EvidenceBundleR2Prototype,
    VerificationResultR2Prototype,
    EvaluationArtifactR2Prototype,
    Ed25519PayloadR3Source,
}

impl DigestDomain {
    pub const fn label(self) -> &'static str {
        match self {
            Self::CanonicalJsonR1Draft => "canonical-json:r1-draft",
            Self::CanonicalJsonR2Prototype => "canonical-json:r2-prototype",
            Self::EvidenceBundleR1Draft => "evidence-bundle:r1-draft",
            Self::VerificationResultR1Draft => "verification-result:r1-draft",
            Self::LocalUnsignedPayloadR2Prototype => "local-unsigned-payload:r2-prototype",
            Self::EvidenceBundleR2Prototype => "evidence-bundle:r2-prototype",
            Self::VerificationResultR2Prototype => "verification-result:r2-prototype",
            Self::EvaluationArtifactR2Prototype => "evaluation-artifact:r2-prototype",
            Self::Ed25519PayloadR3Source => "ed25519-payload:r3-source",
        }
    }
}

/// A SHA-256 digest encoded only when an adapter needs a human-readable form.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Digest([u8; 32]);

impl Digest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_prefixed_hex(&self) -> String {
        let mut encoded = String::from("sha256:");
        encoded.push_str(&self.to_hex());
        encoded
    }

    pub fn to_hex(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(self.0.len() * 2);
        for byte in self.0 {
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        encoded
    }

    pub fn from_hex(value: &str) -> Result<Self, Problem> {
        if value.len() != 64 {
            return Err(Problem::new(ProblemCode::InvalidDigest));
        }
        let mut bytes = [0_u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            let start = index.saturating_mul(2);
            let high = hex_value(value.as_bytes()[start])?;
            let low = hex_value(value.as_bytes()[start.saturating_add(1)])?;
            *byte = (high << 4) | low;
        }
        Ok(Self(bytes))
    }
}

/// Canonical bytes plus the fixed domain-separated digest over those bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalDocument {
    bytes: Vec<u8>,
    digest: Digest,
}

impl CanonicalDocument {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub const fn digest(&self) -> Digest {
        self.digest
    }
}

/// Canonicalises a strict JSON value to stable UTF-8 bytes.
pub fn canonicalize(value: &JsonValue, limits: CanonicalizationLimits) -> Result<Vec<u8>, Problem> {
    let mut writer = CanonicalWriter::new(limits);
    writer.write_value(value, 0)?;
    Ok(writer.into_bytes())
}

/// Applies the R1 draft canonicalisation profile and its canonical JSON domain.
pub fn canonical_document(value: &JsonValue) -> Result<CanonicalDocument, Problem> {
    canonical_document_in_domain(value, DigestDomain::CanonicalJsonR1Draft)
}

/// Canonicalises a document and hashes it in a named local profile domain.
pub fn canonical_document_in_domain(
    value: &JsonValue,
    domain: DigestDomain,
) -> Result<CanonicalDocument, Problem> {
    let bytes = canonicalize(value, CanonicalizationLimits::R1_FOUNDATION)?;
    let digest = domain_separated_digest(domain, &bytes);
    Ok(CanonicalDocument { bytes, digest })
}

/// Computes a canonical payload digest after removing one top-level envelope
/// member. R2 uses this only for the explicit local-unsigned signature field,
/// avoiding a circular self-digest.
pub fn canonical_document_without_top_level_member(
    value: &JsonValue,
    member: &str,
    domain: DigestDomain,
) -> Result<CanonicalDocument, Problem> {
    let mut payload = value.clone();
    let JsonValue::Object(fields) = &mut payload else {
        return Err(Problem::new(ProblemCode::InvalidArgument));
    };
    if fields.remove(member).is_none() {
        return Err(Problem::new(ProblemCode::InvalidArgument));
    }
    canonical_document_in_domain(&payload, domain)
}

/// Hashes exact bytes in a fixed, version-labelled domain.
pub fn domain_separated_digest(domain: DigestDomain, bytes: &[u8]) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"fenrua-trust-gate\0");
    hasher.update(domain.label().as_bytes());
    hasher.update(b"\0");
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut output = [0_u8; 32];
    output.copy_from_slice(&digest);
    Digest(output)
}

struct CanonicalWriter {
    limits: CanonicalizationLimits,
    output: Vec<u8>,
}

impl CanonicalWriter {
    fn new(limits: CanonicalizationLimits) -> Self {
        Self {
            limits,
            output: Vec::new(),
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        self.output
    }

    fn write_value(&mut self, value: &JsonValue, depth: usize) -> Result<(), Problem> {
        match value {
            JsonValue::Null => self.write_bytes(b"null"),
            JsonValue::Bool(true) => self.write_bytes(b"true"),
            JsonValue::Bool(false) => self.write_bytes(b"false"),
            JsonValue::Number(number) => self.write_number(number),
            JsonValue::String(string) => self.write_string(string),
            JsonValue::Array(values) => self.write_array(values, depth),
            JsonValue::Object(values) => self.write_object(values, depth),
        }
    }

    fn write_array(&mut self, values: &[JsonValue], depth: usize) -> Result<(), Problem> {
        self.require_depth(depth)?;
        if values.len() > self.limits.max_collection_items {
            return Err(Problem::new(ProblemCode::MaxArrayItemsExceeded));
        }
        self.write_byte(b'[')?;
        for (index, value) in values.iter().enumerate() {
            if index != 0 {
                self.write_byte(b',')?;
            }
            self.write_value(value, depth.saturating_add(1))?;
        }
        self.write_byte(b']')
    }

    fn write_object(
        &mut self,
        values: &std::collections::BTreeMap<String, JsonValue>,
        depth: usize,
    ) -> Result<(), Problem> {
        self.require_depth(depth)?;
        if values.len() > self.limits.max_collection_items {
            return Err(Problem::new(ProblemCode::MaxObjectMembersExceeded));
        }
        self.write_byte(b'{')?;
        for (index, (key, value)) in values.iter().enumerate() {
            if index != 0 {
                self.write_byte(b',')?;
            }
            self.write_string(key)?;
            self.write_byte(b':')?;
            self.write_value(value, depth.saturating_add(1))?;
        }
        self.write_byte(b'}')
    }

    fn write_number(&mut self, number: &JsonNumber) -> Result<(), Problem> {
        let canonical = canonical_number(number, self.limits)?;
        self.write_bytes(canonical.as_bytes())
    }

    fn write_string(&mut self, value: &str) -> Result<(), Problem> {
        self.write_byte(b'\"')?;
        for character in value.chars() {
            match character {
                '\"' => self.write_bytes(b"\\\"")?,
                '\\' => self.write_bytes(b"\\\\")?,
                '\u{0008}' => self.write_bytes(b"\\b")?,
                '\u{000c}' => self.write_bytes(b"\\f")?,
                '\n' => self.write_bytes(b"\\n")?,
                '\r' => self.write_bytes(b"\\r")?,
                '\t' => self.write_bytes(b"\\t")?,
                control if control <= '\u{001f}' => {
                    let code = control as u32;
                    let escaped = [
                        b'\\',
                        b'u',
                        b'0',
                        b'0',
                        hex((code >> 4) as u8),
                        hex(code as u8),
                    ];
                    self.write_bytes(&escaped)?;
                }
                other => {
                    let mut buffer = [0_u8; 4];
                    self.write_bytes(other.encode_utf8(&mut buffer).as_bytes())?;
                }
            }
        }
        self.write_byte(b'\"')
    }

    fn write_byte(&mut self, byte: u8) -> Result<(), Problem> {
        self.write_bytes(&[byte])
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), Problem> {
        let next_length = self.output.len().saturating_add(bytes.len());
        if next_length > self.limits.max_output_bytes {
            return Err(Problem::new(ProblemCode::MaxCanonicalBytesExceeded));
        }
        self.output.extend_from_slice(bytes);
        Ok(())
    }

    fn require_depth(&self, depth: usize) -> Result<(), Problem> {
        if depth >= self.limits.max_depth {
            return Err(Problem::new(ProblemCode::MaxDepthExceeded));
        }
        Ok(())
    }
}

fn hex(value: u8) -> u8 {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    HEX[usize::from(value & 0x0f)]
}

fn hex_value(value: u8) -> Result<u8, Problem> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(Problem::new(ProblemCode::InvalidDigest)),
    }
}

fn canonical_number(
    number: &JsonNumber,
    limits: CanonicalizationLimits,
) -> Result<String, Problem> {
    let token = number.lexeme();
    let (negative, unsigned) = match token.strip_prefix('-') {
        Some(unsigned) => (true, unsigned),
        None => (false, token),
    };
    let (mantissa, exponent) = match unsigned.find(['e', 'E']) {
        Some(index) => (
            &unsigned[..index],
            parse_exponent(&unsigned[index + 1..], limits)?,
        ),
        None => (unsigned, 0_i64),
    };
    let (integer, fraction) = match mantissa.split_once('.') {
        Some((integer, fraction)) => (integer, fraction),
        None => (mantissa, ""),
    };

    let joined = format!("{integer}{fraction}");
    let significant = joined.trim_start_matches('0');
    if significant.is_empty() {
        return Ok("0".to_owned());
    }
    let without_trailing = significant.trim_end_matches('0');
    let trailing_zeroes = significant.len().saturating_sub(without_trailing.len());
    let fractional_digits = i64::try_from(fraction.len())
        .map_err(|_| Problem::new(ProblemCode::MaxCanonicalExponentExceeded))?;
    let trailing_zeroes = i64::try_from(trailing_zeroes)
        .map_err(|_| Problem::new(ProblemCode::MaxCanonicalExponentExceeded))?;
    let scale = fractional_digits
        .checked_sub(exponent)
        .and_then(|value| value.checked_sub(trailing_zeroes))
        .ok_or_else(|| Problem::new(ProblemCode::MaxCanonicalExponentExceeded))?;

    let mut output = String::new();
    if negative {
        output.push('-');
    }
    if scale <= 0 {
        output.push_str(without_trailing);
        let zeroes = usize::try_from(scale.unsigned_abs())
            .map_err(|_| Problem::new(ProblemCode::MaxCanonicalExponentExceeded))?;
        append_zeroes(&mut output, zeroes, limits)?;
    } else {
        let scale = usize::try_from(scale)
            .map_err(|_| Problem::new(ProblemCode::MaxCanonicalExponentExceeded))?;
        if scale >= without_trailing.len() {
            output.push_str("0.");
            append_zeroes(
                &mut output,
                scale.saturating_sub(without_trailing.len()),
                limits,
            )?;
            output.push_str(without_trailing);
        } else {
            let split = without_trailing.len().saturating_sub(scale);
            output.push_str(&without_trailing[..split]);
            output.push('.');
            output.push_str(&without_trailing[split..]);
        }
    }
    if output.len() > limits.max_output_bytes {
        return Err(Problem::new(ProblemCode::MaxCanonicalBytesExceeded));
    }
    Ok(output)
}

fn parse_exponent(input: &str, limits: CanonicalizationLimits) -> Result<i64, Problem> {
    let (negative, digits) = match input.strip_prefix('-') {
        Some(digits) => (true, digits),
        None => match input.strip_prefix('+') {
            Some(digits) => (false, digits),
            None => (false, input),
        },
    };
    let mut value = 0_u64;
    for digit in digits.bytes() {
        let digit = match digit.checked_sub(b'0') {
            Some(digit @ 0..=9) => u64::from(digit),
            _ => return Err(Problem::new(ProblemCode::InvalidJson)),
        };
        value = match value
            .checked_mul(10)
            .and_then(|base| base.checked_add(digit))
        {
            Some(value) => value,
            None => return Err(Problem::new(ProblemCode::MaxCanonicalExponentExceeded)),
        };
        if value > u64::from(limits.max_exponent_abs) {
            return Err(Problem::new(ProblemCode::MaxCanonicalExponentExceeded));
        }
    }
    let signed = i64::try_from(value)
        .map_err(|_| Problem::new(ProblemCode::MaxCanonicalExponentExceeded))?;
    Ok(if negative { -signed } else { signed })
}

fn append_zeroes(
    target: &mut String,
    count: usize,
    limits: CanonicalizationLimits,
) -> Result<(), Problem> {
    let next_length = target.len().saturating_add(count);
    if next_length > limits.max_output_bytes {
        return Err(Problem::new(ProblemCode::MaxCanonicalBytesExceeded));
    }
    target.extend(std::iter::repeat_n('0', count));
    Ok(())
}

#[cfg(test)]
mod tests {
    use fenrua_protocol::{JsonValue, ParseLimits, ProblemCode, parse_json};

    use super::{
        CanonicalizationLimits, Digest, DigestDomain, canonical_document,
        canonical_document_in_domain, canonical_document_without_top_level_member, canonicalize,
        domain_separated_digest,
    };

    fn parse(input: &[u8]) -> JsonValue {
        match parse_json(input, ParseLimits::R1_FOUNDATION) {
            Ok(value) => value,
            Err(error) => panic!("fixture must parse: {error}"),
        }
    }

    #[test]
    fn object_member_order_and_number_spelling_have_one_canonical_form() {
        let first = parse(br#"{"z":1e0,"a":"text"}"#);
        let second = parse(br#"{"a":"text","z":1.0}"#);
        let first_document = match canonical_document(&first) {
            Ok(document) => document,
            Err(error) => panic!("first fixture must canonicalize: {error}"),
        };
        let second_document = match canonical_document(&second) {
            Ok(document) => document,
            Err(error) => panic!("second fixture must canonicalize: {error}"),
        };

        assert_eq!(first_document.bytes(), br#"{"a":"text","z":1}"#);
        assert_eq!(first_document, second_document);
        assert_eq!(
            first_document.digest().to_prefixed_hex(),
            "sha256:aa37f2d20a68a5d9f5579d08d2e07ca74ef8fc99555fe19bd901f3fc2b02e5bb"
        );
    }

    #[test]
    fn domain_separation_changes_an_otherwise_identical_digest() {
        let bytes = br#"{"a":1}"#;
        assert_ne!(
            domain_separated_digest(DigestDomain::CanonicalJsonR1Draft, bytes),
            domain_separated_digest(DigestDomain::EvidenceBundleR1Draft, bytes)
        );
    }

    #[test]
    fn canonicalization_is_bounded_independently_of_the_parser() {
        let value = parse(br#"[1,2]"#);
        let limits = CanonicalizationLimits {
            max_collection_items: 1,
            ..CanonicalizationLimits::R1_FOUNDATION
        };
        let error = match canonicalize(&value, limits) {
            Ok(_) => panic!("manual values must still observe collection limits"),
            Err(error) => error,
        };
        assert_eq!(error.code(), ProblemCode::MaxArrayItemsExceeded);
    }

    #[test]
    fn negative_zero_is_canonicalized_without_a_sign() {
        let value = parse(br#"-0.000e12"#);
        let bytes = match canonicalize(&value, CanonicalizationLimits::R1_FOUNDATION) {
            Ok(bytes) => bytes,
            Err(error) => panic!("negative zero must canonicalize: {error}"),
        };
        assert_eq!(bytes, b"0");
    }

    #[test]
    fn local_unsigned_payload_omits_only_the_explicit_signature_member() {
        let value = parse(br#"{"signature":{"payloadDigest":"not-used"},"z":1,"a":"text"}"#);
        let payload = match canonical_document_without_top_level_member(
            &value,
            "signature",
            DigestDomain::LocalUnsignedPayloadR2Prototype,
        ) {
            Ok(payload) => payload,
            Err(error) => panic!("payload must canonicalize: {error}"),
        };
        let direct = match canonical_document_in_domain(
            &parse(br#"{"a":"text","z":1}"#),
            DigestDomain::LocalUnsignedPayloadR2Prototype,
        ) {
            Ok(document) => document,
            Err(error) => panic!("direct payload must canonicalize: {error}"),
        };
        assert_eq!(payload, direct);
    }

    #[test]
    fn lowercase_hex_round_trips_and_other_forms_fail_closed() {
        let original =
            domain_separated_digest(DigestDomain::EvaluationArtifactR2Prototype, b"r2-fixture");
        let parsed = match Digest::from_hex(&original.to_hex()) {
            Ok(parsed) => parsed,
            Err(error) => panic!("generated lowercase hex must parse: {error}"),
        };
        assert_eq!(parsed, original);
        assert!(Digest::from_hex("A".repeat(64).as_str()).is_err());
    }
}
