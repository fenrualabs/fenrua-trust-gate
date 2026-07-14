use core::fmt;

/// Stable categories for safe, machine-readable local prototype failures.
///
/// The category intentionally excludes user-controlled input, filesystem paths,
/// host details, stack traces, and nested dependency messages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProblemCode {
    InputTooLarge,
    InputInvalidUtf8,
    InvalidJson,
    DuplicateKey,
    MaxDepthExceeded,
    MaxArrayItemsExceeded,
    MaxObjectMembersExceeded,
    MaxStringBytesExceeded,
    MaxNumberBytesExceeded,
    MaxCanonicalBytesExceeded,
    MaxCanonicalExponentExceeded,
    TrailingData,
    UnsupportedSchema,
    UnsupportedProfile,
    FeatureUnavailable,
    InvalidArgument,
    IntegrityMismatch,
    SchemaValidationFailed,
    InvalidTimestamp,
    InvalidDigest,
    IoFailure,
}

impl ProblemCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InputTooLarge => "input_too_large",
            Self::InputInvalidUtf8 => "input_invalid_utf8",
            Self::InvalidJson => "invalid_json",
            Self::DuplicateKey => "duplicate_key",
            Self::MaxDepthExceeded => "max_depth_exceeded",
            Self::MaxArrayItemsExceeded => "max_array_items_exceeded",
            Self::MaxObjectMembersExceeded => "max_object_members_exceeded",
            Self::MaxStringBytesExceeded => "max_string_bytes_exceeded",
            Self::MaxNumberBytesExceeded => "max_number_bytes_exceeded",
            Self::MaxCanonicalBytesExceeded => "max_canonical_bytes_exceeded",
            Self::MaxCanonicalExponentExceeded => "max_canonical_exponent_exceeded",
            Self::TrailingData => "trailing_data",
            Self::UnsupportedSchema => "unsupported_schema",
            Self::UnsupportedProfile => "unsupported_profile",
            Self::FeatureUnavailable => "feature_unavailable",
            Self::InvalidArgument => "invalid_argument",
            Self::IntegrityMismatch => "integrity_mismatch",
            Self::SchemaValidationFailed => "schema_validation_failed",
            Self::InvalidTimestamp => "invalid_timestamp",
            Self::InvalidDigest => "invalid_digest",
            Self::IoFailure => "io_failure",
        }
    }

    pub const fn title(self) -> &'static str {
        match self {
            Self::InputTooLarge => "Input exceeds the configured bound",
            Self::InputInvalidUtf8 => "Input is not valid UTF-8",
            Self::InvalidJson => "Input is not valid JSON",
            Self::DuplicateKey => "JSON object contains a duplicate key",
            Self::MaxDepthExceeded => "JSON nesting exceeds the configured bound",
            Self::MaxArrayItemsExceeded => "JSON array exceeds the configured bound",
            Self::MaxObjectMembersExceeded => "JSON object exceeds the configured bound",
            Self::MaxStringBytesExceeded => "JSON string exceeds the configured bound",
            Self::MaxNumberBytesExceeded => "JSON number exceeds the configured bound",
            Self::MaxCanonicalBytesExceeded => "Canonical JSON exceeds the configured bound",
            Self::MaxCanonicalExponentExceeded => {
                "JSON exponent exceeds the configured canonical bound"
            }
            Self::TrailingData => "Input contains trailing data",
            Self::UnsupportedSchema => "Schema is not accepted by this foundation",
            Self::UnsupportedProfile => "Profile is not accepted by this foundation",
            Self::FeatureUnavailable => "Feature is unavailable in the active local profile",
            Self::InvalidArgument => "Command arguments are invalid",
            Self::IntegrityMismatch => "Canonical digest does not match",
            Self::SchemaValidationFailed => {
                "Input does not satisfy the active local schema profile"
            }
            Self::InvalidTimestamp => "Timestamp is not valid for the active local profile",
            Self::InvalidDigest => "Digest is not valid for the active local profile",
            Self::IoFailure => "Local input or output operation failed",
        }
    }

    pub const fn status(self) -> u16 {
        match self {
            Self::InputTooLarge
            | Self::MaxDepthExceeded
            | Self::MaxArrayItemsExceeded
            | Self::MaxObjectMembersExceeded
            | Self::MaxStringBytesExceeded
            | Self::MaxNumberBytesExceeded
            | Self::MaxCanonicalBytesExceeded
            | Self::MaxCanonicalExponentExceeded => 413,
            Self::UnsupportedSchema
            | Self::UnsupportedProfile
            | Self::FeatureUnavailable
            | Self::SchemaValidationFailed => 422,
            Self::IntegrityMismatch => 409,
            Self::InputInvalidUtf8
            | Self::InvalidJson
            | Self::DuplicateKey
            | Self::TrailingData
            | Self::InvalidArgument
            | Self::InvalidTimestamp
            | Self::InvalidDigest => 400,
            Self::IoFailure => 500,
        }
    }
}

/// A safe error record. `offset` is a byte count into the caller's input, not
/// user content, a filesystem path, or an internal implementation detail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Problem {
    code: ProblemCode,
    offset: Option<usize>,
}

impl Problem {
    pub const fn new(code: ProblemCode) -> Self {
        Self { code, offset: None }
    }

    pub const fn at(code: ProblemCode, offset: usize) -> Self {
        Self {
            code,
            offset: Some(offset),
        }
    }

    pub const fn code(self) -> ProblemCode {
        self.code
    }

    pub const fn offset(self) -> Option<usize> {
        self.offset
    }

    pub const fn envelope(self) -> ProblemEnvelope {
        ProblemEnvelope {
            schema: "fenrua.problem-envelope.r1-draft",
            code: self.code,
            title: self.code.title(),
            status: self.code.status(),
            retryable: false,
            offset: self.offset,
        }
    }
}

impl fmt::Display for Problem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.title())
    }
}

impl std::error::Error for Problem {}

/// Stable, non-leaky JSON representation for local CLI and library adapters.
///
/// It is an R1 draft envelope, not a released API or schema contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProblemEnvelope {
    schema: &'static str,
    code: ProblemCode,
    title: &'static str,
    status: u16,
    retryable: bool,
    offset: Option<usize>,
}

impl ProblemEnvelope {
    pub const fn schema(self) -> &'static str {
        self.schema
    }

    pub const fn code(self) -> ProblemCode {
        self.code
    }

    pub const fn title(self) -> &'static str {
        self.title
    }

    pub const fn status(self) -> u16 {
        self.status
    }

    pub const fn retryable(self) -> bool {
        self.retryable
    }

    pub const fn offset(self) -> Option<usize> {
        self.offset
    }

    /// Serializes only static values and an optional numeric byte offset.
    pub fn to_json(self) -> String {
        let mut rendered = format!(
            "{{\"schema\":\"{}\",\"code\":\"{}\",\"title\":\"{}\",\"status\":{},\"retryable\":{}",
            self.schema,
            self.code.as_str(),
            self.title,
            self.status,
            self.retryable
        );
        if let Some(offset) = self.offset {
            rendered.push_str(&format!(",\"offset\":{offset}"));
        }
        rendered.push('}');
        rendered
    }
}
