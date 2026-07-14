//! Strict local parsing, R1 foundation, and R2 local-profile primitives.
//!
//! This crate deliberately does not define a released Trust Gate schema
//! contract. Its R2 validators accept only a closed, pinned local subset of
//! the separately governed Fenrua schema registry.

mod bounded_json;
mod problem;
mod r2;
mod schema;

pub use bounded_json::{JsonNumber, JsonValue, ParseLimits, parse_json};
pub use problem::{Problem, ProblemCode, ProblemEnvelope};
pub use r2::{
    LOCAL_UNSIGNED_KEY_ID, LOCAL_UNSIGNED_PROFILE, R2_LOCAL_PROFILE_ID, R2_LOCAL_SCHEMA_PIN,
    R2_LOCAL_SPECS_COMMIT, R2_LOCAL_SPECS_REPOSITORY, R2Document, R2DocumentKind, array_items,
    bool_value, object_fields, optional_field, parse_r2_document, required_field, string_value,
    validate_r2_document, validate_r2_timestamp,
};
pub use schema::{SchemaDescriptor, SchemaStatus, reserved_schemas};
