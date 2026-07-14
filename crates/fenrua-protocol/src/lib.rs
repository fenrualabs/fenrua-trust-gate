//! Strict local parsing and protocol-discovery primitives for the unreleased R1
//! foundation. This crate deliberately does not define or accept a released
//! Trust Gate schema contract.

mod bounded_json;
mod problem;
mod schema;

pub use bounded_json::{JsonNumber, JsonValue, ParseLimits, parse_json};
pub use problem::{Problem, ProblemCode, ProblemEnvelope};
pub use schema::{SchemaDescriptor, SchemaStatus, reserved_schemas};
