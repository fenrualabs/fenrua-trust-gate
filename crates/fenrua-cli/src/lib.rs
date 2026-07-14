//! Explicit local-file CLI for the unreleased R2 prototype.
//!
//! Every path is caller supplied. The CLI has no network client, no key
//! operation, no execution adapter, and no durable replay store.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::process::ExitCode;

use fenrua_c14n::{
    Digest, DigestDomain, canonical_document_in_domain, canonical_document_without_top_level_member,
};
use fenrua_crypto::profile_descriptors;
use fenrua_gate::{EvaluationInput, evaluate};
use fenrua_protocol::{
    JsonValue, LOCAL_UNSIGNED_KEY_ID, LOCAL_UNSIGNED_PROFILE, ParseLimits, Problem, ProblemCode,
    R2_LOCAL_PROFILE_ID, R2_LOCAL_SCHEMA_PIN, R2Document, R2DocumentKind, array_items,
    object_fields, parse_json, parse_r2_document, required_field, string_value,
};
use fenrua_verify::verify_local_evaluation;

const COMPONENT: &str = "fenrua-trust-gate";
const MATURITY: &str = "R2 prototype";
const CONTRACT_STATUS: &str = "local-unsigned-r2-prototype";
const PRODUCT_AVAILABILITY: &str = "not-released";

const HELP: &str = "fenrua Trust Gate R2 local prototype (not released)\n\nLocal commands:\n  fenrua version [--json]\n  fenrua schema list [--json]\n  fenrua manifest validate <file>\n  fenrua policy validate <file>\n  fenrua request validate <file>\n  fenrua revocations validate <file>\n  fenrua gate evaluate --manifest <file> --policy <file> --request <file> --revocations <file> --at <UTC-millis> --output <file>\n  fenrua evidence verify <bundle>\n  fenrua receipt inspect <receipt>\n  fenrua doctor [--json]\n\nThe R2 profile uses explicit local files and a caller-supplied time. It has no network, keys, durable replay store, or execution adapter. An ALLOW record is never an instruction to execute an action.\n";

/// Runs the explicit R2 local command surface.
pub fn run(arguments: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> ExitCode {
    match dispatch(arguments) {
        Ok(CommandResult { code, output }) => match stdout.write_all(output.as_bytes()) {
            Ok(()) => code,
            Err(_) => ExitCode::FAILURE,
        },
        Err(problem) => write_problem(stderr, problem),
    }
}

struct CommandResult {
    code: ExitCode,
    output: String,
}

fn dispatch(arguments: &[String]) -> Result<CommandResult, Problem> {
    match arguments {
        [] => text_result(ExitCode::SUCCESS, HELP),
        [argument] if is_help(argument) => text_result(ExitCode::SUCCESS, HELP),
        [argument] if argument == "--version" => text_result(ExitCode::SUCCESS, &version_human()),
        [command] if command == "version" => text_result(ExitCode::SUCCESS, &version_human()),
        [command, option] if command == "version" && option == "--json" => {
            text_result(ExitCode::SUCCESS, &version_json())
        }
        [command, subcommand] if command == "schema" && subcommand == "list" => {
            text_result(ExitCode::SUCCESS, &schema_list_human())
        }
        [command, subcommand, option]
            if command == "schema" && subcommand == "list" && option == "--json" =>
        {
            text_result(ExitCode::SUCCESS, &schema_list_json())
        }
        [command] if command == "doctor" => text_result(ExitCode::SUCCESS, &doctor_human()),
        [command, option] if command == "doctor" && option == "--json" => {
            text_result(ExitCode::SUCCESS, &doctor_json())
        }
        [command, subcommand, path] if command == "manifest" && subcommand == "validate" => {
            validate_file(path, R2DocumentKind::EntityManifest)
        }
        [command, subcommand, path] if command == "policy" && subcommand == "validate" => {
            validate_file(path, R2DocumentKind::AuthorityPolicy)
        }
        [command, subcommand, path] if command == "request" && subcommand == "validate" => {
            validate_file(path, R2DocumentKind::ToolCallRequest)
        }
        [command, subcommand, path] if command == "revocations" && subcommand == "validate" => {
            validate_file(path, R2DocumentKind::RevocationSet)
        }
        [command, subcommand, rest @ ..] if command == "gate" && subcommand == "evaluate" => {
            evaluate_files(rest)
        }
        [command, subcommand, path] if command == "evidence" && subcommand == "verify" => {
            verify_file(path)
        }
        [command, subcommand, path] if command == "receipt" && subcommand == "inspect" => {
            inspect_receipt(path)
        }
        _ => Err(Problem::new(ProblemCode::InvalidArgument)),
    }
}

fn is_help(argument: &str) -> bool {
    matches!(argument, "help" | "--help" | "-h")
}

fn validate_file(path: &str, kind: R2DocumentKind) -> Result<CommandResult, Problem> {
    let document = read_document(path, kind)?;
    let digest =
        canonical_document_in_domain(document.value(), DigestDomain::CanonicalJsonR2Prototype)?
            .digest();
    let output = object([
        ("schemaVersion", text("fenrua.local-validation.r2-draft")),
        ("kind", text(kind.label())),
        ("profileId", text(R2_LOCAL_PROFILE_ID)),
        ("schemaPin", text(R2_LOCAL_SCHEMA_PIN)),
        ("status", text("valid-local-r2-prototype")),
        ("canonicalDigest", digest_json(digest.to_hex().as_str())),
    ]);
    json_result(ExitCode::SUCCESS, output)
}

fn evaluate_files(arguments: &[String]) -> Result<CommandResult, Problem> {
    let options = named_options(
        arguments,
        &[
            "--manifest",
            "--policy",
            "--request",
            "--revocations",
            "--at",
            "--output",
        ],
    )?;
    let manifest = read_document(
        option(&options, "--manifest")?,
        R2DocumentKind::EntityManifest,
    )?;
    let policy = read_document(
        option(&options, "--policy")?,
        R2DocumentKind::AuthorityPolicy,
    )?;
    let request = read_document(
        option(&options, "--request")?,
        R2DocumentKind::ToolCallRequest,
    )?;
    let revocations = read_document(
        option(&options, "--revocations")?,
        R2DocumentKind::RevocationSet,
    )?;
    let input = EvaluationInput::new(
        manifest,
        policy,
        request,
        revocations,
        option(&options, "--at")?.to_owned(),
    )?;
    let artifact = evaluate(&input)?;
    let verification = verify_local_evaluation(artifact.value())?;
    if !verification.integrity_verified() {
        return Err(Problem::new(ProblemCode::IntegrityMismatch));
    }
    let bytes = canonical_bytes(artifact.value())?;
    write_new_output(option(&options, "--output")?, &bytes)?;
    let decision = decision_value(artifact.value())?;
    let code = if decision == "ALLOW" {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(20)
    };
    let output = object([
        (
            "schemaVersion",
            text("fenrua.local-evaluation-result.r2-draft"),
        ),
        ("decision", text(decision)),
        ("outputWritten", JsonValue::Bool(true)),
        (
            "verificationState",
            text(if verification.integrity_verified() {
                "PASS_WITH_LIMITATIONS"
            } else {
                "INTEGRITY_MISMATCH"
            }),
        ),
        ("executionInstruction", text("absent")),
    ]);
    json_result(code, output)
}

fn verify_file(path: &str) -> Result<CommandResult, Problem> {
    let bytes = read_bytes(path)?;
    let value = parse_json(&bytes, ParseLimits::R1_FOUNDATION)?;
    let report = verify_local_evaluation(&value)?;
    let code = if report.integrity_verified() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(20)
    };
    json_result(code, report.into_result())
}

fn inspect_receipt(path: &str) -> Result<CommandResult, Problem> {
    let receipt = read_document(path, R2DocumentKind::Receipt)?;
    let integrity_verified = local_unsigned_signature_matches(receipt.value())?;
    let fields = object_fields(receipt.value())?;
    let reasons = array_items(required_field(fields, "reasonCodes")?)?;
    let mut reason_codes = Vec::new();
    for reason in reasons {
        reason_codes.push(text(string_value(reason)?));
    }
    let output = object([
        (
            "schemaVersion",
            text("fenrua.local-receipt-inspection.r2-draft"),
        ),
        ("receiptId", text(field_string(fields, "receiptId")?)),
        ("decision", text(field_string(fields, "decision")?)),
        ("reasonCodes", JsonValue::Array(reason_codes)),
        (
            "integrityState",
            text(if integrity_verified {
                "LOCAL_PAYLOAD_MATCH"
            } else {
                "INTEGRITY_MISMATCH"
            }),
        ),
        ("executionInstruction", text("absent")),
    ]);
    json_result(
        if integrity_verified {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(20)
        },
        output,
    )
}

fn named_options(
    arguments: &[String],
    expected: &[&str],
) -> Result<BTreeMap<String, String>, Problem> {
    if arguments.len() != expected.len().saturating_mul(2) {
        return Err(Problem::new(ProblemCode::InvalidArgument));
    }
    let mut options = BTreeMap::new();
    let mut index = 0_usize;
    while index < arguments.len() {
        let name = arguments
            .get(index)
            .ok_or_else(|| Problem::new(ProblemCode::InvalidArgument))?;
        let value = arguments
            .get(index.saturating_add(1))
            .ok_or_else(|| Problem::new(ProblemCode::InvalidArgument))?;
        if !expected.contains(&name.as_str()) || value.starts_with("--") {
            return Err(Problem::new(ProblemCode::InvalidArgument));
        }
        if options.insert(name.clone(), value.clone()).is_some() {
            return Err(Problem::new(ProblemCode::InvalidArgument));
        }
        index = index.saturating_add(2);
    }
    if options.len() != expected.len() || expected.iter().any(|name| !options.contains_key(*name)) {
        return Err(Problem::new(ProblemCode::InvalidArgument));
    }
    Ok(options)
}

fn option<'a>(options: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str, Problem> {
    options
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| Problem::new(ProblemCode::InvalidArgument))
}

fn read_document(path: &str, kind: R2DocumentKind) -> Result<R2Document, Problem> {
    parse_r2_document(&read_bytes(path)?, kind)
}

fn read_bytes(path: &str) -> Result<Vec<u8>, Problem> {
    let maximum_bytes = u64::try_from(ParseLimits::R1_FOUNDATION.max_bytes)
        .map_err(|_| Problem::new(ProblemCode::InputTooLarge))?;
    let file = File::open(path).map_err(|_| Problem::new(ProblemCode::IoFailure))?;
    if file
        .metadata()
        .map_err(|_| Problem::new(ProblemCode::IoFailure))?
        .len()
        > maximum_bytes
    {
        return Err(Problem::new(ProblemCode::InputTooLarge));
    }
    let mut bounded = file.take(maximum_bytes.saturating_add(1));
    let mut bytes = Vec::new();
    bounded
        .read_to_end(&mut bytes)
        .map_err(|_| Problem::new(ProblemCode::IoFailure))?;
    if bytes.len() > ParseLimits::R1_FOUNDATION.max_bytes {
        return Err(Problem::new(ProblemCode::InputTooLarge));
    }
    Ok(bytes)
}

fn write_new_output(path: &str, bytes: &[u8]) -> Result<(), Problem> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| Problem::new(ProblemCode::IoFailure))?;
    file.write_all(bytes)
        .map_err(|_| Problem::new(ProblemCode::IoFailure))?;
    file.write_all(b"\n")
        .map_err(|_| Problem::new(ProblemCode::IoFailure))?;
    file.sync_all()
        .map_err(|_| Problem::new(ProblemCode::IoFailure))
}

fn decision_value(value: &JsonValue) -> Result<&str, Problem> {
    let fields = object_fields(value)?;
    let decision = object_fields(required_field(fields, "decision")?)?;
    field_string(decision, "decision")
}

fn canonical_bytes(value: &JsonValue) -> Result<Vec<u8>, Problem> {
    Ok(
        canonical_document_in_domain(value, DigestDomain::CanonicalJsonR2Prototype)?
            .bytes()
            .to_vec(),
    )
}

fn json_result(code: ExitCode, value: JsonValue) -> Result<CommandResult, Problem> {
    let mut output = String::from_utf8(canonical_bytes(&value)?)
        .map_err(|_| Problem::new(ProblemCode::IoFailure))?;
    output.push('\n');
    Ok(CommandResult { code, output })
}

fn text_result(code: ExitCode, output: &str) -> Result<CommandResult, Problem> {
    Ok(CommandResult {
        code,
        output: output.to_owned(),
    })
}

fn version_human() -> String {
    format!(
        "{COMPONENT} {}\nmaturity: {MATURITY}\ncontract status: {CONTRACT_STATUS}\nproduct availability: {PRODUCT_AVAILABILITY}\n",
        env!("CARGO_PKG_VERSION")
    )
}

fn version_json() -> String {
    format!(
        "{{\"component\":\"{COMPONENT}\",\"contractStatus\":\"{CONTRACT_STATUS}\",\"maturity\":\"R2\",\"productAvailability\":\"{PRODUCT_AVAILABILITY}\",\"profileId\":\"{R2_LOCAL_PROFILE_ID}\",\"version\":\"{}\"}}\n",
        env!("CARGO_PKG_VERSION")
    )
}

fn schema_list_human() -> String {
    let mut output = String::from(
        "Schema discovery\ncontract status: local R2 prototype; not released\naccepted local inputs:\n",
    );
    for kind in [
        R2DocumentKind::EntityManifest,
        R2DocumentKind::AuthorityPolicy,
        R2DocumentKind::ToolCallRequest,
        R2DocumentKind::RevocationSet,
    ] {
        output.push_str("  ");
        output.push_str(kind.schema_version());
        output.push_str(" [local-unsigned-r2-prototype]\n");
    }
    output.push_str(
        "generated local records: decision, evidence-bundle, receipt, verification-result\n",
    );
    output
}

fn schema_list_json() -> String {
    let entries = [
        R2DocumentKind::EntityManifest,
        R2DocumentKind::AuthorityPolicy,
        R2DocumentKind::ToolCallRequest,
        R2DocumentKind::RevocationSet,
    ];
    let mut output = String::from(
        "{\"acceptedLocalInputCount\":4,\"contractStatus\":\"local-r2-prototype-not-released\",\"schemas\":[",
    );
    for (index, kind) in entries.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        output.push_str("{\"id\":\"");
        output.push_str(kind.schema_version());
        output.push_str("\",\"schemaId\":\"");
        output.push_str(kind.schema_id().unwrap_or(""));
        output.push_str("\",\"status\":\"local-unsigned-r2-prototype\"}");
    }
    output.push_str("]}\n");
    output
}

fn doctor_human() -> String {
    let mut output = String::from(
        "R2 local prototype doctor self-description\nThis is not a runtime health check, release attestation, or production capability claim.\n",
    );
    for (name, state, detail) in doctor_checks() {
        output.push_str("  ");
        output.push_str(name);
        output.push_str(": ");
        output.push_str(state);
        output.push_str(" - ");
        output.push_str(detail);
        output.push('\n');
    }
    output
}

fn doctor_json() -> String {
    let mut output = String::from(
        "{\"component\":\"fenrua-trust-gate\",\"contractStatus\":\"local-r2-prototype-not-released\",\"doctorKind\":\"static-r2-self-description\",\"checks\":[",
    );
    for (index, (name, state, detail)) in doctor_checks().iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        output.push_str("{\"detail\":\"");
        output.push_str(detail);
        output.push_str("\",\"id\":\"");
        output.push_str(name);
        output.push_str("\",\"state\":\"");
        output.push_str(state);
        output.push_str("\"}");
    }
    output.push_str("]}\n");
    output
}

fn doctor_checks() -> [(&'static str, &'static str, &'static str); 6] {
    [
        (
            "network",
            "not-implemented",
            "no network client or remote loading path is included",
        ),
        (
            "schema-admission",
            "local-r2-prototype",
            "four pinned local input roles are strictly admitted",
        ),
        (
            "evaluation",
            "local-r2-prototype",
            "deterministic deny-overrides evaluation requires explicit files and time",
        ),
        (
            "evidence-verification",
            "local-r2-prototype",
            "separate package recomputes local evidence relationships",
        ),
        (
            "key-operations",
            "not-implemented",
            "local-unsigned profile provides no key operation or signer authentication",
        ),
        (
            "profiles",
            "reserved-plus-local-prototype",
            profile_count_detail(),
        ),
    ]
}

fn profile_count_detail() -> &'static str {
    match profile_descriptors().len() {
        4 => "four bootstrap profile labels remain reserved; only local-unsigned is admitted in R2",
        _ => "bootstrap profile registry differs from the documented set",
    }
}

fn field_string<'a>(
    fields: &'a BTreeMap<String, JsonValue>,
    name: &str,
) -> Result<&'a str, Problem> {
    string_value(required_field(fields, name)?)
}

fn digest_json(value: &str) -> JsonValue {
    object([("algorithm", text("sha-256")), ("value", text(value))])
}

fn local_unsigned_signature_matches(value: &JsonValue) -> Result<bool, Problem> {
    let fields = object_fields(value)?;
    let signature = object_fields(required_field(fields, "signature")?)?;
    if field_string(signature, "profile")? != LOCAL_UNSIGNED_PROFILE
        || field_string(signature, "keyId")? != LOCAL_UNSIGNED_KEY_ID
    {
        return Ok(false);
    }
    let digest = object_fields(required_field(signature, "payloadDigest")?)?;
    let expected = Digest::from_hex(field_string(digest, "value")?)?;
    let actual = canonical_document_without_top_level_member(
        value,
        "signature",
        DigestDomain::LocalUnsignedPayloadR2Prototype,
    )?
    .digest();
    Ok(actual == expected)
}

fn text(value: &str) -> JsonValue {
    JsonValue::String(value.to_owned())
}

fn object<const N: usize>(entries: [(&str, JsonValue); N]) -> JsonValue {
    let mut fields = BTreeMap::new();
    for (name, value) in entries {
        fields.insert(name.to_owned(), value);
    }
    JsonValue::Object(fields)
}

fn write_problem(stderr: &mut dyn Write, problem: Problem) -> ExitCode {
    let envelope = problem.envelope().to_json();
    match stderr.write_all(envelope.as_bytes()) {
        Ok(()) => ExitCode::from(64),
        Err(_) => ExitCode::FAILURE,
    }
}

#[cfg(test)]
mod tests {
    use std::process::ExitCode;
    use std::time::{SystemTime, UNIX_EPOCH};

    use fenrua_protocol::{ParseLimits, ProblemCode};

    use super::{read_bytes, run};

    fn execute(arguments: &[&str]) -> (ExitCode, String, String) {
        let arguments = arguments
            .iter()
            .map(|argument| (*argument).to_owned())
            .collect::<Vec<_>>();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run(&arguments, &mut stdout, &mut stderr);
        let stdout = match String::from_utf8(stdout) {
            Ok(stdout) => stdout,
            Err(_) => panic!("CLI stdout must be UTF-8"),
        };
        let stderr = match String::from_utf8(stderr) {
            Ok(stderr) => stderr,
            Err(_) => panic!("CLI stderr must be UTF-8"),
        };
        (code, stdout, stderr)
    }

    #[test]
    fn version_json_is_truthful_about_r2_status() {
        let (code, stdout, stderr) = execute(&["version", "--json"]);
        assert_eq!(code, ExitCode::SUCCESS);
        assert!(stderr.is_empty());
        assert!(stdout.contains("\"maturity\":\"R2\""));
        assert!(stdout.contains("\"productAvailability\":\"not-released\""));
    }

    #[test]
    fn schema_list_names_only_the_local_input_subset() {
        let (code, stdout, stderr) = execute(&["schema", "list", "--json"]);
        assert_eq!(code, ExitCode::SUCCESS);
        assert!(stderr.is_empty());
        assert!(stdout.contains("\"acceptedLocalInputCount\":4"));
        assert!(stdout.contains("fenrua.entity-manifest.v1"));
        assert!(!stdout.contains("fenrua.approval.v1"));
    }

    #[test]
    fn malformed_gate_arguments_have_a_non_leaky_problem_envelope() {
        let (code, stdout, stderr) = execute(&["gate", "evaluate", "--manifest", "only-one"]);
        assert_eq!(code, ExitCode::from(64));
        assert!(stdout.is_empty());
        assert_eq!(
            stderr,
            "{\"schema\":\"fenrua.problem-envelope.r1-draft\",\"code\":\"invalid_argument\",\"title\":\"Command arguments are invalid\",\"status\":400,\"retryable\":false}"
        );
    }

    #[test]
    fn file_adapter_rejects_an_oversized_input_before_parsing() {
        let suffix = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => duration.as_nanos(),
            Err(_) => 0,
        };
        let path = std::env::temp_dir().join(format!(
            "fenrua-r2-oversized-{}-{suffix}.json",
            std::process::id()
        ));
        let bytes = vec![b'x'; ParseLimits::R1_FOUNDATION.max_bytes.saturating_add(1)];
        if let Err(error) = std::fs::write(&path, bytes) {
            panic!("test fixture must be written: {error}");
        }
        let error = match read_bytes(path.to_string_lossy().as_ref()) {
            Ok(_) => panic!("oversized file must fail before parsing"),
            Err(error) => error,
        };
        if let Err(error) = std::fs::remove_file(&path) {
            panic!("test fixture must be removed: {error}");
        }
        assert_eq!(error.code(), ProblemCode::InputTooLarge);
    }
}
