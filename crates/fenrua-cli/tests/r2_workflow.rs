use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use fenrua_c14n::{DigestDomain, canonical_document_in_domain};
use fenrua_protocol::{JsonValue, ParseLimits, parse_json};

struct TestWorkspace {
    path: PathBuf,
}

impl TestWorkspace {
    fn new() -> Self {
        // The process id prevents collisions with an independently running
        // cargo test process without changing any workflow input or output.
        let path =
            std::env::temp_dir().join(format!("fenrua-cli-r2-workflow-{}", std::process::id()));
        match fs::remove_dir_all(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("test workspace cleanup must succeed: {error}"),
        }
        match fs::create_dir_all(&path) {
            Ok(()) => Self { path },
            Err(error) => panic!("test workspace creation must succeed: {error}"),
        }
    }

    fn output(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for TestWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn fixture_path(name: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/r2")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

fn path_argument(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn evaluation_arguments(output: &Path) -> Vec<String> {
    vec![
        "gate".to_owned(),
        "evaluate".to_owned(),
        "--manifest".to_owned(),
        fixture_path("manifest.json"),
        "--policy".to_owned(),
        fixture_path("policy-allow.json"),
        "--request".to_owned(),
        fixture_path("request-offline.json"),
        "--revocations".to_owned(),
        fixture_path("revocations-current.json"),
        "--at".to_owned(),
        "2026-07-14T00:01:00.000Z".to_owned(),
        "--output".to_owned(),
        path_argument(output),
    ]
}

fn run_cli(arguments: Vec<String>) -> (ExitCode, String, String) {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = fenrua_cli::run(&arguments, &mut stdout, &mut stderr);
    let stdout = match String::from_utf8(stdout) {
        Ok(value) => value,
        Err(error) => panic!("CLI stdout must be UTF-8: {error}"),
    };
    let stderr = match String::from_utf8(stderr) {
        Ok(value) => value,
        Err(error) => panic!("CLI stderr must be UTF-8: {error}"),
    };
    (code, stdout, stderr)
}

fn read(path: &Path) -> Vec<u8> {
    match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => panic!("test artifact must be readable: {error}"),
    }
}

fn parse(bytes: &[u8]) -> JsonValue {
    match parse_json(bytes, ParseLimits::R1_FOUNDATION) {
        Ok(value) => value,
        Err(error) => panic!("CLI JSON output must parse: {error}"),
    }
}

fn object(value: &JsonValue) -> &BTreeMap<String, JsonValue> {
    let JsonValue::Object(fields) = value else {
        panic!("expected JSON object");
    };
    fields
}

fn object_mut(value: &mut JsonValue) -> &mut BTreeMap<String, JsonValue> {
    let JsonValue::Object(fields) = value else {
        panic!("expected mutable JSON object");
    };
    fields
}

fn string_field<'a>(fields: &'a BTreeMap<String, JsonValue>, name: &str) -> &'a str {
    let Some(JsonValue::String(value)) = fields.get(name) else {
        panic!("expected string field {name}");
    };
    value
}

#[test]
fn r2_cli_workflow_writes_verifies_refuses_overwrite_and_detects_tampering() {
    let workspace = TestWorkspace::new();
    let output = workspace.output("evaluation.json");

    let (code, stdout, stderr) = run_cli(evaluation_arguments(&output));
    assert_eq!(code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert!(stdout.contains("\"decision\":\"ALLOW\""));
    assert!(stdout.contains("\"outputWritten\":true"));

    let artifact = read(&output);
    let envelope = parse(&artifact);
    let envelope_fields = object(&envelope);
    assert_eq!(
        string_field(envelope_fields, "schemaVersion"),
        "fenrua.local-evaluation.r2-draft"
    );
    let Some(JsonValue::Object(decision)) = envelope_fields.get("decision") else {
        panic!("local envelope must contain a decision object");
    };
    assert_eq!(string_field(decision, "decision"), "ALLOW");
    let Some(JsonValue::Object(evidence)) = envelope_fields.get("evidenceBundle") else {
        panic!("local envelope must contain an evidence bundle object");
    };
    assert_eq!(
        string_field(evidence, "schemaVersion"),
        "fenrua.evidence-bundle.v2"
    );
    let Some(JsonValue::Array(inputs)) = evidence.get("inputs") else {
        panic!("evidence bundle must contain input references");
    };
    assert!(inputs.iter().any(|input| {
        let JsonValue::Object(input) = input else {
            return false;
        };
        matches!(
            input.get("schemaId"),
            Some(JsonValue::String(schema_id))
                if schema_id == "urn:fenrua:schema:authority-policy-v2"
        )
    }));

    let (code, stdout, stderr) = run_cli(vec![
        "evidence".to_owned(),
        "verify".to_owned(),
        path_argument(&output),
    ]);
    assert_eq!(code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert_eq!(
        string_field(object(&parse(stdout.as_bytes())), "verificationState"),
        "PASS_WITH_LIMITATIONS"
    );

    let (code, stdout, stderr) = run_cli(evaluation_arguments(&output));
    assert_eq!(code, ExitCode::from(64));
    assert!(stdout.is_empty());
    assert!(stderr.contains("\"code\":\"io_failure\""));
    assert_eq!(read(&output), artifact);

    let mut tampered = parse(&artifact);
    let tampered_fields = object_mut(&mut tampered);
    let Some(JsonValue::Object(decision)) = tampered_fields.get_mut("decision") else {
        panic!("local envelope must contain a mutable decision object");
    };
    decision.insert("decision".to_owned(), JsonValue::String("DENY".to_owned()));
    let canonical =
        match canonical_document_in_domain(&tampered, DigestDomain::CanonicalJsonR2Prototype) {
            Ok(document) => document,
            Err(error) => panic!("tampered local envelope must canonicalize: {error}"),
        };
    let tampered_output = workspace.output("tampered-evaluation.json");
    match fs::write(&tampered_output, canonical.bytes()) {
        Ok(()) => {}
        Err(error) => panic!("tampered local envelope must be writable: {error}"),
    }

    let (code, stdout, stderr) = run_cli(vec![
        "evidence".to_owned(),
        "verify".to_owned(),
        path_argument(&tampered_output),
    ]);
    assert_eq!(code, ExitCode::from(20));
    assert!(stderr.is_empty());
    assert_eq!(
        string_field(object(&parse(stdout.as_bytes())), "verificationState"),
        "INTEGRITY_MISMATCH"
    );
}
