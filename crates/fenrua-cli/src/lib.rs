//! Thin, local-only discovery adapter for the unreleased R1 foundation.
//!
//! The CLI deliberately exposes version, schema discovery, and a static doctor
//! self-description only. It does not read input files, evaluate policy, emit
//! decisions, contact a service, or handle keys.

use std::io::Write;
use std::process::ExitCode;

use fenrua_crypto::profile_descriptors;
use fenrua_protocol::{Problem, ProblemCode, reserved_schemas};

const COMPONENT: &str = "fenrua-trust-gate";
const MATURITY: &str = "R1";
const CONTRACT_STATUS: &str = "unreleased";
const PRODUCT_AVAILABILITY: &str = "not-available";

const HELP: &str = "fenrua Trust Gate R1 foundation (unreleased)\n\nAvailable local discovery commands:\n  fenrua version [--json]\n  fenrua schema list [--json]\n  fenrua doctor [--json]\n\nNo schema validation, evaluation, evidence verification, file I/O, network, or key operations are enabled in this R1 foundation.\n";

/// Runs the intentionally small discovery command surface.
pub fn run(arguments: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> ExitCode {
    match arguments {
        [] => write_text(stdout, HELP),
        [argument] if is_help(argument) => write_text(stdout, HELP),
        [argument] if argument == "--version" => write_text(stdout, &version_human()),
        [command] if command == "version" => write_text(stdout, &version_human()),
        [command, option] if command == "version" && option == "--json" => {
            write_text(stdout, &version_json())
        }
        [command, subcommand] if command == "schema" && subcommand == "list" => {
            write_text(stdout, &schema_list_human())
        }
        [command, subcommand, option]
            if command == "schema" && subcommand == "list" && option == "--json" =>
        {
            write_text(stdout, &schema_list_json())
        }
        [command] if command == "doctor" => write_text(stdout, &doctor_human()),
        [command, option] if command == "doctor" && option == "--json" => {
            write_text(stdout, &doctor_json())
        }
        _ => write_problem(stderr, Problem::new(ProblemCode::InvalidArgument)),
    }
}

fn is_help(argument: &str) -> bool {
    matches!(argument, "help" | "--help" | "-h")
}

fn version_human() -> String {
    format!(
        "{COMPONENT} {}\nmaturity: {MATURITY} foundation\ncontract status: {CONTRACT_STATUS}\nproduct availability: {PRODUCT_AVAILABILITY}\n",
        env!("CARGO_PKG_VERSION")
    )
}

fn version_json() -> String {
    format!(
        "{{\"component\":\"{COMPONENT}\",\"contractStatus\":\"{CONTRACT_STATUS}\",\"maturity\":\"{MATURITY}\",\"productAvailability\":\"{PRODUCT_AVAILABILITY}\",\"version\":\"{}\"}}\n",
        env!("CARGO_PKG_VERSION")
    )
}

fn schema_list_human() -> String {
    let mut output = String::from(
        "Schema discovery\ncontract status: unreleased\naccepted schemas: 0\nreserved bootstrap identifiers (not accepted as input):\n",
    );
    for descriptor in reserved_schemas() {
        output.push_str("  ");
        output.push_str(descriptor.id());
        output.push_str(" [");
        output.push_str(descriptor.status().as_str());
        output.push_str("]\n");
    }
    output
}

fn schema_list_json() -> String {
    let mut output =
        String::from("{\"acceptedSchemaCount\":0,\"contractStatus\":\"unreleased\",\"schemas\":[");
    for (index, descriptor) in reserved_schemas().iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        output.push_str("{\"acceptsDocuments\":false,\"id\":\"");
        output.push_str(descriptor.id());
        output.push_str("\",\"status\":\"");
        output.push_str(descriptor.status().as_str());
        output.push_str("\"}");
    }
    output.push_str("]}\n");
    output
}

fn doctor_human() -> String {
    let mut output = String::from(
        "R1 foundation doctor self-description\nThis is not a runtime health check or release attestation.\n",
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
        "{\"component\":\"fenrua-trust-gate\",\"contractStatus\":\"unreleased\",\"doctorKind\":\"static-r1-self-description\",\"checks\":[",
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

fn doctor_checks() -> [(&'static str, &'static str, &'static str); 5] {
    [
        (
            "network",
            "not-implemented",
            "no network client or remote loading path is included",
        ),
        (
            "schema-validation",
            "not-implemented",
            "reserved names are discoverable but no schema is accepted",
        ),
        (
            "evaluation",
            "not-implemented",
            "no policy evaluator or authorization decision entrypoint is included",
        ),
        (
            "key-operations",
            "not-implemented",
            "profile labels are registry-only and no key operation is included",
        ),
        ("profiles", "reserved-unreleased", profile_count_detail()),
    ]
}

fn profile_count_detail() -> &'static str {
    match profile_descriptors().len() {
        4 => "four bootstrap profile labels are reserved and unavailable",
        _ => "bootstrap profile registry differs from the R1 documented set",
    }
}

fn write_text(output: &mut dyn Write, value: &str) -> ExitCode {
    match output.write_all(value.as_bytes()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
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

    use super::run;

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
    fn version_json_is_truthful_about_r1_status() {
        let (code, stdout, stderr) = execute(&["version", "--json"]);
        assert_eq!(code, ExitCode::SUCCESS);
        assert!(stderr.is_empty());
        assert_eq!(
            stdout,
            "{\"component\":\"fenrua-trust-gate\",\"contractStatus\":\"unreleased\",\"maturity\":\"R1\",\"productAvailability\":\"not-available\",\"version\":\"0.1.0-r1.0\"}\n"
        );
    }

    #[test]
    fn schema_list_does_not_claim_validation_support() {
        let (code, stdout, stderr) = execute(&["schema", "list", "--json"]);
        assert_eq!(code, ExitCode::SUCCESS);
        assert!(stderr.is_empty());
        assert!(stdout.contains("\"acceptedSchemaCount\":0"));
        assert!(stdout.contains("\"acceptsDocuments\":false"));
        assert!(stdout.contains("fenrua.entity-manifest.v1"));
    }

    #[test]
    fn doctor_is_a_static_self_description_not_a_health_claim() {
        let (code, stdout, stderr) = execute(&["doctor", "--json"]);
        assert_eq!(code, ExitCode::SUCCESS);
        assert!(stderr.is_empty());
        assert!(stdout.contains("static-r1-self-description"));
        assert!(stdout.contains("not-implemented"));
    }

    #[test]
    fn invalid_arguments_have_a_non_leaky_problem_envelope() {
        let (code, stdout, stderr) = execute(&["gate", "evaluate", "untrusted-value"]);
        assert_eq!(code, ExitCode::from(64));
        assert!(stdout.is_empty());
        assert_eq!(
            stderr,
            "{\"schema\":\"fenrua.problem-envelope.r1-draft\",\"code\":\"invalid_argument\",\"title\":\"Command arguments are invalid\",\"status\":400,\"retryable\":false}"
        );
    }
}
