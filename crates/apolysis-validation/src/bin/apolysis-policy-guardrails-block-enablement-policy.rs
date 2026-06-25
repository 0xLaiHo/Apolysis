// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io::Read;
use std::path::PathBuf;

use apolysis_validation::{
    evaluate_policy_guardrails_block_enablement_policy, PolicyGuardrailsBlockEnablementRequest,
    PolicyGuardrailsBlockValidationGateReport,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct EnablementPolicyInput {
    requests: Vec<PolicyGuardrailsBlockEnablementRequest>,
}

fn main() {
    if let Err(error) = run(std::env::args().skip(1).collect()) {
        eprintln!("apolysis-policy-guardrails-block-enablement-policy: {error}");
        std::process::exit(2);
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    let validation_gate_path = parse_validation_gate_arg(args)?;
    let validation_input = fs::read_to_string(&validation_gate_path).map_err(|error| {
        format!(
            "failed to read validation gate report {}: {error}",
            validation_gate_path.display()
        )
    })?;
    let validation: PolicyGuardrailsBlockValidationGateReport =
        serde_json::from_str(&validation_input)
            .map_err(|error| format!("failed to parse validation gate JSON: {error}"))?;

    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .map_err(|error| format!("failed to read stdin: {error}"))?;
    let parsed: EnablementPolicyInput = serde_json::from_str(&input)
        .map_err(|error| format!("failed to parse enablement request JSON: {error}"))?;

    let report = evaluate_policy_guardrails_block_enablement_policy(validation, parsed.requests);
    let output = serde_json::to_string_pretty(&report)
        .map_err(|error| format!("failed to serialize enablement policy report: {error}"))?;
    println!("{output}");
    if report.passed {
        Ok(())
    } else {
        std::process::exit(1);
    }
}

fn parse_validation_gate_arg(args: Vec<String>) -> Result<PathBuf, String> {
    match args.as_slice() {
        [flag, path] if flag == "--validation-gate" => Ok(PathBuf::from(path)),
        _ => Err(
            "usage: apolysis-policy-guardrails-block-enablement-policy --validation-gate <path>"
                .to_string(),
        ),
    }
}
