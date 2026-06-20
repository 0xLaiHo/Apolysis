// SPDX-License-Identifier: Apache-2.0

use std::io::Read;

use apolysis_validation::{
    evaluate_f4_gvisor_metadata_evidence_gate, evaluate_f4_runtime_adapter_evidence_gate,
    evaluate_f4_runtime_guardrail_matrix,
    evaluate_f4_runtime_guardrail_matrix_with_adapter_evidence, F3BlockValidationReport,
    F4GvisorMetadataEvidenceReport, F4RuntimeAdapterEvidenceReport,
};
use serde_json::Value;

fn main() {
    if let Err(error) = run() {
        eprintln!("apolysis-f4-runtime-guardrail-matrix: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .map_err(|error| format!("failed to read stdin: {error}"))?;
    let parsed: Value = serde_json::from_str(&input)
        .map_err(|error| format!("failed to parse F4 runtime guardrail matrix JSON: {error}"))?;
    let matrix = if parsed.is_array() {
        let reports: Vec<F3BlockValidationReport> =
            serde_json::from_value(parsed).map_err(|error| {
                format!("failed to parse F3 block validation reports JSON: {error}")
            })?;
        evaluate_f4_runtime_guardrail_matrix(reports)
    } else if parsed.is_object() {
        let block_validation_reports: Vec<F3BlockValidationReport> = serde_json::from_value(
            parsed
                .get("block_validation_reports")
                .cloned()
                .ok_or_else(|| "missing block_validation_reports".to_string())?,
        )
        .map_err(|error| format!("failed to parse block_validation_reports: {error}"))?;
        let runtime_adapter_evidence_reports: Vec<F4RuntimeAdapterEvidenceReport> =
            serde_json::from_value(
                parsed
                    .get("runtime_adapter_evidence_reports")
                    .cloned()
                    .ok_or_else(|| "missing runtime_adapter_evidence_reports".to_string())?,
            )
            .map_err(|error| {
                format!("failed to parse runtime_adapter_evidence_reports: {error}")
            })?;
        let gvisor_metadata_evidence_reports: Vec<F4GvisorMetadataEvidenceReport> = parsed
            .get("gvisor_metadata_evidence_reports")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| format!("failed to parse gvisor_metadata_evidence_reports: {error}"))?
            .unwrap_or_default();
        let adapter_gate =
            evaluate_f4_runtime_adapter_evidence_gate(runtime_adapter_evidence_reports);
        if !adapter_gate.passed {
            let gate_json = serde_json::to_string_pretty(&adapter_gate).map_err(|error| {
                format!("failed to serialize F4 runtime adapter evidence gate: {error}")
            })?;
            eprintln!("{gate_json}");
            std::process::exit(1);
        }
        if gvisor_metadata_evidence_reports.is_empty() {
            evaluate_f4_runtime_guardrail_matrix_with_adapter_evidence(
                block_validation_reports,
                adapter_gate,
            )
        } else {
            let gvisor_gate =
                evaluate_f4_gvisor_metadata_evidence_gate(gvisor_metadata_evidence_reports);
            if !gvisor_gate.passed {
                let gate_json = serde_json::to_string_pretty(&gvisor_gate).map_err(|error| {
                    format!("failed to serialize F4 gVisor metadata evidence gate: {error}")
                })?;
                eprintln!("{gate_json}");
                std::process::exit(1);
            }
            apolysis_validation::evaluate_f4_runtime_guardrail_matrix_with_gvisor_metadata(
                block_validation_reports,
                adapter_gate,
                gvisor_gate,
            )
        }
    } else {
        return Err("F4 runtime guardrail matrix input must be a JSON array or object".to_string());
    };
    let output = serde_json::to_string_pretty(&matrix)
        .map_err(|error| format!("failed to serialize F4 runtime guardrail matrix: {error}"))?;
    println!("{output}");
    Ok(())
}
