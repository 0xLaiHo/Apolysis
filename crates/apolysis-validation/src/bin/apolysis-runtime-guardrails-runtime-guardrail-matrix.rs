// SPDX-License-Identifier: Apache-2.0

use std::io::Read;

use apolysis_validation::{
    evaluate_runtime_guardrails_gvisor_metadata_evidence_gate,
    evaluate_runtime_guardrails_kata_boundary_evidence_gate,
    evaluate_runtime_guardrails_kubernetes_agent_sandbox_evidence_gate,
    evaluate_runtime_guardrails_runtime_adapter_evidence_gate,
    evaluate_runtime_guardrails_runtime_guardrail_matrix,
    evaluate_runtime_guardrails_runtime_guardrail_matrix_with_runtime_metadata,
    PolicyGuardrailsBlockValidationReport, RuntimeGuardrailsGvisorMetadataEvidenceGateReport,
    RuntimeGuardrailsGvisorMetadataEvidenceReport, RuntimeGuardrailsKataBoundaryEvidenceGateReport,
    RuntimeGuardrailsKataBoundaryEvidenceReport,
    RuntimeGuardrailsKubernetesAgentSandboxEvidenceGateReport,
    RuntimeGuardrailsKubernetesAgentSandboxEvidenceReport,
    RuntimeGuardrailsRuntimeAdapterEvidenceReport,
};
use serde_json::Value;

fn main() {
    if let Err(error) = run() {
        eprintln!("apolysis-runtime-guardrails-runtime-guardrail-matrix: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .map_err(|error| format!("failed to read stdin: {error}"))?;
    let parsed: Value = serde_json::from_str(&input).map_err(|error| {
        format!("failed to parse RuntimeGuardrails runtime guardrail matrix JSON: {error}")
    })?;
    let matrix = if parsed.is_array() {
        let reports: Vec<PolicyGuardrailsBlockValidationReport> = serde_json::from_value(parsed)
            .map_err(|error| {
                format!("failed to parse PolicyGuardrails block validation reports JSON: {error}")
            })?;
        evaluate_runtime_guardrails_runtime_guardrail_matrix(reports)
    } else if parsed.is_object() {
        let block_validation_reports: Vec<PolicyGuardrailsBlockValidationReport> =
            serde_json::from_value(
                parsed
                    .get("block_validation_reports")
                    .cloned()
                    .ok_or_else(|| "missing block_validation_reports".to_string())?,
            )
            .map_err(|error| format!("failed to parse block_validation_reports: {error}"))?;
        let runtime_adapter_evidence_reports: Vec<RuntimeGuardrailsRuntimeAdapterEvidenceReport> =
            serde_json::from_value(
                parsed
                    .get("runtime_adapter_evidence_reports")
                    .cloned()
                    .ok_or_else(|| "missing runtime_adapter_evidence_reports".to_string())?,
            )
            .map_err(|error| {
                format!("failed to parse runtime_adapter_evidence_reports: {error}")
            })?;
        let gvisor_metadata_evidence_reports: Vec<RuntimeGuardrailsGvisorMetadataEvidenceReport> =
            parsed
                .get("gvisor_metadata_evidence_reports")
                .cloned()
                .map(serde_json::from_value)
                .transpose()
                .map_err(|error| {
                    format!("failed to parse gvisor_metadata_evidence_reports: {error}")
                })?
                .unwrap_or_default();
        let kubernetes_agent_sandbox_evidence_reports: Vec<
            RuntimeGuardrailsKubernetesAgentSandboxEvidenceReport,
        > = parsed
            .get("kubernetes_agent_sandbox_evidence_reports")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| {
                format!("failed to parse kubernetes_agent_sandbox_evidence_reports: {error}")
            })?
            .unwrap_or_default();
        let kata_boundary_evidence_reports: Vec<RuntimeGuardrailsKataBoundaryEvidenceReport> =
            parsed
                .get("kata_boundary_evidence_reports")
                .cloned()
                .map(serde_json::from_value)
                .transpose()
                .map_err(|error| {
                    format!("failed to parse kata_boundary_evidence_reports: {error}")
                })?
                .unwrap_or_default();
        let adapter_gate = evaluate_runtime_guardrails_runtime_adapter_evidence_gate(
            runtime_adapter_evidence_reports,
        );
        if !adapter_gate.passed {
            let gate_json = serde_json::to_string_pretty(&adapter_gate).map_err(|error| {
                format!(
                    "failed to serialize RuntimeGuardrails runtime adapter evidence gate: {error}"
                )
            })?;
            eprintln!("{gate_json}");
            std::process::exit(1);
        }
        let gvisor_gate = if gvisor_metadata_evidence_reports.is_empty() {
            RuntimeGuardrailsGvisorMetadataEvidenceGateReport {
                schema_version: 1,
                passed: true,
                reports: Vec::new(),
                validated_evidence: Vec::new(),
                failures: Vec::new(),
            }
        } else {
            let gvisor_gate = evaluate_runtime_guardrails_gvisor_metadata_evidence_gate(
                gvisor_metadata_evidence_reports,
            );
            if !gvisor_gate.passed {
                let gate_json = serde_json::to_string_pretty(&gvisor_gate).map_err(|error| {
                    format!("failed to serialize RuntimeGuardrails gVisor metadata evidence gate: {error}")
                })?;
                eprintln!("{gate_json}");
                std::process::exit(1);
            }
            gvisor_gate
        };
        let kubernetes_gate = if kubernetes_agent_sandbox_evidence_reports.is_empty() {
            RuntimeGuardrailsKubernetesAgentSandboxEvidenceGateReport {
                schema_version: 1,
                passed: true,
                reports: Vec::new(),
                validated_evidence: Vec::new(),
                failures: Vec::new(),
            }
        } else {
            let kubernetes_gate =
                evaluate_runtime_guardrails_kubernetes_agent_sandbox_evidence_gate(
                    kubernetes_agent_sandbox_evidence_reports,
                );
            if !kubernetes_gate.passed {
                let gate_json =
                    serde_json::to_string_pretty(&kubernetes_gate).map_err(|error| {
                        format!("failed to serialize RuntimeGuardrails Kubernetes Agent Sandbox evidence gate: {error}")
                    })?;
                eprintln!("{gate_json}");
                std::process::exit(1);
            }
            kubernetes_gate
        };
        let kata_gate = if kata_boundary_evidence_reports.is_empty() {
            RuntimeGuardrailsKataBoundaryEvidenceGateReport {
                schema_version: 1,
                passed: true,
                reports: Vec::new(),
                validated_evidence: Vec::new(),
                failures: Vec::new(),
            }
        } else {
            let kata_gate = evaluate_runtime_guardrails_kata_boundary_evidence_gate(
                kata_boundary_evidence_reports,
            );
            if !kata_gate.passed {
                let gate_json = serde_json::to_string_pretty(&kata_gate).map_err(|error| {
                    format!("failed to serialize RuntimeGuardrails Kata boundary evidence gate: {error}")
                })?;
                eprintln!("{gate_json}");
                std::process::exit(1);
            }
            kata_gate
        };
        evaluate_runtime_guardrails_runtime_guardrail_matrix_with_runtime_metadata(
            block_validation_reports,
            adapter_gate,
            gvisor_gate,
            kubernetes_gate,
            kata_gate,
        )
    } else {
        return Err(
            "RuntimeGuardrails runtime guardrail matrix input must be a JSON array or object"
                .to_string(),
        );
    };
    let output = serde_json::to_string_pretty(&matrix).map_err(|error| {
        format!("failed to serialize RuntimeGuardrails runtime guardrail matrix: {error}")
    })?;
    println!("{output}");
    Ok(())
}
