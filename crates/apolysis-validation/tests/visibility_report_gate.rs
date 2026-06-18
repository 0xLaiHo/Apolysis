// SPDX-License-Identifier: Apache-2.0

use apolysis_validation::{
    evaluate_visibility_report_gate, required_f2_visibility_targets, VisibilityReport,
};

#[test]
fn f2_visibility_gate_requires_every_published_runtime_target() {
    let reports = required_f2_visibility_targets()
        .into_iter()
        .map(|target| VisibilityReport {
            target,
            live_validated: true,
            evidence_source: "f2-runtime-adapter-matrix".to_string(),
            host_visibility_scope: "runtime_boundary".to_string(),
            guest_semantics_claimed: false,
        })
        .collect();

    let report = evaluate_visibility_report_gate(reports);

    assert!(report.passed, "{report:#?}");
    assert!(report.failures.is_empty(), "{report:#?}");
    assert_eq!(report.reports.len(), 9);
}

#[test]
fn f2_visibility_gate_rejects_missing_or_unvalidated_reports() {
    let mut targets = required_f2_visibility_targets();
    let missing = targets.pop().expect("one target to remove");
    let mut reports: Vec<_> = targets
        .into_iter()
        .map(|target| VisibilityReport {
            target,
            live_validated: true,
            evidence_source: "f2-runtime-adapter-matrix".to_string(),
            host_visibility_scope: "runtime_boundary".to_string(),
            guest_semantics_claimed: false,
        })
        .collect();
    reports[0].live_validated = false;
    reports[0].evidence_source.clear();
    reports[0].host_visibility_scope.clear();

    let report = evaluate_visibility_report_gate(reports);

    assert!(!report.passed, "{report:#?}");
    let failure_text = serde_json::to_string(&report.failures).expect("serialize failures");
    assert!(
        failure_text.contains(&format!(
            "missing visibility report for {}",
            missing.as_str()
        )),
        "{failure_text}"
    );
    assert!(
        failure_text.contains("visibility report is not live validated"),
        "{failure_text}"
    );
    assert!(
        failure_text.contains("visibility report is missing evidence source"),
        "{failure_text}"
    );
    assert!(
        failure_text.contains("visibility report is missing host visibility scope"),
        "{failure_text}"
    );
}
