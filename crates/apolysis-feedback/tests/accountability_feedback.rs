// SPDX-License-Identifier: Apache-2.0

use apolysis_accountability::{
    AccountabilityFinding, EvidenceBoundary, FindingDecision, FindingKind, RuntimeIdentity,
    FINDING_SCHEMA_V1,
};
use apolysis_feedback::FeedbackWriter;

#[test]
fn writes_latest_accountability_finding_feedback_atomically() {
    let directory = std::env::temp_dir().join(format!(
        "apolysis-accountability-feedback-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    let writer = FeedbackWriter::new(&directory);

    writer
        .write_last_accountability_finding(&finding(
            FindingKind::UnknownEgress,
            FindingDecision::Review,
            "network endpoint is outside the declared egress set",
        ))
        .expect("accountability feedback");

    let text =
        std::fs::read_to_string(writer.accountability_path()).expect("text finding feedback");
    assert!(text.contains("Apolysis accountability finding"));
    assert!(text.contains("session_id: session-f2"));
    assert!(text.contains("kind: unknown_egress"));
    assert!(text.contains("decision: review"));

    let json =
        std::fs::read_to_string(writer.accountability_json_path()).expect("JSON finding feedback");
    let value: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(value["session_id"], "session-f2");
    assert_eq!(value["kind"], "unknown_egress");
    assert_eq!(value["decision"], "review");
    assert_eq!(value["runtime"]["runtime"], "docker");
    assert_eq!(value["runtime"]["container_id"], "container-7");

    let temporary_files: Vec<_> = std::fs::read_dir(&directory)
        .expect("feedback directory")
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp-"))
        .collect();
    assert!(
        temporary_files.is_empty(),
        "temporary files remain: {temporary_files:?}"
    );

    let _ = std::fs::remove_dir_all(&directory);
}

fn finding(kind: FindingKind, decision: FindingDecision, reason: &str) -> AccountabilityFinding {
    AccountabilityFinding {
        schema_version: FINDING_SCHEMA_V1,
        session_id: "session-f2".to_string(),
        kind,
        decision,
        reason: reason.to_string(),
        evidence_ref: "raw_kernel_event:1:2:connect".to_string(),
        runtime: RuntimeIdentity {
            runtime: "docker".to_string(),
            container_id: Some("container-7".to_string()),
            pod_uid: None,
            cgroup_id: Some(42),
        },
        evidence_boundary: EvidenceBoundary::HostBoundary,
    }
}
