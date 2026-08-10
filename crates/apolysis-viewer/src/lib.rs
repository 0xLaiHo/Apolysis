// SPDX-License-Identifier: Apache-2.0

//! Offline presentation of one frozen Agent Observation Record.

use apolysis_accountability::{
    validate_agent_observation_record_v1, AgentObservationRecord,
    AgentObservationRecordValidationError, AGENT_OBSERVATION_RECORD_SCHEMA_V1,
};
use serde::Deserialize;

mod html;

use html::render_record;

const MAX_VIEWER_INPUT_BYTES: usize = 128 * 1024 * 1024;

/// A complete, self-contained HTML document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StandaloneHtml(Box<[u8]>);

impl AsRef<[u8]> for StandaloneHtml {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Stable, payload-free viewer failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ViewerError {
    InputLimitExceeded,
    MalformedRecord,
    UnsupportedRecordType,
    UnsupportedSchemaVersion,
    InconsistentRecord,
    ArtifactLimitExceeded,
}

impl std::fmt::Display for ViewerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InputLimitExceeded => "viewer input exceeds its byte limit",
            Self::MalformedRecord => "viewer input is not a valid Agent Observation Record",
            Self::UnsupportedRecordType => "viewer input has an unsupported record type",
            Self::UnsupportedSchemaVersion => "viewer input has an unsupported schema version",
            Self::InconsistentRecord => "Agent Observation Record is internally inconsistent",
            Self::ArtifactLimitExceeded => "viewer artifact exceeds its byte limit",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ViewerError {}

#[derive(Deserialize)]
struct RecordEnvelope {
    record_type: String,
    schema_version: u32,
}

/// Render one Agent Observation Record v1 as deterministic standalone HTML.
pub fn render_agent_observation_record_v1(
    record_json: &[u8],
) -> Result<StandaloneHtml, ViewerError> {
    if record_json.len() > MAX_VIEWER_INPUT_BYTES {
        return Err(ViewerError::InputLimitExceeded);
    }
    let envelope: RecordEnvelope =
        serde_json::from_slice(record_json).map_err(|_| ViewerError::MalformedRecord)?;
    if envelope.record_type != "agent_observation_record" {
        return Err(ViewerError::UnsupportedRecordType);
    }
    if envelope.schema_version != AGENT_OBSERVATION_RECORD_SCHEMA_V1 {
        return Err(ViewerError::UnsupportedSchemaVersion);
    }
    let record: AgentObservationRecord =
        serde_json::from_slice(record_json).map_err(|_| ViewerError::MalformedRecord)?;
    validate_agent_observation_record_v1(&record).map_err(|error| match error {
        AgentObservationRecordValidationError::UnsupportedRecordType => {
            ViewerError::UnsupportedRecordType
        }
        AgentObservationRecordValidationError::UnsupportedSchemaVersion => {
            ViewerError::UnsupportedSchemaVersion
        }
        _ => ViewerError::InconsistentRecord,
    })?;
    render_record(&record)
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::{render_agent_observation_record_v1, ViewerError};

    #[test]
    fn standalone_report_is_interactive_without_executing_record_text() {
        let mut record = reviewable_record();
        record["runtime_observations"][0]["resource"] =
            json!("</script><script>window.APOLYSIS_VIEW_PWNED = true</script>");
        record["runtime_observations"][0]["timestamp_unix_ms"] = json!(u64::MAX);

        let html = render_agent_observation_record_v1(
            &serde_json::to_vec(&record).expect("serialize test record"),
        )
        .expect("render valid record");
        let html = std::str::from_utf8(html.as_ref()).expect("viewer output is utf-8");

        assert!(html.contains("data-action=\"toggle-theme\""));
        assert!(html.contains("data-action=\"toggle-density\""));
        assert!(html.contains("<body data-default-panel=\"findings\""));
        assert!(html.contains("data-panel-target=\"observations\""));
        assert!(html.contains("data-evidence-target=\"observation-2\""));
        assert!(html.contains("/summary/evidence_state"));
        assert!(html.contains("/summary/collector_health"));
        assert!(html.contains("/summary/review_state"));
        assert!(html.contains("No canonical process tree in schema v1."));
        assert!(html.contains("connect-src 'none'"));
        assert!(html.contains("base-uri 'none'"));
        assert!(html.contains("18446744073709551615"));
        assert!(html.contains(
            "&lt;/script&gt;&lt;script&gt;window.APOLYSIS_VIEW_PWNED = true&lt;/script&gt;"
        ));
        assert_eq!(html.matches("<script>").count(), 1);
        assert!(!html.contains("innerHTML"));
        assert!(!html.contains("document.write"));
        assert!(!html.contains("eval("));
        assert!(!html.contains("fetch("));
        assert!(!html.contains("XMLHttpRequest"));
        assert!(!html.contains("WebSocket"));
        assert!(!html.contains("serviceWorker"));
        assert!(!html.contains("localStorage"));
        assert!(!html.contains("src=\"http"));
        assert!(!html.contains("href=\"http"));
    }

    #[test]
    fn report_preserves_saved_attribution_gap_and_lifecycle_facts_without_inferred_tree() {
        let mut record = reviewable_record();
        record["runtime_observations"][0]["container_id"] =
            json!("container-42</bdi><script>window.APOLYSIS_ATTRIBUTION_PWNED=true</script>");
        record["runtime_observations"][0]["cgroup_id"] = json!("cgroup-18446744073709551615");
        record["runtime_observations"][0]["process_started_at_unix_ms"] =
            json!(18446744073709551614_u64);
        record["findings"][0]["runtime"]["container_id"] = json!("runtime-container-42");
        record["findings"][0]["runtime"]["pod_uid"] = json!("00000000-0000-0000-0000-000000000042");
        record["findings"][0]["runtime"]["cgroup_id"] = json!(18446744073709551615_u64);
        record["collector_lifecycle"][0]["collector_instance_id"] =
            json!("collector-instance:restart/2");
        record["collector_lifecycle"][1]["collector_instance_id"] =
            json!("collector-instance:restart/2");
        record["collector_lifecycle"][1]["source_ordinal"] = json!(4);
        record["findings"][0]["source_ordinal"] = json!(5);
        record["observation_gaps"] = json!([{
            "source_ordinal": 3,
            "schema_version": 1,
            "timestamp_unix_ms": 1003,
            "operation": "process_exec</bdi><script>window.APOLYSIS_GAP_PWNED=true</script>",
            "kind": "missing_entry",
            "count": 2,
            "detail": "bounded_loss_counter"
        }]);
        record["issues"] = json!([{
            "code": "missing_capability",
            "source_ordinal": null,
            "count": 1
        }, {
            "code": "observation_gap",
            "source_ordinal": 3,
            "count": 2
        }]);
        record["summary"]["observation_gap_record_count"] = json!(1);
        record["summary"]["known_missing_observation_count"] = json!(2);
        record["summary"]["gap_kind_counts"] = json!({"missing_entry": 1});

        let html = render_agent_observation_record_v1(
            &serde_json::to_vec(&record).expect("serialize attributed record"),
        )
        .expect("render attributed record");
        let html = std::str::from_utf8(html.as_ref()).expect("viewer output is utf-8");

        assert!(html.contains(
            "<dt>Operation</dt><dd><bdi class=\"fact-text\">process_exec&lt;/bdi&gt;&lt;script&gt;window.APOLYSIS_GAP_PWNED=true&lt;/script&gt;</bdi></dd>"
        ));
        assert!(html.contains(
            "<dt>Container ID</dt><dd><bdi class=\"fact-text\">container-42&lt;/bdi&gt;&lt;script&gt;window.APOLYSIS_ATTRIBUTION_PWNED=true&lt;/script&gt;</bdi></dd>"
        ));
        assert!(html.contains(
            "<dt>Cgroup ID</dt><dd><bdi class=\"fact-text\">cgroup-18446744073709551615</bdi></dd>"
        ));
        assert!(html.contains(
            "<dt>Process started (Unix ms)</dt><dd class=\"mono-value\">18446744073709551614</dd>"
        ));
        assert!(html.contains("<dt>Parent process generation</dt><dd class=\"mono-value\">3</dd>"));
        assert!(html.contains("<dt>Parent exec generation</dt><dd class=\"mono-value\">1</dd>"));
        assert!(html.contains(
            "<dt>Container ID</dt><dd><bdi class=\"fact-text\">runtime-container-42</bdi></dd>"
        ));
        assert!(html.contains(
            "<dt>Pod UID</dt><dd><bdi class=\"fact-text\">00000000-0000-0000-0000-000000000042</bdi></dd>"
        ));
        assert!(
            html.contains("<dt>Cgroup ID</dt><dd class=\"mono-value\">18446744073709551615</dd>")
        );
        assert_eq!(
            html.matches(
                "<dt>Collector instance</dt><dd><bdi class=\"fact-text\">collector-instance:restart/2</bdi></dd>"
            )
            .count(),
            2
        );
        assert!(html.contains("No canonical process tree in schema v1."));
        assert!(!html.contains("<script>window.APOLYSIS_ATTRIBUTION_PWNED"));
        assert!(!html.contains("<script>window.APOLYSIS_GAP_PWNED"));
    }

    #[test]
    fn renderer_rejects_non_v1_and_trailing_payloads_with_payload_free_errors() {
        let mut record = reviewable_record();
        record["record_type"] = json!("APOLYSIS_SECRET_OTHER_RECORD");
        let error = render_agent_observation_record_v1(
            &serde_json::to_vec(&record).expect("serialize wrong record type"),
        )
        .expect_err("wrong record type must fail");
        assert_eq!(error, ViewerError::UnsupportedRecordType);
        assert!(!error.to_string().contains("APOLYSIS_SECRET"));

        let mut record = reviewable_record();
        record["schema_version"] = json!(2);
        assert_eq!(
            render_agent_observation_record_v1(
                &serde_json::to_vec(&record).expect("serialize wrong schema")
            ),
            Err(ViewerError::UnsupportedSchemaVersion)
        );

        let mut record = serde_json::to_vec(&reviewable_record()).expect("serialize valid record");
        record.extend_from_slice(b"\n{}");
        assert_eq!(
            render_agent_observation_record_v1(&record),
            Err(ViewerError::MalformedRecord)
        );
    }

    fn reviewable_record() -> Value {
        json!({
            "record_type": "agent_observation_record",
            "schema_version": 1,
            "agent_run_id": "run-viewer-unit",
            "source_integrity": "unverified_plain_jsonl",
            "summary": {
                "evidence_state": "incomplete",
                "collector_health": "healthy",
                "review_state": "requires_review",
                "runtime_observation_count": 1,
                "runtime_identity_count": 1,
                "finding_count": 1,
                "observation_gap_record_count": 0,
                "known_missing_observation_count": 0,
                "unknown_history_boundary_count": 0,
                "event_type_counts": {"network_connect": 1},
                "outcome_counts": {"succeeded": 1},
                "relation_counts": {"exact": 1},
                "finding_kind_counts": {"unknown_egress": 1},
                "gap_kind_counts": {}
            },
            "capability_manifests": [],
            "runtime_identities": [{
                "identity_id": "identity-1",
                "host_boot_id": "00000000-0000-0000-0000-000000000042",
                "scope_generation": 7,
                "pid": 42,
                "process_generation": 11,
                "process_start_time_ns": 123456,
                "exec_generation": 2,
                "first_source_ordinal": 2,
                "last_source_ordinal": 2,
                "observation_count": 1
            }],
            "runtime_observations": [{
                "source_ordinal": 2,
                "timestamp_unix_ms": 1002,
                "event_source": "kernel_tracepoint",
                "event_type": "network_connect",
                "raw_event_id": "event-1",
                "pid": 42,
                "ppid": 1,
                "actor": "agent",
                "resource": "address_token:0123456789abcdef01234567:port:443",
                "action": "connect",
                "outcome": "succeeded",
                "return_value": 0,
                "errno": null,
                "container_id": null,
                "cgroup_id": null,
                "relation_status": "exact",
                "relation_reason": "host_boot_scope_process_start_exec_generation",
                "process_executable": "executable_ref:agent",
                "process_started_at_unix_ms": null,
                "runtime_identity_id": "identity-1",
                "parent_process_generation": 3,
                "parent_exec_generation": 1
            }],
            "collector_lifecycle": [{
                "source_ordinal": 1,
                "schema_version": 1,
                "timestamp_unix_ms": 1001,
                "collector": "apolysis_observer",
                "collector_instance_id": "collector-1",
                "state": "started",
                "health": "healthy",
                "stop_reason": null,
                "counters": zero_counters()
            }, {
                "source_ordinal": 3,
                "schema_version": 1,
                "timestamp_unix_ms": 1003,
                "collector": "apolysis_observer",
                "collector_instance_id": "collector-1",
                "state": "stopped",
                "health": "healthy",
                "stop_reason": "agent_exited",
                "counters": zero_counters()
            }],
            "findings": [{
                "source_ordinal": 4,
                "schema_version": 1,
                "kind": "unknown_egress",
                "decision": "review",
                "reason": "network endpoint is outside the declared egress set",
                "evidence_ref": "event-1",
                "runtime": {
                    "runtime": "native",
                    "container_id": null,
                    "pod_uid": null,
                    "cgroup_id": null
                },
                "evidence_boundary": "host_boundary"
            }],
            "observation_gaps": [],
            "issues": [{
                "code": "missing_capability",
                "source_ordinal": null,
                "count": 1
            }]
        })
    }

    fn zero_counters() -> Value {
        json!({
            "global_reserve_failures": 0,
            "global_map_pressure": 0,
            "global_abi_mismatches": 0,
            "global_decode_failures": 0,
            "global_truncations": 0,
            "scope_missing_entries": 0,
            "scope_missing_exits": 0,
            "scope_pending": 0
        })
    }
}
