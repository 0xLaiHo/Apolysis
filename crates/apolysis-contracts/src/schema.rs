// SPDX-License-Identifier: Apache-2.0

//! Deterministic JSON Schema exports for the public v0.1 contract roots.

use std::collections::BTreeMap;

use schemars::{schema_for, Schema};
use serde_json::json;

use crate::{
    AgentExecutionRecordItem, BindRuntimeRequest, BindRuntimeResponse, CoverageSummary,
    FinishRunRequest, FinishRunResponse, GatewayErrorResponse, IngestAck, IngestRequest,
    OpenRunRequest, OpenRunResponse, QueryError, RunExplorerPage, RunOverview, SourceEnvelope,
    SourceManifest, TimelinePage, TypedEvidencePayload,
};

/// Generate every committed v0.1 schema from the Rust wire types.
pub fn contract_schemas() -> BTreeMap<&'static str, Schema> {
    BTreeMap::from([
        (
            "agent-execution-record-item.schema.json",
            schema_for!(AgentExecutionRecordItem),
        ),
        (
            "bind-runtime-request.schema.json",
            schema_for!(BindRuntimeRequest),
        ),
        (
            "bind-runtime-response.schema.json",
            schema_for!(BindRuntimeResponse),
        ),
        ("coverage-summary.schema.json", schema_for!(CoverageSummary)),
        (
            "finish-run-request.schema.json",
            schema_for!(FinishRunRequest),
        ),
        (
            "finish-run-response.schema.json",
            schema_for!(FinishRunResponse),
        ),
        (
            "gateway-error-response.schema.json",
            schema_for!(GatewayErrorResponse),
        ),
        ("ingest-ack.schema.json", schema_for!(IngestAck)),
        ("ingest-request.schema.json", schema_for!(IngestRequest)),
        ("open-run-request.schema.json", schema_for!(OpenRunRequest)),
        (
            "open-run-response.schema.json",
            schema_for!(OpenRunResponse),
        ),
        ("query-error.schema.json", schema_for!(QueryError)),
        (
            "run-explorer-page.schema.json",
            schema_for!(RunExplorerPage),
        ),
        ("run-overview.schema.json", schema_for!(RunOverview)),
        ("source-envelope.schema.json", source_envelope_schema()),
        ("source-manifest.schema.json", schema_for!(SourceManifest)),
        ("timeline-page.schema.json", schema_for!(TimelinePage)),
        (
            "typed-evidence-payload.schema.json",
            schema_for!(TypedEvidencePayload),
        ),
    ])
}

fn source_envelope_schema() -> Schema {
    let mut schema = schema_for!(SourceEnvelope);
    schema.insert(
        "oneOf".to_string(),
        json!([
            {
                "required": ["inline_payload"],
                "properties": {
                    "inline_payload": {"not": {"type": "null"}},
                    "object_ref": {"type": "null"}
                }
            },
            {
                "required": ["object_ref"],
                "properties": {
                    "inline_payload": {"type": "null"},
                    "object_ref": {"not": {"type": "null"}}
                }
            }
        ]),
    );
    schema
}
