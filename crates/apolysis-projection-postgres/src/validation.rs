// SPDX-License-Identifier: Apache-2.0

use apolysis_contracts::{AgentExecutionRecordFact, AgentExecutionRecordItem, SchemaVersion};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::InputFailureCode;

pub(crate) const MAX_LEDGER_ITEM_BYTES: i32 = 1_048_576;
const MAX_I_JSON_INTEGER: u64 = 9_007_199_254_740_991;
const BATCH_DIGEST_DOMAIN: &[u8] = b"apolysis.projection.input-batch/v1\0";

pub(crate) struct StoredLedgerRow {
    pub organization_id: String,
    pub run_id: String,
    pub ingest_sequence: i64,
    pub schema_version: String,
    pub ingested_at_unix_ms: i64,
    pub fact_kind: String,
    pub fact_json: Option<Value>,
    pub fact_size: i32,
    pub fact_digest: Vec<u8>,
    pub outbox_topic: String,
    pub outbox_state: String,
}

pub(crate) struct ValidatedLedgerRow {
    pub item: AgentExecutionRecordItem,
    pub fact_digest: [u8; 32],
}

pub(crate) fn validate_stored_ledger_row(
    row: StoredLedgerRow,
) -> Result<ValidatedLedgerRow, InputFailureCode> {
    if row.fact_size > MAX_LEDGER_ITEM_BYTES {
        return Err(InputFailureCode::OversizedInput);
    }
    let raw = row.fact_json.ok_or(InputFailureCode::InvalidContract)?;
    validate_i_json_numbers(&raw).map_err(|()| InputFailureCode::InvalidContract)?;
    let raw_canonical =
        serde_json_canonicalizer::to_vec(&raw).map_err(|_| InputFailureCode::InvalidContract)?;
    let calculated = Sha256::digest(&raw_canonical);
    if row.fact_digest.len() != calculated.len()
        || !constant_time_eq(&row.fact_digest, calculated.as_slice())
    {
        return Err(InputFailureCode::DigestMismatch);
    }

    let item: AgentExecutionRecordItem =
        serde_json::from_value(raw).map_err(|_| InputFailureCode::InvalidContract)?;
    let typed_canonical =
        serde_json_canonicalizer::to_vec(&item).map_err(|_| InputFailureCode::InvalidContract)?;
    if !constant_time_eq(&raw_canonical, &typed_canonical) {
        return Err(InputFailureCode::InvalidContract);
    }

    let sequence =
        u64::try_from(row.ingest_sequence).map_err(|_| InputFailureCode::MetadataMismatch)?;
    let ingested_at =
        u64::try_from(row.ingested_at_unix_ms).map_err(|_| InputFailureCode::MetadataMismatch)?;
    if item.organization_id().as_str() != row.organization_id
        || item.run_id().as_str() != row.run_id
        || item.ingest_sequence() != sequence
        || item.ingested_at_unix_ms() != ingested_at
        || item.schema_version() != SchemaVersion::V0_1
        || row.schema_version != "0.1"
        || fact_kind(item.fact()) != row.fact_kind
        || row.outbox_topic != "agent_execution_record"
    {
        return Err(InputFailureCode::MetadataMismatch);
    }

    let digest: [u8; 32] = row
        .fact_digest
        .try_into()
        .map_err(|_| InputFailureCode::DigestMismatch)?;
    Ok(ValidatedLedgerRow {
        item,
        fact_digest: digest,
    })
}

pub(crate) fn batch_digest(
    organization_id: &str,
    from_watermark: u64,
    through_watermark: u64,
    rows: &[ValidatedLedgerRow],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(BATCH_DIGEST_DOMAIN);
    hasher.update((organization_id.len() as u64).to_be_bytes());
    hasher.update(organization_id.as_bytes());
    hasher.update(from_watermark.to_be_bytes());
    hasher.update(through_watermark.to_be_bytes());
    for row in rows {
        hasher.update(row.item.ingest_sequence().to_be_bytes());
        hasher.update(row.fact_digest);
    }
    hasher.finalize().into()
}

pub(crate) fn fact_kind(fact: &AgentExecutionRecordFact) -> &'static str {
    match fact {
        AgentExecutionRecordFact::RunOpened(_) => "run_opened",
        AgentExecutionRecordFact::RunStateChanged(_) => "run_state_changed",
        AgentExecutionRecordFact::RunFinalizationDeclared(_) => "run_finalization_declared",
        AgentExecutionRecordFact::SourceRegistered(_) => "source_registered",
        AgentExecutionRecordFact::RuntimeBound(_) => "runtime_bound",
        AgentExecutionRecordFact::EvidenceAccepted(_) => "evidence_accepted",
        AgentExecutionRecordFact::CoverageComputed(_) => "coverage_computed",
    }
}

fn validate_i_json_numbers(value: &Value) -> Result<(), ()> {
    match value {
        Value::Number(number) => {
            let safe = number
                .as_u64()
                .map(|value| value <= MAX_I_JSON_INTEGER)
                .or_else(|| {
                    number.as_i64().map(|value| {
                        value >= -(MAX_I_JSON_INTEGER as i64) && value <= MAX_I_JSON_INTEGER as i64
                    })
                })
                .unwrap_or_else(|| number.as_f64().is_some_and(f64::is_finite));
            if !safe {
                return Err(());
            }
        }
        Value::Array(values) => {
            for value in values {
                validate_i_json_numbers(value)?;
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                validate_i_json_numbers(value)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::String(_) => {}
    }
    Ok(())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_value() -> Value {
        serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../apolysis-contracts/tests/fixtures/positive/record_item.json"
        )))
        .expect("record item JSON")
    }

    fn stored_row(value: Value) -> StoredLedgerRow {
        let canonical = serde_json_canonicalizer::to_vec(&value).expect("canonical fixture");
        StoredLedgerRow {
            organization_id: "org_acme".to_string(),
            run_id: "run_01".to_string(),
            ingest_sequence: 41,
            schema_version: "0.1".to_string(),
            ingested_at_unix_ms: 1_783_891_200_300,
            fact_kind: "evidence_accepted".to_string(),
            fact_size: i32::try_from(canonical.len()).expect("bounded fixture"),
            fact_digest: Sha256::digest(&canonical).to_vec(),
            fact_json: Some(value),
            outbox_topic: "agent_execution_record".to_string(),
            outbox_state: "pending".to_string(),
        }
    }

    #[test]
    fn batch_digest_is_generation_independent_and_order_sensitive() {
        let fixture = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../apolysis-contracts/tests/fixtures/positive/record_item.json"
        ));
        let item: AgentExecutionRecordItem = serde_json::from_str(fixture).expect("record item");
        let canonical = serde_json_canonicalizer::to_vec(&item).expect("canonical item");
        let fact_digest: [u8; 32] = Sha256::digest(canonical).into();
        let rows = [ValidatedLedgerRow { item, fact_digest }];

        assert_eq!(
            batch_digest("org_acme", 0, 1, &rows),
            batch_digest("org_acme", 0, 1, &rows)
        );
        assert_ne!(
            batch_digest("org_acme", 0, 1, &rows),
            batch_digest("org_other", 0, 1, &rows)
        );
    }

    #[test]
    fn valid_jsonb_round_trips_through_the_typed_contract() {
        let validated =
            validate_stored_ledger_row(stored_row(fixture_value())).expect("valid stored record");
        assert_eq!(validated.item.ingest_sequence(), 41);
    }

    #[test]
    fn digest_and_redundant_metadata_mismatches_fail_closed() {
        let mut wrong_digest = stored_row(fixture_value());
        wrong_digest.fact_digest = vec![0; 32];
        assert!(matches!(
            validate_stored_ledger_row(wrong_digest),
            Err(InputFailureCode::DigestMismatch)
        ));

        let mut wrong_kind = stored_row(fixture_value());
        wrong_kind.fact_kind = "run_opened".to_string();
        assert!(matches!(
            validate_stored_ledger_row(wrong_kind),
            Err(InputFailureCode::MetadataMismatch)
        ));
    }

    #[test]
    fn valid_digest_with_unknown_nested_input_still_fails_contract_round_trip() {
        let mut value = fixture_value();
        value["fact"]["fact"]["envelope"]["flags"]["unexpected"] = Value::Bool(true);
        assert!(matches!(
            validate_stored_ledger_row(stored_row(value)),
            Err(InputFailureCode::InvalidContract)
        ));
    }

    #[test]
    fn oversized_input_is_rejected_without_materializing_json() {
        let mut row = stored_row(fixture_value());
        row.fact_size = MAX_LEDGER_ITEM_BYTES + 1;
        row.fact_json = None;
        assert!(matches!(
            validate_stored_ledger_row(row),
            Err(InputFailureCode::OversizedInput)
        ));
    }
}
