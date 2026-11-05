// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};

use apolysis_core::SessionIntentReasonRecord;
use serde_json::{json, Value};

/// Enrich declarations and already established exact relations. Reasons never
/// participate in selecting a Tool Call or suppressing an evidence gap.
pub fn enrich(intents: &str, input: &str, correlations: &mut Vec<Value>) -> Result<(), String> {
    let intents = crate::parse_intent_records(intents)?;
    if !input.is_empty() && !input.ends_with('\n') {
        return Err("intent reason input has an incomplete trailing line".to_string());
    }
    let mut reasons = Vec::<SessionIntentReasonRecord>::new();
    let mut conflicts = BTreeSet::new();
    for line in input.lines() {
        let mut record = apolysis_store::parse_intent_reason(line)
            .map_err(|_| "invalid intent reason input".to_string())?;
        record.timestamp_unix_ms = 0;
        if let Some(prior) = reasons.iter().find(|prior| {
            prior.session_id == record.session_id && prior.reason_id == record.reason_id
        }) {
            if prior != &record {
                conflicts.insert((prior.session_id.clone(), prior.intent_id.clone()));
                conflicts.insert((record.session_id.clone(), record.intent_id.clone()));
            }
        } else {
            reasons.push(record);
        }
    }
    let mut grouped = BTreeMap::<(&str, &str), Vec<&SessionIntentReasonRecord>>::new();
    for reason in &reasons {
        grouped
            .entry((&reason.session_id, &reason.intent_id))
            .or_default()
            .push(reason);
    }
    for (session, intent) in &conflicts {
        grouped.entry((session, intent)).or_default();
    }
    for ((session_id, intent_id), group) in grouped {
        let diagnostic = |code: &str| {
            json!({
                "record_type": "intent_reason_diagnostic", "session_id": session_id,
                "intent_id": intent_id, "reason": code,
            })
        };
        if conflicts.contains(&(session_id.to_string(), intent_id.to_string())) {
            correlations.push(diagnostic("conflicting_reason_id"));
            continue;
        }
        let declarations: Vec<_> = intents
            .iter()
            .filter(|intent| intent.session_id == session_id && intent.intent_id == intent_id)
            .collect();
        let intent = match declarations.as_slice() {
            [] => {
                correlations.push(diagnostic("unbound_reason"));
                continue;
            }
            [intent] => intent,
            _ => {
                correlations.push(diagnostic("ambiguous_reason_intent"));
                continue;
            }
        };
        if group.iter().any(|reason| {
            reason.intent_source != intent.intent_source
                || Some(reason.harness_session_id.as_str()) != intent.harness_session_id.as_deref()
                || Some(reason.source_event_id.as_str()) != intent.source_event_id.as_deref()
        }) {
            correlations.push(diagnostic("reason_identity_mismatch"));
            continue;
        }
        let mut superseded = BTreeSet::new();
        let mut invalid_chain = false;
        for (index, reason) in group.iter().enumerate() {
            if let Some(parent) = reason.supersedes_reason_id.as_deref() {
                // Parent must precede the correction, belong to this same call,
                // and have exactly one successor. This also excludes cycles.
                if !group[..index].iter().any(|r| r.reason_id == parent)
                    || !superseded.insert(parent)
                {
                    invalid_chain = true;
                }
            }
        }
        if invalid_chain {
            correlations.push(diagnostic("invalid_reason_correction"));
            continue;
        }
        let active: Vec<_> = group
            .iter()
            .filter(|r| !superseded.contains(r.reason_id.as_str()))
            .collect();
        let [reason] = active.as_slice() else {
            correlations.push(diagnostic("ambiguous_reason"));
            continue;
        };
        let declared_reason = json!({
            "reason_id": reason.reason_id, "reason_code": reason.reason_code,
            "reason_source": reason.reason_source, "reason_summary": reason.reason_summary,
            "task_ref": reason.task_ref,
        });
        // A semantic-only declaration can be annotated, but never receives a
        // fabricated execution edge. Existing inferred candidates are untouched.
        for relation in correlations.iter_mut().filter(|relation| {
            relation["record_type"] == "intent_correlation"
                && relation["relation_status"] == "exact"
                && relation["session_id"] == session_id
                && relation["intent_id"] == intent_id
        }) {
            relation["declared_reason"] = declared_reason.clone();
        }
        correlations.push(json!({
            "record_type": "intent_reason_binding", "session_id": session_id,
            "intent_id": intent_id, "binding_status": "declared",
            "observation_mode": intent.observation_mode,
            "declared_reason": declared_reason,
        }));
    }
    Ok(())
}
