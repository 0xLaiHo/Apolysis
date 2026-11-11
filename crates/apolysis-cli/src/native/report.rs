// SPDX-License-Identifier: Apache-2.0

//! Read-only presentation of existing evidence. A report cannot turn a declared
//! purpose, an executable-name candidate, or an observed attempt into success.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use serde_json::{json, Value};

const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const SOURCES: [&str; 4] = [
    "intent.jsonl",
    "intent.jsonl.reasons.jsonl",
    "timeline.jsonl",
    "correlation.jsonl",
];

/// Values are controller metadata, never native stdout, stderr, argv or prompts.
pub(super) struct RunOutcome {
    pub agent: String,
    pub session_id: String,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub interrupted: bool,
    /// Static controller diagnostics only. Details containing user data belong
    /// neither in this field nor in the persisted report.
    pub errors: Vec<String>,
    /// Static adapter capability notes, for example the shell bridge boundary.
    pub notes: Vec<String>,
}

pub(super) struct RenderedReport {
    pub json: String,
    pub markdown: String,
    pub html: String,
    pub summary: String,
    pub complete: bool,
}

#[derive(Default)]
struct Diagnostics(BTreeMap<&'static str, u64>);

impl Diagnostics {
    fn add(&mut self, code: &'static str) {
        *self.0.entry(code).or_default() += 1;
    }

    fn rows(&self) -> Vec<Value> {
        self.0
            .iter()
            .map(|(code, count)| json!({"code": code, "count": count}))
            .collect()
    }
}

struct Artifact {
    text: String,
    rows: Vec<Value>,
    valid: bool,
}

fn read_artifact(path: &Path, session: &str, diagnostics: &mut Diagnostics) -> Artifact {
    let mut text = String::new();
    let loaded =
        File::open(path).and_then(|file| file.take(MAX_FILE_BYTES + 1).read_to_string(&mut text));
    if loaded.is_err() || text.len() as u64 > MAX_FILE_BYTES {
        diagnostics.add("artifact_missing_unreadable_or_oversize");
        return Artifact {
            text: String::new(),
            rows: Vec::new(),
            valid: false,
        };
    }
    let mut valid = true;
    if !text.is_empty() && !text.ends_with('\n') {
        diagnostics.add("artifact_partial_final_record");
        valid = false;
    }
    let mut rows = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let value = match serde_json::from_str::<Value>(line) {
            Ok(value) if value.is_object() && string(&value, "record_type").is_some() => value,
            _ => {
                diagnostics.add("artifact_malformed_record");
                valid = false;
                continue;
            }
        };
        if string(&value, "session_id") != Some(session) {
            diagnostics.add("artifact_session_mismatch");
            valid = false;
            continue;
        }
        rows.push(value);
    }
    Artifact { text, rows, valid }
}

fn string<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn kind(value: &Value) -> &str {
    string(value, "record_type").unwrap_or("")
}

fn bounded(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_control() && !matches!(c, '\u{2028}' | '\u{2029}'))
        .take(512)
        .collect()
}

fn clean_field(value: &Value, field: &str) -> Value {
    string(value, field)
        .map(bounded)
        .map_or(Value::Null, Value::String)
}

fn increment(counts: &mut BTreeMap<String, u64>, key: &str) {
    *counts.entry(bounded(key)).or_default() += 1;
}

fn indexed<'a>(
    rows: impl Iterator<Item = &'a Value>,
    key: &str,
) -> BTreeMap<&'a str, Vec<&'a Value>> {
    let mut result = BTreeMap::<_, Vec<_>>::new();
    for row in rows {
        if let Some(id) = string(row, key).filter(|id| !id.is_empty()) {
            result.entry(id).or_default().push(row);
        }
    }
    result
}

fn same_fields(left: &Value, right: &Value, keys: &[&str]) -> bool {
    keys.iter().all(|key| left.get(*key) == right.get(*key))
}

fn valid_relation(
    relation: &Value,
    call: &Value,
    raw: &BTreeMap<&str, Vec<&Value>>,
    canonical: &BTreeMap<&str, Vec<&Value>>,
) -> bool {
    if string(call, "observation_mode") == Some("semantic_only")
        || string(relation, "relation_status") != Some("exact")
        || !same_fields(relation, call, &["intent_id", "intent_source", "tool_name"])
    {
        return false;
    }
    let Some(id) = string(relation, "raw_event_id") else {
        return false;
    };
    let (Some(raw), Some(canonical)) = (raw.get(id), canonical.get(id)) else {
        return false;
    };
    let ([raw], [canonical]) = (raw.as_slice(), canonical.as_slice()) else {
        return false;
    };
    if !same_fields(relation, raw, &["session_id", "pid", "resource"])
        || !same_fields(
            relation,
            canonical,
            &["session_id", "pid", "resource", "event_type"],
        )
        || !matches!(
            string(relation, "event_type"),
            Some(
                "exec"
                    | "file_open"
                    | "file_create"
                    | "file_truncate"
                    | "file_unlink"
                    | "file_rename"
                    | "network_connect"
                    | "credential_read"
            )
        )
    {
        return false;
    }
    match string(relation, "match_basis") {
        Some("intent_id") => {
            same_fields(raw, call, &["intent_id"]) && same_fields(canonical, call, &["intent_id"])
        }
        Some("raw_event_id") => {
            string(call, "raw_event_id") == Some(id)
                && [raw, canonical].iter().all(|row| {
                    string(row, "intent_id").is_none() || same_fields(row, call, &["intent_id"])
                })
        }
        _ => false,
    }
}

/// Read existing artifacts and return three presentations without modifying
/// source evidence. Malformed or missing data produces an incomplete report.
pub(super) fn render(evidence: &Path, outcome: &RunOutcome) -> RenderedReport {
    let mut diagnostics = Diagnostics::default();
    let [intents, reasons, timeline, correlations] = SOURCES
        .map(|name| read_artifact(&evidence.join(name), &outcome.session_id, &mut diagnostics));
    let mut capture_valid = timeline.valid && !outcome.session_id.is_empty();
    let mut correlation_valid = intents.valid && reasons.valid && correlations.valid;

    // An empty/truncated or stale correlation file must not look complete just
    // because every relation that survived happens to be valid.
    let mut expected = crate::correlate_intents(&intents.text, &timeline.text);
    if let Ok(rows) = &mut expected {
        if crate::intent::reason_binding::enrich(&intents.text, &reasons.text, rows).is_err() {
            expected = Err("invalid reason evidence".into());
        }
    }
    if !expected.is_ok_and(|expected| normalized(&expected) == normalized(&correlations.rows)) {
        diagnostics.add("correlation_artifact_missing_or_mismatched");
        correlation_valid = false;
    }

    // The domain binder validates complete native identities and correction
    // chains. Display only its selected reason, never arbitrary relation prose.
    let mut bindings = Vec::new();
    if crate::intent::reason_binding::enrich(&intents.text, &reasons.text, &mut bindings).is_err() {
        diagnostics.add("reason_input_invalid");
        correlation_valid = false;
        bindings.clear();
    }
    bindings.retain(|row| string(row, "session_id") == Some(&outcome.session_id));
    let bound = indexed(
        bindings
            .iter()
            .filter(|r| kind(r) == "intent_reason_binding"),
        "intent_id",
    );

    let raw = indexed(
        timeline
            .rows
            .iter()
            .filter(|r| kind(r) == "raw_kernel_event"),
        "event_id",
    );
    let canonical = indexed(
        timeline.rows.iter().filter(|r| kind(r) == "event"),
        "raw_event_id",
    );
    let raw_count = timeline
        .rows
        .iter()
        .filter(|r| kind(r) == "raw_kernel_event")
        .count() as u64;
    if raw.values().any(|rows| rows.len() != 1) || raw.len() as u64 != raw_count {
        diagnostics.add("raw_event_identity_invalid");
        capture_valid = false;
    }
    if canonical.values().any(|rows| rows.len() != 1) {
        diagnostics.add("canonical_event_identity_ambiguous");
        capture_valid = false;
    }
    let mut summaries = Vec::new();
    let mut loss = 0_u64;
    let mut truncated = 0_u64;
    let mut exits = Vec::new();
    let mut policy_rules = BTreeMap::new();
    let mut policy_notifications = 0_u64;
    let mut prevention_claims = 0_u64;
    for row in &timeline.rows {
        match kind(row) {
            "observer_diagnostic" => {
                let Some(count) = row.get("count").and_then(Value::as_u64) else {
                    diagnostics.add("observer_diagnostic_invalid");
                    capture_valid = false;
                    continue;
                };
                let destination = match string(row, "kind") {
                    Some("summary") => {
                        summaries.push(count);
                        continue;
                    }
                    Some("truncation") => &mut truncated,
                    Some(
                        "ring_buffer_reserve_failure"
                        | "map_pressure"
                        | "decode_failure"
                        | "attach_failure"
                        | "verifier_failure",
                    ) => &mut loss,
                    _ => {
                        diagnostics.add("observer_diagnostic_unknown");
                        capture_valid = false;
                        continue;
                    }
                };
                if let Some(total) = destination.checked_add(count) {
                    *destination = total;
                } else {
                    *destination = u64::MAX;
                    diagnostics.add("observer_count_overflow");
                    capture_valid = false;
                }
            }
            "event" if string(row, "resource") == Some("agent-exit-status") => exits.push(row),
            "policy_violation" => {
                policy_notifications += 1;
                increment(
                    &mut policy_rules,
                    string(row, "rule_id").unwrap_or("unknown"),
                );
            }
            "enforcement_metadata" if row.get("preoperation_prevention") == Some(&json!(true)) => {
                prevention_claims += 1
            }
            "event" | "raw_kernel_event" | "enforcement_metadata" => {}
            _ => {
                diagnostics.add("timeline_record_type_unknown");
                capture_valid = false;
            }
        }
    }
    let native_exit = exits
        .first()
        .and_then(|row| string(row, "action"))
        .and_then(|value| value.strip_prefix("exit:"))
        .and_then(|value| value.parse::<i32>().ok());
    let expected_exit = outcome.exit_code.or_else(|| {
        outcome
            .signal
            .and_then(|signal| 128_i32.checked_add(signal))
    });
    if summaries != [raw_count] || raw_count == 0 {
        diagnostics.add("capture_final_summary_missing_or_mismatched");
        capture_valid = false;
    }
    if exits.len() != 1 || native_exit.is_none() || native_exit != expected_exit {
        diagnostics.add("native_exit_missing_or_mismatched");
        capture_valid = false;
    }
    capture_valid &= loss == 0 && outcome.errors.is_empty() && !outcome.interrupted;

    let declarations = indexed(
        intents.rows.iter().filter(|r| kind(r) == "intent"),
        "intent_id",
    );
    if intents.rows.iter().any(|r| kind(r) != "intent") {
        diagnostics.add("intent_artifact_wrong_record_type");
        correlation_valid = false;
    }
    let mut calls = Vec::new();
    let mut call_resources: Vec<BTreeMap<String, Vec<String>>> = Vec::new();
    let mut admitted = BTreeSet::new();
    let mut exact_total = 0_u64;
    let mut semantic_count = 0_u64;
    for (id, declarations) in &declarations {
        let [call] = declarations.as_slice() else {
            diagnostics.add("intent_identity_ambiguous");
            correlation_valid = false;
            continue;
        };
        let native_identity_valid = [
            "intent_source",
            "harness_session_id",
            "source_event_id",
            "tool_name",
        ]
        .iter()
        .all(|key| string(call, key).is_some_and(|s| !s.trim().is_empty()))
            && string(call, "intent_source") == Some(&outcome.agent)
            && matches!(
                string(call, "observation_mode"),
                Some("local_shell" | "semantic_only")
            );
        let identity_count = intents
            .rows
            .iter()
            .filter(|other| {
                same_fields(
                    other,
                    call,
                    &["intent_source", "harness_session_id", "source_event_id"],
                )
            })
            .count();
        if !native_identity_valid || identity_count != 1 {
            diagnostics.add("native_call_identity_invalid_or_ambiguous");
            correlation_valid = false;
            continue;
        }
        let semantic = string(call, "observation_mode") == Some("semantic_only");
        semantic_count += u64::from(semantic);
        let selected_reason = match bound.get(id).map(Vec::as_slice) {
            Some([binding]) => binding
                .get("declared_reason")
                .cloned()
                .unwrap_or(Value::Null),
            _ => Value::Null,
        };
        let mut event_counts = BTreeMap::new();
        let mut basis_counts = BTreeMap::new();
        let mut samples = Vec::new();
        let mut resources_by_type: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut seen_raw = BTreeSet::new();
        for (index, relation) in correlations.rows.iter().enumerate().filter(|(_, row)| {
            kind(row) == "intent_correlation" && string(row, "intent_id") == Some(id)
        }) {
            if !valid_relation(relation, call, &raw, &canonical)
                || relation
                    .get("declared_reason")
                    .is_some_and(|reason| reason != &selected_reason)
            {
                diagnostics.add("exact_relation_unverified");
                correlation_valid = false;
                continue;
            }
            let raw_id = string(relation, "raw_event_id").unwrap_or("");
            if !seen_raw.insert(raw_id) {
                diagnostics.add("duplicate_exact_relation");
                correlation_valid = false;
                continue;
            }
            admitted.insert(index);
            exact_total += 1;
            let ev_type = string(relation, "event_type").unwrap_or("unknown");
            increment(&mut event_counts, ev_type);
            increment(
                &mut basis_counts,
                string(relation, "match_basis").unwrap_or("unknown"),
            );
            let res = bounded(string(relation, "resource").unwrap_or("unknown"));
            if !res.is_empty() && res != "unknown" {
                let list = resources_by_type.entry(bounded(ev_type)).or_default();
                if list.len() < 3 && !list.contains(&res) {
                    list.push(res);
                }
            }
            samples.push(json!({
                "event_type": clean_field(relation, "event_type"),
                "raw_event_id": clean_field(relation, "raw_event_id"),
                "pid": relation.get("pid").and_then(Value::as_u64),
                "resource": clean_field(relation, "resource"),
            }));
            // Keep network/credential attempts visible even after dozens of
            // ordinary library opens, without reproducing the entire timeline.
            samples.sort_by_key(|sample| match string(sample, "event_type") {
                Some("network_connect" | "credential_read") => 0,
                Some("exec") => 1,
                _ => 2,
            });
            samples.truncate(6);
        }
        call_resources.push(resources_by_type);
        calls.push(json!({
            "intent_id": bounded(id), "tool_name": clean_field(call, "tool_name"),
            "observation_mode": clean_field(call, "observation_mode"),
            "harness_session_id": clean_field(call, "harness_session_id"),
            "source_event_id": clean_field(call, "source_event_id"),
            "reason": selected_reason,
            "reason_status": if bound.contains_key(id) { "declared" } else { "unknown_or_unbound" },
            "exact_relations": seen_raw.len(), "event_counts": event_counts,
            "match_bases": basis_counts, "event_samples": samples,
            "execution_status": if semantic { "semantic_only" } else if seen_raw.is_empty() { "not_exactly_attributed" } else { "observed_attempts" },
            "task_outcome": "not_verified",
        }));
    }
    let mut findings = BTreeMap::new();
    let mut candidates = BTreeMap::new();
    let mut relation_diagnostics = BTreeMap::new();
    let mut reason_diagnostics = BTreeMap::new();
    for (index, row) in correlations.rows.iter().enumerate() {
        match kind(row) {
            "intent_correlation" if !admitted.contains(&index) => {
                diagnostics.add("unadmitted_exact_relation");
                correlation_valid = false;
            }
            "accountability_finding" => {
                increment(&mut findings, string(row, "kind").unwrap_or("unknown"))
            }
            "intent_correlation_candidate" => increment(
                &mut candidates,
                string(row, "relation_status").unwrap_or("unknown"),
            ),
            "intent_correlation_diagnostic" => increment(
                &mut relation_diagnostics,
                string(row, "reason").unwrap_or("unknown"),
            ),
            "intent_reason_diagnostic" => increment(
                &mut reason_diagnostics,
                string(row, "reason").unwrap_or("unknown"),
            ),
            "intent_reason_binding" | "intent_correlation" => {}
            _ => {
                diagnostics.add("correlation_record_type_unknown");
                correlation_valid = false;
            }
        }
    }
    // Recomputed binding diagnostics also remain visible if a producer omitted
    // them from the correlation artifact.
    for row in bindings
        .iter()
        .filter(|r| kind(r) == "intent_reason_diagnostic")
    {
        let code = string(row, "reason").unwrap_or("unknown");
        reason_diagnostics.entry(bounded(code)).or_insert(1);
    }
    let complete = capture_valid && correlation_valid;
    let document = json!({
        "record_type": "native_observation_report", "schema_version": 1,
        "session_id": bounded(&outcome.session_id), "agent": bounded(&outcome.agent),
        "controller_runtime": "rust",
        "capture_status": if capture_valid { "complete" } else { "incomplete" },
        "correlation_status": if correlation_valid { "complete" } else { "incomplete" },
        "report_status": if complete { "complete" } else { "incomplete" },
        "application": {
            "status": if outcome.interrupted { "interrupted" } else if outcome.signal.is_some() { "signaled" } else if outcome.exit_code.is_some() { "exited" } else { "unknown" },
            "exit_code": outcome.exit_code, "signal": outcome.signal,
        },
        "task_outcome": "not_verified",
        "kernel_events": raw_count, "loss_or_failure_count": loss, "truncations": truncated,
        "timeline_records": timeline.rows.len(),
        "canonical_events": timeline.rows.iter().filter(|r| kind(r) == "event").count(),
        "totals": { "tool_calls": calls.len(), "semantic_only_calls": semantic_count,
            "exact_relations": exact_total, "findings": findings, "candidates": candidates,
            "correlation_diagnostics": relation_diagnostics, "reason_diagnostics": reason_diagnostics,
            "policy_notifications": policy_notifications, "policy_rules": policy_rules,
            "preoperation_prevention_claims": prevention_claims },
        "calls": calls, "diagnostics": diagnostics.rows(),
        "controller_errors": outcome.errors.iter().map(|s| bounded(s)).collect::<Vec<_>>(),
        "coverage_notes": outcome.notes.iter().map(|s| bounded(s)).collect::<Vec<_>>(),
        "source_artifacts": SOURCES,
    });
    // Serializing a Value to a string cannot fail; use Display to avoid a
    // fallible writer and keep reporting available on failed launch paths.
    RenderedReport {
        json: format!("{document:#}\n"),
        markdown: markdown(&document),
        html: html(&document),
        summary: terminal_summary(&document, &call_resources),
        complete,
    }
}

fn split_intent_and_detail(reason: &Value) -> (String, Option<String>) {
    if reason.is_null() {
        return ("undeclared".into(), None);
    }
    match string(reason, "reason_summary") {
        Some("[redacted]") => ("[redacted]".into(), None),
        Some(summary) if !summary.is_empty() => {
            if let Some((intent, detail)) =
                summary.strip_suffix('）').and_then(|s| s.split_once('（'))
            {
                return (intent.to_string(), Some(detail.to_string()));
            }
            (summary.to_string(), None)
        }
        _ => (
            format!(
                "{} ({})",
                text(reason, "reason_code"),
                text(reason, "reason_source")
            ),
            None,
        ),
    }
}

fn terminal_summary(report: &Value, call_resources: &[BTreeMap<String, Vec<String>>]) -> String {
    let totals = &report["totals"];
    let mut out = format!(
        "Apolysis Session Summary (agent: {} | tool calls: {} | exact relations: {} | dropped: {})\n",
        text(report, "agent"),
        count(totals, "tool_calls"),
        count(totals, "exact_relations"),
        count(report, "loss_or_failure_count"),
    );
    let Some(calls) = report["calls"].as_array() else {
        return out;
    };
    if calls.is_empty() {
        let _ = writeln!(
            out,
            "└─ (no tool declarations recorded; {} kernel events observed)",
            count(report, "kernel_events")
        );
        return out;
    }
    struct GroupedCall<'a> {
        index: usize,
        call: &'a Value,
        detail: Option<String>,
    }
    let mut groups: Vec<(String, Vec<GroupedCall<'_>>)> = Vec::new();
    for (index, call) in calls.iter().enumerate() {
        let (intent, detail) = split_intent_and_detail(&call["reason"]);
        let item = GroupedCall {
            index,
            call,
            detail,
        };
        if let Some((_, items)) = groups.iter_mut().find(|(key, _)| *key == intent) {
            items.push(item);
        } else {
            groups.push((intent, vec![item]));
        }
    }
    let order = [
        "network_connect",
        "exec",
        "file_create",
        "file_truncate",
        "file_unlink",
        "file_rename",
        "file_open",
        "credential_read",
    ];
    for (group_idx, (intent, items)) in groups.iter().enumerate() {
        let is_last_group = group_idx + 1 == groups.len();
        let group_branch = if is_last_group { "└─" } else { "├─" };
        let group_prefix = if is_last_group { "   " } else { "│  " };
        let _ = writeln!(out, "{group_branch} Intent: {intent}");
        for (item_idx, item) in items.iter().enumerate() {
            let (call_idx, call, detail) = (item.index, item.call, &item.detail);
            let is_last_item = item_idx + 1 == items.len();
            let item_branch = if is_last_item { "└─" } else { "├─" };
            let item_prefix = if is_last_item { "   " } else { "│  " };
            let tool = text(call, "tool_name");
            let detail_suffix = detail
                .as_deref()
                .map(|d| format!(" ({d})"))
                .unwrap_or_default();
            let exact = count(call, "exact_relations");
            let exec_status = text(call, "execution_status");
            let short_id: String = text(call, "intent_id").chars().take(8).collect();
            if exec_status == "semantic_only" {
                let _ = writeln!(
                    out,
                    "{group_prefix}{item_branch} [{}] {}{} — semantic_only (0 kernel events) [intent_id: {}...]",
                    call_idx + 1,
                    tool,
                    detail_suffix,
                    short_id
                );
                continue;
            }
            let _ = writeln!(
                out,
                "{group_prefix}{item_branch} [{}] {}{} — {} kernel event(s) [intent_id: {}...]",
                call_idx + 1,
                tool,
                detail_suffix,
                exact,
                short_id
            );
            if let Some(counts) = call["event_counts"].as_object() {
                let mut ordered_events: Vec<(&str, u64)> = order
                    .iter()
                    .copied()
                    .filter_map(|name| counts.get(name).and_then(Value::as_u64).map(|c| (name, c)))
                    .collect();
                for (name, val) in counts {
                    if !order.contains(&name.as_str()) {
                        if let Some(c) = val.as_u64() {
                            ordered_events.push((name.as_str(), c));
                        }
                    }
                }
                let resources_map = call_resources.get(call_idx);
                for (ev_idx, (ev_name, ev_count)) in ordered_events.iter().enumerate() {
                    let ev_branch = if ev_idx + 1 == ordered_events.len() {
                        "└─"
                    } else {
                        "├─"
                    };
                    let samples = resources_map
                        .and_then(|m| m.get(*ev_name))
                        .filter(|list| !list.is_empty())
                        .map(|list| {
                            let joined =
                                list.iter().take(3).cloned().collect::<Vec<_>>().join(", ");
                            if *ev_count as usize > list.len().min(3) {
                                format!(": {joined}, ...")
                            } else {
                                format!(": {joined}")
                            }
                        })
                        .unwrap_or_default();
                    let _ = writeln!(
                        out,
                        "{group_prefix}{item_prefix}{ev_branch} {ev_name} ({ev_count}){samples}"
                    );
                }
            }
        }
    }
    out
}

fn normalized(rows: &[Value]) -> Vec<String> {
    let mut result = rows
        .iter()
        .map(|row| {
            let mut row = row.clone();
            if let Some(object) = row.as_object_mut() {
                object.remove("timestamp_unix_ms");
            }
            row.to_string()
        })
        .collect::<Vec<_>>();
    result.sort();
    result
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    string(value, key).unwrap_or("unknown")
}

fn count(value: &Value, key: &str) -> u64 {
    value.get(key).and_then(Value::as_u64).unwrap_or(0)
}

fn status(value: &str) -> &str {
    match value {
        "complete" => "检查完成",
        "incomplete" => "不完整",
        "exited" => "进程已退出",
        "interrupted" => "会话被中断",
        "signaled" => "进程被信号终止",
        "semantic_only" => "仅有工具声明",
        "observed_attempts" => "已观测到关联尝试",
        "not_exactly_attributed" => "未建立精确执行归属",
        _ => "未知",
    }
}

fn event_label(value: &str) -> &str {
    match value {
        "exec" => "程序执行",
        "file_open" => "文件打开尝试",
        "file_create" => "文件创建尝试",
        "file_truncate" => "文件截断尝试",
        "file_unlink" => "文件删除尝试",
        "file_rename" => "文件重命名尝试",
        "network_connect" => "网络连接尝试",
        "credential_read" => "凭证路径规则命中",
        _ => value,
    }
}

fn reason_text(call: &Value) -> String {
    let reason = &call["reason"];
    if reason.is_null() {
        return "未知：没有可绑定的调用理由。".into();
    }
    let source = match text(reason, "reason_source") {
        "agent_declared" => "模型显式声明",
        "tool_description" => "原生工具描述（不是已验证的调用动机）",
        "operator_annotation" => "操作员注释",
        _ => "未知来源",
    };
    let summary = match string(reason, "reason_summary") {
        Some("[redacted]") => "摘要已脱敏",
        Some(value) if !value.is_empty() => value,
        _ => "未保留摘要",
    };
    format!("{} · {}：{}", source, text(reason, "reason_code"), summary)
}

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn md(value: &str) -> String {
    let mut output = String::new();
    for c in bounded(value).chars() {
        if matches!(
            c,
            '\\' | '`'
                | '*'
                | '_'
                | '{'
                | '}'
                | '['
                | ']'
                | '('
                | ')'
                | '#'
                | '+'
                | '-'
                | '.'
                | '!'
                | '|'
                | '~'
        ) {
            output.push('\\');
        }
        match c {
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '&' => output.push_str("&amp;"),
            _ => output.push(c),
        }
    }
    output
}

fn markdown(report: &Value) -> String {
    let totals = &report["totals"];
    let application = &report["application"];
    let mut output = format!(
        "# 原生应用观测报告\n\n应用：{}。**任务是否成功：未验证。**\n\n| 项目 | 结果 |\n| --- | --- |\n| 原生应用 | {}，退出码 {}，信号 {} |\n| 采集 | {} |\n| 关联 | {} |\n| 工具调用 | {}（其中 {} 次仅有声明） |\n| 精确归属事件 | {} |\n| 原始内核事件 | {} |\n| 丢失或失败 / 截断 | {} / {} |\n\n采集与关联检查完成，不代表所有系统调用都被覆盖或任务成功。原始事件与规范化副本没有重复计数。\n\n## 工具调用\n\n",
        md(text(report, "agent")), status(text(application, "status")), application["exit_code"], application["signal"],
        status(text(report, "capture_status")), status(text(report, "correlation_status")),
        count(totals, "tool_calls"), count(totals, "semantic_only_calls"), count(totals, "exact_relations"),
        count(report, "kernel_events"), count(report, "loss_or_failure_count"), count(report, "truncations"),
    );
    if let Some(calls) = report["calls"].as_array() {
        if calls.is_empty() {
            output.push_str("没有可展示的有效工具声明；这不证明应用没有执行操作。\n\n");
        }
        for (index, call) in calls.iter().enumerate() {
            let _ = writeln!(
                output,
                "### 调用 {} · {}\n\n{}\n\n{}；精确归属 {} 条事件。\n\nintent\\_id：{}\n",
                index + 1,
                md(text(call, "tool_name")),
                md(&reason_text(call)),
                status(text(call, "execution_status")),
                count(call, "exact_relations"),
                md(text(call, "intent_id"))
            );
            if let Some(events) = call["event_counts"].as_object() {
                for (name, count) in events {
                    let _ = writeln!(output, "- {}：{}", md(event_label(name)), count);
                }
            }
            output.push('\n');
        }
    }
    output.push_str("## 单独查看的提醒\n\n");
    for (label, field) in [
        ("未归属或未观测提醒", "findings"),
        ("推断或歧义候选", "candidates"),
        ("关联诊断", "correlation_diagnostics"),
        ("原因诊断", "reason_diagnostics"),
    ] {
        let _ = writeln!(output, "- {label}：{}", md(&totals[field].to_string()));
    }
    let _ = writeln!(
        output,
        "- 策略提醒：{}；执行前阻断声明：{}。策略匹配、凭证路径命中不等于攻击或数据泄露。\n",
        count(totals, "policy_notifications"),
        count(totals, "preoperation_prevention_claims")
    );
    output.push_str("## 解释边界\n\n文件与网络事件只证明尝试；connect 不证明 HTTP 响应成功，正常退出也不证明任务完成。WebSearch、远程工具等 semantic\\_only 声明不会被补造系统调用关联。原生工具描述不会升级成模型显式声明。报告不复制提示词、完整 argv 或工具输出；原生应用自己的历史设置仍由其管理。\n\n");
    for field in ["coverage_notes", "controller_errors"] {
        if let Some(notes) = report[field].as_array() {
            for note in notes.iter().filter_map(Value::as_str) {
                let _ = writeln!(output, "- {}", md(note));
            }
        }
    }
    let _ = writeln!(
        output,
        "\n报告诊断：{}\n\n采集会话：{}\n\n## 原始证据\n",
        md(&report["diagnostics"].to_string()),
        md(text(report, "session_id"))
    );
    for source in SOURCES {
        let _ = writeln!(output, "- [{source}]({source})");
    }
    output
}

fn map_html(value: &Value) -> String {
    let Some(entries) = value.as_object() else {
        return "未知".into();
    };
    if entries.is_empty() {
        return "无记录".into();
    }
    let mut output = String::from("<ul>");
    for (key, count) in entries {
        let _ = write!(
            output,
            "<li><code>{}</code>：{}</li>",
            escape(key),
            escape(&count.to_string())
        );
    }
    output.push_str("</ul>");
    output
}

fn html(report: &Value) -> String {
    let totals = &report["totals"];
    let application = &report["application"];
    let mut body = format!(
        "<header><p class=eyebrow>APOLYSIS · NATIVE OBSERVATION</p><h1>{} · 执行证据</h1><p class=lead>按工具调用查看理由和实际执行尝试。<br><strong>任务是否成功：未验证。</strong></p><div class=badges><span>{}</span><span>采集：{}</span><span>关联：{}</span></div></header><section class=metrics><div><b>{}</b><span>工具调用</span></div><div><b>{}</b><span>精确归属事件</span></div><div><b>{}</b><span>原始内核事件</span></div><div><b>{}</b><span>截断计数</span></div></section><section><h2>工具调用</h2>",
        escape(text(report, "agent")), status(text(application, "status")), status(text(report, "capture_status")), status(text(report, "correlation_status")),
        count(totals, "tool_calls"), count(totals, "exact_relations"), count(report, "kernel_events"), count(report, "truncations"),
    );
    if let Some(calls) = report["calls"].as_array() {
        if calls.is_empty() {
            body.push_str("<p>没有可展示的有效工具声明。这不证明应用没有执行操作。</p>");
        }
        for (index, call) in calls.iter().enumerate() {
            let _ = write!(body, "<article class=call><div class=callhead><h3>{} · {}</h3><span>{}</span></div><p>{}</p><p><strong>{} 条精确关联</strong> · <code>{}</code></p>",
                index + 1, escape(text(call, "tool_name")), status(text(call, "execution_status")), escape(&reason_text(call)), count(call, "exact_relations"), escape(text(call, "intent_id")));
            if let Some(events) = call["event_counts"].as_object() {
                body.push_str("<div class=chips>");
                for (name, count) in events {
                    let _ = write!(
                        body,
                        "<span>{} <b>{}</b></span>",
                        escape(event_label(name)),
                        count
                    );
                }
                body.push_str("</div>");
            }
            let _ = write!(body, "<details><summary>身份与事件样例</summary><p>原生会话：<code>{}</code><br>原生调用：<code>{}</code><br>关联依据：{}</p><table><thead><tr><th>事件</th><th>脱敏资源</th><th>原始事件 ID</th></tr></thead><tbody>", escape(text(call, "harness_session_id")), escape(text(call, "source_event_id")), map_html(&call["match_bases"]));
            if let Some(samples) = call["event_samples"].as_array() {
                for sample in samples {
                    let _ = write!(
                        body,
                        "<tr><td>{}</td><td><code>{}</code></td><td><code>{}</code></td></tr>",
                        escape(event_label(text(sample, "event_type"))),
                        escape(text(sample, "resource")),
                        escape(text(sample, "raw_event_id"))
                    );
                }
            }
            body.push_str("</tbody></table><p class=note>最多显示 6 条样例；完整关系保留在 correlation.jsonl。原因是声明，不是授权或已验证动机。</p></details></article>");
        }
    }
    let _ = write!(body, "</section><section><h2>采集状态与任务结果分开看</h2><table><tbody><tr><th>原生应用</th><td>{}；退出码 {}；信号 {}</td></tr><tr><th>丢失 / 失败诊断</th><td>{}；截断另计 {} 次</td></tr><tr><th>时间线记录</th><td>{} 行，包含原始事件、规范化副本和诊断；不是系统调用次数</td></tr><tr><th>任务结果</th><td>未验证。未保存完整对话、工具结果或网络响应。</td></tr></tbody></table><p class=note>采集 complete 表示收尾与计数检查通过，不代表完整 syscall 覆盖；关联 complete 也不代表所有事件都已归属。</p></section><section><h2>单独审核的提醒</h2>", status(text(application, "status")), escape(&application["exit_code"].to_string()), escape(&application["signal"].to_string()), count(report, "loss_or_failure_count"), count(report, "truncations"), count(report, "timeline_records"));
    for (label, field) in [
        ("未归属或未观测提醒", "findings"),
        ("推断与歧义候选（不算精确关联）", "candidates"),
        ("关联诊断", "correlation_diagnostics"),
        ("原因诊断", "reason_diagnostics"),
    ] {
        let _ = write!(
            body,
            "<details><summary>{label}</summary>{}</details>",
            map_html(&totals[field])
        );
    }
    let _ = write!(body, "<details><summary>策略提醒：{} 条</summary>{}<p>执行前阻断声明：{}。规则匹配不等于攻击、实际阻断或凭证泄露；未归属的启动活动不能全部归给某次工具调用。</p></details></section><section><h2>解释边界</h2><p>文件和网络事件表示尝试，不能仅根据 connect 判断 HTTP 或天气查询成功。semantic_only 表示只有工具声明；未知理由保持未知。Apolysis 不复制完整提示词，原生应用自己的历史保存行为维持不变。</p>", count(totals, "policy_notifications"), map_html(&totals["policy_rules"]), count(totals, "preoperation_prevention_claims"));
    for field in ["coverage_notes", "controller_errors"] {
        if let Some(notes) = report[field].as_array() {
            for note in notes.iter().filter_map(Value::as_str) {
                let _ = write!(body, "<p class=note>{}</p>", escape(note));
            }
        }
    }
    let _ = write!(body, "<details><summary>报告诊断与原始证据</summary><pre>{}</pre><p>采集会话：<code>{}</code></p><div class=links>", escape(&report["diagnostics"].to_string()), escape(text(report, "session_id")));
    for source in SOURCES {
        let _ = write!(body, "<a href=\"{source}\">{source}</a>");
    }
    body.push_str("</div></details></section><footer>本地静态报告 · 无外部资源 · <a href=\"report.md\">Markdown</a> · <a href=\"result.json\">JSON</a></footer>");
    format!("<!doctype html><html lang=zh-CN><head><meta charset=utf-8><meta name=viewport content=\"width=device-width, initial-scale=1\"><meta http-equiv=Content-Security-Policy content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\"><title>Apolysis · 原生应用观测</title><style>{STYLE}</style></head><body><main>{body}</main></body></html>\n")
}

const STYLE: &str = "*{box-sizing:border-box}body{margin:0;background:#f4f6f8;color:#182735;font:16px/1.65 system-ui,sans-serif}main{max-width:1100px;margin:auto;padding:40px 24px}.eyebrow{font-size:12px;letter-spacing:2px;color:#536877}h1{font-size:34px;line-height:1.25}h2{font-size:21px;margin:0 0 16px}h3{font-size:18px;margin:0}.lead{font-size:19px;color:#40576a}.lead strong{color:#8b4e12}.badges,.chips,.links{display:flex;flex-wrap:wrap;gap:9px}.badges span,.chips span{padding:4px 10px;border-radius:5px;background:#eaf0f4;font-size:13px}section{margin:20px 0;background:white;border:1px solid #dce3e9;border-radius:12px;padding:24px}.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:16px}.metrics b{display:block;font-size:34px}.metrics span,.note{font-size:13px;color:#5b6a78}.call{border-top:1px solid #e4ebef;padding:20px 0}.call:first-of-type{border-top:0}.callhead{display:flex;justify-content:space-between;align-items:baseline;gap:16px}.callhead span{font-size:12px;color:#506878}.chips{margin:14px 0}table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;vertical-align:top;padding:10px;border-bottom:1px solid #e5ebef}th{color:#496175}details{padding:14px 0;border-bottom:1px solid #e5ebef}summary{cursor:pointer;font-weight:600}code,pre{font:12px/1.6 ui-monospace,monospace;overflow-wrap:anywhere;white-space:pre-wrap}a{color:#1c6688}footer{font-size:12px;color:#607080;padding:18px 0}@media(max-width:720px){main{padding:24px 12px}.metrics{grid-template-columns:repeat(2,1fr)}.callhead{display:block}section{padding:18px}h1{font-size:28px}}";

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    const INTENT: &str = "0123456789abcdef0123456789abcdef";

    struct Fixture {
        root: TempDir,
        intents: Vec<Value>,
        reasons: Vec<Value>,
        timeline: Vec<Value>,
        outcome: RunOutcome,
    }

    fn jsonl(rows: &[Value]) -> String {
        rows.iter().map(|row| format!("{row}\n")).collect()
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                root: tempfile::tempdir().unwrap(),
                intents: vec![json!({
                    "record_type":"intent", "timestamp_unix_ms":1, "session_id":"capture",
                    "intent_source":"claude", "intent_id":INTENT, "harness_session_id":"native",
                    "source_event_id":"call-1", "tool_name":"Bash", "observation_mode":"local_shell",
                    "command":"executable_ref:cat argv_redacted:true", "raw_event_id":null,
                })],
                reasons: vec![json!({
                    "record_type":"intent_reason", "timestamp_unix_ms":1, "session_id":"capture",
                    "intent_source":"claude", "intent_id":INTENT, "harness_session_id":"native",
                    "source_event_id":"call-1", "reason_id":"reason-1", "reason_code":"unknown",
                    "reason_source":"tool_description", "reason_summary":"读取文件确认结果",
                    "task_ref":null, "supersedes_reason_id":null,
                })],
                timeline: vec![
                    json!({"record_type":"raw_kernel_event", "session_id":"capture", "event_id":"raw-1", "event_name":"openat", "pid":42, "resource":"/work/example.txt", "intent_id":INTENT}),
                    json!({"record_type":"event", "session_id":"capture", "raw_event_id":"raw-1", "event_type":"file_open", "pid":42, "resource":"/work/example.txt", "intent_id":INTENT}),
                    json!({"record_type":"event", "session_id":"capture", "event_type":"runtime_metadata", "resource":"agent-exit-status", "action":"exit:0"}),
                    json!({"record_type":"observer_diagnostic", "session_id":"capture", "kind":"summary", "count":1}),
                    json!({"record_type":"observer_diagnostic", "session_id":"capture", "kind":"truncation", "count":2}),
                    json!({"record_type":"policy_violation", "session_id":"capture", "rule_id":"credentials.deny_read"}),
                    json!({"record_type":"enforcement_metadata", "session_id":"capture", "preoperation_prevention":false}),
                ],
                outcome: RunOutcome {
                    agent: "claude".into(),
                    session_id: "capture".into(),
                    exit_code: Some(0),
                    signal: None,
                    interrupted: false,
                    errors: vec![],
                    notes: vec![],
                },
            }
        }

        fn write(&self) {
            let intents = jsonl(&self.intents);
            let reasons = jsonl(&self.reasons);
            let timeline = jsonl(&self.timeline);
            let mut correlations = crate::correlate_intents(&intents, &timeline).unwrap();
            crate::intent::reason_binding::enrich(&intents, &reasons, &mut correlations).unwrap();
            for (name, data) in
                SOURCES
                    .into_iter()
                    .zip([intents, reasons, timeline, jsonl(&correlations)])
            {
                fs::write(self.root.path().join(name), data).unwrap();
            }
        }

        fn render(&self) -> (RenderedReport, Value) {
            let report = render(self.root.path(), &self.outcome);
            let value = serde_json::from_str(&report.json).unwrap();
            (report, value)
        }
    }

    #[test]
    fn native_report_groups_calls_without_double_counting_raw_and_canonical_events() {
        let fixture = Fixture::new();
        fixture.write();
        let (report, value) = fixture.render();
        assert!(report.complete, "{}", report.json);
        assert_eq!(value["kernel_events"], 1);
        assert_eq!(value["timeline_records"], 7);
        assert_eq!(value["canonical_events"], 2);
        assert_eq!(value["totals"]["exact_relations"], 1);
        assert_eq!(value["calls"][0]["event_counts"]["file_open"], 1);
        assert_eq!(
            value["calls"][0]["reason"]["reason_source"],
            "tool_description"
        );
        assert_eq!(value["totals"]["policy_notifications"], 1);
        assert_eq!(value["totals"]["preoperation_prevention_claims"], 0);
        assert_eq!(value["truncations"], 2);
        assert_eq!(value["task_outcome"], "not_verified");
        assert!(report.html.contains("凭证泄露"));
        assert!(report
            .summary
            .contains("Apolysis Session Summary (agent: claude | tool calls: 1 | exact relations: 1 | dropped: 0)"));
        assert!(report.summary.contains("Intent: 读取文件确认结果"));
        assert!(report.summary.contains("file_open (1): /work/example.txt"));
    }

    #[test]
    fn native_report_never_upgrades_semantic_only_or_absent_reasons() {
        let mut fixture = Fixture::new();
        fixture.intents[0]["observation_mode"] = json!("semantic_only");
        fixture.intents[0]["tool_name"] = json!("WebSearch");
        fixture.reasons.clear();
        fixture.write();
        let (report, value) = fixture.render();
        assert!(report.complete, "{}", report.json);
        assert_eq!(value["totals"]["exact_relations"], 0);
        assert_eq!(value["calls"][0]["execution_status"], "semantic_only");
        assert_eq!(value["calls"][0]["reason_status"], "unknown_or_unbound");
        assert!(value["calls"][0]["reason"].is_null());
        assert!(report.html.contains("没有可绑定的调用理由"));
    }

    #[test]
    fn native_report_nonzero_exit_does_not_invalidate_well_formed_capture() {
        let mut fixture = Fixture::new();
        fixture.outcome.exit_code = Some(7);
        fixture.timeline[2]["action"] = json!("exit:7");
        fixture.write();
        let (report, value) = fixture.render();
        assert!(report.complete, "{}", report.json);
        assert_eq!(value["application"]["exit_code"], 7);
        assert_eq!(value["task_outcome"], "not_verified");
    }

    #[test]
    fn native_report_missing_exit_or_summary_and_event_loss_are_incomplete() {
        for change in 0..4 {
            let mut fixture = Fixture::new();
            match change {
                0 => { fixture.timeline.remove(2); }
                1 => fixture.timeline[3]["count"] = json!(2),
                2 => fixture.timeline.push(json!({"record_type":"observer_diagnostic", "session_id":"capture", "kind":"ring_buffer_reserve_failure", "count":1})),
                _ => fixture.outcome.interrupted = true,
            }
            fixture.write();
            let (report, value) = fixture.render();
            assert!(!report.complete);
            assert_eq!(value["capture_status"], "incomplete");
        }
    }

    #[test]
    fn native_report_rejects_mixed_session_data_without_displaying_foreign_content() {
        let fixture = Fixture::new();
        fixture.write();
        let mut foreign = fixture.reasons[0].clone();
        foreign["session_id"] = json!("other-session");
        foreign["reason_summary"] = json!("FOREIGN_PRIVATE_SUMMARY");
        fs::write(fixture.root.path().join(SOURCES[1]), jsonl(&[foreign])).unwrap();
        let (report, value) = fixture.render();
        assert!(!report.complete);
        assert_eq!(value["correlation_status"], "incomplete");
        assert!(!report.html.contains("FOREIGN_PRIVATE_SUMMARY"));
        assert!(!report.json.contains("FOREIGN_PRIVATE_SUMMARY"));
    }

    #[test]
    fn native_report_rejects_dangling_or_changed_raw_relation_identity() {
        for change in 0..3 {
            let mut fixture = Fixture::new();
            match change {
                0 => fixture.timeline[0]["event_id"] = json!("different-raw-event"),
                1 => fixture.timeline[0]["pid"] = json!(99),
                _ => fixture.timeline[0]["intent_id"] = Value::Null,
            }
            fixture.write();
            let (report, value) = fixture.render();
            assert!(!report.complete);
            assert_eq!(value["totals"]["exact_relations"], 0);
            assert_eq!(value["correlation_status"], "incomplete");
        }
    }

    #[test]
    fn native_report_detects_empty_stale_or_duplicate_correlation_artifacts() {
        for change in 0..3 {
            let fixture = Fixture::new();
            fixture.write();
            let path = fixture.root.path().join(SOURCES[3]);
            let data = fs::read_to_string(&path).unwrap();
            match change {
                0 => fs::write(&path, "").unwrap(),
                1 => fs::write(&path, data.replace("raw-1", "not-a-real-event")).unwrap(),
                _ => fs::write(&path, format!("{data}{data}")).unwrap(),
            }
            let (report, value) = fixture.render();
            assert!(!report.complete);
            assert_eq!(value["correlation_status"], "incomplete");
            assert!(count(&value["totals"], "exact_relations") <= 1);
        }
    }

    #[test]
    fn native_report_partial_malformed_and_missing_artifacts_do_not_echo_content() {
        for change in 0..3 {
            let fixture = Fixture::new();
            fixture.write();
            let path = fixture.root.path().join(SOURCES[2]);
            match change {
                0 => {
                    let mut data = fs::read_to_string(&path).unwrap();
                    data.pop();
                    fs::write(&path, data).unwrap();
                }
                1 => fs::write(&path, "PRIVATE_PARSE_ERROR_CANARY\n").unwrap(),
                _ => fs::remove_file(&path).unwrap(),
            }
            let (report, value) = fixture.render();
            assert!(!report.complete);
            assert_eq!(value["capture_status"], "incomplete");
            assert!(!report.json.contains("PRIVATE_PARSE_ERROR_CANARY"));
            assert!(!report.html.contains("PRIVATE_PARSE_ERROR_CANARY"));
        }
    }

    #[test]
    fn native_report_escapes_html_and_markdown_without_copying_prompt_or_tool_payloads() {
        let mut fixture = Fixture::new();
        let hostile = "<img src=x onerror=alert(1)> [open](javascript:alert(1))";
        fixture.reasons[0]["reason_summary"] = json!(hostile);
        fixture.intents[0]["prompt"] = json!("PROMPT_MUST_NOT_APPEAR");
        fixture.intents[0]["command"] = json!("ARGV_MUST_NOT_APPEAR");
        fixture.timeline[0]["raw_payload"] = json!("TOOL_RESULT_MUST_NOT_APPEAR");
        fixture.write();
        let (report, _) = fixture.render();
        assert!(report.complete, "{}", report.json);
        assert!(!report.html.contains("<img"));
        assert!(!report.html.contains("href=\"javascript:"));
        assert!(report.html.contains("&lt;img"));
        assert!(!report.markdown.contains("[open](javascript:"));
        assert!(!report.markdown.contains("<img"));
        for canary in [
            "PROMPT_MUST_NOT_APPEAR",
            "ARGV_MUST_NOT_APPEAR",
            "TOOL_RESULT_MUST_NOT_APPEAR",
        ] {
            assert!(!report.json.contains(canary));
            assert!(!report.html.contains(canary));
            assert!(!report.markdown.contains(canary));
            assert!(!report.summary.contains(canary));
        }
    }

    #[test]
    fn native_report_keeps_reason_corrections_and_conflicts_distinct() {
        let mut fixture = Fixture::new();
        let mut corrected = fixture.reasons[0].clone();
        corrected["reason_id"] = json!("reason-2");
        corrected["supersedes_reason_id"] = json!("reason-1");
        corrected["reason_summary"] = json!("修正后的描述");
        fixture.reasons.push(corrected);
        fixture.write();
        let (report, value) = fixture.render();
        assert!(report.complete, "{}", report.json);
        assert_eq!(value["calls"][0]["reason"]["reason_id"], "reason-2");
        fixture.reasons[1]["source_event_id"] = json!("wrong-native-call");
        fixture.write();
        let (_, value) = fixture.render();
        assert!(value["calls"][0]["reason"].is_null());
        assert_eq!(
            value["totals"]["reason_diagnostics"]["reason_identity_mismatch"],
            1
        );
    }

    #[test]
    fn native_report_does_not_count_inferred_candidates_as_exact() {
        let mut fixture = Fixture::new();
        fixture.timeline[0]
            .as_object_mut()
            .unwrap()
            .remove("intent_id");
        fixture.timeline[1]
            .as_object_mut()
            .unwrap()
            .remove("intent_id");
        fixture.timeline[0]["event_name"] = json!("sched_process_exec");
        fixture.timeline[0]["resource"] = json!("executable_ref:cat");
        fixture.timeline[1]["event_type"] = json!("exec");
        fixture.timeline[1]["resource"] = json!("executable_ref:cat");
        fixture.timeline[1]["process_executable"] = json!("executable_ref:cat");
        fixture.write();
        let (report, value) = fixture.render();
        assert!(report.complete, "{}", report.json);
        assert_eq!(value["totals"]["exact_relations"], 0);
        assert_eq!(value["totals"]["candidates"]["inferred"], 1);
        assert_eq!(
            value["calls"][0]["execution_status"],
            "not_exactly_attributed"
        );
    }
}
