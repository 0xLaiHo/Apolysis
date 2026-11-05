// SPDX-License-Identifier: Apache-2.0

use apolysis_core::SessionIntentReasonRecord;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::ErrorKind;
use std::path::Path;

fn read_bytes(path: &Path) -> Result<Vec<u8>, String> {
    match fs::read(path) {
        Ok(bytes) => Ok(bytes),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(Vec::new()),
        Err(_) => Err("could not read chat evidence".to_string()),
    }
}

fn parse_complete(bytes: &[u8]) -> Result<Vec<Value>, String> {
    let end = bytes
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |index| index + 1);
    bytes[..end]
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| {
            serde_json::from_slice(line)
                .map_err(|_| "chat evidence contains an invalid JSON record".to_string())
        })
        .collect()
}

/// A live writer may still be appending the last line. Complete invalid lines
/// are errors, and their contents must never appear in an error message.
pub(super) fn read_complete(path: &Path) -> Result<Vec<Value>, String> {
    parse_complete(&read_bytes(path)?)
}

fn read_final(path: &Path) -> Result<Vec<Value>, String> {
    let bytes = read_bytes(path)?;
    if bytes.is_empty() || !bytes.ends_with(b"\n") {
        return Err("chat evidence is missing or has an unfinished record".to_string());
    }
    parse_complete(&bytes)
}

fn field<'a>(row: &'a Value, name: &str) -> Option<&'a str> {
    row.get(name).and_then(Value::as_str)
}

fn required_field<'a>(row: &'a Value, name: &str) -> Result<&'a str, String> {
    field(row, name)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "chat evidence has an incomplete identity".to_string())
}

/// Report collection completeness independently of conversation success. Use a
/// single snapshot for both the parsed records and the final-newline check.
pub(super) fn capture_report(
    evidence: &Path,
    session: &str,
    turns: &[Value],
    closed_normally: bool,
) -> Result<Value, String> {
    let bytes = read_bytes(&evidence.join("timeline.jsonl"))?;
    let records = parse_complete(&bytes)?;
    let mut valid = !session.is_empty() && bytes.ends_with(b"\n");
    let mut raw_count = 0_u64;
    let mut summary_counts = Vec::new();
    let mut exits = Vec::new();
    let mut errors = 0_u64;
    let mut truncations = 0_u64;
    for row in &records {
        valid &= field(row, "session_id") == Some(session);
        match field(row, "record_type") {
            Some("raw_kernel_event") => raw_count += 1,
            Some("event") if field(row, "resource") == Some("agent-exit-status") => {
                exits.push(row);
            }
            Some("observer_diagnostic") => {
                let kind = field(row, "kind");
                let count = row.get("count").and_then(Value::as_u64);
                valid &= matches!(
                    kind,
                    Some(
                        "summary"
                            | "truncation"
                            | "ring_buffer_reserve_failure"
                            | "map_pressure"
                            | "decode_failure"
                            | "attach_failure"
                            | "verifier_failure"
                    )
                ) && count.is_some();
                if kind == Some("summary") {
                    summary_counts.push(count);
                } else if let Some(count) = count {
                    let total = if kind == Some("truncation") {
                        &mut truncations
                    } else {
                        &mut errors
                    };
                    match total.checked_add(count) {
                        Some(sum) => *total = sum,
                        None => {
                            valid = false;
                            *total = u64::MAX;
                        }
                    }
                }
            }
            _ => {}
        }
    }
    let exited = exits.len() == 1
        && field(exits[0], "session_id") == Some(session)
        && field(exits[0], "action") == Some("exit:0");
    let complete = closed_normally
        && valid
        && exited
        && raw_count > 0
        && errors == 0
        && summary_counts == [Some(raw_count)];
    Ok(json!({
        "session_id": session,
        "capture_status": if complete { "complete" } else { "incomplete" },
        "turns": turns,
        "kernel_events": raw_count,
        "loss_or_failure_count": errors,
        "truncations": truncations,
        "native_exit_success": exited,
        "forced_stop": !closed_normally,
    }))
}

fn valid_intent_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn reason_matches_call(reason: &SessionIntentReasonRecord, call: &Value) -> bool {
    [
        ("session_id", reason.session_id.as_str()),
        ("intent_id", reason.intent_id.as_str()),
        ("intent_source", reason.intent_source.as_str()),
        ("harness_session_id", reason.harness_session_id.as_str()),
        ("source_event_id", reason.source_event_id.as_str()),
    ]
    .iter()
    .all(|(key, value)| field(call, key) == Some(*value))
}

fn exact_reason(row: &Value, reason: &SessionIntentReasonRecord) -> bool {
    field(row, "record_type") == Some("intent_correlation")
        && field(row, "relation_status") == Some("exact")
        && field(row, "match_basis") == Some("intent_id")
        && field(row, "session_id") == Some(reason.session_id.as_str())
        && field(row, "intent_id") == Some(reason.intent_id.as_str())
        && field(row, "intent_source") == Some(reason.intent_source.as_str())
        && row.get("declared_reason")
            == Some(&json!({
                "reason_id": reason.reason_id,
                "reason_code": reason.reason_code,
                "reason_source": reason.reason_source,
                "reason_summary": reason.reason_summary,
                "task_ref": reason.task_ref,
            }))
}

fn python_executable(value: &str) -> bool {
    let executable = value.strip_prefix("executable_ref:").unwrap_or(value);
    let name = Path::new(executable)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    name == "python"
        || name.strip_prefix("python").is_some_and(|version| {
            !version.is_empty()
                && version
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || byte == b'.')
        })
}

fn runtime_is_python(row: &Value) -> bool {
    let exec = (field(row, "record_type") == Some("raw_kernel_event")
        && matches!(
            field(row, "event_name"),
            Some("sched_process_exec" | "execve" | "execveat")
        ))
        || (field(row, "record_type") == Some("event") && field(row, "event_type") == Some("exec"));
    exec && ["resource", "process_executable"]
        .iter()
        .any(|key| field(row, key).is_some_and(python_executable))
}

fn record_index<'a>(
    rows: &'a [Value],
    record_type: &str,
    id_field: &str,
) -> Result<HashMap<&'a str, &'a Value>, String> {
    let mut index = HashMap::new();
    for row in rows
        .iter()
        .filter(|row| field(row, "record_type") == Some(record_type))
    {
        // Runtime metadata events intentionally have no raw event identifier.
        if record_type == "event" && row.get(id_field).is_none_or(Value::is_null) {
            continue;
        }
        let id = required_field(row, id_field)?;
        if index.insert(id, row).is_some() {
            return Err("chat evidence repeats a kernel event identity".to_string());
        }
    }
    Ok(index)
}

fn file_chain(row: &Value, raw: &Value, canonical: &Value) -> bool {
    let pid = row.get("pid").and_then(Value::as_u64);
    pid.is_some_and(|pid| pid > 0)
        && matches!(
            field(raw, "event_name"),
            Some("open" | "openat" | "openat2")
        )
        && field(raw, "event_source") == Some("kernel_tracepoint")
        && field(canonical, "event_source") == Some("kernel_tracepoint")
        && field(canonical, "event_type") == Some("file_open")
        && ["session_id", "intent_id", "pid", "resource"]
            .iter()
            .all(|key| {
                row.get(key).is_some()
                    && row.get(key) == raw.get(key)
                    && row.get(key) == canonical.get(key)
            })
        && field(row, "process_executable").is_some()
        && row.get("process_executable") == canonical.get("process_executable")
}

pub(super) fn validate_smoke(
    workspace: &Path,
    evidence: &Path,
    turns: &[Value],
) -> Result<(), String> {
    if turns.len() != 3
        || turns[2].get("tool_calls").and_then(Value::as_u64) != Some(0)
        || turns[..2].iter().any(|turn| {
            !turn
                .get("tool_calls")
                .and_then(Value::as_u64)
                .is_some_and(|count| count > 0)
        })
    {
        return Err(
            "smoke run did not complete two tool turns and one conversation-only turn".to_string(),
        );
    }
    let greeting = fs::read_to_string(workspace.join("greeting.txt"))
        .map_err(|_| "smoke run did not produce the requested file".to_string())?;
    if greeting.trim() != "hello apolysis" {
        return Err("smoke run did not produce the requested file".to_string());
    }
    let intents = read_final(&evidence.join("intent.jsonl"))?;
    let reason_rows = read_final(&evidence.join("intent.jsonl.reasons.jsonl"))?;
    let joined = read_final(&evidence.join("correlation.jsonl"))?;
    let timeline = read_final(&evidence.join("timeline.jsonl"))?;
    if intents.len() < 2 || intents.len() != reason_rows.len() {
        return Err("smoke call identity or reason count mismatch".to_string());
    }
    let session = required_field(&intents[0], "session_id")?;
    let native_session = required_field(&intents[0], "harness_session_id")?;
    if reason_rows
        .iter()
        .chain(&joined)
        .chain(&timeline)
        .any(|row| field(row, "session_id") != Some(session))
    {
        return Err("smoke evidence contains a missing or foreign session".to_string());
    }
    let mut calls = HashMap::new();
    let mut native_calls = HashSet::new();
    for call in &intents {
        let id = required_field(call, "intent_id")?;
        if field(call, "record_type") != Some("intent")
            || field(call, "intent_source") != Some("claude")
            || field(call, "session_id") != Some(session)
            || field(call, "harness_session_id") != Some(native_session)
            || !valid_intent_id(id)
            || !native_calls.insert(required_field(call, "source_event_id")?)
            || calls.insert(id, call).is_some()
        {
            return Err("smoke run has inconsistent native call identities".to_string());
        }
    }
    let reasons = reason_rows
        .iter()
        .map(|row| {
            apolysis_store::parse_intent_reason(&row.to_string())
                .map_err(|_| "smoke evidence contains an invalid reason".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut reason_calls = HashMap::new();
    let mut reason_ids = HashSet::new();
    let mut readable_summary = false;
    for reason in &reasons {
        let summary = reason
            .reason_summary
            .as_deref()
            .filter(|value| !value.trim().is_empty());
        if reason.reason_source != "agent_declared"
            || summary.is_none()
            || reason.supersedes_reason_id.is_some()
            || !calls
                .get(reason.intent_id.as_str())
                .is_some_and(|call| reason_matches_call(reason, call))
            || reason_calls
                .insert(reason.intent_id.as_str(), reason)
                .is_some()
            || !reason_ids.insert(reason.reason_id.as_str())
            || !joined.iter().any(|row| exact_reason(row, reason))
        {
            return Err("smoke call lacks a unique exact model-declared reason".to_string());
        }
        readable_summary |= summary.is_some_and(|value| value != "[redacted]");
    }
    if !readable_summary {
        return Err("smoke run has no readable model-written reason summary".to_string());
    }
    if joined
        .iter()
        .any(|row| field(row, "record_type") == Some("intent_reason_diagnostic"))
    {
        return Err("smoke reason binding reported a diagnostic".to_string());
    }
    if timeline.iter().any(runtime_is_python) {
        return Err("smoke run executed a Python runtime".to_string());
    }
    if !timeline.iter().any(|row| {
        field(row, "record_type") == Some("raw_kernel_event")
            && field(row, "event_name") == Some("sched_process_exec")
    }) {
        return Err("smoke run has no runtime exec evidence".to_string());
    }
    let raw = record_index(&timeline, "raw_kernel_event", "event_id")?;
    let canonical = record_index(&timeline, "event", "raw_event_id")?;
    let absolute_greeting = workspace.join("greeting.txt");
    let target_chain = joined.iter().any(|row| {
        if field(row, "event_type") != Some("file_open")
            || !field(row, "resource").is_some_and(|value| {
                value == "greeting.txt" || Path::new(value) == absolute_greeting
            })
        {
            return false;
        }
        let Some(reason) = field(row, "intent_id").and_then(|id| reason_calls.get(id)) else {
            return false;
        };
        if !exact_reason(row, reason) {
            return false;
        }
        let Some(id) = field(row, "raw_event_id") else {
            return false;
        };
        match (raw.get(id), canonical.get(id)) {
            (Some(raw), Some(canonical)) => file_chain(row, raw, canonical),
            _ => false,
        }
    });
    if !target_chain {
        return Err("requested file lacks an exact raw-to-canonical reason relation".to_string());
    }
    Ok(())
}

pub(super) fn display_turn(evidence: &Path, before: &HashSet<String>) -> Result<usize, String> {
    let intents = read_complete(&evidence.join("intent.jsonl"))?;
    let reasons = read_complete(&evidence.join("intent.jsonl.reasons.jsonl"))?
        .iter()
        .map(|row| {
            apolysis_store::parse_intent_reason(&row.to_string())
                .map_err(|_| "chat evidence contains an invalid reason".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let joined = read_complete(&evidence.join("correlation.jsonl"))?;
    let mut seen = HashSet::new();
    let mut count = 0;
    for call in &intents {
        let id = required_field(call, "intent_id")?;
        if !valid_intent_id(id) || !seen.insert(id) {
            return Err("chat evidence has invalid or duplicate call identities".to_string());
        }
        if before.contains(id) {
            continue;
        }
        let matched = reasons
            .iter()
            .filter(|reason| reason_matches_call(reason, call))
            .collect::<Vec<_>>();
        let reason = if matched.len() == 1 {
            matched.first()
        } else {
            None
        };
        let explanation = reason
            .map(|reason| match reason.reason_summary.as_deref() {
                Some("[redacted]") => format!("{}（摘要已脱敏）", reason.reason_code),
                Some(summary) => summary.to_string(),
                None => reason.reason_code.clone(),
            })
            .unwrap_or_else(|| "未声明或存在歧义".to_string());
        let exact = joined
            .iter()
            .filter(|row| {
                field(row, "record_type") == Some("intent_correlation")
                    && field(row, "relation_status") == Some("exact")
                    && field(row, "match_basis") == Some("intent_id")
                    && field(row, "intent_id") == Some(id)
                    && row.get("session_id") == call.get("session_id")
                    && row.get("intent_source") == call.get("intent_source")
            })
            .count();
        println!("观测：intent_id={id}；理由={explanation}；已关联事件={exact}");
        count += 1;
    }
    if count == 0 {
        println!("观测：本轮未调用工具。");
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT: AtomicUsize = AtomicUsize::new(0);
    const SESSION: &str = "chat-test-session";
    const FIRST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SECOND: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    struct Fixture {
        root: PathBuf,
        workspace: PathBuf,
        evidence: PathBuf,
        turns: Vec<Value>,
        intents: Vec<Value>,
        reasons: Vec<Value>,
        timeline: Vec<Value>,
        joined: Vec<Value>,
    }

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "apolysis-chat-evidence-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap();
            let workspace = root.join("workspace");
            let evidence = root.join("evidence");
            fs::create_dir(&workspace).unwrap();
            fs::create_dir(&evidence).unwrap();
            fs::write(workspace.join("greeting.txt"), "hello apolysis\n").unwrap();
            let intents = [FIRST, SECOND]
                .iter()
                .enumerate()
                .map(|(index, id)| {
                    json!({
                        "record_type":"intent", "session_id":SESSION, "intent_id":id,
                        "intent_source":"claude", "harness_session_id":"native-session",
                        "source_event_id":format!("native-call-{index}"), "tool_name":"Bash",
                    })
                })
                .collect::<Vec<_>>();
            let reasons = intents.iter().enumerate().map(|(index, call)| json!({
                "record_type":"intent_reason", "timestamp_unix_ms":1,
                "session_id":SESSION, "intent_id":call["intent_id"],
                "intent_source":"claude", "harness_session_id":"native-session",
                "source_event_id":call["source_event_id"], "reason_id":format!("reason-{index}"),
                "reason_code":"verify_change", "reason_source":"agent_declared",
                "reason_summary":if index == 0 { "[redacted]" } else { "读取文件并统计单词" },
                "task_ref":null, "supersedes_reason_id":null,
            })).collect::<Vec<_>>();
            let mut timeline = Vec::new();
            let mut joined = Vec::new();
            for (index, id) in [FIRST, SECOND].iter().enumerate() {
                let raw_id = format!("raw-{index}");
                let resource = if index == 0 {
                    "executable_ref:bash"
                } else {
                    "greeting.txt"
                };
                let event_type = if index == 0 { "exec" } else { "file_open" };
                timeline.push(json!({
                    "record_type":"raw_kernel_event", "session_id":SESSION,
                    "event_source":"kernel_tracepoint", "event_id":raw_id,
                    "event_name":if index == 0 { "sched_process_exec" } else { "openat" },
                    "intent_id":id, "pid":50+index, "resource":resource,
                    "process_start_time_ns":500,
                }));
                let canonical = json!({
                    "record_type":"event", "session_id":SESSION,
                    "event_source":"kernel_tracepoint", "raw_event_id":raw_id,
                    "event_type":event_type, "intent_id":id, "pid":50+index,
                    "resource":resource, "process_executable":"executable_ref:bash",
                });
                let mut relation = canonical.clone();
                relation["record_type"] = json!("intent_correlation");
                relation["intent_source"] = json!("claude");
                relation["relation_status"] = json!("exact");
                relation["match_basis"] = json!("intent_id");
                relation["declared_reason"] = json!({
                    "reason_id":reasons[index]["reason_id"],
                    "reason_code":reasons[index]["reason_code"],
                    "reason_source":reasons[index]["reason_source"],
                    "reason_summary":reasons[index]["reason_summary"], "task_ref":null,
                });
                timeline.push(canonical);
                joined.push(relation);
            }
            timeline.push(json!({"record_type":"event", "session_id":SESSION,
                "resource":"agent-exit-status", "action":"exit:0"}));
            timeline.push(
                json!({"record_type":"observer_diagnostic", "session_id":SESSION,
                "kind":"summary", "count":2}),
            );
            let fixture = Self {
                root,
                workspace,
                evidence,
                intents,
                reasons,
                timeline,
                joined,
                turns: vec![
                    json!({"turn":1,"tool_calls":1}),
                    json!({"turn":2,"tool_calls":1}),
                    json!({"turn":3,"tool_calls":0}),
                ],
            };
            fixture.persist();
            fixture
        }

        fn persist(&self) {
            for (name, rows) in [
                ("intent.jsonl", &self.intents),
                ("intent.jsonl.reasons.jsonl", &self.reasons),
                ("timeline.jsonl", &self.timeline),
                ("correlation.jsonl", &self.joined),
            ] {
                fs::write(
                    self.evidence.join(name),
                    rows.iter()
                        .map(|row| format!("{row}\n"))
                        .collect::<String>(),
                )
                .unwrap();
            }
        }

        fn report(&self, normal: bool) -> Value {
            capture_report(&self.evidence, SESSION, &self.turns, normal).unwrap()
        }

        fn smoke(&self) -> Result<(), String> {
            validate_smoke(&self.workspace, &self.evidence, &self.turns)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn live_reader_ignores_only_an_unfinished_last_line_and_never_echoes_content() {
        let fixture = Fixture::new();
        let path = fixture.evidence.join("snapshot.jsonl");
        assert!(read_complete(&path).unwrap().is_empty());
        fs::write(&path, b"{\"ok\":true}\n{\"unfinished\":").unwrap();
        assert_eq!(read_complete(&path).unwrap(), [json!({"ok":true})]);
        fs::write(&path, b"{\"ok\":true}\nPRIVATE_INVALID_CONTENT\n").unwrap();
        assert_eq!(
            read_complete(&path).unwrap_err(),
            "chat evidence contains an invalid JSON record"
        );
        fs::write(&path, b"{\"ok\":true}\n\xff\n").unwrap();
        assert_eq!(
            read_complete(&path).unwrap_err(),
            "chat evidence contains an invalid JSON record"
        );
    }

    #[test]
    fn report_accepts_complete_capture_and_reports_truncation_separately() {
        let mut fixture = Fixture::new();
        fixture.timeline.push(
            json!({"record_type":"observer_diagnostic", "session_id":SESSION,
            "kind":"truncation", "count":3}),
        );
        fixture.persist();
        let report = fixture.report(true);
        assert_eq!(report["capture_status"], "complete");
        assert_eq!(report["kernel_events"], 2);
        assert_eq!(report["truncations"], 3);
        assert_eq!(report["loss_or_failure_count"], 0);
        assert_eq!(fixture.report(false)["capture_status"], "incomplete");
    }

    #[test]
    fn report_rejects_foreign_missing_and_non_object_records() {
        for replacement in [
            json!({"record_type":"event","session_id":"other"}),
            json!({"record_type":"event"}),
            json!(true),
        ] {
            let mut fixture = Fixture::new();
            fixture.timeline.push(replacement);
            fixture.persist();
            assert_eq!(fixture.report(true)["capture_status"], "incomplete");
        }
    }

    #[test]
    fn report_rejects_unknown_diagnostics_and_non_integer_counts() {
        for (kind, count) in [
            ("unknown", json!(0)),
            ("truncation", json!(-1)),
            ("truncation", json!(true)),
            ("truncation", Value::Null),
            ("truncation", json!(1.5)),
        ] {
            let mut fixture = Fixture::new();
            fixture.timeline.push(
                json!({"record_type":"observer_diagnostic", "session_id":SESSION,
                "kind":kind, "count":count}),
            );
            fixture.persist();
            assert_eq!(fixture.report(true)["capture_status"], "incomplete");
        }
    }

    #[test]
    fn report_requires_one_matching_summary_and_one_successful_exit() {
        for variant in 0..6 {
            let mut fixture = Fixture::new();
            match variant {
                0 => {
                    fixture.timeline.pop();
                }
                1 => fixture.timeline.push(fixture.timeline[5].clone()),
                2 => fixture.timeline[5]["count"] = json!(1),
                3 => {
                    fixture.timeline.remove(4);
                }
                4 => fixture.timeline.push(fixture.timeline[4].clone()),
                5 => fixture.timeline[4]["action"] = json!("exit:1"),
                _ => unreachable!(),
            }
            fixture.persist();
            assert_eq!(
                fixture.report(true)["capture_status"],
                "incomplete",
                "variant {variant}"
            );
        }
    }

    #[test]
    fn report_rejects_event_loss_final_partial_record_and_missing_timeline() {
        let mut fixture = Fixture::new();
        fixture.timeline.push(
            json!({"record_type":"observer_diagnostic", "session_id":SESSION,
            "kind":"decode_failure", "count":1}),
        );
        fixture.persist();
        assert_eq!(fixture.report(true)["loss_or_failure_count"], 1);
        assert_eq!(fixture.report(true)["capture_status"], "incomplete");
        fixture.timeline.pop();
        fixture.persist();
        let path = fixture.evidence.join("timeline.jsonl");
        let mut bytes = fs::read(&path).unwrap();
        bytes.extend_from_slice(b"{\"partial\":");
        fs::write(&path, bytes).unwrap();
        assert_eq!(fixture.report(true)["capture_status"], "incomplete");
        fs::remove_file(path).unwrap();
        assert_eq!(fixture.report(true)["capture_status"], "incomplete");
    }

    #[test]
    fn report_count_overflow_is_incomplete_without_panicking() {
        let mut fixture = Fixture::new();
        for count in [u64::MAX, 1] {
            fixture.timeline.push(
                json!({"record_type":"observer_diagnostic", "session_id":SESSION,
                "kind":"truncation", "count":count}),
            );
        }
        fixture.persist();
        assert_eq!(fixture.report(true)["capture_status"], "incomplete");
    }

    #[test]
    fn smoke_accepts_complete_identity_chain_with_one_redacted_summary() {
        assert!(Fixture::new().smoke().is_ok());
    }

    #[test]
    fn smoke_rejects_wrong_file_third_turn_tool_and_native_identity_changes() {
        for variant in 0..5 {
            let mut fixture = Fixture::new();
            match variant {
                0 => fs::write(fixture.workspace.join("greeting.txt"), "incorrect").unwrap(),
                1 => fixture.turns[2]["tool_calls"] = json!(1),
                2 => fixture.intents[1]["harness_session_id"] = json!("different-native-session"),
                3 => fixture.intents[1]["intent_id"] = json!(FIRST),
                4 => {
                    fixture.intents[1]["source_event_id"] =
                        fixture.intents[0]["source_event_id"].clone()
                }
                _ => unreachable!(),
            }
            fixture.persist();
            assert!(fixture.smoke().is_err(), "variant {variant}");
        }
    }

    #[test]
    fn smoke_requires_each_reason_to_bind_the_full_call_and_exact_summary() {
        for variant in 0..6 {
            let mut fixture = Fixture::new();
            match variant {
                0 => fixture.reasons[1]["source_event_id"] = json!("different-call"),
                1 => fixture.reasons[1]["reason_source"] = json!("operator_annotation"),
                2 => fixture.reasons[1]["reason_summary"] = Value::Null,
                3 => {
                    fixture.joined[1]["declared_reason"]["reason_summary"] =
                        json!("different summary")
                }
                4 => fixture.joined[1]["match_basis"] = json!("executable"),
                5 => fixture.reasons[1]["intent_id"] = json!(FIRST),
                _ => unreachable!(),
            }
            fixture.persist();
            assert!(fixture.smoke().is_err(), "variant {variant}");
        }
    }

    #[test]
    fn smoke_rejects_all_redacted_summaries_and_reason_diagnostics() {
        let mut fixture = Fixture::new();
        fixture.reasons[1]["reason_summary"] = json!("[redacted]");
        fixture.joined[1]["declared_reason"]["reason_summary"] = json!("[redacted]");
        fixture.persist();
        assert!(fixture.smoke().is_err());
        let mut fixture = Fixture::new();
        fixture
            .joined
            .push(json!({"record_type":"intent_reason_diagnostic", "session_id":SESSION}));
        fixture.persist();
        assert!(fixture.smoke().is_err());
    }

    #[test]
    fn smoke_rejects_broken_raw_canonical_correlation_identity_chains() {
        for variant in 0..8 {
            let mut fixture = Fixture::new();
            match variant {
                0 => fixture.timeline[2]["event_id"] = json!("different-raw"),
                1 => fixture.timeline[3]["raw_event_id"] = json!("different-canonical"),
                2 => fixture.timeline[2]["pid"] = json!(999),
                3 => fixture.timeline[3]["intent_id"] = json!(FIRST),
                4 => fixture.timeline[2]["resource"] = json!("different.txt"),
                5 => fixture.timeline[2]["event_source"] = json!("fixture"),
                6 => fixture.timeline.push(fixture.timeline[2].clone()),
                7 => fixture.timeline.push(fixture.timeline[3].clone()),
                _ => unreachable!(),
            }
            fixture.persist();
            assert!(fixture.smoke().is_err(), "variant {variant}");
        }
    }

    #[test]
    fn smoke_detects_python_from_raw_and_canonical_exec_metadata() {
        for (index, key, executable) in [
            (0, "resource", "executable_ref:python3"),
            (0, "resource", "/usr/bin/python"),
            (1, "process_executable", "executable_ref:python3.13"),
        ] {
            let mut fixture = Fixture::new();
            fixture.timeline[index][key] = json!(executable);
            fixture.persist();
            assert_eq!(
                fixture.smoke().unwrap_err(),
                "smoke run executed a Python runtime"
            );
        }
    }

    #[test]
    fn smoke_rejects_foreign_evidence_and_final_partial_artifacts() {
        let mut fixture = Fixture::new();
        fixture.joined[0]["session_id"] = json!("foreign-session");
        fixture.persist();
        assert!(fixture.smoke().is_err());
        for name in [
            "intent.jsonl",
            "intent.jsonl.reasons.jsonl",
            "timeline.jsonl",
            "correlation.jsonl",
        ] {
            let fixture = Fixture::new();
            let path = fixture.evidence.join(name);
            let mut bytes = fs::read(&path).unwrap();
            bytes.pop();
            fs::write(&path, bytes).unwrap();
            assert!(fixture.smoke().is_err());
        }
    }

    #[test]
    fn display_counts_only_new_calls_and_rejects_duplicate_ids() {
        let mut fixture = Fixture::new();
        assert_eq!(display_turn(&fixture.evidence, &HashSet::new()).unwrap(), 2);
        let before = HashSet::from([FIRST.to_string(), SECOND.to_string()]);
        assert_eq!(display_turn(&fixture.evidence, &before).unwrap(), 0);
        fixture.intents.push(fixture.intents[0].clone());
        fixture.persist();
        assert!(display_turn(&fixture.evidence, &before).is_err());
    }

    #[test]
    fn display_rejects_malformed_reason_without_echoing_its_contents() {
        let mut fixture = Fixture::new();
        fixture.reasons[0]["reason_source"] = json!("PRIVATE_INVALID_SOURCE");
        fixture.persist();
        assert_eq!(
            display_turn(&fixture.evidence, &HashSet::new()).unwrap_err(),
            "chat evidence contains an invalid reason"
        );
    }
}
