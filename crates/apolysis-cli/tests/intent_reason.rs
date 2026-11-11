// SPDX-License-Identifier: Apache-2.0
use serde_json::{json, Value};
use std::{
    io::Write,
    path::PathBuf,
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
};
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "apolysis-reason-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self, name: &str) -> String {
        self.0.join(name).to_str().unwrap().to_string()
    }
    fn hook(&self, harness: &str, payload: &Value, flags: &[&str]) -> Output {
        self.call(
            &[
                "intent",
                "hook",
                "--harness",
                harness,
                "--session",
                "capture",
                "--output",
                &self.path("intent"),
                "--workspace-root",
                self.0.to_str().unwrap(),
            ],
            payload,
            flags,
        )
    }
    fn call(&self, args: &[&str], payload: &Value, flags: &[&str]) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_apolysis"))
            .args(args)
            .args(flags)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(payload.to_string().as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }
    fn read(&self, name: &str) -> Vec<Value> {
        std::fs::read_to_string(self.path(name))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
    fn correlate(&self, extra: &str) -> Vec<Value> {
        std::fs::write(self.path("events"), extra).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_apolysis"))
            .args([
                "intent",
                "correlate",
                "--intent-input",
                &self.path("intent"),
                "--timeline-input",
                &self.path("events"),
                "--reason-input",
                &self.path("intent.reasons.jsonl"),
                "--output",
                &self.path("correlation"),
            ])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        self.read("correlation")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn payload(tool: &str, field: &str) -> Value {
    let mut p = json!({"session_id":"native", "tool_use_id":"call", "tool_name":tool, "hook_event_name":"preToolUse", "prompt":"PROMPT_MUST_NOT_PERSIST", "transcript_path":"/should/not/be/read", "tool_result":"RESULT_MUST_NOT_PERSIST", "tool_input":{"description":"DESCRIPTION_MUST_NOT_PERSIST"}});
    p["tool_input"][field] = "# APOLYSIS_REASON_CODE=verify_change\nprintf fixture".into();
    p
}
fn events(id: &str) -> String {
    ["exec", "file_open", "network_connect"].iter().enumerate().map(|(i, ty)| json!({"record_type":"event","session_id":"capture", "raw_event_id":format!("e{i}"), "event_type":ty, "resource":"fixture", "intent_id":id}).to_string()+"\n").collect()
}
#[test]
fn five_harnesses_record_content_off_reason_and_keep_marker_id_stable() {
    for (harness, tool, field) in [
        ("codex", "exec_command", "cmd"),
        ("claude", "Bash", "command"),
        ("cursor", "Shell", "command"),
        ("pi", "bash", "command"),
        ("opencode", "bash", "command"),
    ] {
        let f = Fixture::new();
        let p = payload(tool, field);
        let first = f.hook(harness, &p, &[]);
        assert!(
            first.status.success(),
            "{harness}: {}",
            String::from_utf8_lossy(&first.stderr)
        );
        let second = f.hook(harness, &p, &[]);
        assert!(second.status.success());
        let intents = f.read("intent");
        let reasons = f.read("intent.reasons.jsonl");
        assert_eq!(intents.len(), 1);
        assert_eq!(reasons.len(), 1);
        let id = intents[0]["intent_id"].as_str().unwrap();
        assert_eq!(reasons[0]["intent_id"], id);
        assert_eq!(reasons[0]["reason_code"], "verify_change");
        assert_eq!(reasons[0]["reason_source"], "agent_declared");
        assert!(reasons[0]["reason_summary"].is_null());
        assert!(String::from_utf8(first.stdout)
            .unwrap()
            .contains(&format!("APOLYSIS_INTENT_ID={id}")));
        let persisted = format!("{intents:?}{reasons:?}");
        for secret in [
            "PROMPT_MUST_NOT_PERSIST",
            "RESULT_MUST_NOT_PERSIST",
            "DESCRIPTION_MUST_NOT_PERSIST",
            "printf fixture",
            "/should/not/be/read",
        ] {
            assert!(!persisted.contains(secret));
        }
        let joined = f.correlate(&events(id));
        let exact: Vec<_> = joined
            .iter()
            .filter(|r| r["record_type"] == "intent_correlation")
            .collect();
        assert_eq!(exact.len(), 3);
        assert!(exact
            .iter()
            .all(|r| r["declared_reason"]["reason_code"] == "verify_change"));
        let mut no_reason = p.clone();
        no_reason["tool_input"][field] = "printf fixture".into();
        no_reason["tool_input"]
            .as_object_mut()
            .unwrap()
            .remove("description");
        // Same native call without reason still has exactly the same intent ID.
        assert!(f.hook(harness, &no_reason, &[]).status.success());
        assert_eq!(f.read("intent").len(), 1);
    }
}
#[test]
fn late_reason_correction_and_cross_session_isolation() {
    let f = Fixture::new();
    let mut p = payload("Bash", "command");
    p["tool_input"] = json!({"command":"true"});
    assert!(f.hook("claude", &p, &[]).status.success());
    let id = f.read("intent")[0]["intent_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(!PathBuf::from(f.path("intent.reasons.jsonl")).exists());
    p["apolysis_reason"] = json!({"reason_code":"inspect_context","reason_id":"first","reason_summary":"PRIVATE_LATE_REASON"});
    let args = [
        "intent",
        "reason",
        "--harness",
        "claude",
        "--session",
        "capture",
        "--output",
        &f.path("intent.reasons.jsonl"),
    ];
    assert!(f.call(&args, &p, &[]).status.success());
    p["apolysis_reason"] = json!({"reason_code":"verify_change","reason_id":"correction","supersedes_reason_id":"first"});
    assert!(f.call(&args, &p, &[]).status.success());
    assert!(f.call(&args, &p, &[]).status.success());
    assert_eq!(f.read("intent.reasons.jsonl").len(), 2);
    let mut event = events(&id);
    event.push_str(&json!({"record_type":"event","session_id":"other","raw_event_id":"unrelated","event_type":"file_open","resource":"fixture","intent_id":id}).to_string());
    let joined = f.correlate(&event);
    assert_eq!(
        joined
            .iter()
            .filter(|r| r["record_type"] == "intent_reason_binding")
            .count(),
        1
    );
    assert!(
        joined
            .iter()
            .filter(|r| r["record_type"] == "intent_correlation")
            .all(|r| r["declared_reason"]["reason_id"] == "correction"
                && r["session_id"] == "capture")
    );
    assert_eq!(f.read("intent").len(), 1);
}
#[test]
fn semantic_only_reason_cannot_manufacture_a_syscall_relation() {
    let f = Fixture::new();
    let mut p = payload("WebSearch", "query");
    p["apolysis_reason"] = json!({"reason_code":"gather_evidence"});
    assert!(f.hook("claude", &p, &[]).status.success());
    let id = f.read("intent")[0]["intent_id"]
        .as_str()
        .unwrap()
        .to_string();
    let joined = f.correlate(&events(&id));
    assert!(joined
        .iter()
        .any(|r| r["record_type"] == "intent_reason_binding"));
    assert!(!joined
        .iter()
        .any(|r| r["record_type"] == "intent_correlation"));
}
#[test]
fn reason_failure_returns_no_marker_and_does_not_overwrite_records() {
    let f = Fixture::new();
    let mut p = payload("Bash", "command");
    let first = f.hook("claude", &p, &[]);
    assert!(first.status.success());
    let before = std::fs::read(f.path("intent.reasons.jsonl")).unwrap();
    p["tool_input"]["command"] = "# APOLYSIS_REASON_CODE=implement_change\nprintf fixture".into();
    let result = f.hook("claude", &p, &[]);
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert_eq!(
        before,
        std::fs::read(f.path("intent.reasons.jsonl")).unwrap()
    );
    let result = f.hook("claude", &p, &["--reason-output", &f.path("intent")]);
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
}
#[test]
fn externally_conflicting_reasons_are_diagnostics_not_guessed_attribution() {
    for corruption in ["conflict", "second", "identity", "cycle", "unbound"] {
        let f = Fixture::new();
        assert!(f
            .hook("claude", &payload("Bash", "command"), &[])
            .status
            .success());
        let mut reasons = f.read("intent.reasons.jsonl");
        let mut r = reasons[0].clone();
        match corruption {
            "conflict" => r["reason_code"] = "inspect_context".into(),
            "second" => r["reason_id"] = "independent".into(),
            "identity" => {
                r["source_event_id"] = "another_call".into();
                reasons.clear();
            }
            "cycle" => {
                r["supersedes_reason_id"] = "missing".into();
                reasons.clear();
            }
            "unbound" => {
                r["session_id"] = "another_capture".into();
                reasons.clear();
            }
            _ => unreachable!(),
        }
        reasons.push(r);
        std::fs::write(
            f.path("intent.reasons.jsonl"),
            reasons
                .iter()
                .map(|r| r.to_string() + "\n")
                .collect::<String>(),
        )
        .unwrap();
        let id = f.read("intent")[0]["intent_id"]
            .as_str()
            .unwrap()
            .to_string();
        let joined = f.correlate(&events(&id));
        assert!(
            joined
                .iter()
                .any(|r| r["record_type"] == "intent_reason_diagnostic"),
            "{corruption}"
        );
        assert!(!joined
            .iter()
            .any(|r| r["record_type"] == "intent_reason_binding"));
        assert_eq!(
            joined
                .iter()
                .filter(|r| r["record_type"] == "intent_correlation")
                .count(),
            3
        );
        assert!(joined.iter().all(|r| r.get("declared_reason").is_none()));
    }
}
