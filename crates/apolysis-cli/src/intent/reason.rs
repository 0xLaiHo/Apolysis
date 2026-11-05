// SPDX-License-Identifier: Apache-2.0

//! Explicit tool-call reasons. This module never reads prompts or transcripts.

use apolysis_core::{now_unix_ms, SessionIntentReasonRecord, SessionIntentRecord};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

const REASON_HEADER: &str = "# APOLYSIS_REASON_CODE=";
const INTENT_HEADER: &str = "# APOLYSIS_INTENT_ID=";
const MAX_SUMMARY_CHARS: usize = 240;
const REDACTED_SUMMARY: &str = "[redacted]";

/// Collect an explicitly supplied reason, without changing the call's identity.
///
/// Native descriptions are metadata, not inferred explanations. Free text is
/// omitted unless opted in; its conservative filter is not a secrecy guarantee.
pub fn collect(
    input: &Value,
    record: &SessionIntentRecord,
    allow_summary: bool,
) -> Result<Option<SessionIntentReasonRecord>, String> {
    let comment_code = shell_reason_code(input, record)?;
    let (code, source, summary, task_ref, supplied_id, supersedes) =
        if let Some(envelope) = input.get("apolysis_reason") {
            let envelope = envelope
                .as_object()
                .ok_or("apolysis_reason must be an object")?;
            validate_envelope_fields(envelope)?;
            let code = envelope
                .get("reason_code")
                .and_then(Value::as_str)
                .ok_or("reason_code must be a string")?;
            validate_code(code)?;
            if comment_code
                .as_deref()
                .is_some_and(|comment| comment != code)
            {
                return Err("reason envelope conflicts with shell reason code".to_string());
            }
            (
                code,
                "agent_declared",
                optional_text(envelope, "reason_summary")?,
                optional_identifier(envelope, "task_ref")?,
                optional_identifier(envelope, "reason_id")?,
                optional_identifier(envelope, "supersedes_reason_id")?,
            )
        } else if let Some(code) = comment_code.as_deref() {
            (code, "agent_declared", None, None, None, None)
        } else if let Some(description) = input
            .pointer("/tool_input/description")
            .and_then(Value::as_str)
            .filter(|description| !description.trim().is_empty())
        {
            (
                "unknown",
                "tool_description",
                Some(description),
                None,
                None,
                None,
            )
        } else {
            return Ok(None);
        };

    let harness_session_id = record
        .harness_session_id
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or("reason requires a native harness session")?;
    let source_event_id = record
        .source_event_id
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or("reason requires a native tool call id")?;
    let reason_id = supplied_id
        .map(ToString::to_string)
        .unwrap_or_else(|| default_reason_id(record, source));
    if supersedes == Some(reason_id.as_str()) {
        return Err("reason cannot supersede itself".to_string());
    }
    let reason = SessionIntentReasonRecord {
        timestamp_unix_ms: now_unix_ms(),
        session_id: record.session_id.clone(),
        intent_id: record.intent_id.clone(),
        intent_source: record.intent_source.clone(),
        harness_session_id: harness_session_id.to_string(),
        source_event_id: source_event_id.to_string(),
        reason_id,
        reason_code: code.to_string(),
        reason_source: source.to_string(),
        reason_summary: if allow_summary {
            summary.and_then(sanitize_summary)
        } else {
            None
        },
        task_ref: task_ref.map(ToString::to_string),
        supersedes_reason_id: supersedes.map(ToString::to_string),
    };
    reason.validate().map_err(ToString::to_string)?;
    Ok(Some(reason))
}

/// Remove only our complete, closed-code reason header for content-off command
/// metadata. The executable command returned to the harness keeps this comment.
pub fn command_body(command: &str) -> &str {
    let Some((code, body)) = command
        .strip_prefix(REASON_HEADER)
        .and_then(|rest| rest.split_once('\n'))
    else {
        return command;
    };
    if validate_code(code).is_ok() {
        body
    } else {
        command
    }
}

fn validate_code(code: &str) -> Result<(), String> {
    if matches!(
        code,
        "unknown"
            | "inspect_context"
            | "verify_change"
            | "reproduce_issue"
            | "implement_change"
            | "diagnose_failure"
            | "gather_evidence"
    ) {
        Ok(())
    } else {
        Err("unsupported reason_code".to_string())
    }
}

fn validate_envelope_fields(envelope: &Map<String, Value>) -> Result<(), String> {
    if envelope.keys().any(|field| {
        !matches!(
            field.as_str(),
            "reason_code" | "reason_summary" | "task_ref" | "reason_id" | "supersedes_reason_id"
        )
    }) {
        return Err("unsupported apolysis_reason field".to_string());
    }
    Ok(())
}

fn optional_text<'a>(
    envelope: &'a Map<String, Value>,
    field: &str,
) -> Result<Option<&'a str>, String> {
    match envelope.get(field) {
        None => Ok(None),
        Some(Value::String(value)) => Ok(Some(value)),
        Some(_) => Err("optional reason metadata must be a string".to_string()),
    }
}

fn optional_identifier<'a>(
    envelope: &'a Map<String, Value>,
    field: &str,
) -> Result<Option<&'a str>, String> {
    let value = optional_text(envelope, field)?;
    if value.is_some_and(|value| {
        value.is_empty()
            || value.len() > 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    }) {
        return Err("reason metadata requires a bounded opaque identifier".to_string());
    }
    Ok(value)
}

fn shell_reason_code(
    input: &Value,
    record: &SessionIntentRecord,
) -> Result<Option<String>, String> {
    if record.observation_mode.as_deref() != Some("local_shell") {
        return Ok(None);
    }
    let Some(field) = super::shell_command_field(
        &record.intent_source,
        &record.tool_name,
        input.get("tool_input"),
    ) else {
        return Ok(None);
    };
    let Some(command) = input
        .get("tool_input")
        .and_then(|value| value.get(field))
        .and_then(Value::as_str)
    else {
        return Ok(None);
    };
    let unwrapped = super::shell_bridge::unwrap(command, &record.intent_id)?;
    let mut command = unwrapped
        .as_ref()
        .map_or(command, |(decoded, _)| decoded.as_str());
    if let Some(rest) = command.strip_prefix(INTENT_HEADER) {
        let Some((id, body)) = rest.split_once('\n') else {
            return Ok(None);
        };
        if id.len() != 32
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Ok(None);
        }
        if id != record.intent_id {
            return Err("reason command has a conflicting intent marker".to_string());
        }
        command = body;
    }
    let Some(rest) = command.strip_prefix(REASON_HEADER) else {
        return Ok(None);
    };
    let Some((code, _)) = rest.split_once('\n') else {
        return Ok(None);
    };
    validate_code(code)?;
    Ok(Some(code.to_string()))
}

fn default_reason_id(record: &SessionIntentRecord, source: &str) -> String {
    let mut digest = Sha256::new();
    for value in [&record.session_id, &record.intent_id, source] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    digest.finalize()[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Keep only short, plain prose. Suspicious input is replaced as a whole so
/// removing a keyword cannot leave its adjacent value behind. Detection runs
/// before truncation, including on content past the retained character limit.
fn sanitize_summary(summary: &str) -> Option<String> {
    let normalized = summary.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty() {
        return None;
    }
    let lower = normalized.to_lowercase();
    let sensitive_word = [
        "secret",
        "password",
        "passwd",
        "credential",
        "token",
        "authorization",
        "bearer",
        "api_key",
        "apikey",
        "api key",
        "access key",
        "private-key",
        "passphrase",
        "private key",
        "cookie",
        "session key",
        "密钥",
        "密码",
        "令牌",
        "凭证",
        "口令",
    ]
    .iter()
    .any(|word| lower.contains(word));
    let non_prose = summary.chars().any(|ch| {
        (!ch.is_alphabetic()
            && !ch.is_whitespace()
            && !matches!(
                ch,
                '.' | ','
                    | ';'
                    | ':'
                    | '!'
                    | '?'
                    | '-'
                    | '，'
                    | '。'
                    | '；'
                    | '：'
                    | '！'
                    | '？'
                    | '、'
            ))
            || (ch.is_control() && !ch.is_whitespace())
    });
    let address_or_token = normalized.split_whitespace().any(|token| {
        let token = token.trim_end_matches(['.', ',', ';', ':', '!', '?']);
        token.contains('.')
            || (token.len() >= 24
                && token.is_ascii()
                && token
                    .chars()
                    .all(|ch| ch.is_ascii_alphabetic() || ch == '-'))
    });
    if sensitive_word || non_prose || address_or_token {
        return Some(REDACTED_SUMMARY.to_string());
    }
    Some(normalized.chars().take(MAX_SUMMARY_CHARS).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn intent() -> SessionIntentRecord {
        SessionIntentRecord::new(
            "capture",
            "claude",
            "0123456789abcdef0123456789abcdef",
            "tool_call",
            "Bash",
        )
        .with_harness_session_id("native")
        .with_source_event_id("call/1")
        .with_observation_mode("local_shell")
    }

    #[test]
    fn explicit_reason_is_bound_without_changing_intent_identity() {
        let record = intent();
        let input = json!({"apolysis_reason": {
            "reason_code": "verify_change", "reason_summary": "Run focused tests", "task_ref": "task-1",
        }});
        let reason = collect(&input, &record, false).unwrap().unwrap();
        assert_eq!(reason.intent_id, record.intent_id);
        assert_eq!(reason.session_id, "capture");
        assert_eq!(reason.harness_session_id, "native");
        assert_eq!(reason.source_event_id, "call/1");
        assert_eq!(reason.reason_source, "agent_declared");
        assert_eq!(reason.reason_code, "verify_change");
        assert_eq!(reason.task_ref.as_deref(), Some("task-1"));
        assert_eq!(reason.reason_summary, None);
        assert_eq!(reason.reason_id.len(), 32);
        assert!(reason
            .reason_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
        assert_eq!(
            collect(&input, &record, true)
                .unwrap()
                .unwrap()
                .reason_summary
                .as_deref(),
            Some("Run focused tests")
        );
    }

    #[test]
    fn reason_identity_does_not_depend_on_text_code_or_ingestion_time() {
        let record = intent();
        let first = collect(&json!({"apolysis_reason": {"reason_code":"verify_change", "reason_summary":"Run tests"}}), &record, true).unwrap().unwrap();
        let second = collect(&json!({"apolysis_reason": {"reason_code":"inspect_context", "reason_summary":"Inspect context"}}), &record, true).unwrap().unwrap();
        assert_eq!(first.reason_id, second.reason_id);
        let native = collect(
            &json!({"tool_input":{"description":"Run tests"}}),
            &record,
            true,
        )
        .unwrap()
        .unwrap();
        assert_ne!(first.reason_id, native.reason_id);
        let mut other = record.clone();
        other.session_id = "another-capture".to_string();
        assert_ne!(
            first.reason_id,
            collect(
                &json!({"apolysis_reason":{"reason_code":"verify_change"}}),
                &other,
                false
            )
            .unwrap()
            .unwrap()
            .reason_id
        );
    }

    #[test]
    fn only_complete_leading_supported_shell_reason_comments_are_collected() {
        let record = intent();
        for command in [
            "# APOLYSIS_REASON_CODE=reproduce_issue\nprintf safe".to_string(),
            format!(
                "# APOLYSIS_INTENT_ID={}\n# APOLYSIS_REASON_CODE=reproduce_issue\nprintf safe",
                record.intent_id
            ),
        ] {
            let reason = collect(&json!({"tool_input":{"command":command}}), &record, false)
                .unwrap()
                .unwrap();
            assert_eq!(reason.reason_code, "reproduce_issue");
            assert_eq!(reason.reason_source, "agent_declared");
        }
        for command in [
            "# APOLYSIS_REASON_CODE=verify_change",
            "printf safe\n# APOLYSIS_REASON_CODE=verify_change\n",
            " # APOLYSIS_REASON_CODE=verify_change\nprintf safe",
        ] {
            assert!(
                collect(&json!({"tool_input":{"command":command}}), &record, true)
                    .unwrap()
                    .is_none()
            );
        }
        let mut remote = record.clone().with_observation_mode("semantic_only");
        remote.tool_name = "MCP:execute".to_string();
        assert!(collect(
            &json!({"tool_input":{"command":"# APOLYSIS_REASON_CODE=verify_change\nprintf safe"}}),
            &remote,
            true
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn command_metadata_ignores_only_a_complete_known_reason_header() {
        assert_eq!(
            command_body("# APOLYSIS_REASON_CODE=verify_change\ncargo test"),
            "cargo test"
        );
        assert_eq!(command_body("# APOLYSIS_REASON_CODE=unknown\n"), "");
        for command in [
            "# APOLYSIS_REASON_CODE=verify_change",
            "# APOLYSIS_REASON_CODE=unsupported\ncargo test",
            " # APOLYSIS_REASON_CODE=verify_change\ncargo test",
            "# ordinary comment\ncargo test",
        ] {
            assert_eq!(command_body(command), command);
        }
    }

    #[test]
    fn optional_references_use_core_opaque_identifier_constraints() {
        let valid = "a".repeat(64);
        assert!(collect(
            &json!({"apolysis_reason": {
                "reason_code":"unknown", "reason_id":valid,
            }}),
            &intent(),
            false
        )
        .is_ok());
        for invalid in ["a".repeat(65), "ref.with.dot".into(), "ref:colon".into()] {
            assert!(collect(
                &json!({"apolysis_reason": {
                    "reason_code":"unknown", "reason_id":invalid,
                }}),
                &intent(),
                false
            )
            .is_err());
        }
        let mut record = intent();
        record.session_id = "   ".to_string();
        assert!(collect(
            &json!({"apolysis_reason":{"reason_code":"unknown"}}),
            &record,
            false
        )
        .is_err());
    }

    #[test]
    fn codex_cmd_field_is_used_instead_of_unrelated_command_field() {
        let mut record = intent();
        record.intent_source = "codex".to_string();
        record.tool_name = "exec_command".to_string();
        let reason = collect(
            &json!({"tool_input":{
                "cmd":"# APOLYSIS_REASON_CODE=gather_evidence\nprintf safe",
                "command":"# APOLYSIS_REASON_CODE=implement_change\nignored",
            }}),
            &record,
            false,
        )
        .unwrap()
        .unwrap();
        assert_eq!(reason.reason_code, "gather_evidence");
    }

    #[test]
    fn native_description_never_infers_a_reason_code_or_reads_other_content() {
        let input = json!({"tool_input":{"description":"Run tests", "prompt":"DO_NOT_RETAIN"},
            "prompt":"DO_NOT_RETAIN", "transcript_path":"/does/not/exist", "reasoning":"DO_NOT_RETAIN"});
        let reason = collect(&input, &intent(), false).unwrap().unwrap();
        assert_eq!(reason.reason_code, "unknown");
        assert_eq!(reason.reason_source, "tool_description");
        assert_eq!(reason.reason_summary, None);
        assert!(collect(
            &json!({"prompt":"DO_NOT_RETAIN","tool_input":{"command":"cargo test"}}),
            &intent(),
            true
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn explicit_revisions_validate_without_echoing_values() {
        let reason = collect(&json!({"apolysis_reason": {
            "reason_code":"diagnose_failure", "reason_id":"revision-2", "supersedes_reason_id":"revision-1",
        }}), &intent(), false).unwrap().unwrap();
        assert_eq!(reason.reason_id, "revision-2");
        assert_eq!(reason.supersedes_reason_id.as_deref(), Some("revision-1"));
        for envelope in [
            json!(null),
            json!({"reason_code":123}),
            json!({"reason_code":"DO_NOT_ECHO"}),
            json!({"reason_code":"unknown","DO_NOT_ECHO":"secret"}),
            json!({"reason_code":"unknown","reason_source":"operator_annotation"}),
            json!({"reason_code":"unknown","reason_summary":false}),
            json!({"reason_code":"unknown","task_ref":"https://DO_NOT_ECHO"}),
            json!({"reason_code":"unknown","reason_id":""}),
            json!({"reason_code":"unknown","reason_id":"same","supersedes_reason_id":"same"}),
        ] {
            let error = collect(&json!({"apolysis_reason":envelope}), &intent(), true).unwrap_err();
            assert!(!error.contains("DO_NOT_ECHO"));
            assert!(!error.contains("secret"));
        }
    }

    #[test]
    fn conflicting_headers_and_envelopes_do_not_silently_win_by_priority() {
        let record = intent();
        for input in [
            json!({"tool_input":{"command":"# APOLYSIS_REASON_CODE=DO_NOT_ECHO\nprintf safe"}}),
            json!({"tool_input":{"command":"# APOLYSIS_INTENT_ID=ffffffffffffffffffffffffffffffff\n# APOLYSIS_REASON_CODE=verify_change\nprintf safe"}}),
            json!({"tool_input":{"command":"# APOLYSIS_REASON_CODE=verify_change\nprintf safe"},
                "apolysis_reason":{"reason_code":"implement_change"}}),
        ] {
            let error = collect(&input, &record, true).unwrap_err();
            assert!(!error.contains("DO_NOT_ECHO"));
            assert!(!error.contains("printf"));
        }
    }

    #[test]
    fn summaries_are_opt_in_single_line_bounded_and_conservatively_redacted() {
        for value in [
            "password is DO_NOT_RETAIN",
            "api key abcdef",
            "private-key abcdef",
            "口令是秘密",
            "token DO_NOT_RETAIN",
            "open https://private.example",
            "read /home/private/file",
            "read C:\\private\\file",
            "email user@example.test",
            "use 'DO_NOT_RETAIN'",
            "use \"DO_NOT_RETAIN\"",
            "run `DO_NOT_RETAIN`",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZZ",
            "abcd-efgh-ijkl-mnop-qrst-uvwx",
            "key=DO_NOT_RETAIN",
            "密码是秘密",
            "review \u{202e}text",
        ] {
            assert_eq!(sanitize_summary(value).as_deref(), Some(REDACTED_SUMMARY));
        }
        assert_eq!(
            sanitize_summary(" Run\n\t focused   tests ").as_deref(),
            Some("Run focused tests")
        );
        let long = "检查修改结果".repeat(60);
        let summary = sanitize_summary(&long).unwrap();
        assert_eq!(summary.chars().count(), 240);
        assert!(!summary.contains('\n'));
        assert_eq!(
            sanitize_summary(&(long + " token DO_NOT_RETAIN")).as_deref(),
            Some(REDACTED_SUMMARY)
        );
        assert_eq!(sanitize_summary(" \n\t "), None);
    }

    #[test]
    fn a_reason_requires_an_existing_exact_native_call_binding() {
        let mut record = intent();
        record.source_event_id = None;
        let input = json!({"apolysis_reason":{"reason_code":"unknown"}});
        assert!(collect(&input, &record, false).is_err());
        record.source_event_id = Some("call".to_string());
        record.harness_session_id = None;
        assert!(collect(&input, &record, false).is_err());
        assert!(collect(&json!({}), &record, false).unwrap().is_none());
    }
}
