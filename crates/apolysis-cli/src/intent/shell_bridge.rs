// SPDX-License-Identifier: Apache-2.0

//! Explicit subshell boundary for harnesses that evaluate commands in-process.
//! This is never enabled implicitly: shell state cannot flow back to the caller.

use std::os::unix::fs::PermissionsExt;

const SHELLS: [&str; 8] = [
    "/bin/bash",
    "/bin/zsh",
    "/bin/dash",
    "/bin/sh",
    "/usr/bin/bash",
    "/usr/bin/zsh",
    "/usr/bin/dash",
    "/usr/bin/sh",
];

pub(super) fn validate(shell: &str) -> Result<(), String> {
    if !SHELLS.contains(&shell) {
        return Err("shell bridge requires a supported absolute shell path".to_string());
    }
    let metadata = std::fs::metadata(shell)
        .map_err(|_| "shell bridge executable is unavailable".to_string())?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err("shell bridge executable is unavailable".to_string());
    }
    Ok(())
}

fn quote(command: &str) -> String {
    format!("'{}'", command.replace('\'', "'\\''"))
}

pub(super) fn wrap(shell: &str, command: &str) -> String {
    format!("{shell} -c {}", quote(command))
}

/// Recognize only our complete canonical wrapper, never evaluate shell text.
/// The returned command still includes the validated leading intent header.
pub(super) fn unwrap(
    command: &str,
    expected_id: &str,
) -> Result<Option<(String, &'static str)>, String> {
    let Some((decoded, shell)) = decode(command)? else {
        return Ok(None);
    };
    if super::leading_stamp(&decoded)?.is_some_and(|(id, _)| id != expected_id) {
        return Err("shell bridge marker belongs to a different tool call or session".to_string());
    }
    Ok(Some((decoded, shell)))
}

pub(super) fn has_complete_marker(command: &str) -> bool {
    decode(command).is_ok_and(|decoded| decoded.is_some())
}

fn decode(command: &str) -> Result<Option<(String, &'static str)>, String> {
    for shell in SHELLS {
        let Some(quoted) = command.strip_prefix(&format!("{shell} -c ")) else {
            continue;
        };
        let Some(encoded) = quoted.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')) else {
            return Ok(None);
        };
        let decoded = encoded.replace("'\\''", "'");
        if quote(&decoded) != quoted {
            return Ok(None);
        }
        let Some(_) = super::leading_stamp(&decoded)? else {
            return Ok(None);
        };
        return Ok(Some((decoded, shell)));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    const ID: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn canonical_wrapper_round_trips_arbitrary_shell_text() {
        for body in [
            "",
            "printf '%s\\n' \"a'b\"",
            "for x in a b; do printf '%s' \"$x\"; done",
            "cat <<'EOF'\na'b\nEOF\n",
            "printf '\\n'\nexit 7",
        ] {
            let stamped = format!("# APOLYSIS_INTENT_ID={ID}\n{body}");
            let wrapped = wrap("/bin/bash", &stamped);
            assert_eq!(unwrap(&wrapped, ID).unwrap(), Some((stamped, "/bin/bash")));
        }
    }

    #[test]
    fn eval_wrapper_preserves_output_exit_and_original_inner_argv() {
        for body in [
            "for x in a b; do printf '%s\\n' \"$x\"; done",
            "printf '%s\\n' \"a'b\"; printf error >&2; exit 7",
            "cat <<'EOF'\na'b\nEOF\n",
        ] {
            let expected = Command::new("/bin/bash")
                .args(["-c", body])
                .output()
                .unwrap();
            let stamped = format!("# APOLYSIS_INTENT_ID={ID}\n{body}");
            let outer = format!(
                "export APOLYSIS_BRIDGE_TEST=1; eval {}",
                quote(&wrap("/bin/bash", &stamped))
            );
            let actual = Command::new("/bin/bash")
                .args(["-c", &outer])
                .output()
                .unwrap();
            assert_eq!(actual.status.code(), expected.status.code());
            assert_eq!(actual.stdout, expected.stdout);
            assert_eq!(actual.stderr, expected.stderr);
        }
        // /proc exposes the actual exec argv, independent of a diagnostic log.
        let body = "cat /proc/$$/cmdline; :";
        let stamped = format!("# APOLYSIS_INTENT_ID={ID}\n{body}");
        let outer = format!(
            "export APOLYSIS_BRIDGE_TEST=1; eval {}",
            quote(&wrap("/bin/bash", &stamped))
        );
        let output = Command::new("/bin/bash")
            .args(["-c", &outer])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(output
            .stdout
            .split(|b| *b == 0)
            .any(|arg| arg == stamped.as_bytes()));
    }

    #[test]
    fn arbitrary_shell_commands_are_not_unwrapped() {
        assert_eq!(unwrap("/bin/bash -c 'printf ok'", ID).unwrap(), None);
        assert!(unwrap(
            &wrap(
                "/bin/bash",
                "# APOLYSIS_INTENT_ID=ffffffffffffffffffffffffffffffff\ntrue"
            ),
            ID
        )
        .is_err());
        assert!(validate("/private/DO_NOT_LOG")
            .unwrap_err()
            .find("DO_NOT_LOG")
            .is_none());
    }

    #[test]
    fn hook_retry_preserves_declaration_reason_and_product_permission_flow() {
        use serde_json::json;
        for (harness, tool, field, pointer) in [
            (
                "claude",
                "Bash",
                "command",
                "/hookSpecificOutput/updatedInput/command",
            ),
            (
                "codex",
                "exec_command",
                "cmd",
                "/hookSpecificOutput/updatedInput/cmd",
            ),
            ("cursor", "Shell", "command", "/updated_input/command"),
            ("pi", "bash", "command", "/command"),
            ("opencode", "bash", "command", "/command"),
        ] {
            let mut input = json!({"session_id":"native","tool_use_id":"call","tool_name":tool,"hook_event_name":"preToolUse","tool_input":{"description":"Run tests","timeout":7}});
            input["tool_input"][field] =
                "# APOLYSIS_REASON_CODE=verify_change\nprintf '%s\\n' \"a'b\"".into();
            let run = |input: &serde_json::Value| {
                super::super::hook_with_shell_bridge(
                    harness,
                    input,
                    std::path::Path::new("/tmp"),
                    Some("capture"),
                    Some("/bin/bash"),
                )
                .unwrap()
            };
            let first = run(&input);
            let original_reason =
                super::super::reason::collect(&input, first.record.as_ref().unwrap(), false)
                    .unwrap()
                    .unwrap();
            input["tool_input"][field] = first.response.pointer(pointer).unwrap().clone();
            let retry = run(&input);
            let retry_reason =
                super::super::reason::collect(&input, retry.record.as_ref().unwrap(), false)
                    .unwrap()
                    .unwrap();
            assert_eq!(first.response, retry.response);
            assert_eq!(
                first.record.as_ref().unwrap().intent_id,
                retry.record.as_ref().unwrap().intent_id
            );
            assert_eq!(
                first.record.as_ref().unwrap().command,
                retry.record.as_ref().unwrap().command
            );
            assert_eq!(original_reason.reason_id, retry_reason.reason_id);
            assert_eq!(retry_reason.reason_code, "verify_change");
            assert_eq!(retry_reason.reason_source, "agent_declared");
            if harness == "claude" {
                assert!(retry
                    .response
                    .pointer("/hookSpecificOutput/permissionDecision")
                    .is_none());
                assert_eq!(
                    retry
                        .response
                        .pointer("/hookSpecificOutput/updatedInput/timeout"),
                    Some(&json!(7))
                );
            }
            if harness == "codex" {
                assert_eq!(
                    retry
                        .response
                        .pointer("/hookSpecificOutput/permissionDecision"),
                    Some(&json!("allow"))
                );
            }
            input["tool_use_id"] = "other-private-call".into();
            let error = super::super::hook_with_shell_bridge(
                harness,
                &input,
                std::path::Path::new("/tmp"),
                Some("capture"),
                Some("/bin/bash"),
            )
            .unwrap_err();
            assert!(!error.contains("other-private-call"));
        }
    }

    #[test]
    fn bridge_is_explicit_and_rejects_different_tool_shells() {
        use serde_json::json;
        let mut input = json!({"session_id":"native","tool_use_id":"call","tool_name":"Bash","tool_input":{"command":"printf ok"}});
        let default =
            super::super::hook("claude", &input, std::path::Path::new("/tmp"), None).unwrap();
        assert!(default
            .response
            .pointer("/hookSpecificOutput/updatedInput/command")
            .unwrap()
            .as_str()
            .unwrap()
            .starts_with("# APOLYSIS_INTENT_ID="));
        input["tool_input"]["shell"] = "/bin/zsh".into();
        assert!(super::super::hook_with_shell_bridge(
            "claude",
            &input,
            std::path::Path::new("/tmp"),
            None,
            Some("/bin/bash")
        )
        .is_err());
        input["tool_name"] = "Read".into();
        let non_shell = super::super::hook_with_shell_bridge(
            "claude",
            &input,
            std::path::Path::new("/tmp"),
            None,
            Some("/bin/bash"),
        )
        .unwrap();
        assert!(non_shell
            .response
            .pointer("/hookSpecificOutput/updatedInput")
            .is_none());
    }

    #[test]
    fn reason_headers_cannot_hide_nested_attribution() {
        use serde_json::json;
        let marker = format!("# APOLYSIS_INTENT_ID={ID}\nprintf private_body");
        for body in [marker.clone(), wrap("/bin/bash", &marker)] {
            for prefix in [
                "# APOLYSIS_REASON_CODE=verify_change\n",
                "# APOLYSIS_REASON_CODE=verify_change\n# APOLYSIS_REASON_CODE=inspect_context\n",
            ] {
                let input = json!({"session_id":"native","tool_use_id":"new_call","tool_name":"Bash","tool_input":{"command":format!("{prefix}{body}")}});
                let error = super::super::hook_with_shell_bridge(
                    "claude",
                    &input,
                    std::path::Path::new("/tmp"),
                    None,
                    Some("/bin/bash"),
                )
                .unwrap_err();
                assert!(!error.contains("private_body"));
            }
        }
    }
}
