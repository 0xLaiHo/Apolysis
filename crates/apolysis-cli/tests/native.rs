// SPDX-License-Identifier: Apache-2.0

#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

fn native_fixture(directory: &Path, name: &str) {
    let executable = directory.join(name);
    fs::write(&executable, b"#!/bin/sh\nprintf 'native:%s\\n' \"$@\"\n").unwrap();
    fs::set_permissions(executable, fs::Permissions::from_mode(0o755)).unwrap();
}

fn invoke(directory: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_apolysis"))
        .args(args)
        .env_clear()
        .env("PATH", directory)
        .env("HOME", directory)
        .current_dir(directory)
        .output()
        .unwrap()
}

#[test]
fn native_help_and_version_are_forwarded_to_each_selected_application_without_capture() {
    for (product, executable) in [
        ("claude", "claude"),
        ("codex", "codex"),
        ("pi", "pi"),
        ("cursor", "cursor-agent"),
        ("opencode", "opencode"),
    ] {
        let root = tempfile::tempdir().unwrap();
        native_fixture(root.path(), executable);
        for option in ["--help", "--version"] {
            let output = invoke(root.path(), &["observe", "--agent", product, "--", option]);
            assert!(
                output.status.success(),
                "{product}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(output.stdout, format!("native:{option}\n").as_bytes());
            assert!(
                output.stderr.is_empty(),
                "{product}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
    }
}

#[test]
fn informational_invocations_ignore_capture_paths_without_creating_artifacts() {
    let root = tempfile::tempdir().unwrap();
    native_fixture(root.path(), "claude");
    let output = invoke(
        root.path(),
        &[
            "observe",
            "--agent",
            "claude",
            "--output-dir",
            "never-created",
            "--bpf-object",
            "/missing-native-test.bpf.o",
            "--",
            "--help",
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"native:--help\n");
    assert!(!root.path().join("never-created").exists());
}

#[test]
fn native_options_require_the_separator_instead_of_becoming_apolysis_options() {
    let root = tempfile::tempdir().unwrap();
    native_fixture(root.path(), "claude");
    let output = invoke(
        root.path(),
        &["observe", "--agent", "claude", "--model", "native-model"],
    );
    assert!(!output.status.success());
    assert!(!output.stdout.starts_with(b"native:"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--"));
}

#[test]
fn an_agent_is_required_and_an_unknown_agent_never_falls_back_to_claude() {
    let root = tempfile::tempdir().unwrap();
    native_fixture(root.path(), "claude");
    for args in [
        vec!["observe", "--agent"],
        vec!["observe", "--agent", "unsupported", "--", "--help"],
    ] {
        let output = invoke(root.path(), &args);
        assert!(!output.status.success());
        assert!(!output.stdout.starts_with(b"native:"));
    }
}

#[test]
fn missing_bpf_prevents_native_execution_instead_of_claiming_a_capture() {
    let root = tempfile::tempdir().unwrap();
    native_fixture(root.path(), "claude");
    let output = invoke(
        root.path(),
        &[
            "observe",
            "--agent",
            "claude",
            "--bpf-object",
            "/missing-native-test.bpf.o",
            "--",
            "--model",
            "--help",
        ],
    );
    assert!(!output.status.success());
    assert!(!output.stdout.starts_with(b"native:"));
    assert!(String::from_utf8_lossy(&output.stderr)
        .to_lowercase()
        .contains("bpf"));
}
