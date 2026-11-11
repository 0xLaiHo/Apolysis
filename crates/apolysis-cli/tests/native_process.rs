// SPDX-License-Identifier: Apache-2.0

//! Exercise the actual native launch executable with an independent pipe peer.
//! These tests need neither a provider nor privileges/BPF and never substitute a
//! fake successful observer. They verify the boundary before capture readiness.

#![cfg(target_os = "linux")]

use std::fs::{self, File};
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

const SECRET: &str = "NATIVE_ARGUMENT_CANARY_NEVER_ECHO_7a91";

struct GateProcess {
    child: Option<Child>,
    gate: Option<File>,
}

impl GateProcess {
    fn spawn() -> Self {
        let mut fds = [0; 2];
        // SAFETY: pipe2 initializes exactly two descriptor slots.
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        // SAFETY: successful pipe2 transfers ownership of distinct descriptors.
        let read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let write = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        let read_fd = read.as_raw_fd();
        let mut command = Command::new(env!("CARGO_BIN_EXE_apolysis"));
        command
            .arg("_native-exec")
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // SAFETY: the closure performs only async-signal-safe fd/process calls.
        unsafe {
            command.pre_exec(move || {
                if libc::setpgid(0, 0) != 0
                    || libc::dup2(read_fd, 3) < 0
                    || libc::fcntl(3, libc::F_SETFD, 0) < 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn().expect("spawn actual native gate binary");
        drop(read);
        Self {
            child: Some(child),
            gate: Some(File::from(write)),
        }
    }

    fn write(&mut self, bytes: &[u8]) {
        self.gate.as_mut().unwrap().write_all(bytes).unwrap();
    }

    fn launch(&mut self, description: &Value) {
        let data = serde_json::to_vec(description).unwrap();
        self.write(&(data.len() as u32).to_be_bytes());
        self.write(&data);
    }

    fn release(&mut self) {
        self.write(&[1]);
        self.gate.take();
    }

    fn stdin(&mut self, bytes: &[u8]) {
        let mut input = self.child.as_mut().unwrap().stdin.take().unwrap();
        input.write_all(bytes).unwrap();
    }

    fn finish(mut self) -> Output {
        self.gate.take();
        self.child.as_mut().unwrap().stdin.take();
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.child.as_mut().unwrap().try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline, "native gate did not terminate");
            std::thread::sleep(Duration::from_millis(5));
        }
        self.child.take().unwrap().wait_with_output().unwrap()
    }
}

impl Drop for GateProcess {
    fn drop(&mut self) {
        self.gate.take();
        if let Some(child) = self.child.as_mut() {
            // Keep cleanup restricted to an unreaped child and its own group.
            // Reaped PIDs must never be used to signal potentially reused IDs.
            if child.try_wait().ok().flatten().is_none() {
                // SAFETY: our pre_exec created this child's exclusive group.
                unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
                for _ in 0..100 {
                    if child.try_wait().ok().flatten().is_some() {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        }
    }
}

fn marker_launch(marker: &std::path::Path) -> Value {
    json!({
        "executable": "/bin/sh",
        "args": ["-c", "printf ran > \"$1\"; printf launched", "native-gate-test", marker],
    })
}

fn assert_private_failure(output: &Output) {
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains(SECRET));
    assert!(
        !output.stderr.is_empty(),
        "failure should have a bounded diagnostic"
    );
    assert!(
        output.stderr.len() < 512,
        "diagnostic must not contain the frame"
    );
}

#[test]
fn actual_application_cannot_start_before_capture_releases_gate() {
    let directory = tempfile::tempdir().unwrap();
    let marker = directory.path().join("launched");
    let mut process = GateProcess::spawn();
    process.launch(&marker_launch(&marker));
    std::thread::sleep(Duration::from_millis(200));
    assert!(!marker.exists(), "application ran before capture readiness");
    assert!(process
        .child
        .as_mut()
        .unwrap()
        .try_wait()
        .unwrap()
        .is_none());
    process.release();
    let output = process.finish();
    assert!(output.status.success());
    assert_eq!(fs::read(marker).unwrap(), b"ran");
    assert_eq!(output.stdout, b"launched");
    assert!(output.stderr.is_empty());
}

#[test]
fn abandoned_or_rejected_gate_never_executes_application() {
    for release in [None, Some(0), Some(2)] {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("launched");
        let mut process = GateProcess::spawn();
        process.launch(&marker_launch(&marker));
        if let Some(byte) = release {
            process.write(&[byte]);
        }
        let output = process.finish();
        assert_private_failure(&output);
        assert!(!marker.exists());
    }
}

#[test]
fn invalid_truncated_or_oversized_frames_fail_without_echoing_content() {
    let cases = [
        Vec::new(),
        vec![0, 0],
        0_u32.to_be_bytes().to_vec(),
        (1024_u32 * 1024 + 1).to_be_bytes().to_vec(),
        {
            let bytes = format!("{{invalid json {SECRET}").into_bytes();
            let mut data = (bytes.len() as u32).to_be_bytes().to_vec();
            data.extend(bytes);
            data
        },
        {
            let bytes = SECRET.as_bytes();
            let mut data = (bytes.len() as u32 + 10).to_be_bytes().to_vec();
            data.extend(bytes);
            data
        },
    ];
    for frame in cases {
        let mut process = GateProcess::spawn();
        process.write(&frame);
        assert_private_failure(&process.finish());
    }
    let mut process = GateProcess::spawn();
    process.launch(&json!({"executable":"/bin/true", "args":[], "extra":SECRET}));
    assert_private_failure(&process.finish());
}

#[test]
fn native_arguments_and_stdio_keep_their_exact_byte_boundaries() {
    let arguments = [
        "two words",
        "'single' and \"double\"",
        "--agent",
        "--model=literal",
        "--",
        "$(must_not_execute)",
        "`must_not_execute`",
        "first\nsecond",
        "中文",
        "",
    ];
    let mut args = vec![
        "-c".to_string(),
        "printf '%s\\0' \"$@\"; /bin/cat".to_string(),
        "native-argv-test".to_string(),
    ];
    args.extend(arguments.iter().map(|value| (*value).to_string()));
    let input = b"unmodified stdin\0with binary\n--agent not-an-option\n";
    let mut expected = arguments
        .iter()
        .flat_map(|argument| argument.as_bytes().iter().copied().chain([0]))
        .collect::<Vec<_>>();
    expected.extend(input);
    let mut process = GateProcess::spawn();
    // Input is written before launch. Control traffic must not consume it.
    process.stdin(input);
    process.launch(&json!({"executable":"/bin/sh", "args":args}));
    process.release();
    let output = process.finish();
    assert!(output.status.success());
    assert_eq!(output.stdout, expected);
    assert!(output.stderr.is_empty());
}

#[test]
fn native_nonzero_exit_and_signal_are_not_replaced_by_launcher_success() {
    for (script, expected_code, expected_signal) in [
        ("exit 23", Some(23), None),
        ("kill -TERM $$", None, Some(libc::SIGTERM)),
    ] {
        let mut process = GateProcess::spawn();
        process.launch(&json!({"executable":"/bin/sh", "args":["-c",script]}));
        process.release();
        let output = process.finish();
        assert_eq!(output.status.code(), expected_code);
        assert_eq!(output.status.signal(), expected_signal);
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn failed_native_exec_does_not_expose_argument_or_executable_content() {
    let mut process = GateProcess::spawn();
    process.launch(&json!({
        "executable": format!("/nonexistent-apolysis-native-test/{SECRET}"),
        "args": [SECRET, "--model", SECRET],
    }));
    process.release();
    assert_private_failure(&process.finish());
}

#[test]
fn direct_internal_invocation_without_a_gate_fails_without_aborting_runtime() {
    let output = Command::new(env!("CARGO_BIN_EXE_apolysis"))
        .arg("_native-exec")
        .env_clear()
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.status.signal(), None);
    assert_private_failure(&output);
}

#[test]
fn inherited_regular_file_is_not_accepted_or_read_as_a_launch_pipe() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("private-input");
    fs::write(&path, SECRET).unwrap();
    let input = File::open(&path).unwrap();
    let input_fd = input.as_raw_fd();
    let mut command = Command::new(env!("CARGO_BIN_EXE_apolysis"));
    command.arg("_native-exec").env_clear().stdin(Stdio::null());
    // SAFETY: the inherited test descriptor remains open through spawn; only
    // async-signal-safe duplication and descriptor flag operations are used.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(input_fd, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let output = command.output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_private_failure(&output);
    // Duplicated file descriptors share their offset. Rejection must precede
    // any attempted frame read from this unrelated application descriptor.
    use std::io::Seek;
    assert_eq!(input.try_clone().unwrap().stream_position().unwrap(), 0);
}

#[test]
fn informational_native_launch_updates_pwd_to_the_canonical_launch_directory() {
    let directory = tempfile::tempdir().unwrap();
    let caller = directory.path().join("caller");
    let workspace = directory.path().join("launch workspace");
    let linked_workspace = directory.path().join("workspace-link");
    let executables = directory.path().join("bin");
    for path in [&caller, &workspace, &executables] {
        fs::create_dir(path).unwrap();
    }
    std::os::unix::fs::symlink(&workspace, &linked_workspace).unwrap();
    let claude = executables.join("claude");
    fs::write(
        &claude,
        // Shells may repair PWD themselves. Read the original exec environment
        // from procfs, not the shell's repaired variable, so the regression
        // cannot pass merely because the probe happened to be a shell script.
        "#!/bin/sh\n/bin/pwd -P\n/bin/cat /proc/$$/environ\n",
    )
    .unwrap();
    fs::set_permissions(&claude, fs::Permissions::from_mode(0o700)).unwrap();
    let original_pwd = std::env::var_os("PWD");
    let output = Command::new(env!("CARGO_BIN_EXE_apolysis"))
        .args(["observe", "--agent", "claude", "--workspace"])
        .arg(&linked_workspace)
        .args(["--", "--help"])
        .current_dir(&caller)
        .env_clear()
        .env("PATH", &executables)
        .env("PWD", &caller)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let canonical = workspace.canonicalize().unwrap();
    let newline = output
        .stdout
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap();
    assert_eq!(
        &output.stdout[..newline],
        canonical.as_os_str().as_encoded_bytes()
    );
    let environment = &output.stdout[newline + 1..];
    let expected = format!("PWD={}", canonical.display());
    assert!(environment
        .split(|byte| *byte == 0)
        .any(|entry| entry == expected.as_bytes()));
    assert_eq!(std::env::var_os("PWD"), original_pwd);
}
