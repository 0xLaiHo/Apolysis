// SPDX-License-Identifier: Apache-2.0

use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn bounded_kernel_header_parser_and_capture_loss_transition() {
    match Command::new("clang").arg("--version").output() {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("SKIP: native eBPF header regression requires clang");
            return;
        }
        result => assert!(result.expect("check clang").status.success()),
    }
    let output = std::env::temp_dir().join(format!(
        "apolysis-intent-header-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    let include = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ebpf/include");
    let mut compiler = Command::new("clang")
        .args(["-O2", "-std=c11", "-Werror", "-x", "c", "-"])
        .arg("-I")
        .arg(include)
        .arg("-o")
        .arg(&output)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("compile actual shared kernel header parser");
    compiler.stdin.take().expect("compiler input").write_all(br##"
#include <assert.h>
#include <string.h>
#include "apolysis_intent.h"
int main(void) {
    const char *shells[] = {"sh", "bash", "zsh", "dash", "ash", "ksh", "fish", "/bin/sh", "/usr/bin/bash", "/long/path/zsh"};
    for (unsigned int i = 0; i < sizeof(shells) / sizeof(shells[0]); i++)
        assert(apolysis_executable_is_shell(shells[i], strlen(shells[i])));
    const char *other[] = {"", "h", "/", "/bash/", "notbash", "/bin/notsh", "/bin/python3", "/bin/BASH", "ssh", "sash"};
    for (unsigned int i = 0; i < sizeof(other) / sizeof(other[0]); i++)
        assert(!apolysis_executable_is_shell(other[i], strlen(other[i])));
    char long_path[APOLYSIS_RESOURCE_LEN] = {0};
    memset(long_path, 'x', sizeof(long_path) - 1);
    memcpy(long_path + sizeof(long_path) - 6, "/bash", 5);
    assert(apolysis_executable_is_shell(long_path, sizeof(long_path) - 1));
    assert(!apolysis_executable_is_shell(long_path, sizeof(long_path)));
    const char valid[] = "# APOLYSIS_INTENT_ID=0123456789abcdef0123456789abcdef\n";
    char id[APOLYSIS_INTENT_ID_LEN] = {0};
    assert(sizeof(valid) - 1 == 54);
    /* All truncations of the real header must fail, including the old 31-byte limit. */
    for (unsigned int len = 0; len < 54; len++)
        assert(apolysis_parse_intent_header(valid, len, id) == APOLYSIS_INTENT_UNKNOWN);
    assert(apolysis_parse_intent_header(valid, 54, id) == APOLYSIS_INTENT_PRESENT);
    assert(!memcmp(id, "0123456789abcdef0123456789abcdef", 32));
    assert(apolysis_parse_intent_header("echo # APOLYSIS_INTENT_ID=0123456789abcdef0123456789abcdef\n", 54, id) == APOLYSIS_INTENT_ABSENT);
    char invalid[sizeof(valid)];
    memcpy(invalid, valid, sizeof(valid));
    invalid[21] = 'A';
    assert(apolysis_parse_intent_header(invalid, 54, id) == APOLYSIS_INTENT_UNKNOWN);
    memcpy(invalid, valid, sizeof(valid));
    invalid[53] = '0'; /* too-long ID: no exact newline terminator */
    assert(apolysis_parse_intent_header(invalid, 54, id) == APOLYSIS_INTENT_UNKNOWN);
    memcpy(invalid, valid, sizeof(valid));
    invalid[42] = '\0';
    assert(apolysis_parse_intent_header(invalid, 54, id) == APOLYSIS_INTENT_UNKNOWN);
    /* Missing/uncertain enter capture must clear a previous successful tool token. */
    assert(apolysis_intent_update_for_capture(0, 0, 0) == APOLYSIS_INTENT_CLEAR);
    assert(apolysis_intent_update_for_capture(1, 0, 0) == APOLYSIS_INTENT_CLEAR);
    assert(apolysis_intent_update_for_capture(1, 0, 1) == APOLYSIS_INTENT_CLEAR);
    assert(apolysis_intent_update_for_capture(1, 1, 0) == APOLYSIS_INTENT_KEEP);
    assert(apolysis_intent_update_for_capture(1, 1, 1) == APOLYSIS_INTENT_REPLACE);
    return 0;
}
"##).expect("write native regression");
    let compiled = compiler.wait_with_output().expect("wait for clang");
    assert!(
        compiled.status.success(),
        "native regression compilation: {}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&output)
        .output()
        .expect("run native regression");
    std::fs::remove_file(output).expect("remove native regression executable");
    assert!(
        result.status.success(),
        "native header/capture regression: {}",
        String::from_utf8_lossy(&result.stderr)
    );
}
