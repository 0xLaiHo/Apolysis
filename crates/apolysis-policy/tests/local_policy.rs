// SPDX-License-Identifier: Apache-2.0

use apolysis_policy::{Policy, PolicyDecision};

#[test]
fn local_policy_parses_credential_deny_and_runtime_limits() {
    let policy = Policy::parse(
        r#"
version: 1
credentials:
  deny_read:
    - ~/.ssh
    - .env
runtime:
  max_seconds: 60
  max_processes: 128
"#,
    )
    .expect("parse policy");

    assert!(policy.denies_credential_path("/home/dev/.ssh/id_rsa"));
    assert!(policy.denies_credential_path("/work/repo/.env"));
    assert_eq!(policy.runtime.max_seconds, Some(60));
    assert_eq!(policy.runtime.max_processes, Some(128));
}

#[test]
fn audit_only_policy_notifies_for_denied_credentials() {
    let policy = Policy::parse(
        r#"
version: 1
credentials:
  deny_read:
    - ~/.aws
"#,
    )
    .expect("parse policy");

    let decision = policy.evaluate_file_read("/home/dev/.aws/credentials");

    assert_eq!(
        decision,
        PolicyDecision::Notify {
            rule_id: "credentials.deny_read".to_string(),
            reason: "file path matches credential deny list".to_string()
        }
    );
}
