// SPDX-License-Identifier: Apache-2.0

use apolysis_contracts::{
    AuthorityKind, AuthorityRef, ContractError, EnvironmentKind, PrincipalKind, PrincipalRef,
    RunDescriptor, RunPolicySelection, RunState, SchemaVersion, SourceKind,
};

#[test]
fn run_lifecycle_accepts_only_forward_contract_transitions() {
    let authority = AuthorityRef::new(AuthorityKind::Service, "authority_ci")
        .expect("valid authority reference");
    let principal = PrincipalRef::new(PrincipalKind::Workload, "principal_runner")
        .expect("valid principal reference");
    let mut run = RunDescriptor::new(
        "org_acme",
        "run_01",
        authority,
        principal,
        "objective_sha256_012345",
        EnvironmentKind::CiRunnerOrRemoteWorkspace,
        RunPolicySelection::new(
            "privacy_content_off_v1",
            "retention_30d_v1",
            vec![SourceKind::SemanticHook],
        )
        .expect("valid run policy selection"),
    )
    .expect("valid run descriptor");

    assert_eq!(run.schema_version(), SchemaVersion::V0_1);
    assert_eq!(run.state(), RunState::Opening);
    assert_eq!(run.policy().privacy_profile_ref(), "privacy_content_off_v1");
    assert_eq!(run.policy().retention_profile_ref(), "retention_30d_v1");
    assert_eq!(
        run.policy().expected_source_kinds(),
        &[SourceKind::SemanticHook]
    );
    run.transition_to(RunState::Active)
        .expect("opening to active");
    run.transition_to(RunState::Finishing)
        .expect("active to finishing");
    run.transition_to(RunState::Finished)
        .expect("finishing to finished");

    let error = run
        .transition_to(RunState::Active)
        .expect_err("terminal run cannot reopen");
    assert!(matches!(error, ContractError::InvalidTransition { .. }));
}

#[test]
fn incomplete_is_terminal_from_every_nonterminal_state() {
    for state in [RunState::Opening, RunState::Active, RunState::Finishing] {
        assert!(state.can_transition_to(RunState::Incomplete));
    }
    assert!(!RunState::Finished.can_transition_to(RunState::Incomplete));
    assert!(!RunState::Incomplete.can_transition_to(RunState::Active));
}
