// SPDX-License-Identifier: Apache-2.0

use apolysis_core::ObservationGapKind;
use apolysis_observer::abi::{
    KernelEventKind, FLAG_RESOURCE_TRUNCATED, KERNEL_ABI_VERSION, KERNEL_EVENT_RECORD_LEN,
};
use apolysis_observer::{
    network_connect_observation_gaps, DaemonObserver, DaemonObserverConfig, DaemonObserverCounters,
    ObserverBatchDecoder,
};

#[test]
fn daemon_observer_rejects_a_missing_bpf_object_before_loading() {
    let path = std::env::temp_dir().join(format!(
        "apolysis-missing-daemon-observer-{}.bpf.o",
        std::process::id()
    ));
    let config = DaemonObserverConfig::new(&path);

    let error = match DaemonObserver::load(config) {
        Ok(_) => panic!("missing BPF object must be rejected"),
        Err(error) => error,
    };

    assert!(error.contains("BPF object does not exist"));
    assert!(error.contains(path.to_str().expect("UTF-8 temporary path")));
}

#[test]
fn daemon_batch_decoder_accounts_for_invalid_and_truncated_records() {
    let decoder = ObserverBatchDecoder::new(1_000_000_000, 10_000);
    let mut valid = vec![0_u8; KERNEL_EVENT_RECORD_LEN];
    valid[0..4].copy_from_slice(&KERNEL_ABI_VERSION.to_ne_bytes());
    valid[4..8].copy_from_slice(&(KERNEL_EVENT_RECORD_LEN as u32).to_ne_bytes());
    valid[8..16].copy_from_slice(&1_002_000_000_u64.to_ne_bytes());
    valid[40..44].copy_from_slice(&(KernelEventKind::Exec as u32).to_ne_bytes());
    valid[44..48].copy_from_slice(&FLAG_RESOURCE_TRUNCATED.to_ne_bytes());
    let mut abi_mismatch = vec![0_u8; KERNEL_EVENT_RECORD_LEN];
    abi_mismatch[0..4].copy_from_slice(&3_u32.to_ne_bytes());
    abi_mismatch[4..8].copy_from_slice(&(KERNEL_EVENT_RECORD_LEN as u32).to_ne_bytes());

    let batch = decoder.decode(vec![valid, abi_mismatch, vec![0_u8; 4]]);

    assert_eq!(batch.events.len(), 1);
    assert_eq!(batch.events[0].timestamp_unix_ms, 10_002);
    assert_eq!(batch.abi_mismatches, 1);
    assert_eq!(batch.decode_failures, 1);
    assert_eq!(batch.truncations, 1);
}

#[test]
fn network_connect_counters_become_explicit_agent_run_observation_gaps() {
    let gaps = network_connect_observation_gaps(
        "agent-run-connect-gaps",
        &DaemonObserverCounters {
            connect_missing_entries: 2,
            connect_missing_exits: 1,
            connect_pending: 2,
            ..DaemonObserverCounters::default()
        },
    );

    assert_eq!(gaps.len(), 2);
    assert_eq!(gaps[0].kind, ObservationGapKind::MissingEntry);
    assert_eq!(gaps[0].count, 2);
    assert_eq!(gaps[1].kind, ObservationGapKind::MissingExit);
    assert_eq!(gaps[1].count, 3);
    assert!(gaps[1].detail.contains("pending_at_stop:2"));
}
