// SPDX-License-Identifier: Apache-2.0

use apolysis_core::ObservationGapKind;
use apolysis_observer::abi::{
    KernelEventKind, FLAG_RESOURCE_TRUNCATED, KERNEL_ABI_VERSION, KERNEL_EVENT_RECORD_LEN,
};
use apolysis_observer::{
    file_operation_observation_gaps, network_connect_observation_gaps, DaemonObserver,
    DaemonObserverConfig, FileOperationCounters, NetworkConnectCounters, ObserverBatchDecoder,
    OperationPairCounters,
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
    abi_mismatch[0..4].copy_from_slice(&2_u32.to_ne_bytes());
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
        &NetworkConnectCounters {
            missing_entries: 2,
            missing_exits: 1,
            pending: 2,
        },
    );

    assert_eq!(gaps.len(), 2);
    assert_eq!(gaps[0].kind, ObservationGapKind::MissingEntry);
    assert_eq!(gaps[0].count, 2);
    assert_eq!(gaps[1].kind, ObservationGapKind::MissingExit);
    assert_eq!(gaps[1].count, 3);
    assert!(gaps[1].detail.contains("pending_at_stop:2"));
}

#[test]
fn file_operation_counters_become_operation_specific_observation_gaps() {
    let gaps = file_operation_observation_gaps(
        "agent-run-file-gaps",
        &FileOperationCounters {
            open: OperationPairCounters {
                missing_entries: 2,
                ..OperationPairCounters::default()
            },
            rename: OperationPairCounters {
                missing_exits: 1,
                pending: 2,
                ..OperationPairCounters::default()
            },
            ..FileOperationCounters::default()
        },
    );

    assert_eq!(gaps.len(), 2);
    assert_eq!(gaps[0].operation, "file_open");
    assert_eq!(gaps[0].kind, ObservationGapKind::MissingEntry);
    assert_eq!(gaps[0].count, 2);
    assert_eq!(gaps[1].operation, "file_rename");
    assert_eq!(gaps[1].kind, ObservationGapKind::MissingExit);
    assert_eq!(gaps[1].count, 3);
    assert!(gaps[1].detail.contains("pending_at_stop:2"));
}
