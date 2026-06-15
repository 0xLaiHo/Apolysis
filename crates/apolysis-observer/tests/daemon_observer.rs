// SPDX-License-Identifier: Apache-2.0

use apolysis_observer::abi::{KernelEventKind, FLAG_RESOURCE_TRUNCATED, KERNEL_EVENT_RECORD_LEN};
use apolysis_observer::{DaemonObserver, DaemonObserverConfig, ObserverBatchDecoder};

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
    valid[0..8].copy_from_slice(&1_002_000_000_u64.to_ne_bytes());
    valid[32..36].copy_from_slice(&(KernelEventKind::Exec as u32).to_ne_bytes());
    valid[36..40].copy_from_slice(&FLAG_RESOURCE_TRUNCATED.to_ne_bytes());

    let batch = decoder.decode(vec![valid, vec![0_u8; 8]]);

    assert_eq!(batch.events.len(), 1);
    assert_eq!(batch.events[0].timestamp_unix_ms, 10_002);
    assert_eq!(batch.decode_failures, 1);
    assert_eq!(batch.truncations, 1);
}
