// SPDX-License-Identifier: Apache-2.0

use apolysis_core::{OperationOutcome, OperationResult, RuntimeRelation};
use apolysis_observer::abi::{
    KernelEventDecodeError, KernelEventKind, KernelEventRecord, ACTION_LEN, COMM_LEN,
    FLAG_ARGV_TRUNCATED, FLAG_PAYLOAD_SOCKADDR, FLAG_PAYLOAD_TRUNCATED, FLAG_RETURN_VALUE,
    KERNEL_ABI_VERSION, KERNEL_EVENT_RECORD_LEN, PAYLOAD_LEN, RESOURCE_LEN,
};
use apolysis_observer::raw_event_from_record;

#[test]
fn kernel_event_record_matches_the_c_abi_size() {
    assert_eq!(KERNEL_ABI_VERSION, 3);
    assert_eq!(std::mem::size_of::<KernelEventRecord>(), 656);
    assert_eq!(KERNEL_EVENT_RECORD_LEN, 656);
}

#[test]
fn kernel_event_record_decodes_a_signed_syscall_return_value() {
    let mut bytes = vec![0_u8; KERNEL_EVENT_RECORD_LEN];
    bytes[0..4].copy_from_slice(&KERNEL_ABI_VERSION.to_ne_bytes());
    bytes[4..8].copy_from_slice(&(KERNEL_EVENT_RECORD_LEN as u32).to_ne_bytes());
    bytes[40..44].copy_from_slice(&(KernelEventKind::Connect as u32).to_ne_bytes());
    bytes[44..48].copy_from_slice(&FLAG_RETURN_VALUE.to_ne_bytes());
    bytes[48..56].copy_from_slice(&(-13_i64).to_ne_bytes());

    let record = KernelEventRecord::decode(&bytes).expect("decode connect exit record");

    assert_eq!(record.return_value(), Some(-13));
}

#[test]
fn kernel_event_record_decodes_native_endian_fields_and_fixed_buffers() {
    let mut bytes = vec![0_u8; KERNEL_EVENT_RECORD_LEN];
    bytes[0..4].copy_from_slice(&KERNEL_ABI_VERSION.to_ne_bytes());
    bytes[4..8].copy_from_slice(&(KERNEL_EVENT_RECORD_LEN as u32).to_ne_bytes());
    bytes[8..16].copy_from_slice(&123_000_000_u64.to_ne_bytes());
    bytes[16..24].copy_from_slice(&456_u64.to_ne_bytes());
    bytes[24..28].copy_from_slice(&101_u32.to_ne_bytes());
    bytes[28..32].copy_from_slice(&100_u32.to_ne_bytes());
    bytes[32..36].copy_from_slice(&1000_u32.to_ne_bytes());
    bytes[36..40].copy_from_slice(&1001_u32.to_ne_bytes());
    bytes[40..44].copy_from_slice(&(KernelEventKind::Connect as u32).to_ne_bytes());
    bytes[44..48].copy_from_slice(&3_u32.to_ne_bytes());
    bytes[56..64].copy_from_slice(&11_u64.to_ne_bytes());
    bytes[64..72].copy_from_slice(&22_u64.to_ne_bytes());
    bytes[72..80].copy_from_slice(&33_u64.to_ne_bytes());
    bytes[80..88].copy_from_slice(&44_u64.to_ne_bytes());
    bytes[88..92].copy_from_slice(&5_u32.to_ne_bytes());
    bytes[92..96].copy_from_slice(&4_u32.to_ne_bytes());
    write_fixed(&mut bytes[96..96 + COMM_LEN], b"python3");
    write_fixed(
        &mut bytes[96 + COMM_LEN..96 + COMM_LEN + RESOURCE_LEN],
        b"1.1.1.1:443",
    );
    write_fixed(
        &mut bytes[96 + COMM_LEN + RESOURCE_LEN..96 + COMM_LEN + RESOURCE_LEN + ACTION_LEN],
        b"connect",
    );
    write_fixed(
        &mut bytes[KERNEL_EVENT_RECORD_LEN - PAYLOAD_LEN..],
        b"family=inet",
    );

    let record = KernelEventRecord::decode(&bytes).expect("decode record");

    assert_eq!(record.abi_version, KERNEL_ABI_VERSION);
    assert_eq!(record.record_size, KERNEL_EVENT_RECORD_LEN as u32);
    assert_eq!(record.timestamp_ns, 123_000_000);
    assert_eq!(record.cgroup_id, 456);
    assert_eq!(record.pid, 101);
    assert_eq!(record.ppid, 100);
    assert_eq!(record.uid, 1000);
    assert_eq!(record.gid, 1001);
    assert_eq!(record.kind().expect("known kind"), KernelEventKind::Connect);
    assert_eq!(record.flags, 3);
    assert_eq!(record.scope_generation, 11);
    assert_eq!(record.process_generation, 22);
    assert_eq!(record.process_start_time_ns, 33);
    assert_eq!(record.parent_process_generation, 44);
    assert_eq!(record.exec_generation, 5);
    assert_eq!(record.parent_exec_generation, 4);
    assert_eq!(record.comm(), "python3");
    assert_eq!(record.resource(), "1.1.1.1:443");
    assert_eq!(record.action(), "connect");
    assert_eq!(record.payload(), "family=inet");
}

#[test]
fn kernel_event_record_rejects_short_ring_buffer_items() {
    let mut bytes = [0_u8; 32];
    bytes[0..4].copy_from_slice(&KERNEL_ABI_VERSION.to_ne_bytes());
    bytes[4..8].copy_from_slice(&(KERNEL_EVENT_RECORD_LEN as u32).to_ne_bytes());
    let error = KernelEventRecord::decode(&bytes).expect_err("short record must fail");

    assert_eq!(
        error,
        KernelEventDecodeError::UnexpectedRecordLength {
            expected: 656,
            received: 32,
        }
    );
    assert!(!error.is_abi_mismatch());
}

#[test]
fn kernel_event_record_rejects_an_unsupported_abi_version() {
    let mut bytes = vec![0_u8; KERNEL_EVENT_RECORD_LEN];
    bytes[0..4].copy_from_slice(&2_u32.to_ne_bytes());
    bytes[4..8].copy_from_slice(&(KERNEL_EVENT_RECORD_LEN as u32).to_ne_bytes());

    let error = KernelEventRecord::decode(&bytes).expect_err("unknown ABI must fail");

    assert_eq!(
        error,
        KernelEventDecodeError::UnsupportedAbiVersion {
            expected: KERNEL_ABI_VERSION,
            received: 2,
        }
    );
    assert!(error.is_abi_mismatch());
}

#[test]
fn kernel_event_record_classifies_a_different_sized_future_abi_by_version() {
    let mut bytes = vec![0_u8; 664];
    bytes[0..4].copy_from_slice(&4_u32.to_ne_bytes());
    bytes[4..8].copy_from_slice(&664_u32.to_ne_bytes());

    let error = KernelEventRecord::decode(&bytes).expect_err("future ABI must fail");

    assert_eq!(
        error,
        KernelEventDecodeError::UnsupportedAbiVersion {
            expected: KERNEL_ABI_VERSION,
            received: 4,
        }
    );
}

#[test]
fn kernel_event_record_rejects_a_declared_record_size_mismatch() {
    let mut bytes = vec![0_u8; KERNEL_EVENT_RECORD_LEN];
    bytes[0..4].copy_from_slice(&KERNEL_ABI_VERSION.to_ne_bytes());
    bytes[4..8].copy_from_slice(&648_u32.to_ne_bytes());

    let error = KernelEventRecord::decode(&bytes).expect_err("wrong ABI size must fail");

    assert_eq!(
        error,
        KernelEventDecodeError::DeclaredRecordSizeMismatch {
            expected: KERNEL_EVENT_RECORD_LEN as u32,
            received: 648,
        }
    );
    assert!(error.is_abi_mismatch());
}

#[test]
fn live_file_record_converts_to_the_fixture_compatible_raw_schema() {
    let mut record = empty_record(KernelEventKind::Open);
    record.timestamp_ns = 44_000_000;
    record.cgroup_id = 901;
    record.pid = 44;
    record.ppid = 40;
    write_fixed(&mut record.comm, b"cat");
    write_fixed(&mut record.resource, b"/workspace/input.txt");
    write_fixed(&mut record.action, b"read");

    let raw = raw_event_from_record(&record, "session-live", 1_700_000_000_044)
        .expect("convert live record");

    assert_eq!(raw.session_id, "session-live");
    assert_eq!(raw.event_name, "openat");
    assert_eq!(raw.pid, 44);
    assert_eq!(raw.ppid, 40);
    assert_eq!(raw.resource, "/workspace/input.txt");
    assert_eq!(raw.action, "read");
    assert_eq!(raw.cgroup_id.as_deref(), Some("901"));
}

#[test]
fn live_record_normalizes_a_stable_runtime_identity() {
    let mut record = empty_record(KernelEventKind::Open);
    record.cgroup_id = 901;
    record.scope_generation = 7;
    record.pid = 44;
    record.process_generation = 22;
    record.process_start_time_ns = 33;
    record.exec_generation = 5;
    record.ppid = 40;
    record.parent_process_generation = 11;
    record.parent_exec_generation = 4;

    let raw = raw_event_from_record(
        &record,
        "session-live",
        1_700_000_000_044,
        "boot-test",
    )
    .expect("convert stable runtime identity");

    assert_eq!(raw.host_boot_id.as_deref(), Some("boot-test"));
    assert_eq!(raw.scope_generation, Some(7));
    assert_eq!(raw.process_generation, Some(22));
    assert_eq!(raw.process_start_time_ns, Some(33));
    assert_eq!(raw.exec_generation, Some(5));
    assert_eq!(raw.parent_process_generation, Some(11));
    assert_eq!(raw.parent_exec_generation, Some(4));
    assert_eq!(raw.relation_status, RuntimeRelation::Exact);
    assert_eq!(
        raw.relation_reason,
        "host_boot_process_exec_generation"
    );
}

#[test]
fn live_file_records_map_linux_return_values_to_synchronous_outcomes() {
    for kind in [
        KernelEventKind::Open,
        KernelEventKind::Create,
        KernelEventKind::Truncate,
        KernelEventKind::Unlink,
        KernelEventKind::Rename,
    ] {
        for (return_value, expected) in [
            (
                3,
                OperationResult::new(OperationOutcome::Succeeded, 3, None),
            ),
            (
                -13,
                OperationResult::new(OperationOutcome::Denied, -13, Some(13)),
            ),
            (
                -2,
                OperationResult::new(OperationOutcome::Failed, -2, Some(2)),
            ),
            (
                -115,
                OperationResult::new(OperationOutcome::Failed, -115, Some(115)),
            ),
        ] {
            let mut record = empty_record(kind);
            record.flags = FLAG_RETURN_VALUE;
            record.return_value = return_value;

            let raw = raw_event_from_record(&record, "agent-run-file-result", 1)
                .expect("convert file result record");

            assert_eq!(raw.operation_result, Some(expected), "kind: {kind:?}");
        }
    }
}

#[test]
fn live_connect_record_decodes_ipv4_sockaddr() {
    let mut record = empty_record(KernelEventKind::Connect);
    record.flags = FLAG_PAYLOAD_SOCKADDR;
    record.payload[0..2].copy_from_slice(&2_u16.to_ne_bytes());
    record.payload[2..4].copy_from_slice(&443_u16.to_be_bytes());
    record.payload[4..8].copy_from_slice(&[1, 1, 1, 1]);
    write_fixed(&mut record.action, b"connect");

    let raw = raw_event_from_record(&record, "session-live", 1).expect("convert sockaddr record");

    assert_eq!(raw.event_name, "connect");
    assert_eq!(raw.resource, "1.1.1.1:443");
    assert_eq!(raw.raw_payload, "family:inet");
}

#[test]
fn live_connect_record_maps_linux_return_values_to_supported_outcomes() {
    for (return_value, expected) in [
        (
            0,
            OperationResult::new(OperationOutcome::Succeeded, 0, None),
        ),
        (
            -13,
            OperationResult::new(OperationOutcome::Denied, -13, Some(13)),
        ),
        (
            -115,
            OperationResult::new(OperationOutcome::Pending, -115, Some(115)),
        ),
        (
            -114,
            OperationResult::new(OperationOutcome::Pending, -114, Some(114)),
        ),
        (
            -111,
            OperationResult::new(OperationOutcome::Failed, -111, Some(111)),
        ),
    ] {
        let mut record = empty_record(KernelEventKind::Connect);
        record.flags = FLAG_RETURN_VALUE;
        record.return_value = return_value;

        let raw = raw_event_from_record(&record, "agent-run-connect-result", 1)
            .expect("convert connect result record");

        assert_eq!(raw.operation_result, Some(expected));
    }
}

#[test]
fn live_exec_record_preserves_argv_payload_and_truncation_markers() {
    let mut record = empty_record(KernelEventKind::Exec);
    record.flags = FLAG_ARGV_TRUNCATED | FLAG_PAYLOAD_TRUNCATED;
    write_fixed(&mut record.comm, b"sed");
    write_fixed(&mut record.resource, b"/usr/bin/sed");
    write_fixed(&mut record.action, b"exec");
    write_fixed(&mut record.payload, b"argv:/usr/bin/sed -n 1,8p README.md");

    let raw = raw_event_from_record(&record, "session-live", 1).expect("convert exec record");

    assert_eq!(raw.event_name, "sched_process_exec");
    assert_eq!(raw.resource, "/usr/bin/sed");
    assert_eq!(raw.action, "exec");
    assert_eq!(
        raw.raw_payload,
        "argv:/usr/bin/sed -n 1,8p README.md,argv_truncated:true,payload_truncated:true"
    );
}

fn write_fixed(target: &mut [u8], value: &[u8]) {
    target[..value.len()].copy_from_slice(value);
}

fn empty_record(kind: KernelEventKind) -> KernelEventRecord {
    KernelEventRecord {
        abi_version: KERNEL_ABI_VERSION,
        record_size: KERNEL_EVENT_RECORD_LEN as u32,
        timestamp_ns: 0,
        cgroup_id: 0,
        pid: 0,
        ppid: 0,
        uid: 0,
        gid: 0,
        event_kind: kind as u32,
        flags: 0,
        return_value: 0,
        scope_generation: 0,
        process_generation: 0,
        process_start_time_ns: 0,
        parent_process_generation: 0,
        exec_generation: 0,
        parent_exec_generation: 0,
        comm: [0; COMM_LEN],
        resource: [0; RESOURCE_LEN],
        action: [0; ACTION_LEN],
        payload: [0; PAYLOAD_LEN],
    }
}
