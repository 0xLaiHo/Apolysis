// SPDX-License-Identifier: Apache-2.0

use apolysis_observer::abi::{
    KernelEventKind, KernelEventRecord, ACTION_LEN, COMM_LEN, FLAG_ARGV_TRUNCATED,
    FLAG_PAYLOAD_SOCKADDR, FLAG_PAYLOAD_TRUNCATED, INTENT_ID_LEN, KERNEL_EVENT_RECORD_LEN,
    PAYLOAD_LEN, RESOURCE_LEN,
};
use apolysis_observer::raw_event_from_record;

#[test]
fn kernel_event_record_matches_the_c_abi_size() {
    assert_eq!(std::mem::size_of::<KernelEventRecord>(), 648);
    assert_eq!(KERNEL_EVENT_RECORD_LEN, 648);
}

#[test]
fn kernel_event_record_decodes_native_endian_fields_and_fixed_buffers() {
    let mut bytes = vec![0_u8; KERNEL_EVENT_RECORD_LEN];
    bytes[0..8].copy_from_slice(&123_000_000_u64.to_ne_bytes());
    bytes[8..16].copy_from_slice(&456_u64.to_ne_bytes());
    bytes[16..20].copy_from_slice(&101_u32.to_ne_bytes());
    bytes[20..24].copy_from_slice(&100_u32.to_ne_bytes());
    bytes[24..28].copy_from_slice(&1000_u32.to_ne_bytes());
    bytes[28..32].copy_from_slice(&1001_u32.to_ne_bytes());
    bytes[32..36].copy_from_slice(&(KernelEventKind::Connect as u32).to_ne_bytes());
    bytes[36..40].copy_from_slice(&3_u32.to_ne_bytes());
    write_fixed(&mut bytes[40..40 + COMM_LEN], b"python3");
    write_fixed(
        &mut bytes[40 + COMM_LEN..40 + COMM_LEN + RESOURCE_LEN],
        b"1.1.1.1:443",
    );
    write_fixed(
        &mut bytes[40 + COMM_LEN + RESOURCE_LEN..40 + COMM_LEN + RESOURCE_LEN + ACTION_LEN],
        b"connect",
    );
    write_fixed(&mut bytes[600 - PAYLOAD_LEN..600], b"family=inet");

    let record = KernelEventRecord::decode(&bytes).expect("decode record");

    assert_eq!(record.timestamp_ns, 123_000_000);
    assert_eq!(record.cgroup_id, 456);
    assert_eq!(record.pid, 101);
    assert_eq!(record.ppid, 100);
    assert_eq!(record.uid, 1000);
    assert_eq!(record.gid, 1001);
    assert_eq!(record.kind().expect("known kind"), KernelEventKind::Connect);
    assert_eq!(record.flags, 3);
    assert_eq!(record.comm(), "python3");
    assert_eq!(record.resource(), "1.1.1.1:443");
    assert_eq!(record.action(), "connect");
    assert_eq!(record.payload(), "family=inet");
}

#[test]
fn kernel_event_record_rejects_short_ring_buffer_items() {
    let error = KernelEventRecord::decode(&[0_u8; 32]).expect_err("short record must fail");

    assert!(error.contains("expected 648 bytes"));
    assert!(error.contains("received 32"));
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
        timestamp_ns: 0,
        cgroup_id: 0,
        pid: 0,
        ppid: 0,
        uid: 0,
        gid: 0,
        event_kind: kind as u32,
        flags: 0,
        comm: [0; COMM_LEN],
        resource: [0; RESOURCE_LEN],
        action: [0; ACTION_LEN],
        payload: [0; PAYLOAD_LEN],
        process_start_time_ns: 0,
        parent_start_time_ns: 0,
        intent_id: [0; INTENT_ID_LEN],
    }
}

#[test]
fn dedicated_token_is_complete_even_when_diagnostic_command_is_truncated() {
    let mut record = empty_record(KernelEventKind::Exec);
    record.flags = FLAG_ARGV_TRUNCATED | FLAG_PAYLOAD_TRUNCATED;
    record
        .intent_id
        .copy_from_slice(b"0123456789abcdef0123456789abcdef");
    record.process_start_time_ns = 1000;
    record.parent_start_time_ns = 500;
    write_fixed(
        &mut record.payload,
        b"argv:/bin/bash -c # APOLYSIS_INTENT_ID=0123456789",
    );
    let raw = raw_event_from_record(&record, "session", 1).expect("record");
    assert_eq!(
        raw.intent_id.as_deref(),
        Some("0123456789abcdef0123456789abcdef")
    );
    assert_eq!(raw.process_start_time_ns, Some(1000));
    assert_eq!(raw.parent_start_time_ns, Some(500));
}

#[test]
fn malformed_or_partial_dedicated_tokens_do_not_fall_back_to_argv() {
    for token in [
        b"0123456789ABCDEF0123456789ABCDEF".as_slice(),
        b"0123456789abcdef",
        b"",
    ] {
        let mut record = empty_record(KernelEventKind::Exec);
        write_fixed(&mut record.intent_id, token);
        write_fixed(
            &mut record.payload,
            b"argv:/bin/bash -c # APOLYSIS_INTENT_ID=0123456789abcdef0123456789abcdef\ntrue",
        );
        let raw = raw_event_from_record(&record, "session", 1).expect("record");
        assert_eq!(raw.intent_id, None);
        assert!(raw.process_start_time_ns.is_some());
    }
}

#[test]
fn record_decodes_process_generations_and_fixed_token() {
    let mut bytes = vec![0_u8; KERNEL_EVENT_RECORD_LEN];
    bytes[600..608].copy_from_slice(&1000_u64.to_ne_bytes());
    bytes[608..616].copy_from_slice(&500_u64.to_ne_bytes());
    bytes[616..648].copy_from_slice(b"0123456789abcdef0123456789abcdef");
    let record = KernelEventRecord::decode(&bytes).expect("record");
    assert_eq!(record.process_start_time_ns, 1000);
    assert_eq!(record.parent_start_time_ns, 500);
    assert_eq!(
        record.intent_id().as_deref(),
        Some("0123456789abcdef0123456789abcdef")
    );
}

#[test]
fn uncertain_capture_drops_any_token_and_survives_content_off_persistence() {
    let mut record = empty_record(KernelEventKind::Exec);
    record.flags = apolysis_observer::abi::FLAG_INTENT_INCOMPLETE | FLAG_PAYLOAD_TRUNCATED;
    record
        .intent_id
        .copy_from_slice(b"0123456789abcdef0123456789abcdef");
    write_fixed(&mut record.payload, b"argv:/bin/bash -c synthetic-command");
    let raw = raw_event_from_record(&record, "session", 1).expect("record");
    assert_eq!(raw.intent_id, None);
    let redactor = apolysis_observer::Redactor::new("session", "/workspace");
    let persisted =
        apolysis_observer::RuntimeEvidencePersistence::new(&redactor).persist_raw(&raw, false);
    assert!(persisted
        .raw_payload
        .contains("intent_capture_incomplete:true"));
    assert!(!persisted.raw_payload.contains("synthetic-command"));
}
