// SPDX-License-Identifier: Apache-2.0

use apolysis_observer::abi::{
    KernelEventKind, KernelEventRecord, ACTION_LEN, COMM_LEN, FLAG_PAYLOAD_SOCKADDR,
    KERNEL_EVENT_RECORD_LEN, PAYLOAD_LEN, RESOURCE_LEN,
};
use apolysis_observer::raw_event_from_record;

#[test]
fn kernel_event_record_matches_the_c_abi_size() {
    assert_eq!(std::mem::size_of::<KernelEventRecord>(), 600);
    assert_eq!(KERNEL_EVENT_RECORD_LEN, 600);
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
    write_fixed(
        &mut bytes[KERNEL_EVENT_RECORD_LEN - PAYLOAD_LEN..],
        b"family=inet",
    );

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

    assert!(error.contains("expected 600 bytes"));
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
    }
}
