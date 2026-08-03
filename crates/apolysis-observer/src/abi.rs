// SPDX-License-Identifier: Apache-2.0

//! Stable userspace mirrors of the observer kernel/userspace ABIs.

use std::fmt;

use aya::Pod;

pub const COMM_LEN: usize = 16;
pub const RESOURCE_LEN: usize = 256;
pub const ACTION_LEN: usize = 32;
pub const PAYLOAD_LEN: usize = 256;
pub const KERNEL_ABI_VERSION: u32 = 3;
pub const KERNEL_EVENT_RECORD_LEN: usize = 96 + COMM_LEN + RESOURCE_LEN + ACTION_LEN + PAYLOAD_LEN;
pub const FLAG_RESOURCE_TRUNCATED: u32 = 1 << 0;
pub const FLAG_PAYLOAD_TRUNCATED: u32 = 1 << 1;
pub const FLAG_PAYLOAD_SOCKADDR: u32 = 1 << 2;
pub const FLAG_ARGV_TRUNCATED: u32 = 1 << 3;
pub const FLAG_RETURN_VALUE: u32 = 1 << 4;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub(crate) struct NetworkConnectCountersAbi {
    pub(crate) missing_entries: u64,
    pub(crate) missing_exits: u64,
    pub(crate) pending: u64,
}

unsafe impl Pod for NetworkConnectCountersAbi {}

const _: [(); 24] = [(); std::mem::size_of::<NetworkConnectCountersAbi>()];
const _: [(); 8] = [(); std::mem::align_of::<NetworkConnectCountersAbi>()];

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub(crate) struct OperationPairCountersAbi {
    pub(crate) missing_entries: u64,
    pub(crate) missing_exits: u64,
    pub(crate) pending: u64,
}

unsafe impl Pod for OperationPairCountersAbi {}

const _: [(); 24] = [(); std::mem::size_of::<OperationPairCountersAbi>()];
const _: [(); 8] = [(); std::mem::align_of::<OperationPairCountersAbi>()];

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub(crate) struct FileOperationCountersAbi {
    pub(crate) open: OperationPairCountersAbi,
    pub(crate) create: OperationPairCountersAbi,
    pub(crate) truncate: OperationPairCountersAbi,
    pub(crate) unlink: OperationPairCountersAbi,
    pub(crate) rename: OperationPairCountersAbi,
}

unsafe impl Pod for FileOperationCountersAbi {}

const _: [(); 120] = [(); std::mem::size_of::<FileOperationCountersAbi>()];
const _: [(); 8] = [(); std::mem::align_of::<FileOperationCountersAbi>()];

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub(crate) struct ObserverCountersAbi {
    pub(crate) reserve_failures: u64,
    pub(crate) map_pressure: u64,
    pub(crate) connect_missing_entries: u64,
    pub(crate) connect_missing_exits: u64,
    pub(crate) connect_pending: u64,
    pub(crate) file_operations: FileOperationCountersAbi,
}

unsafe impl Pod for ObserverCountersAbi {}

const _: [(); 160] = [(); std::mem::size_of::<ObserverCountersAbi>()];
const _: [(); 8] = [(); std::mem::align_of::<ObserverCountersAbi>()];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum TrackedCgroupState {
    Active = 1,
    Draining = 2,
}

impl TryFrom<u8> for TrackedCgroupState {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Active),
            2 => Ok(Self::Draining),
            state => Err(format!("unknown cgroup observer scope state: {state}")),
        }
    }
}

const _: [(); 1] = [(); std::mem::size_of::<TrackedCgroupState>()];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct TrackedCgroupScopeAbi {
    generation: u64,
    state: u8,
    reserved: [u8; 7],
}

unsafe impl Pod for TrackedCgroupScopeAbi {}

impl TrackedCgroupScopeAbi {
    pub fn active(generation: u64) -> Result<Self, String> {
        if generation == 0 {
            return Err("cgroup scope generation must be non-zero".to_string());
        }
        Ok(Self {
            generation,
            state: TrackedCgroupState::Active as u8,
            reserved: [0; 7],
        })
    }

    pub fn generation(self) -> u64 {
        self.generation
    }

    pub fn is_active(self) -> bool {
        self.state == TrackedCgroupState::Active as u8
    }

    pub(crate) fn with_state(self, state: TrackedCgroupState) -> Self {
        Self {
            state: state as u8,
            ..self
        }
    }

    pub(crate) fn state(self) -> Result<TrackedCgroupState, String> {
        self.state.try_into()
    }
}

const _: [(); 16] = [(); std::mem::size_of::<TrackedCgroupScopeAbi>()];
const _: [(); 8] = [(); std::mem::align_of::<TrackedCgroupScopeAbi>()];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KernelEventDecodeError {
    UnexpectedRecordLength { expected: usize, received: usize },
    UnsupportedAbiVersion { expected: u32, received: u32 },
    DeclaredRecordSizeMismatch { expected: u32, received: u32 },
}

impl KernelEventDecodeError {
    pub fn is_abi_mismatch(&self) -> bool {
        matches!(
            self,
            Self::UnsupportedAbiVersion { .. } | Self::DeclaredRecordSizeMismatch { .. }
        )
    }
}

impl fmt::Display for KernelEventDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedRecordLength { expected, received } => write!(
                formatter,
                "invalid kernel event record: expected {expected} bytes, received {received}"
            ),
            Self::UnsupportedAbiVersion { expected, received } => write!(
                formatter,
                "unsupported kernel event ABI version: expected {expected}, received {received}"
            ),
            Self::DeclaredRecordSizeMismatch { expected, received } => write!(
                formatter,
                "kernel event ABI record-size mismatch: expected {expected}, received {received}"
            ),
        }
    }
}

impl std::error::Error for KernelEventDecodeError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum KernelEventKind {
    Exec = 1,
    Open = 2,
    Create = 3,
    Truncate = 4,
    Unlink = 5,
    Rename = 6,
    Connect = 7,
    Exit = 8,
    Fork = 9,
}

impl TryFrom<u32> for KernelEventKind {
    type Error = String;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Exec),
            2 => Ok(Self::Open),
            3 => Ok(Self::Create),
            4 => Ok(Self::Truncate),
            5 => Ok(Self::Unlink),
            6 => Ok(Self::Rename),
            7 => Ok(Self::Connect),
            8 => Ok(Self::Exit),
            9 => Ok(Self::Fork),
            unknown => Err(format!("unknown kernel event kind: {unknown}")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct KernelEventRecord {
    pub abi_version: u32,
    pub record_size: u32,
    pub timestamp_ns: u64,
    pub cgroup_id: u64,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub event_kind: u32,
    pub flags: u32,
    pub return_value: i64,
    pub scope_generation: u64,
    pub process_generation: u64,
    pub process_start_time_ns: u64,
    pub parent_process_generation: u64,
    pub exec_generation: u32,
    pub parent_exec_generation: u32,
    pub comm: [u8; COMM_LEN],
    pub resource: [u8; RESOURCE_LEN],
    pub action: [u8; ACTION_LEN],
    pub payload: [u8; PAYLOAD_LEN],
}

impl KernelEventRecord {
    pub fn decode(bytes: &[u8]) -> Result<Self, KernelEventDecodeError> {
        if bytes.len() < 8 {
            return Err(KernelEventDecodeError::UnexpectedRecordLength {
                expected: 8,
                received: bytes.len(),
            });
        }
        let abi_version = read_u32(bytes, 0);
        if abi_version != KERNEL_ABI_VERSION {
            return Err(KernelEventDecodeError::UnsupportedAbiVersion {
                expected: KERNEL_ABI_VERSION,
                received: abi_version,
            });
        }
        let record_size = read_u32(bytes, 4);
        if record_size != KERNEL_EVENT_RECORD_LEN as u32 {
            return Err(KernelEventDecodeError::DeclaredRecordSizeMismatch {
                expected: KERNEL_EVENT_RECORD_LEN as u32,
                received: record_size,
            });
        }
        if bytes.len() != record_size as usize {
            return Err(KernelEventDecodeError::UnexpectedRecordLength {
                expected: record_size as usize,
                received: bytes.len(),
            });
        }

        let mut record = Self {
            abi_version,
            record_size,
            timestamp_ns: read_u64(bytes, 8),
            cgroup_id: read_u64(bytes, 16),
            pid: read_u32(bytes, 24),
            ppid: read_u32(bytes, 28),
            uid: read_u32(bytes, 32),
            gid: read_u32(bytes, 36),
            event_kind: read_u32(bytes, 40),
            flags: read_u32(bytes, 44),
            return_value: read_i64(bytes, 48),
            scope_generation: read_u64(bytes, 56),
            process_generation: read_u64(bytes, 64),
            process_start_time_ns: read_u64(bytes, 72),
            parent_process_generation: read_u64(bytes, 80),
            exec_generation: read_u32(bytes, 88),
            parent_exec_generation: read_u32(bytes, 92),
            comm: [0; COMM_LEN],
            resource: [0; RESOURCE_LEN],
            action: [0; ACTION_LEN],
            payload: [0; PAYLOAD_LEN],
        };

        let mut offset = 96;
        copy_fixed(bytes, &mut offset, &mut record.comm);
        copy_fixed(bytes, &mut offset, &mut record.resource);
        copy_fixed(bytes, &mut offset, &mut record.action);
        copy_fixed(bytes, &mut offset, &mut record.payload);
        Ok(record)
    }

    pub fn kind(&self) -> Result<KernelEventKind, String> {
        self.event_kind.try_into()
    }

    pub fn comm(&self) -> String {
        fixed_string(&self.comm)
    }

    pub fn resource(&self) -> String {
        fixed_string(&self.resource)
    }

    pub fn action(&self) -> String {
        fixed_string(&self.action)
    }

    pub fn payload(&self) -> String {
        fixed_string(&self.payload)
    }

    pub fn payload_bytes(&self) -> &[u8] {
        &self.payload
    }

    pub fn return_value(&self) -> Option<i64> {
        (self.flags & FLAG_RETURN_VALUE != 0).then_some(self.return_value)
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_ne_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("validated kernel event record length"),
    )
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_ne_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("validated kernel event record length"),
    )
}

fn read_i64(bytes: &[u8], offset: usize) -> i64 {
    i64::from_ne_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("validated kernel event record length"),
    )
}

fn copy_fixed<const N: usize>(bytes: &[u8], offset: &mut usize, target: &mut [u8; N]) {
    target.copy_from_slice(&bytes[*offset..*offset + N]);
    *offset += N;
}

fn fixed_string(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}
