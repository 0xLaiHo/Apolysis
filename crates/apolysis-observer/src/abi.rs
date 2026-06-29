// SPDX-License-Identifier: Apache-2.0

//! Stable userspace mirror of the observer ring-buffer ABI.

pub const COMM_LEN: usize = 16;
pub const RESOURCE_LEN: usize = 256;
pub const ACTION_LEN: usize = 32;
pub const PAYLOAD_LEN: usize = 256;
pub const KERNEL_EVENT_RECORD_LEN: usize = 40 + COMM_LEN + RESOURCE_LEN + ACTION_LEN + PAYLOAD_LEN;
pub const FLAG_RESOURCE_TRUNCATED: u32 = 1 << 0;
pub const FLAG_PAYLOAD_TRUNCATED: u32 = 1 << 1;
pub const FLAG_PAYLOAD_SOCKADDR: u32 = 1 << 2;
pub const FLAG_ARGV_TRUNCATED: u32 = 1 << 3;

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
    pub timestamp_ns: u64,
    pub cgroup_id: u64,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub event_kind: u32,
    pub flags: u32,
    pub comm: [u8; COMM_LEN],
    pub resource: [u8; RESOURCE_LEN],
    pub action: [u8; ACTION_LEN],
    pub payload: [u8; PAYLOAD_LEN],
}

impl KernelEventRecord {
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != KERNEL_EVENT_RECORD_LEN {
            return Err(format!(
                "invalid kernel event record: expected {KERNEL_EVENT_RECORD_LEN} bytes, received {}",
                bytes.len()
            ));
        }

        let mut record = Self {
            timestamp_ns: read_u64(bytes, 0),
            cgroup_id: read_u64(bytes, 8),
            pid: read_u32(bytes, 16),
            ppid: read_u32(bytes, 20),
            uid: read_u32(bytes, 24),
            gid: read_u32(bytes, 28),
            event_kind: read_u32(bytes, 32),
            flags: read_u32(bytes, 36),
            comm: [0; COMM_LEN],
            resource: [0; RESOURCE_LEN],
            action: [0; ACTION_LEN],
            payload: [0; PAYLOAD_LEN],
        };

        let mut offset = 40;
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
