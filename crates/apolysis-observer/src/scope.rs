// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;

pub const MAX_TRACKED_CGROUPS: usize = 16_384;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScopeSetError {
    InvalidCgroupId,
    CapacityReached { capacity: usize },
}

impl std::fmt::Display for ScopeSetError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCgroupId => formatter.write_str("cgroup id must be non-zero"),
            Self::CapacityReached { capacity } => {
                write!(formatter, "cgroup scope capacity reached: {capacity}")
            }
        }
    }
}

impl std::error::Error for ScopeSetError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopeSet {
    capacity: usize,
    cgroup_ids: BTreeSet<u64>,
}

impl ScopeSet {
    pub fn new() -> Self {
        Self::with_capacity(MAX_TRACKED_CGROUPS)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity,
            cgroup_ids: BTreeSet::new(),
        }
    }

    pub fn insert(&mut self, cgroup_id: u64) -> Result<bool, ScopeSetError> {
        if cgroup_id == 0 {
            return Err(ScopeSetError::InvalidCgroupId);
        }
        if self.cgroup_ids.contains(&cgroup_id) {
            return Ok(false);
        }
        if self.cgroup_ids.len() >= self.capacity {
            return Err(ScopeSetError::CapacityReached {
                capacity: self.capacity,
            });
        }
        Ok(self.cgroup_ids.insert(cgroup_id))
    }

    pub fn remove(&mut self, cgroup_id: u64) -> bool {
        self.cgroup_ids.remove(&cgroup_id)
    }

    pub fn contains(&self, cgroup_id: u64) -> bool {
        self.cgroup_ids.contains(&cgroup_id)
    }

    pub fn len(&self) -> usize {
        self.cgroup_ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cgroup_ids.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn iter(&self) -> impl Iterator<Item = &u64> {
        self.cgroup_ids.iter()
    }
}

impl Default for ScopeSet {
    fn default() -> Self {
        Self::new()
    }
}
