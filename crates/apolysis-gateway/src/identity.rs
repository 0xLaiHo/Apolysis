// SPDX-License-Identifier: Apache-2.0

use std::time::{SystemTime, UNIX_EPOCH};

/// Server clock injected at the application boundary.
pub trait GatewayClock: Send + Sync {
    fn now_unix_ms(&self) -> u64;
}

/// Production wall clock. Persisted timestamps remain server-assigned facts.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl GatewayClock for SystemClock {
    fn now_unix_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or_default()
    }
}

/// Secure opaque identity source. Implementations must not derive lease IDs
/// from request content, time, counters, or tenant identifiers.
pub trait GatewayIdGenerator: Send + Sync {
    fn next_id(&self, kind: &'static str) -> Result<String, String>;
}

/// Operating-system CSPRNG-backed identity source.
#[derive(Clone, Copy, Debug, Default)]
pub struct OsRandomIdGenerator;

impl GatewayIdGenerator for OsRandomIdGenerator {
    fn next_id(&self, kind: &'static str) -> Result<String, String> {
        if !matches!(kind, "run" | "stream" | "lease") {
            return Err("unsupported Gateway identity kind".to_string());
        }
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes)
            .map_err(|_| "operating-system entropy unavailable".to_string())?;
        Ok(format!("{kind}_{}", hex(&bytes)))
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}
