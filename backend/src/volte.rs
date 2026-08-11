//! Native IMS/VoLTE runtime boundary.
//!
//! The beta9 runtime is intentionally kept separate from ModemManager's
//! ordinary data and SMS paths.  This module currently exposes the persisted
//! runtime snapshot used by the API; the DATA6/QMI and SIP workers will update
//! the same snapshot as they are ported.

use serde::{Deserialize, Serialize};
use std::fs;

pub const RUNTIME_STATUS_PATH: &str = "/run/simadmin/volte-status.json";

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeStatus {
    #[serde(default)]
    pub phase: String,
    #[serde(default)]
    pub registered: bool,
    #[serde(default)]
    pub sms_ready: bool,
    #[serde(default)]
    pub transport: String,
    #[serde(default)]
    pub interface: String,
    #[serde(default)]
    pub last_error: String,
}

pub fn read_runtime_status() -> Option<RuntimeStatus> {
    let contents = fs::read_to_string(RUNTIME_STATUS_PATH).ok()?;
    serde_json::from_str(&contents).ok()
}

#[cfg(test)]
mod tests {
    use super::RuntimeStatus;

    #[test]
    fn defaults_missing_runtime_fields() {
        let status: RuntimeStatus = serde_json::from_str(r#"{"registered":true}"#).unwrap();
        assert!(status.registered);
        assert!(!status.sms_ready);
        assert!(status.transport.is_empty());
    }
}
