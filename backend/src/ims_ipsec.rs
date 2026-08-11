//! XFRM/IPsec primitives used by the native IMS registration path.
//!
//! The AKA worker supplies the negotiated keys and SPIs.  This module keeps
//! command construction and validation separate so an incomplete auth result
//! can never install a partial policy.

use anyhow::{anyhow, Result};
use std::net::Ipv6Addr;
use std::process::Stdio;
use tokio::process::Command;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EspSecurityAssociation {
    pub local: Ipv6Addr,
    pub remote: Ipv6Addr,
    pub spi: u32,
    pub auth_key_hex: String,
    pub enc_key_hex: String,
}

impl EspSecurityAssociation {
    fn validate(&self) -> Result<()> {
        if self.spi == 0 {
            return Err(anyhow!("IPsec SPI must be non-zero"));
        }
        if self.auth_key_hex.is_empty() || self.enc_key_hex.is_empty() {
            return Err(anyhow!("IPsec keys must not be empty"));
        }
        if !is_hex(&self.auth_key_hex) || !is_hex(&self.enc_key_hex) {
            return Err(anyhow!("IPsec keys must be hexadecimal"));
        }
        Ok(())
    }

    fn args(&self) -> Vec<String> {
        vec![
            "xfrm".into(),
            "state".into(),
            "add".into(),
            "src".into(),
            self.local.to_string(),
            "dst".into(),
            self.remote.to_string(),
            "proto".into(),
            "esp".into(),
            "spi".into(),
            format!("0x{:08x}", self.spi),
            "mode".into(),
            "transport".into(),
            "auth-trunc".into(),
            "hmac(sha1)".into(),
            self.auth_key_hex.clone(),
            "96".into(),
            "enc".into(),
            "cbc(aes)".into(),
            self.enc_key_hex.clone(),
        ]
    }
}

fn is_hex(value: &str) -> bool {
    value.len() % 2 == 0 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub async fn install_esp_state(sa: &EspSecurityAssociation) -> Result<()> {
    sa.validate()?;
    let output = Command::new("ip")
        .args(sa.args())
        .stdin(Stdio::null())
        .output()
        .await?;
    if !output.status.success() {
        return Err(anyhow!(
            "failed to install IMS IPsec state: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> EspSecurityAssociation {
        EspSecurityAssociation {
            local: "2001:db8::1".parse().unwrap(),
            remote: "2001:db8::2".parse().unwrap(),
            spi: 0x1234,
            auth_key_hex: "aa".repeat(20),
            enc_key_hex: "bb".repeat(16),
        }
    }

    #[test]
    fn rejects_empty_keys() {
        let mut sa = sample();
        sa.auth_key_hex.clear();
        assert!(sa.validate().is_err());
    }

    #[test]
    fn builds_transport_esp_arguments() {
        let args = sample().args();
        assert!(args
            .windows(2)
            .any(|pair| pair[0] == "mode" && pair[1] == "transport"));
        assert!(args.iter().any(|value| value == "0x00001234"));
    }
}
