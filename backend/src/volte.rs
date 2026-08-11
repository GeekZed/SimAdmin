//! Native IMS/VoLTE runtime boundary.
//!
//! The beta9 runtime is intentionally kept separate from ModemManager's
//! ordinary data and SMS paths.  This module currently exposes the persisted
//! runtime snapshot used by the API; the DATA6/QMI and SIP workers will update
//! the same snapshot as they are ported.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Command;

use anyhow::{anyhow, Result};
use crate::config::ConfigManager;
use zbus::Connection;

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

pub fn write_runtime_status(status: &RuntimeStatus) -> Result<()> {
    let path = Path::new(RUNTIME_STATUS_PATH);
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("invalid VoLTE runtime status path"))?;
    fs::create_dir_all(parent)?;
    let temporary = path.with_extension("json.tmp");
    fs::write(&temporary, serde_json::to_vec(status)?)?;
    fs::rename(temporary, path)?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QmiBearerSettings {
    pub ipv6_address: String,
    pub ipv6_gateway: String,
    pub mtu: Option<u32>,
}

/// Parse the stable fields emitted by `qmicli --wds-get-current-settings`.
/// The parser intentionally ignores localized labels and fields that are not
/// needed by the IMS path; callers must still validate that both IPv6 values
/// are present before installing routes or XFRM policies.
pub fn parse_qmi_bearer_settings(output: &str) -> Option<QmiBearerSettings> {
    let value = |label: &str| {
        output
            .lines()
            .find_map(|line| line.trim().strip_prefix(label))
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    };

    let ipv6_address = value("IPv6 address:")?;
    let ipv6_gateway = value("IPv6 gateway address:")?;
    let mtu = value("MTU:").and_then(|value| value.parse().ok());
    Some(QmiBearerSettings {
        ipv6_address,
        ipv6_gateway,
        mtu,
    })
}

pub fn parse_qmi_packet_handle(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let (label, value) = line.split_once(':')?;
        if label.trim() == "Packet data handle" {
            let value = value.trim().trim_matches('\'');
            (!value.is_empty()).then(|| value.to_string())
        } else {
            None
        }
    })
}

pub fn parse_qmi_connection_status(output: &str) -> Option<bool> {
    output.lines().find_map(|line| {
        let (label, value) = line.split_once(':')?;
        if label.trim() != "Connection status" {
            return None;
        }
        match value.trim().trim_matches('\'') {
            "connected" => Some(true),
            "disconnected" => Some(false),
            _ => None,
        }
    })
}

pub async fn start_secondary_ims_bearer(
    qmi_device: &str,
    apn: &str,
) -> Result<(String, QmiBearerSettings)> {
    if qmi_device.trim().is_empty() || apn.trim().is_empty() {
        return Err(anyhow!("QMI device and IMS APN are required"));
    }

    let start_arg = format!("--wds-start-network=apn={apn},ip-type=6");
    let output = tokio::time::timeout(
        Duration::from_secs(30),
        Command::new("qmicli")
            .args([
                "-d",
                qmi_device,
                "--device-open-proxy",
                &start_arg,
            ])
            .output(),
    )
    .await
    .map_err(|_| anyhow!("timed out starting secondary IMS bearer"))??;

    if !output.status.success() {
        return Err(anyhow!(
            "qmicli failed to start secondary IMS bearer: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let handle = parse_qmi_packet_handle(&stdout)
        .ok_or_else(|| anyhow!("qmicli did not return a packet data handle"))?;
    let settings = read_secondary_bearer_settings(qmi_device).await?;
    Ok((handle, settings))
}

pub async fn read_secondary_bearer_settings(qmi_device: &str) -> Result<QmiBearerSettings> {
    let output = tokio::time::timeout(
        Duration::from_secs(15),
        Command::new("qmicli")
            .args([
                "-d",
                qmi_device,
                "--device-open-proxy",
                "--wds-get-current-settings",
            ])
            .output(),
    )
    .await
    .map_err(|_| anyhow!("timed out reading secondary IMS bearer settings"))??;

    if !output.status.success() {
        return Err(anyhow!(
            "qmicli failed to read secondary IMS bearer settings: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    parse_qmi_bearer_settings(&String::from_utf8_lossy(&output.stdout))
        .ok_or_else(|| anyhow!("secondary IMS bearer did not provide IPv6 settings"))
}

pub async fn register_native_ims(
    conn: &Connection,
    settings: &QmiBearerSettings,
    pcscf: std::net::Ipv6Addr,
) -> Result<()> {
    let local: std::net::Ipv6Addr = settings
        .ipv6_address
        .parse()
        .map_err(|_| anyhow!("IMS bearer IPv6 address is invalid"))?;
    let modem_path = crate::modem_manager::find_modem_path(conn)
        .await
        .map_err(|error| anyhow!("cannot find modem for IMS AKA: {error}"))?;
    let identity = crate::modem_manager::current_sim_identity(conn)
        .await
        .ok_or_else(|| anyhow!("IMS modem identity is unavailable"))?;
    if identity.imsi.is_empty() {
        return Err(anyhow!("IMS modem IMSI is unavailable"));
    }
    let domain = std::env::var("SIMADMIN_IMS_DOMAIN").unwrap_or_else(|_| {
        let mcc = &identity.imsi[..3.min(identity.imsi.len())];
        let mnc = if identity.imsi.len() >= 6 {
            &identity.imsi[3..6]
        } else {
            "000"
        };
        format!("ims.mnc{mnc}.mcc{mcc}.3gppnetwork.org")
    });
    let public_identity = format!("sip:{}@{}", identity.imsi, domain);
    let mut registration = crate::ims_sip::SipRegistration {
        private_identity: identity.imsi.clone(),
        public_identity,
        realm: domain,
        nonce: String::new(),
        aka_res_hex: String::new(),
        call_id: format!(
            "simadmin-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or_default()
        ),
        cseq: 1,
        contact_host: local,
        contact_port: 5062,
    };
    let initial = crate::ims_sip::build_initial_register(&registration, "z9hG4bK-simadmin")?;
    let challenge_response = crate::ims_sip::send_udp_request_from_port(
        local,
        5062,
        pcscf,
        5060,
        &initial,
    )
    .await?;
    if crate::ims_sip::sip_status_code(&challenge_response) != Some(401) {
        return Err(anyhow!(
            "IMS initial REGISTER returned {:?}",
            crate::ims_sip::sip_status_code(&challenge_response)
        ));
    }
    let challenge = crate::ims_sip::parse_aka_challenge(&challenge_response)
        .ok_or_else(|| anyhow!("IMS 401 did not contain an AKA challenge"))?;
    let security = crate::ims_sip::parse_security_server(&challenge_response)
        .ok_or_else(|| anyhow!("IMS 401 did not contain Security-Server"))?;
    let aka_command = crate::ims_uim::build_aka_auth_command(&challenge.nonce)?;
    let aka_output = crate::modem_manager::send_at_command(conn, &modem_path, &aka_command)
        .await
        .map_err(|error| anyhow!("IMS AKA APDU failed: {error}"))?;
    let aka_hex = crate::ims_uim::extract_csim_hex(&aka_output)?;
    let aka = crate::ims_uim::parse_aka_response(&aka_hex)?
        .map_err(|_| anyhow!("IMS AKA requested AUTS resynchronization"))?;
    let ik_hex = crate::ims_uim::encode_hex(&aka.ik);
    crate::ims_ipsec::install_bidirectional_esp(
        local,
        pcscf,
        security.client_spi,
        security.server_spi,
        &ik_hex,
    )
    .await?;
    registration.realm = challenge.realm;
    registration.nonce = challenge.nonce;
    registration.aka_res_hex = crate::ims_uim::encode_hex(&aka.res);
    registration.cseq = 2;
    let security_header = crate::ims_sip::build_security_client_header(
        security.client_spi,
        security.server_spi,
        security.client_port,
        security.server_port,
    );
    let authenticated = crate::ims_sip::build_register_with_security(
        &registration,
        "z9hG4bK-simadmin-auth",
        &security_header,
    )?;
    let registered = crate::ims_sip::send_udp_request_from_port(
        local,
        security.client_port,
        pcscf,
        security.server_port,
        &authenticated,
    )
    .await?;
    if crate::ims_sip::sip_status_code(&registered) != Some(200) {
        return Err(anyhow!(
            "IMS authenticated REGISTER returned {:?}",
            crate::ims_sip::sip_status_code(&registered)
        ));
    }
    Ok(())
}

pub async fn secondary_ims_bearer_connected(qmi_device: &str) -> Result<bool> {
    let output = tokio::time::timeout(
        Duration::from_secs(15),
        Command::new("qmicli")
            .args([
                "-d",
                qmi_device,
                "--device-open-proxy",
                "--wds-get-packet-service-status",
            ])
            .output(),
    )
    .await
    .map_err(|_| anyhow!("timed out reading secondary IMS bearer status"))??;

    if !output.status.success() {
        return Err(anyhow!(
            "qmicli failed to read secondary IMS bearer status: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    parse_qmi_connection_status(&String::from_utf8_lossy(&output.stdout))
        .ok_or_else(|| anyhow!("secondary IMS bearer status was not recognized"))
}

pub async fn stop_secondary_ims_bearer(qmi_device: &str, packet_handle: &str) -> Result<()> {
    if qmi_device.trim().is_empty() || packet_handle.trim().is_empty() {
        return Err(anyhow!("QMI device and packet handle are required"));
    }

    let stop_arg = format!("--wds-stop-network={packet_handle}");
    let output = tokio::time::timeout(
        Duration::from_secs(30),
        Command::new("qmicli")
            .args(["-d", qmi_device, "--device-open-proxy", &stop_arg])
            .output(),
    )
    .await
    .map_err(|_| anyhow!("timed out stopping secondary IMS bearer"))??;

    if !output.status.success() {
        return Err(anyhow!(
            "qmicli failed to stop secondary IMS bearer: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    Ok(())
}

pub async fn run_secondary_ims_bearer_supervisor(
    config: Arc<ConfigManager>,
    conn: Arc<Connection>,
) {
    let mut active: Option<(String, String)> = None;

    loop {
        let volte = config.get_config().volte;
        if !volte.feature_enabled {
            active = None;
            let _ = write_runtime_status(&RuntimeStatus {
                phase: "disabled".to_string(),
                transport: "native_qmi".to_string(),
                ..RuntimeStatus::default()
            });
            tokio::time::sleep(Duration::from_secs(10)).await;
            continue;
        }

        if active.is_none() {
            let device = std::env::var("SIMADMIN_SECONDARY_QMI_DEVICE")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .or_else(|| {
                    fs::read_to_string("/run/simadmin/secondary-qmi-device")
                        .ok()
                        .map(|value| value.trim().to_string())
                });
            let Some(device) = device else {
                let _ = write_runtime_status(&RuntimeStatus {
                    phase: "waiting_for_secondary_qmi".to_string(),
                    transport: "native_qmi".to_string(),
                    last_error: "secondary QMI device is unavailable".to_string(),
                    ..RuntimeStatus::default()
                });
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            };

            let _ = write_runtime_status(&RuntimeStatus {
                phase: "starting_ims_bearer".to_string(),
                transport: "native_qmi".to_string(),
                interface: std::env::var("SIMADMIN_SECONDARY_QMI_NETDEV").unwrap_or_default(),
                ..RuntimeStatus::default()
            });
            match start_secondary_ims_bearer(&device, "ims").await {
                Ok((handle, settings)) => {
                    active = Some((device, handle));
                    let mut pcscf_address = None;
                    let _ = write_runtime_status(&RuntimeStatus {
                        phase: "usim_aid_selecting".to_string(),
                        transport: "native_qmi".to_string(),
                        ..RuntimeStatus::default()
                    });
                    match crate::modem_manager::find_modem_path(&conn).await {
                        Ok(modem_path) => {
                            let command = match crate::ims_uim::build_csim_command(
                                "00A4040007A0000000871002",
                            ) {
                                Ok(command) => command,
                                Err(error) => {
                                    let _ = write_runtime_status(&RuntimeStatus {
                                        phase: "usim_aid_failed".to_string(),
                                        transport: "native_qmi".to_string(),
                                        last_error: error.to_string(),
                                        ..RuntimeStatus::default()
                                    });
                                    continue;
                                }
                            };
                            match crate::modem_manager::send_at_command(
                                &conn,
                                &modem_path,
                                &command,
                            )
                            .await
                            {
                                Ok(response) => match crate::ims_uim::extract_csim_hex(&response)
                                    .and_then(|hex| {
                                        crate::ims_uim::parse_aid_from_select_response(&hex)
                                            .map(|_| ())
                                    }) {
                                    Ok(()) => {}
                                    Err(error) => {
                                        let _ = write_runtime_status(&RuntimeStatus {
                                            phase: "usim_aid_failed".to_string(),
                                            transport: "native_qmi".to_string(),
                                            last_error: error.to_string(),
                                            ..RuntimeStatus::default()
                                        });
                                    }
                                },
                                Err(error) => {
                                    let _ = write_runtime_status(&RuntimeStatus {
                                        phase: "usim_aid_failed".to_string(),
                                        transport: "native_qmi".to_string(),
                                        last_error: error,
                                        ..RuntimeStatus::default()
                                    });
                                }
                            }
                        }
                        Err(error) => {
                            let _ = write_runtime_status(&RuntimeStatus {
                                phase: "usim_aid_failed".to_string(),
                                transport: "native_qmi".to_string(),
                                last_error: error.to_string(),
                                ..RuntimeStatus::default()
                            });
                        }
                    }
                    if let Ok(modem_path) = crate::modem_manager::find_modem_path(&conn).await {
                        match crate::modem_manager::send_at_command(
                            &conn,
                            &modem_path,
                            "AT+CGCONTRDP",
                        )
                        .await
                        {
                            Ok(response) => {
                                if let Some(pcscf) = crate::ims_sip::parse_pcscf_from_cgcontrdp(&response)
                                {
                                    tracing::info!(pcscf = %pcscf, "IMS P-CSCF discovered");
                                    pcscf_address = Some(pcscf);
                                    let _ = write_runtime_status(&RuntimeStatus {
                                        phase: "pcscf_discovered".to_string(),
                                        transport: "native_qmi".to_string(),
                                        ..RuntimeStatus::default()
                                    });
                                }
                            }
                            Err(error) => tracing::debug!(error = %error, "IMS P-CSCF AT query failed"),
                        }
                    }
                    let mut registration_succeeded = false;
                    if let Some(pcscf) = pcscf_address {
                        let _ = write_runtime_status(&RuntimeStatus {
                            phase: "ims_registering".to_string(),
                            transport: "native_qmi_ipsec".to_string(),
                            interface: std::env::var("SIMADMIN_SECONDARY_QMI_NETDEV")
                                .unwrap_or_default(),
                            ..RuntimeStatus::default()
                        });
                        match register_native_ims(&conn, &settings, pcscf).await {
                            Ok(()) => {
                                registration_succeeded = true;
                                let _ = write_runtime_status(&RuntimeStatus {
                                    phase: "registered".to_string(),
                                    registered: true,
                                    sms_ready: volte.sms_enabled,
                                    transport: "native_qmi_ipsec".to_string(),
                                    interface: std::env::var("SIMADMIN_SECONDARY_QMI_NETDEV")
                                        .unwrap_or_default(),
                                    ..RuntimeStatus::default()
                                });
                            }
                            Err(error) => {
                                let _ = write_runtime_status(&RuntimeStatus {
                                    phase: "register_failed".to_string(),
                                    transport: "native_qmi_ipsec".to_string(),
                                    last_error: error.to_string(),
                                    ..RuntimeStatus::default()
                                });
                            }
                        }
                    }
                    if !registration_succeeded {
                        let _ = write_runtime_status(&RuntimeStatus {
                            phase: "bearer_connected".to_string(),
                            transport: "native_qmi".to_string(),
                            interface: std::env::var("SIMADMIN_SECONDARY_QMI_NETDEV")
                                .unwrap_or_default(),
                            ..RuntimeStatus::default()
                        });
                    }
                }
                Err(error) => {
                    let _ = write_runtime_status(&RuntimeStatus {
                        phase: "bearer_failed".to_string(),
                        transport: "native_qmi".to_string(),
                        last_error: error.to_string(),
                        ..RuntimeStatus::default()
                    });
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
            continue;
        }

        let (device, handle) = active.as_ref().expect("active bearer exists");
        match secondary_ims_bearer_connected(device).await {
            Ok(true) => {
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
            Ok(false) | Err(_) => {
                let _ = stop_secondary_ims_bearer(device, handle).await;
                active = None;
                let _ = write_runtime_status(&RuntimeStatus {
                    phase: "bearer_disconnected".to_string(),
                    transport: "native_qmi".to_string(),
                    ..RuntimeStatus::default()
                });
            }
        }
    }
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

    #[test]
    fn parses_qmi_ipv6_settings() {
        let output = "IPv6 address: 2001:db8::10\nIPv6 gateway address: 2001:db8::1\nMTU: 1432";
        assert_eq!(
            super::parse_qmi_bearer_settings(output),
            Some(super::QmiBearerSettings {
                ipv6_address: "2001:db8::10".to_string(),
                ipv6_gateway: "2001:db8::1".to_string(),
                mtu: Some(1432),
            })
        );
    }

    #[test]
    fn parses_qmi_packet_handle() {
        assert_eq!(
            super::parse_qmi_packet_handle("Packet data handle: '42'"),
            Some("42".to_string())
        );
    }

    #[test]
    fn parses_qmi_connection_status() {
        assert_eq!(
            super::parse_qmi_connection_status("Connection status: 'connected'"),
            Some(true)
        );
        assert_eq!(
            super::parse_qmi_connection_status("Connection status: 'disconnected'"),
            Some(false)
        );
    }
}
