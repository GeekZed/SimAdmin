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
use std::process::Stdio;
use tokio::process::{Child, Command};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::task::JoinHandle;

use anyhow::{anyhow, Result};
use ring::rand::{SecureRandom, SystemRandom};
use crate::config::ConfigManager;
use crate::db::Database;
use crate::notification::NotificationSender;
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

struct ActiveImsBearer {
    child: Child,
    settings: QmiBearerSettings,
}

#[derive(Debug, Deserialize)]
struct HelperBearerSettings {
    ipv6: String,
    gateway: String,
    mtu: Option<u32>,
}

fn parse_helper_bearer_settings(line: &str) -> Result<QmiBearerSettings> {
    let settings: HelperBearerSettings = serde_json::from_str(line.trim())
        .map_err(|error| anyhow!("invalid QMI helper bearer JSON: {error}"))?;
    if settings.ipv6.trim().is_empty() || settings.gateway.trim().is_empty() {
        return Err(anyhow!("QMI helper bearer JSON has no IPv6 address or gateway"));
    }
    Ok(QmiBearerSettings {
        ipv6_address: settings.ipv6,
        ipv6_gateway: settings.gateway,
        mtu: settings.mtu,
    })
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

    let ipv6_address = value("IPv6 address:")?.split('/').next()?.to_string();
    let ipv6_gateway = value("IPv6 gateway address:")?.split('/').next()?.to_string();
    let mtu = value("MTU:").and_then(|value| value.parse().ok());
    Some(QmiBearerSettings {
        ipv6_address,
        ipv6_gateway,
        mtu,
    })
}

pub async fn configure_secondary_ipv6_interface(
    netdev: &str,
    settings: &QmiBearerSettings,
    pcscf: std::net::Ipv6Addr,
) -> Result<()> {
    if netdev.trim().is_empty() {
        return Err(anyhow!("secondary IMS network interface is unavailable"));
    }
    let address = settings
        .ipv6_address
        .parse::<std::net::Ipv6Addr>()
        .map_err(|_| anyhow!("secondary IMS IPv6 address is invalid"))?;
    let gateway = settings
        .ipv6_gateway
        .parse::<std::net::Ipv6Addr>()
        .map_err(|_| anyhow!("secondary IMS IPv6 gateway is invalid"))?;
    let prefix = 64;
    for args in [
        vec![
            "link".to_string(),
            "set".to_string(),
            "dev".to_string(),
            netdev.to_string(),
            "up".to_string(),
        ],
        vec![
            "-6".to_string(),
            "addr".to_string(),
            "replace".to_string(),
            format!("{address}/{prefix}"),
            "dev".to_string(),
            netdev.to_string(),
        ],
        vec![
            "-6".to_string(),
            "route".to_string(),
            "replace".to_string(),
            format!("{pcscf}/128"),
            "via".to_string(),
            gateway.to_string(),
            "dev".to_string(),
            netdev.to_string(),
        ],
    ] {
        let output = Command::new("ip").args(args).output().await?;
        if !output.status.success() {
            return Err(anyhow!(
                "failed to configure secondary IMS interface: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
    }
    Ok(())
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

pub fn parse_qmi_client_id(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let (label, value) = line.split_once(':')?;
        if label.trim() != "CID" {
            return None;
        }
        let value = value.trim().trim_matches('\'');
        (!value.is_empty()).then(|| value.to_string())
    })
}

pub fn secondary_netdev(qmi_device: &str) -> String {
    if let Ok(value) = std::env::var("SIMADMIN_SECONDARY_QMI_NETDEV") {
        if !value.trim().is_empty() {
            return value;
        }
    }
    if qmi_device == "/dev/wwan0at2" {
        "wwan1".to_string()
    } else {
        String::new()
    }
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
) -> Result<(String, String, QmiBearerSettings)> {
    if qmi_device.trim().is_empty() || apn.trim().is_empty() {
        return Err(anyhow!("QMI device and IMS APN are required"));
    }

    let mut cid = None;
    let mut last_family_error = String::new();
    for _ in 0..3 {
        let noop = tokio::time::timeout(
            Duration::from_secs(15),
            Command::new("qmicli")
                .kill_on_drop(true)
                .args([
                    "-d",
                    qmi_device,
                    "--device-open-proxy",
                    "--device-open-qmi",
                    "--client-no-release-cid",
                    "--wds-noop",
                ])
                .output(),
        )
        .await;
        let Ok(Ok(noop)) = noop else {
            last_family_error = "timed out allocating secondary IMS WDS client".to_string();
            continue;
        };
        if !noop.status.success() {
            last_family_error = String::from_utf8_lossy(&noop.stderr).trim().to_string();
            continue;
        }
        let Some(candidate) = parse_qmi_client_id(&String::from_utf8_lossy(&noop.stdout)) else {
            last_family_error = "qmicli did not return a secondary IMS WDS client id".to_string();
            continue;
        };
        let family = tokio::time::timeout(
            Duration::from_secs(15),
            Command::new("qmicli")
                .kill_on_drop(true)
                .args([
                    "-d",
                    qmi_device,
                    "--device-open-proxy",
                    "--device-open-qmi",
                    &format!("--client-cid={candidate}"),
                    "--wds-set-ip-family=6",
                ])
                .output(),
        )
        .await;
        match family {
            Ok(Ok(output)) if output.status.success() => {
                cid = Some(candidate);
                break;
            }
            Ok(Ok(output)) => last_family_error = String::from_utf8_lossy(&output.stderr).trim().to_string(),
            _ => last_family_error = "timed out setting secondary IMS IPv6 family".to_string(),
        }
    }
    let cid = cid.ok_or_else(|| anyhow!("secondary IMS IPv6 family setup failed: {last_family_error}"))?;

    // The native DATA6 path in beta9 uses the modem's IMS WDS profile.
    let start_arg = format!("--wds-start-network=apn={apn},3gpp-profile=1,ip-type=6");
    let output = tokio::time::timeout(
        Duration::from_secs(30),
        Command::new("qmicli")
            .kill_on_drop(true)
            .args([
                "-d",
                qmi_device,
                "--device-open-proxy",
                "--device-open-qmi",
                "--device-open-net=net-raw-ip|net-no-qos-header",
                &format!("--client-cid={cid}"),
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
    let mut last_error = None;
    for _ in 0..5 {
        match read_secondary_bearer_settings(qmi_device, Some(&cid)).await {
            Ok(settings) => return Ok((cid, handle, settings)),
            Err(error) => last_error = Some(error),
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    let _ = stop_secondary_ims_bearer(qmi_device, Some(&cid), &handle).await;
    Err(last_error.unwrap_or_else(|| anyhow!("secondary IMS bearer settings unavailable")))
}

async fn start_secondary_ims_bearer_helper(qmi_device: &str) -> Result<ActiveImsBearer> {
    let helper = std::env::var("SIMADMIN_QMI_IMS_HELPER")
        .unwrap_or_else(|_| "/opt/simadmin/qmi-ims-helper".to_string());
    let (child, settings) = tokio::time::timeout(
        Duration::from_secs(45),
        async {
            let mut child = Command::new(&helper)
                .arg(qmi_device)
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .kill_on_drop(true)
                .spawn()
                .map_err(|error| anyhow!("failed to start {helper}: {error}"))?;
            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| anyhow!("{helper} did not expose stdout"))?;
            let mut line = String::new();
            BufReader::new(stdout).read_line(&mut line).await?;
        let settings = parse_helper_bearer_settings(&line)?;
            Ok::<_, anyhow::Error>((child, settings))
        },
    )
    .await
    .map_err(|_| anyhow!("timed out starting secondary IMS bearer helper"))??;
    Ok(ActiveImsBearer {
        child,
        settings,
    })
}

async fn configure_ims_pdp_context(conn: &Connection, modem_path: &str) -> Result<()> {
    // beta9 prepares the modem IMS PDP context before issuing the DATA6 WDS
    // request.  CID 4 is the IMS context reported by CGCONTRDP on this modem.
    for command in [
        r#"AT+CGDCONT=4,"IPV6","ims""#,
        "AT$QCPDPIMSCFGE=4,1,1,1",
    ] {
        crate::modem_manager::send_at_command(conn, modem_path, command)
            .await
            .map_err(|error| anyhow!("IMS PDP setup failed for {command}: {error}"))?;
    }
    Ok(())
}

pub async fn read_secondary_bearer_settings(qmi_device: &str, cid: Option<&str>) -> Result<QmiBearerSettings> {
    let mut args = vec!["-d".to_string(), qmi_device.to_string()];
    if cid.is_some() {
        args.push("--device-open-proxy".to_string());
    }
    args.push("--device-open-qmi".to_string());
    args.push("--device-open-net=net-raw-ip|net-no-qos-header".to_string());
    if let Some(cid) = cid.filter(|value| !value.is_empty()) {
        args.push(format!("--client-cid={cid}"));
    }
    args.push("--wds-get-current-settings".to_string());
    let output = tokio::time::timeout(
        Duration::from_secs(15),
        Command::new("qmicli")
            .kill_on_drop(true)
            .args(&args)
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

#[derive(Debug, Clone, Copy)]
pub struct NativeImsRuntime {
    pub receive_port: u16,
    pub send_port: u16,
}

fn allocate_local_udp_port(local: std::net::Ipv6Addr) -> Result<u16> {
    let socket = std::net::UdpSocket::bind((local, 0))?;
    Ok(socket.local_addr()?.port())
}

pub async fn register_native_ims(
    conn: &Connection,
    settings: &QmiBearerSettings,
    pcscf: std::net::Ipv6Addr,
) -> Result<NativeImsRuntime> {
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
        let mnc = if identity.imsi.starts_with("46011") {
            "011"
        } else if identity.imsi.len() >= 6 {
            &identity.imsi[3..6]
        } else {
            "000"
        };
        format!("ims.mnc{mnc}.mcc{mcc}.3gppnetwork.org")
    });
    let public_identity = format!("sip:{}@{}", identity.imsi, domain);
    let access_network_info = crate::modem_manager::get_cell_location(conn)
        .await
        .ok()
        .and_then(|location| location.cell_info)
        .and_then(|cell| {
            crate::ims_sip::build_lte_access_network_info(&cell.mcc, &cell.mnc, cell.cid)
        })
        .unwrap_or_else(|| "3GPP-E-UTRAN-FDD".to_string());
    // The initial REGISTER is sent from the modem-compatible SIP port.  After
    // the 401 challenge, beta9 moves the runtime to two negotiated local ports:
    // one for inbound SIP and one for outbound protected SIP.
    let initial_port = 5060;
    let call_id_suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let mut registration = crate::ims_sip::SipRegistration {
        private_identity: identity.imsi.clone(),
        public_identity,
        realm: domain,
        nonce: String::new(),
        aka_res_hex: String::new(),
        call_id: format!("simadmin-{call_id_suffix}@simadmin-volte"),
        from_tag: format!("{call_id_suffix:016x}"),
        cseq: 1,
        contact_host: local,
        contact_port: initial_port,
    };
    let mut spi_bytes = [0u8; 8];
    SystemRandom::new()
        .fill(&mut spi_bytes)
        .map_err(|_| anyhow!("failed to generate IMS security proposal"))?;
    let security_header = crate::ims_sip::build_security_client_header(
        u32::from_be_bytes(spi_bytes[..4].try_into().unwrap()),
        u32::from_be_bytes(spi_bytes[4..].try_into().unwrap()),
        initial_port,
        5060,
    );
    let mut challenge_response = None;
    for attempt in 0..3 {
        let initial = crate::ims_sip::build_initial_register(
            &registration,
            &format!("z9hG4bK-simadmin-{attempt}"),
            &access_network_info,
            &security_header,
        )?;
        let response = crate::ims_sip::send_udp_request_from_port(
            local,
            initial_port,
            pcscf,
            5060,
            &initial,
        )
        .await?;
        if crate::ims_sip::sip_status_code(&response) == Some(500) && attempt < 2 {
            tokio::time::sleep(Duration::from_secs(2)).await;
            continue;
        }
        challenge_response = Some(response);
        break;
    }
    let challenge_response = challenge_response
        .ok_or_else(|| anyhow!("IMS initial REGISTER produced no response"))?;
    if crate::ims_sip::sip_status_code(&challenge_response) != Some(401) {
        tracing::warn!(
            response = %challenge_response.lines().take(12).collect::<Vec<_>>().join(" | "),
            "IMS initial REGISTER response"
        );
        return Err(anyhow!(
            "IMS initial REGISTER returned {:?}",
            crate::ims_sip::sip_status_code(&challenge_response)
        ));
    }
    let challenge = crate::ims_sip::parse_aka_challenge(&challenge_response)
        .ok_or_else(|| anyhow!("IMS 401 did not contain an AKA challenge"))?;
    let security = crate::ims_sip::parse_security_server(&challenge_response)
        .ok_or_else(|| anyhow!("IMS 401 did not contain Security-Server"))?;
    let aka_apdu = crate::ims_uim::build_aka_auth_apdu(&challenge.nonce)?;
    let aka_output = crate::modem_manager::send_uim_apdu(
        conn,
        &modem_path,
        "A0000000871002",
        &aka_apdu,
        true,
    )
        .await
        .map_err(|error| anyhow!("IMS AKA APDU failed: {error}"))?;
    let aka_hex = crate::ims_uim::extract_csim_hex(&aka_output)?;
    let aka = crate::ims_uim::parse_aka_response(&aka_hex)?
        .map_err(|_| anyhow!("IMS AKA requested AUTS resynchronization"))?;
    let ik_hex = crate::ims_uim::encode_hex(&aka.ik);
    let receive_port = allocate_local_udp_port(local)?;
    let mut send_port = allocate_local_udp_port(local)?;
    if send_port == receive_port {
        send_port = allocate_local_udp_port(local)?;
    }
    crate::ims_ipsec::install_bidirectional_esp(
        local,
        pcscf,
        security.client_spi,
        security.server_spi,
        &ik_hex,
        send_port,
        receive_port,
        security.server_port,
        security.server_port,
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
    registration.contact_port = receive_port;
    let authenticated = crate::ims_sip::build_register_with_security(
        &registration,
        "z9hG4bK-simadmin-auth",
        &security_header,
    )?;
    let registered = crate::ims_sip::send_udp_request_from_port(
        local,
        send_port,
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
    Ok(NativeImsRuntime {
        receive_port,
        send_port,
    })
}

pub async fn secondary_ims_bearer_connected(qmi_device: &str, cid: Option<&str>) -> Result<bool> {
    let mut args = vec![
        "-d".to_string(), qmi_device.to_string(),
        "--device-open-proxy".to_string(),
        "--device-open-qmi".to_string(),
    ];
    if let Some(cid) = cid.filter(|value| !value.is_empty()) {
        args.push(format!("--client-cid={cid}"));
    }
    args.push("--wds-get-packet-service-status".to_string());
    let output = tokio::time::timeout(
        Duration::from_secs(15),
        Command::new("qmicli")
            .kill_on_drop(true)
            .args(&args)
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

pub async fn stop_secondary_ims_bearer(qmi_device: &str, cid: Option<&str>, packet_handle: &str) -> Result<()> {
    if qmi_device.trim().is_empty() || packet_handle.trim().is_empty() {
        return Err(anyhow!("QMI device and packet handle are required"));
    }

    let stop_arg = format!("--wds-stop-network={packet_handle}");
    let mut args = vec![
        "-d".to_string(), qmi_device.to_string(),
        "--device-open-proxy".to_string(),
        "--device-open-qmi".to_string(),
        "--device-open-net=net-raw-ip|net-no-qos-header".to_string(),
    ];
    if let Some(cid) = cid.filter(|value| !value.is_empty()) {
        args.push(format!("--client-cid={cid}"));
    }
    args.push(stop_arg);
    let output = tokio::time::timeout(
        Duration::from_secs(30),
        Command::new("qmicli")
            .kill_on_drop(true)
            .args(&args)
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
    database: Arc<Database>,
    notifications: Arc<NotificationSender>,
) {
    let mut active: Option<ActiveImsBearer> = None;
    let mut sms_listener: Option<JoinHandle<()>> = None;

    loop {
        let volte = config.get_config().volte;
        if !volte.feature_enabled {
            if let Some(listener) = sms_listener.take() {
                listener.abort();
            }
            if let Some(mut bearer) = active.take() {
                let _ = bearer.child.kill().await;
            }
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
            let netdev = secondary_netdev(&device);

            let modem_path = match crate::modem_manager::find_modem_path(&conn).await {
                Ok(path) => path,
                Err(error) => {
                    let _ = write_runtime_status(&RuntimeStatus {
                        phase: "waiting_for_modem".to_string(),
                        transport: "native_qmi".to_string(),
                        interface: netdev.clone(),
                        last_error: error.to_string(),
                        ..RuntimeStatus::default()
                    });
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
            };
            let _ = write_runtime_status(&RuntimeStatus {
                phase: "starting_ims_bearer".to_string(),
                transport: "native_qmi".to_string(),
                interface: netdev.clone(),
                ..RuntimeStatus::default()
            });
            if let Err(error) = configure_ims_pdp_context(&conn, &modem_path).await {
                tracing::warn!(error = %error, "IMS PDP context setup failed");
            }
            match start_secondary_ims_bearer_helper(&device).await {
                Ok(bearer) => {
                    let settings = bearer.settings.clone();
                    active = Some(bearer);
                    let mut pcscf_address = None;
                    let _ = write_runtime_status(&RuntimeStatus {
                        phase: "usim_aid_selecting".to_string(),
                        transport: "native_qmi".to_string(),
                        ..RuntimeStatus::default()
                    });
                    {
                        let apdu = "00A4040007A0000000871002";
                        let command = match crate::ims_uim::build_csim_command(apdu) {
                                Ok(_) => apdu,
                                Err(error) => {
                                    let _ = write_runtime_status(&RuntimeStatus {
                                        phase: "degraded".to_string(),
                                        transport: "native_qmi".to_string(),
                                        last_error: error.to_string(),
                                        ..RuntimeStatus::default()
                                    });
                                    continue;
                                }
                        };
                        match crate::modem_manager::send_uim_apdu(
                            &conn,
                            &modem_path,
                            "A0000000871002",
                            command,
                            false,
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
                                        phase: "degraded".to_string(),
                                        transport: "native_qmi".to_string(),
                                        last_error: error.to_string(),
                                        ..RuntimeStatus::default()
                                    });
                                }
                            }
                            Err(error) => {
                                let _ = write_runtime_status(&RuntimeStatus {
                                    phase: "degraded".to_string(),
                                    transport: "native_qmi".to_string(),
                                    last_error: error,
                                    ..RuntimeStatus::default()
                                });
                            }
                        }
                    }
                    {
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
                            interface: netdev.clone(),
                            ..RuntimeStatus::default()
                        });
                        if let Err(error) = configure_secondary_ipv6_interface(
                            &netdev,
                            &settings,
                            pcscf,
                        )
                        .await
                        {
                            tracing::error!(error = %error, "Failed to configure native IMS IPv6 interface");
                            let _ = write_runtime_status(&RuntimeStatus {
                                phase: "degraded".to_string(),
                                transport: "native_qmi_ipsec".to_string(),
                                interface: netdev.clone(),
                                last_error: error.to_string(),
                                ..RuntimeStatus::default()
                            });
                            continue;
                        }
                        match register_native_ims(&conn, &settings, pcscf).await {
                            Ok(runtime) => {
                                registration_succeeded = true;
                                if volte.sms_enabled {
                                    let sms_local = settings.ipv6_address.parse().ok();
                                    if let Some(sms_local) = sms_local {
                                        let database_clone = Arc::clone(&database);
                                        let notifications_clone = Arc::clone(&notifications);
                                        sms_listener = Some(tokio::spawn(async move {
                                            if let Err(error) = crate::ims_sms::run_ims_sms_listener(
                                                sms_local,
                                                runtime.receive_port,
                                                runtime.send_port,
                                                database_clone,
                                                notifications_clone,
                                            )
                                            .await
                                            {
                                                tracing::warn!(error = %error, "IMS SMS listener stopped");
                                            }
                                        }));
                                    }
                                }
                                let _ = write_runtime_status(&RuntimeStatus {
                                    phase: "registered".to_string(),
                                    registered: true,
                                    sms_ready: volte.sms_enabled,
                                    transport: "native_qmi_ipsec".to_string(),
                                    interface: netdev.clone(),
                                    ..RuntimeStatus::default()
                                });
                            }
                            Err(error) => {
                                tracing::error!(error = %error, "Native VoLTE IMS registration failed");
                                let _ = write_runtime_status(&RuntimeStatus {
                                    phase: "degraded".to_string(),
                                    transport: "native_qmi_ipsec".to_string(),
                                    last_error: error.to_string(),
                                    ..RuntimeStatus::default()
                                });
                            }
                        }
                    }
                    if !registration_succeeded {
                        if let Some(listener) = sms_listener.take() {
                            listener.abort();
                        }
                        if let Some(mut bearer) = active.take() {
                            let _ = bearer.child.kill().await;
                        }
                        let _ = write_runtime_status(&RuntimeStatus {
                            phase: "degraded".to_string(),
                            transport: "native_qmi".to_string(),
                            interface: netdev.clone(),
                            ..RuntimeStatus::default()
                        });
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                }
                Err(error) => {
                    tracing::error!(error = %error, "Native VoLTE QMI helper failed");
                    let _ = write_runtime_status(&RuntimeStatus {
                        phase: "degraded".to_string(),
                        transport: "native_qmi".to_string(),
                        last_error: error.to_string(),
                        ..RuntimeStatus::default()
                    });
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
            continue;
        }

        let bearer = active.as_mut().expect("active bearer exists");
        match bearer.child.try_wait() {
            Ok(None) => {
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
            Ok(Some(_)) | Err(_) => {
                if let Some(listener) = sms_listener.take() {
                    listener.abort();
                }
                let _ = bearer.child.kill().await;
                active = None;
                let _ = write_runtime_status(&RuntimeStatus {
                    phase: "degraded".to_string(),
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
    fn parses_native_qmi_helper_json() {
        assert_eq!(
            super::parse_helper_bearer_settings(
                r#"{"phase":"bearer_up","ipv6":"2001:db8::10","gateway":"2001:db8::1","mtu":1432}"#
            )
            .unwrap(),
            super::QmiBearerSettings {
                ipv6_address: "2001:db8::10".to_string(),
                ipv6_gateway: "2001:db8::1".to_string(),
                mtu: Some(1432),
            }
        );
    }

    #[test]
    fn strips_qmi_ipv6_prefix_lengths() {
        let output =
            "IPv6 address: 2001:db8::10/64\nIPv6 gateway address: 2001:db8::1/64\nMTU: 1432";
        let settings = super::parse_qmi_bearer_settings(output).unwrap();
        assert_eq!(settings.ipv6_address, "2001:db8::10");
        assert_eq!(settings.ipv6_gateway, "2001:db8::1");
    }

    #[test]
    fn parses_qmi_packet_handle() {
        assert_eq!(
            super::parse_qmi_packet_handle("Packet data handle: '42'"),
            Some("42".to_string())
        );
    }

    #[test]
    fn derives_beta9_secondary_netdev() {
        assert_eq!(super::secondary_netdev("/dev/wwan0at2"), "wwan1");
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
