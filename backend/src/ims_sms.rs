//! Decoding of MT SMS carried in 3GPP IMS SIP MESSAGE bodies.

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::UdpSocket;

use crate::db::{beijing_sms_now_string, Database, SmsMessage};
use crate::notification::NotificationSender;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncomingImsSms {
    pub phone_number: String,
    pub content: String,
    pub marker: String,
}

pub fn parse_sip_message(packet: &[u8]) -> Result<(HashMap<String, String>, Vec<u8>)> {
    let separator = packet
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| anyhow!("IMS SIP MESSAGE headers are incomplete"))?;
    let headers = std::str::from_utf8(&packet[..separator])?;
    let mut parsed = HashMap::new();
    for line in headers.lines().skip(1) {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| anyhow!("IMS SIP MESSAGE header is malformed"))?;
        parsed.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
    }
    Ok((parsed, packet[separator + 4..].to_vec()))
}

fn decode_hex(input: &str) -> Result<Vec<u8>> {
    if input.len() % 2 != 0 || !input.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(anyhow!("IMS SMS body is not hexadecimal"));
    }
    (0..input.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&input[index..index + 2], 16).map_err(Into::into))
        .collect()
}

fn decode_address(bytes: &[u8], digits: usize) -> Result<(String, usize)> {
    let octets = digits.div_ceil(2);
    if bytes.len() < octets + 1 {
        return Err(anyhow!("IMS SMS address is truncated"));
    }
    let toa = bytes[0];
    let mut number = String::new();
    for byte in &bytes[1..octets + 1] {
        for nibble in [byte & 0x0f, byte >> 4] {
            if number.len() < digits && nibble <= 9 {
                number.push(char::from(b'0' + nibble));
            }
        }
    }
    if toa & 0x70 == 0x10 {
        number.insert(0, '+');
    }
    Ok((number, octets + 1))
}

fn gsm7_char(value: u8) -> char {
    if value < 0x20 {
        return match value {
            0x0a => '\n',
            0x0d => '\r',
            _ => ' ',
        };
    }
    if value < 0x7f {
        return value as char;
    }
    '?'
}

fn decode_gsm7(data: &[u8], septets: usize) -> String {
    (0..septets)
        .map(|index| {
            let bit = index * 7;
            let byte = bit / 8;
            let shift = bit % 8;
            let mut value = (data.get(byte).copied().unwrap_or_default() >> shift) & 0x7f;
            if shift > 1 {
                value |= data.get(byte + 1).copied().unwrap_or_default() << (8 - shift);
                value &= 0x7f;
            }
            gsm7_char(value)
        })
        .collect()
}

fn decode_sms_deliver(tpdu: &[u8]) -> Result<(String, String)> {
    if tpdu.len() < 2 || tpdu[0] & 0x03 != 0x00 {
        return Err(anyhow!("IMS TPDU is not SMS-DELIVER"));
    }
    let address_digits = tpdu[1] as usize;
    let (phone_number, address_len) = decode_address(&tpdu[2..], address_digits)?;
    let mut index = 2 + address_len + 2 + 7;
    if tpdu.len() <= index {
        return Err(anyhow!("IMS SMS-DELIVER user data is missing"));
    }
    let dcs = tpdu[2 + address_len + 1];
    let length = tpdu[index] as usize;
    index += 1;
    let data = &tpdu[index..];
    let content = if dcs & 0x0c == 0x08 {
        if data.len() < length || length % 2 != 0 {
            return Err(anyhow!("IMS UCS2 SMS data is truncated"));
        }
        String::from_utf16(
            &data[..length]
                .chunks_exact(2)
                .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
                .collect::<Vec<_>>(),
        )?
    } else if dcs & 0x0c == 0x00 {
        decode_gsm7(data, length)
    } else {
        String::from_utf8_lossy(&data[..length.min(data.len())]).into_owned()
    };
    Ok((phone_number, content))
}

pub fn decode_ims_sms(body_hex: &str) -> Result<IncomingImsSms> {
    let rp_data = decode_hex(body_hex)?;
    if rp_data.len() < 4 || rp_data[0] != 0x00 {
        return Err(anyhow!("IMS body is not RP-DATA"));
    }
    let mut index = 2;
    let originator_length = rp_data[index] as usize;
    index += 1 + originator_length;
    let destination_length = *rp_data
        .get(index)
        .ok_or_else(|| anyhow!("IMS RP-DATA destination is missing"))? as usize;
    index += 1 + destination_length;
    let user_data_length = *rp_data
        .get(index)
        .ok_or_else(|| anyhow!("IMS RP-DATA user data is missing"))? as usize;
    index += 1;
    if rp_data.len() < index + user_data_length {
        return Err(anyhow!("IMS RP-DATA user data is truncated"));
    }
    let (phone_number, content) = decode_sms_deliver(&rp_data[index..index + user_data_length])?;
    let marker = format!("volte-mt:{:x}", md5::compute(body_hex.as_bytes()));
    Ok(IncomingImsSms {
        phone_number,
        content,
        marker,
    })
}

pub fn decode_ims_sms_body(body: &[u8]) -> Result<IncomingImsSms> {
    let body_hex: String = if body.iter().all(|byte| byte.is_ascii_hexdigit() || byte.is_ascii_whitespace()) {
        String::from_utf8(body.to_vec())?
            .chars()
            .filter(|character| !character.is_ascii_whitespace())
            .collect()
    } else {
        body.iter().map(|byte| format!("{byte:02X}")).collect()
    };
    decode_ims_sms(&body_hex)
}

fn sip_ok_response(headers: &HashMap<String, String>) -> String {
    let mut response = String::from("SIP/2.0 200 OK\r\n");
    for name in ["via", "from", "to", "call-id", "cseq"] {
        if let Some(value) = headers.get(name) {
            response.push_str(name);
            response.push_str(": ");
            response.push_str(value);
            response.push_str("\r\n");
        }
    }
    response.push_str("Content-Length: 0\r\n\r\n");
    response
}

pub async fn run_ims_sms_listener(
    local: std::net::Ipv6Addr,
    port: u16,
    database: Arc<Database>,
    notifications: Arc<NotificationSender>,
) -> Result<()> {
    let socket = UdpSocket::bind((local, port)).await?;
    let mut buffer = vec![0u8; 8192];
    loop {
        let (length, peer) = socket.recv_from(&mut buffer).await?;
        let packet = &buffer[..length];
        let Ok((headers, body)) = parse_sip_message(packet) else {
            continue;
        };
        let is_message = packet
            .windows(2)
            .position(|window| window == b"\r\n")
            .and_then(|end| std::str::from_utf8(&packet[..end]).ok())
            .is_some_and(|line| line.starts_with("MESSAGE "));
        let content_type = headers
            .get("content-type")
            .map(|value| value.to_ascii_lowercase())
            .unwrap_or_default();
        if !is_message || !content_type.contains("application/vnd.3gpp.sms") {
            continue;
        }
        let response = sip_ok_response(&headers);
        let _ = socket.send_to(response.as_bytes(), peer).await;
        let Ok(incoming) = decode_ims_sms_body(&body) else {
            continue;
        };
        if database.sms_exists_by_pdu(&incoming.marker)? {
            continue;
        }
        let timestamp = beijing_sms_now_string();
        let id = database.insert_sms_at(
            "incoming",
            &incoming.phone_number,
            &incoming.content,
            &timestamp,
            "received",
            Some(&incoming.marker),
        )?;
        let message = SmsMessage {
            id,
            direction: "incoming".to_string(),
            phone_number: incoming.phone_number,
            content: incoming.content,
            timestamp,
            status: "received".to_string(),
            pdu: Some(incoming.marker),
        };
        let _ = notifications.forward_sms(&message).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_ucs2_sms_deliver() {
        let tpdu = "040B912143658709F1000832122310123400044F60597D";
        let rp = format!("00000000{:02X}{}", tpdu.len() / 2, tpdu);
        let sms = decode_ims_sms(&rp).unwrap();
        assert_eq!(sms.phone_number, "+12345678901");
        assert_eq!(sms.content, "你好");
        assert!(sms.marker.starts_with("volte-mt:"));
    }

    #[test]
    fn parses_sip_message_body() {
        let packet = b"MESSAGE sip:x SIP/2.0\r\nContent-Type: application/vnd.3gpp.sms\r\n\r\nAABB";
        let (headers, body) = parse_sip_message(packet).unwrap();
        assert_eq!(headers.get("content-type").unwrap(), "application/vnd.3gpp.sms");
        assert_eq!(body, b"AABB");
    }

    #[test]
    fn accepts_binary_sms_body() {
        let body = [0x00, 0x00, 0x00, 0x00, 0x01, 0x04];
        assert!(decode_ims_sms_body(&body).is_err());
    }
}
