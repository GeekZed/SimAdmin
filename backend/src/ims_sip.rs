//! Minimal 3GPP IMS SIP REGISTER primitives.

use anyhow::{anyhow, Result};
use std::net::Ipv6Addr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SipRegistration {
    pub private_identity: String,
    pub public_identity: String,
    pub realm: String,
    pub nonce: String,
    pub aka_res_hex: String,
    pub call_id: String,
    pub cseq: u32,
    pub contact_host: Ipv6Addr,
    pub contact_port: u16,
}

pub fn parse_pcscf_address(output: &str) -> Option<Ipv6Addr> {
    output.lines().find_map(|line| {
        let (_, value) = line.split_once(':')?;
        let label = line.split_once(':')?.0.trim().to_ascii_lowercase();
        if !label.contains("p-cscf") && !label.contains("pcscf") {
            return None;
        }
        value
            .trim()
            .trim_matches(['\'', '"', '[', ']'])
            .parse()
            .ok()
    })
}

fn md5_hex(value: &str) -> String {
    let digest = md5::compute(value.as_bytes());
    format!("{digest:x}")
}

pub fn aka_md5_response(
    username: &str,
    realm: &str,
    nonce: &str,
    method: &str,
    uri: &str,
    aka_res_hex: &str,
) -> Result<String> {
    if username.is_empty() || realm.is_empty() || nonce.is_empty() || aka_res_hex.is_empty() {
        return Err(anyhow!("IMS AKA digest fields must not be empty"));
    }
    let ha1 = md5_hex(&format!("{username}:{realm}:{aka_res_hex}"));
    let ha2 = md5_hex(&format!("{method}:{uri}"));
    Ok(md5_hex(&format!("{ha1}:{nonce}:{ha2}")))
}

pub fn build_register(registration: &SipRegistration, branch: &str) -> Result<String> {
    if branch.is_empty() || registration.call_id.is_empty() {
        return Err(anyhow!("SIP branch and Call-ID are required"));
    }
    let uri = format!("sip:{}", registration.realm);
    let response = aka_md5_response(
        &registration.private_identity,
        &registration.realm,
        &registration.nonce,
        "REGISTER",
        &uri,
        &registration.aka_res_hex,
    )?;
    let contact_identity = registration
        .public_identity
        .strip_prefix("sip:")
        .unwrap_or(&registration.public_identity);
    let contact = format!("sip:{}@{}:{}", contact_identity, registration.contact_host, registration.contact_port);

    Ok(format!(
        "REGISTER {uri} SIP/2.0\r\n\
Via: SIP/2.0/UDP [{}]:{};branch={branch};rport\r\n\
From: <{}>;tag=simadmin\r\n\
To: <{}>\r\n\
Call-ID: {}\r\n\
CSeq: {} REGISTER\r\n\
Contact: <{}>\r\n\
Max-Forwards: 70\r\n\
User-Agent: SimAdmin\r\n\
Authorization: Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\", algorithm=AKAv1-MD5\r\n\
Content-Length: 0\r\n\r\n",
        registration.contact_host,
        registration.contact_port,
        registration.public_identity,
        registration.public_identity,
        registration.call_id,
        registration.cseq,
        contact,
        registration.private_identity,
        registration.realm,
        registration.nonce,
        uri,
        response
    ))
}

pub fn sip_status_code(response: &str) -> Option<u16> {
    let first_line = response.lines().next()?;
    let mut fields = first_line.split_whitespace();
    if fields.next()? != "SIP/2.0" {
        return None;
    }
    fields.next()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pcscf_ipv6() {
        assert_eq!(
            parse_pcscf_address("P-CSCF address: '[2001:db8::5]'"),
            Some("2001:db8::5".parse().unwrap())
        );
    }

    #[test]
    fn builds_aka_register() {
        let request = build_register(
            &SipRegistration {
                private_identity: "460001234567890".into(),
                public_identity: "sip:460001234567890@ims.example".into(),
                realm: "ims.example".into(),
                nonce: "nonce".into(),
                aka_res_hex: "0011223344556677".into(),
                call_id: "call-id".into(),
                cseq: 1,
                contact_host: "2001:db8::10".parse().unwrap(),
                contact_port: 5060,
            },
            "z9hG4bK-test",
        )
        .unwrap();
        assert!(request.starts_with("REGISTER sip:ims.example SIP/2.0"));
        assert!(request.contains("algorithm=AKAv1-MD5"));
    }

    #[test]
    fn parses_sip_status() {
        assert_eq!(sip_status_code("SIP/2.0 200 OK\r\n"), Some(200));
    }
}
