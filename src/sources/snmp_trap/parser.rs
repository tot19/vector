use bytes::Bytes;
use serde_json::json;
use smallvec::{SmallVec, smallvec};
use snmp_parser::{
    parse_snmp_v1, parse_snmp_v2c, parse_snmp_v3,
    snmp::{
        NetworkAddress, ObjectSyntax, PduType, SnmpGenericPdu, SnmpMessage, SnmpPdu, SnmpVariable,
        VarBindValue,
    },
};
use std::net::SocketAddr;
use vector_lib::event::{Event, LogEvent};

use super::mib::{MibResolver, OidResolution};

pub(crate) const MAX_SNMP_MESSAGE_SIZE: usize = 65_507;

const SYS_UP_TIME_OID: &str = "1.3.6.1.2.1.1.3.0";
const SNMP_TRAP_OID: &str = "1.3.6.1.6.3.1.1.4.1.0";

#[derive(Debug)]
pub(crate) struct ParsedSnmpNotification {
    pub events: SmallVec<[Event; 1]>,
    pub response: Option<Bytes>,
}

#[derive(Debug)]
pub enum ParseError {
    MalformedMessage(String),
    UnsupportedVersion(&'static str),
    TrailingData(usize),
    InvalidPduType(PduType),
    InvalidV1Trap(&'static str),
    InvalidV2cNotification(&'static str),
    InvalidRequestId(&'static str),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::MalformedMessage(msg) => write!(f, "failed to parse SNMP message: {msg}"),
            ParseError::UnsupportedVersion(msg) => write!(f, "{msg}"),
            ParseError::TrailingData(bytes) => {
                write!(f, "SNMP message contained {bytes} trailing bytes")
            }
            ParseError::InvalidPduType(pdu_type) => {
                write!(f, "invalid PDU type for SNMP notification: {pdu_type:?}")
            }
            ParseError::InvalidV1Trap(message) => {
                write!(f, "invalid RFC 1157 SNMPv1 trap: {message}")
            }
            ParseError::InvalidV2cNotification(message) => {
                write!(f, "invalid RFC 3416 SNMPv2 notification: {message}")
            }
            ParseError::InvalidRequestId(message) => {
                write!(f, "invalid RFC 3416 request-id: {message}")
            }
        }
    }
}

impl std::error::Error for ParseError {}

impl ParseError {
    pub(crate) const fn error_code(&self) -> &'static str {
        match self {
            ParseError::MalformedMessage(_) => "malformed_message",
            ParseError::UnsupportedVersion(_) => "unsupported_version",
            ParseError::TrailingData(_) => "trailing_data",
            ParseError::InvalidPduType(_) => "invalid_pdu_type",
            ParseError::InvalidV1Trap(_) => "invalid_v1_trap",
            ParseError::InvalidV2cNotification(_) => "invalid_v2c_notification",
            ParseError::InvalidRequestId(_) => "invalid_request_id",
        }
    }
}

pub fn parse_snmp_trap(
    data: &Bytes,
    source_addr: SocketAddr,
    mib_resolver: &MibResolver,
) -> Result<ParsedSnmpNotification, ParseError> {
    if let Ok((remaining, message)) = parse_snmp_v1(data) {
        ensure_consumed(remaining)?;
        return parse_v1_trap(message, data, source_addr, mib_resolver);
    }

    if let Ok((remaining, message)) = parse_snmp_v2c(data) {
        ensure_consumed(remaining)?;
        let request_id = raw_v2c_request_id(data)?;
        return parse_v2c_notification(message, request_id, source_addr, mib_resolver);
    }

    if let Some((patched, request_id)) = patch_negative_v2c_request_id(data)?
        && let Ok((remaining, message)) = parse_snmp_v2c(&patched)
    {
        ensure_consumed(remaining)?;
        return parse_v2c_notification(message, request_id, source_addr, mib_resolver);
    }

    if parse_snmp_v3(data).is_ok() {
        return Err(ParseError::UnsupportedVersion(
            "SNMPv3 trap parsing is not supported because RFC 3414 authentication and timeliness checks, and RFC 3826 AES privacy handling, are not implemented",
        ));
    }

    Err(ParseError::MalformedMessage(
        "could not parse as SNMPv1 trap or SNMPv2c notification".to_string(),
    ))
}

const fn ensure_consumed(remaining: &[u8]) -> Result<(), ParseError> {
    if remaining.is_empty() {
        Ok(())
    } else {
        Err(ParseError::TrailingData(remaining.len()))
    }
}

fn parse_v1_trap(
    message: SnmpMessage<'_>,
    data: &Bytes,
    source_addr: SocketAddr,
    mib_resolver: &MibResolver,
) -> Result<ParsedSnmpNotification, ParseError> {
    match message.pdu {
        SnmpPdu::TrapV1(trap) => {
            let mut log = LogEvent::default();
            let enterprise_oid = trap.enterprise.to_string();
            let generic_trap = raw_v1_generic_trap(data)?;
            let generic_trap = u8::try_from(generic_trap).map_err(|_| {
                ParseError::InvalidV1Trap("generic-trap must be in the RFC 1157 range 0..=6")
            })?;
            if generic_trap > 6 {
                return Err(ParseError::InvalidV1Trap(
                    "generic-trap must be in the RFC 1157 range 0..=6",
                ));
            }

            log.insert("snmp_version", "1");
            log.insert("pdu_type", "trap_v1");
            log.insert("source_address", source_addr.to_string());
            log.insert("community", message.community);
            log.insert("enterprise_oid", enterprise_oid.as_str());
            insert_oid_resolution(&mut log, "enterprise_oid", &enterprise_oid, mib_resolver);
            log.insert("agent_address", format_network_address(trap.agent_addr));
            log.insert("generic_trap", generic_trap as i64);
            log.insert("generic_trap_name", trap_type_name(generic_trap));
            log.insert("specific_trap", trap.specific_trap as i64);
            log.insert("uptime", trap.timestamp as i64);
            log.insert("varbinds", format_varbinds(&trap.var, mib_resolver));
            log.insert(
                "message",
                format!(
                    "SNMPv1 trap from {} ({}): {}",
                    source_addr,
                    trap.enterprise,
                    trap_type_name(generic_trap)
                ),
            );

            Ok(ParsedSnmpNotification {
                events: smallvec![Event::Log(log)],
                response: None,
            })
        }
        other => Err(ParseError::InvalidPduType(other.pdu_type())),
    }
}

fn parse_v2c_notification(
    message: SnmpMessage<'_>,
    request_id: i64,
    source_addr: SocketAddr,
    mib_resolver: &MibResolver,
) -> Result<ParsedSnmpNotification, ParseError> {
    match message.pdu {
        SnmpPdu::Generic(ref pdu)
            if pdu.pdu_type == PduType::TrapV2 || pdu.pdu_type == PduType::InformRequest =>
        {
            let notification_kind = match pdu.pdu_type {
                PduType::TrapV2 => "trap_v2",
                PduType::InformRequest => "inform_request",
                _ => unreachable!(),
            };

            let mut log = LogEvent::default();
            let (uptime, trap_oid) = validate_v2c_notification_varbinds(pdu)?;

            log.insert("snmp_version", "2c");
            log.insert("pdu_type", notification_kind);
            log.insert("source_address", source_addr.to_string());
            log.insert("community", message.community.as_str());
            log.insert("request_id", request_id);
            log.insert("uptime", uptime);
            log.insert("trap_oid", trap_oid.clone());
            insert_oid_resolution(&mut log, "trap_oid", &trap_oid, mib_resolver);
            log.insert("varbinds", format_varbinds(&pdu.var, mib_resolver));
            log.insert(
                "message",
                format!(
                    "SNMPv2c {} from {}: {}",
                    if pdu.pdu_type == PduType::InformRequest {
                        "inform"
                    } else {
                        "trap"
                    },
                    source_addr,
                    trap_oid
                ),
            );

            let response = (pdu.pdu_type == PduType::InformRequest)
                .then(|| build_inform_response(message.community.as_bytes(), request_id, pdu))
                .flatten();

            Ok(ParsedSnmpNotification {
                events: smallvec![Event::Log(log)],
                response,
            })
        }
        other => Err(ParseError::InvalidPduType(other.pdu_type())),
    }
}

fn validate_v2c_notification_varbinds(
    pdu: &SnmpGenericPdu<'_>,
) -> Result<(i64, String), ParseError> {
    let Some(uptime) = pdu.var.first() else {
        return Err(ParseError::InvalidV2cNotification(
            "missing sysUpTime.0 and snmpTrapOID.0 varbinds",
        ));
    };

    if uptime.oid.to_string() != SYS_UP_TIME_OID {
        return Err(ParseError::InvalidV2cNotification(
            "first varbind must be sysUpTime.0",
        ));
    }

    let VarBindValue::Value(ObjectSyntax::TimeTicks(uptime_value)) = &uptime.val else {
        return Err(ParseError::InvalidV2cNotification(
            "sysUpTime.0 varbind must contain TimeTicks",
        ));
    };

    let Some(trap_oid) = pdu.var.get(1) else {
        return Err(ParseError::InvalidV2cNotification(
            "missing snmpTrapOID.0 varbind",
        ));
    };

    if trap_oid.oid.to_string() != SNMP_TRAP_OID {
        return Err(ParseError::InvalidV2cNotification(
            "second varbind must be snmpTrapOID.0",
        ));
    }

    let VarBindValue::Value(ObjectSyntax::Object(trap_oid_value)) = &trap_oid.val else {
        return Err(ParseError::InvalidV2cNotification(
            "snmpTrapOID.0 varbind must contain an ObjectIdentifier",
        ));
    };

    Ok((*uptime_value as i64, trap_oid_value.to_string()))
}

#[derive(Clone, Copy, Debug)]
struct BerTlv<'a> {
    tag: u8,
    content: &'a [u8],
    content_start: usize,
    content_end: usize,
    tlv_end: usize,
}

fn raw_v1_generic_trap(data: &[u8]) -> Result<i64, ParseError> {
    let (version, _, pdu) = raw_message_fields(data)?;
    if version.tag != 0x02 || decode_ber_integer_i64(version.content)? != 0 {
        return Err(ParseError::MalformedMessage(
            "SNMP message did not contain SNMPv1 version".to_string(),
        ));
    }
    if pdu.tag != 0xa4 {
        return Err(ParseError::MalformedMessage(
            "SNMPv1 message did not contain a Trap-PDU".to_string(),
        ));
    }

    let mut offset = pdu.content_start;
    offset = read_tlv_at(data, offset)?.tlv_end;
    offset = read_tlv_at(data, offset)?.tlv_end;
    let generic_trap = read_tlv_at(data, offset)?;
    if generic_trap.tag != 0x02 {
        return Err(ParseError::MalformedMessage(
            "SNMPv1 generic-trap was not encoded as an INTEGER".to_string(),
        ));
    }

    decode_ber_integer_i64(generic_trap.content)
}

fn raw_v2c_request_id(data: &[u8]) -> Result<i64, ParseError> {
    let (version, _, pdu) = raw_message_fields(data)?;
    if version.tag != 0x02 || decode_ber_integer_i64(version.content)? != 1 {
        return Err(ParseError::MalformedMessage(
            "SNMP message did not contain SNMPv2c version".to_string(),
        ));
    }

    let request_id = read_tlv_at(data, pdu.content_start)?;
    if request_id.tag != 0x02 {
        return Err(ParseError::MalformedMessage(
            "SNMPv2c request-id was not encoded as an INTEGER".to_string(),
        ));
    }
    validate_request_id(decode_ber_integer_i64(request_id.content)?)
}

fn patch_negative_v2c_request_id(data: &Bytes) -> Result<Option<(Bytes, i64)>, ParseError> {
    let Ok((version, _, pdu)) = raw_message_fields(data) else {
        return Ok(None);
    };
    if version.tag != 0x02
        || decode_ber_integer_i64(version.content)? != 1
        || pdu.tag & 0xe0 != 0xa0
    {
        return Ok(None);
    }

    let request_id = read_tlv_at(data, pdu.content_start)?;
    if request_id.tag != 0x02 {
        return Ok(None);
    }
    let request_id_value = validate_request_id(decode_ber_integer_i64(request_id.content)?)?;
    if request_id_value >= 0 {
        return Ok(None);
    }

    let mut patched = data.to_vec();
    for byte in &mut patched[request_id.content_start..request_id.content_end] {
        *byte = 0;
    }

    Ok(Some((Bytes::from(patched), request_id_value)))
}

fn raw_message_fields(data: &[u8]) -> Result<(BerTlv<'_>, BerTlv<'_>, BerTlv<'_>), ParseError> {
    let message = read_tlv_at(data, 0)?;
    if message.tag != 0x30 {
        return Err(ParseError::MalformedMessage(
            "SNMP message must start with a sequence".to_string(),
        ));
    }

    let mut offset = message.content_start;
    let version = read_tlv_at(data, offset)?;
    offset = version.tlv_end;
    let community = read_tlv_at(data, offset)?;
    offset = community.tlv_end;
    let pdu = read_tlv_at(data, offset)?;

    Ok((version, community, pdu))
}

fn read_tlv_at(data: &[u8], offset: usize) -> Result<BerTlv<'_>, ParseError> {
    let Some(tag) = data.get(offset).copied() else {
        return Err(ParseError::MalformedMessage(
            "truncated BER identifier".to_string(),
        ));
    };

    let mut cursor = offset + 1;
    if tag & 0x1f == 0x1f {
        loop {
            let Some(identifier_byte) = data.get(cursor).copied() else {
                return Err(ParseError::MalformedMessage(
                    "truncated high-tag-number BER identifier".to_string(),
                ));
            };
            cursor += 1;
            if identifier_byte & 0x80 == 0 {
                break;
            }
        }
    }

    let (length, content_start) = read_ber_length(data, cursor)?;
    let content_end = content_start.checked_add(length).ok_or_else(|| {
        ParseError::MalformedMessage("BER length overflowed message size".to_string())
    })?;
    if content_end > data.len() {
        return Err(ParseError::MalformedMessage(
            "BER value exceeds message length".to_string(),
        ));
    }

    Ok(BerTlv {
        tag,
        content: &data[content_start..content_end],
        content_start,
        content_end,
        tlv_end: content_end,
    })
}

fn read_ber_length(data: &[u8], offset: usize) -> Result<(usize, usize), ParseError> {
    let Some(first) = data.get(offset).copied() else {
        return Err(ParseError::MalformedMessage(
            "truncated BER length".to_string(),
        ));
    };

    if first & 0x80 == 0 {
        return Ok((first as usize, offset + 1));
    }

    let byte_count = (first & 0x7f) as usize;
    if byte_count == 0 || byte_count > std::mem::size_of::<usize>() {
        return Err(ParseError::MalformedMessage(
            "unsupported BER length encoding".to_string(),
        ));
    }

    let length_start = offset + 1;
    let length_end = length_start
        .checked_add(byte_count)
        .ok_or_else(|| ParseError::MalformedMessage("BER length overflowed".to_string()))?;
    if length_end > data.len() {
        return Err(ParseError::MalformedMessage(
            "truncated BER length".to_string(),
        ));
    }

    let mut length = 0usize;
    for byte in &data[length_start..length_end] {
        length = (length << 8) | *byte as usize;
    }

    Ok((length, length_end))
}

fn decode_ber_integer_i64(content: &[u8]) -> Result<i64, ParseError> {
    if content.is_empty() || content.len() > std::mem::size_of::<i64>() {
        return Err(ParseError::MalformedMessage(
            "BER INTEGER cannot be decoded as i64".to_string(),
        ));
    }

    let fill = if content[0] & 0x80 == 0 { 0x00 } else { 0xff };
    let mut bytes = [fill; std::mem::size_of::<i64>()];
    let start = bytes.len() - content.len();
    bytes[start..].copy_from_slice(content);

    Ok(i64::from_be_bytes(bytes))
}

fn validate_request_id(value: i64) -> Result<i64, ParseError> {
    if (i32::MIN as i64..=i32::MAX as i64).contains(&value) {
        Ok(value)
    } else {
        Err(ParseError::InvalidRequestId(
            "request-id must fit the signed 32-bit RFC 3416 range",
        ))
    }
}

fn format_varbinds(
    variables: &[SnmpVariable<'_>],
    mib_resolver: &MibResolver,
) -> Vec<serde_json::Value> {
    variables
        .iter()
        .map(|variable| {
            let formatted = format_varbind_value(&variable.val);
            let oid = variable.oid.to_string();
            let mut varbind = serde_json::Map::from_iter([
                ("oid".to_string(), json!(oid)),
                ("type".to_string(), json!(formatted.value_type)),
                ("value".to_string(), json!(formatted.value)),
            ]);

            if let Some(value_bytes_hex) = formatted.value_bytes_hex {
                varbind.insert("value_bytes_hex".to_string(), json!(value_bytes_hex));
            }

            insert_json_oid_resolution(&mut varbind, "oid", &oid, mib_resolver);

            if let VarBindValue::Value(ObjectSyntax::Object(value_oid)) = &variable.val {
                let value_oid = value_oid.to_string();
                insert_json_oid_resolution(&mut varbind, "value_oid", &value_oid, mib_resolver);
            }

            serde_json::Value::Object(varbind)
        })
        .collect()
}

#[derive(Debug, PartialEq, Eq)]
struct FormattedVarbindValue {
    value_type: &'static str,
    value: String,
    value_bytes_hex: Option<String>,
}

fn insert_oid_resolution(log: &mut LogEvent, prefix: &str, oid: &str, mib_resolver: &MibResolver) {
    if let Some(resolution) = mib_resolver.resolve(oid) {
        let field = format!("{prefix}_name");
        log.insert(field.as_str(), resolution.name);
        if let Some(module) = resolution.module {
            let field = format!("{prefix}_module");
            log.insert(field.as_str(), module);
        }
        let field = format!("{prefix}_symbol");
        log.insert(field.as_str(), resolution.symbol);
        if let Some(instance) = resolution.instance {
            let field = format!("{prefix}_instance");
            log.insert(field.as_str(), instance);
        }
    }
}

fn insert_json_oid_resolution(
    value: &mut serde_json::Map<String, serde_json::Value>,
    prefix: &str,
    oid: &str,
    mib_resolver: &MibResolver,
) {
    if let Some(resolution) = mib_resolver.resolve(oid) {
        insert_json_resolution(value, prefix, resolution);
    }
}

fn insert_json_resolution(
    value: &mut serde_json::Map<String, serde_json::Value>,
    prefix: &str,
    resolution: OidResolution,
) {
    value.insert(format!("{prefix}_name"), json!(resolution.name));
    if let Some(module) = resolution.module {
        value.insert(format!("{prefix}_module"), json!(module));
    }
    value.insert(format!("{prefix}_symbol"), json!(resolution.symbol));
    if let Some(instance) = resolution.instance {
        value.insert(format!("{prefix}_instance"), json!(instance));
    }
}

fn format_varbind_value(value: &VarBindValue<'_>) -> FormattedVarbindValue {
    match value {
        VarBindValue::Value(value) => format_object_value(value),
        VarBindValue::Unspecified => formatted_value("unspecified", "unspecified"),
        VarBindValue::NoSuchObject => formatted_value("no_such_object", "noSuchObject"),
        VarBindValue::NoSuchInstance => formatted_value("no_such_instance", "noSuchInstance"),
        VarBindValue::EndOfMibView => formatted_value("end_of_mib_view", "endOfMibView"),
    }
}

fn format_object_value(value: &ObjectSyntax<'_>) -> FormattedVarbindValue {
    match value {
        ObjectSyntax::Number(value) => formatted_value("integer", value.to_string()),
        ObjectSyntax::String(value) => {
            let value_bytes_hex = bytes_to_hex(value);
            FormattedVarbindValue {
                value_type: "octet_string",
                value: printable_utf8(value)
                    .map(str::to_string)
                    .unwrap_or_else(|| value_bytes_hex.clone()),
                value_bytes_hex: Some(value_bytes_hex),
            }
        }
        ObjectSyntax::Object(value) => formatted_value("object_identifier", value.to_string()),
        ObjectSyntax::BitString(value) => formatted_bytes_value(
            "bit_string",
            format!(
                "unused_bits={},bytes={}",
                value.unused_bits,
                bytes_to_hex(value.data.as_ref())
            ),
            value.data.as_ref(),
        ),
        ObjectSyntax::IpAddress(value) => {
            formatted_value("ip_address", format_network_address(*value))
        }
        ObjectSyntax::Counter32(value) => formatted_value("counter32", value.to_string()),
        ObjectSyntax::Gauge32(value) => formatted_value("gauge32", value.to_string()),
        ObjectSyntax::TimeTicks(value) => formatted_value("timeticks", value.to_string()),
        ObjectSyntax::Opaque(value) => formatted_bytes_value("opaque", bytes_to_hex(value), value),
        ObjectSyntax::Counter64(value) => formatted_value("counter64", value.to_string()),
        ObjectSyntax::UInteger32(value) => formatted_value("unsigned32", value.to_string()),
        ObjectSyntax::NsapAddress(value) => {
            formatted_bytes_value("nsap_address", bytes_to_hex(value), value)
        }
        ObjectSyntax::Empty => formatted_value("empty", "empty"),
        ObjectSyntax::UnknownSimple(value) => formatted_bytes_value(
            "unknown_simple",
            format_unknown_value(
                value.class(),
                value.header.constructed(),
                value.tag().0,
                value.as_bytes(),
            ),
            value.as_bytes(),
        ),
        ObjectSyntax::UnknownApplication(value) => formatted_bytes_value(
            "unknown_application",
            format_unknown_value(
                value.class(),
                value.header.constructed(),
                value.tag().0,
                value.as_bytes(),
            ),
            value.as_bytes(),
        ),
    }
}

fn formatted_value(value_type: &'static str, value: impl Into<String>) -> FormattedVarbindValue {
    FormattedVarbindValue {
        value_type,
        value: value.into(),
        value_bytes_hex: None,
    }
}

fn formatted_bytes_value(
    value_type: &'static str,
    value: impl Into<String>,
    bytes: &[u8],
) -> FormattedVarbindValue {
    FormattedVarbindValue {
        value_type,
        value: value.into(),
        value_bytes_hex: Some(bytes_to_hex(bytes)),
    }
}

fn printable_utf8(bytes: &[u8]) -> Option<&str> {
    let value = std::str::from_utf8(bytes).ok()?;
    value
        .chars()
        .all(|character| !character.is_control() || matches!(character, '\n' | '\r' | '\t'))
        .then_some(value)
}

fn format_unknown_value(
    class: impl std::fmt::Display,
    constructed: bool,
    tag: u32,
    bytes: &[u8],
) -> String {
    format!(
        "class={},constructed={},tag={},bytes={}",
        class,
        constructed,
        tag,
        bytes_to_hex(bytes)
    )
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn format_network_address(value: NetworkAddress) -> String {
    match value {
        NetworkAddress::IPv4(ip) => ip.to_string(),
    }
}

const fn trap_type_name(value: u8) -> &'static str {
    match value {
        0 => "coldStart",
        1 => "warmStart",
        2 => "linkDown",
        3 => "linkUp",
        4 => "authenticationFailure",
        5 => "egpNeighborLoss",
        6 => "enterpriseSpecific",
        _ => "unknown",
    }
}

fn build_inform_response(
    community: &[u8],
    request_id: i64,
    pdu: &SnmpGenericPdu<'_>,
) -> Option<Bytes> {
    let response = build_v2c_response(community, request_id, 0, 0, Some(pdu.var.as_slice()));

    if response.len() <= MAX_SNMP_MESSAGE_SIZE {
        Some(response)
    } else {
        let response = build_v2c_response(community, request_id, 1, 0, None);
        (response.len() <= MAX_SNMP_MESSAGE_SIZE).then_some(response)
    }
}

fn build_v2c_response(
    community: &[u8],
    request_id: i64,
    error_status: i64,
    error_index: i64,
    variables: Option<&[SnmpVariable<'_>]>,
) -> Bytes {
    let mut pdu = Vec::new();
    pdu.extend(encode_integer_i64(request_id));
    pdu.extend(encode_integer_i64(error_status));
    pdu.extend(encode_integer_i64(error_index));
    pdu.extend(encode_varbind_list(variables.unwrap_or_default()));

    let mut message = Vec::new();
    message.extend(encode_integer_u64(1));
    message.extend(encode_tlv(0x04, community));
    message.extend(encode_tlv(0xa2, &pdu));

    Bytes::from(encode_sequence(&message))
}

fn encode_varbind_list(variables: &[SnmpVariable<'_>]) -> Vec<u8> {
    let mut content = Vec::new();
    for variable in variables {
        let mut varbind = Vec::new();
        varbind.extend(encode_tlv(0x06, variable.oid.as_bytes()));
        varbind.extend(encode_varbind_value(&variable.val));
        content.extend(encode_sequence(&varbind));
    }
    encode_sequence(&content)
}

fn encode_varbind_value(value: &VarBindValue<'_>) -> Vec<u8> {
    match value {
        VarBindValue::Value(value) => encode_object_value(value),
        VarBindValue::Unspecified => encode_tlv(0x05, &[]),
        VarBindValue::NoSuchObject => encode_tlv(0x80, &[]),
        VarBindValue::NoSuchInstance => encode_tlv(0x81, &[]),
        VarBindValue::EndOfMibView => encode_tlv(0x82, &[]),
    }
}

fn encode_object_value(value: &ObjectSyntax<'_>) -> Vec<u8> {
    match value {
        ObjectSyntax::Number(value) => encode_integer_i64(*value as i64),
        ObjectSyntax::String(value) => encode_tlv(0x04, value),
        ObjectSyntax::Object(value) => encode_tlv(0x06, value.as_bytes()),
        ObjectSyntax::BitString(value) => {
            let mut content = Vec::with_capacity(value.data.len() + 1);
            content.push(value.unused_bits);
            content.extend(value.data.iter().copied());
            encode_tlv(0x03, &content)
        }
        ObjectSyntax::IpAddress(NetworkAddress::IPv4(value)) => encode_tlv(0x40, &value.octets()),
        ObjectSyntax::Counter32(value) => encode_application_integer(0x41, *value as u64),
        ObjectSyntax::Gauge32(value) => encode_application_integer(0x42, *value as u64),
        ObjectSyntax::TimeTicks(value) => encode_application_integer(0x43, *value as u64),
        ObjectSyntax::Opaque(value) => encode_tlv(0x44, value),
        ObjectSyntax::NsapAddress(value) => encode_tlv(0x45, value),
        ObjectSyntax::Counter64(value) => encode_application_integer(0x46, *value),
        ObjectSyntax::UInteger32(value) => encode_application_integer(0x47, *value as u64),
        ObjectSyntax::Empty => encode_tlv(0x05, &[]),
        ObjectSyntax::UnknownSimple(value) | ObjectSyntax::UnknownApplication(value) => {
            encode_ber_value(
                value.class() as u8,
                value.header.constructed(),
                value.tag().0,
                value.as_bytes(),
            )
        }
    }
}

fn encode_ber_value(class: u8, constructed: bool, tag: u32, content: &[u8]) -> Vec<u8> {
    let mut value = Vec::with_capacity(5 + content.len());
    encode_identifier(class, constructed, tag, &mut value);
    encode_length(content.len(), &mut value);
    value.extend(content);
    value
}

fn encode_sequence(content: &[u8]) -> Vec<u8> {
    encode_tlv(0x30, content)
}

fn encode_application_integer(tag: u8, value: u64) -> Vec<u8> {
    encode_tlv(tag, &encode_unsigned_integer_content(value))
}

fn encode_integer_u64(value: u64) -> Vec<u8> {
    encode_tlv(0x02, &encode_unsigned_integer_content(value))
}

fn encode_integer_i64(value: i64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let mut start = 0;
    while start + 1 < bytes.len() {
        let current = bytes[start];
        let next = bytes[start + 1];
        if (current == 0x00 && next & 0x80 == 0) || (current == 0xff && next & 0x80 != 0) {
            start += 1;
        } else {
            break;
        }
    }
    encode_tlv(0x02, &bytes[start..])
}

fn encode_unsigned_integer_content(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first_non_zero = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    let mut content = bytes[first_non_zero..].to_vec();
    if content[0] & 0x80 != 0 {
        content.insert(0, 0);
    }
    content
}

fn encode_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut value = Vec::with_capacity(1 + 5 + content.len());
    value.push(tag);
    encode_length(content.len(), &mut value);
    value.extend(content);
    value
}

fn encode_length(length: usize, output: &mut Vec<u8>) {
    if length < 128 {
        output.push(length as u8);
        return;
    }

    let bytes = length.to_be_bytes();
    let first_non_zero = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    let significant = &bytes[first_non_zero..];
    output.push(0x80 | significant.len() as u8);
    output.extend(significant);
}

fn encode_identifier(class: u8, constructed: bool, mut tag: u32, output: &mut Vec<u8>) {
    let constructed_bit = u8::from(constructed) << 5;
    if tag < 31 {
        output.push((class << 6) | constructed_bit | tag as u8);
        return;
    }

    output.push((class << 6) | constructed_bit | 0x1f);
    let mut encoded_tag = vec![(tag & 0x7f) as u8];
    tag >>= 7;
    while tag > 0 {
        encoded_tag.push(((tag & 0x7f) as u8) | 0x80);
        tag >>= 7;
    }
    output.extend(encoded_tag.into_iter().rev());
}

#[cfg(test)]
mod tests {
    use super::*;
    use snmp_parser::snmp::{ErrorStatus, PduType};
    use std::net::{IpAddr, Ipv4Addr};
    use vector_lib::event::Value;

    fn source_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1162)
    }

    fn mib_resolver() -> MibResolver {
        MibResolver::with_builtin_symbols()
    }

    fn oid(arcs: &[u64]) -> Vec<u8> {
        assert!(arcs.len() >= 2);
        let mut encoded = vec![(arcs[0] * 40 + arcs[1]) as u8];
        for mut arc in arcs.iter().copied().skip(2) {
            let mut stack = vec![(arc & 0x7f) as u8];
            arc >>= 7;
            while arc > 0 {
                stack.push(((arc & 0x7f) as u8) | 0x80);
                arc >>= 7;
            }
            encoded.extend(stack.into_iter().rev());
        }
        encoded
    }

    fn oid_value(arcs: &[u64]) -> Vec<u8> {
        encode_tlv(0x06, &oid(arcs))
    }

    fn timeticks(value: u64) -> Vec<u8> {
        encode_application_integer(0x43, value)
    }

    fn integer(value: u64) -> Vec<u8> {
        encode_integer_u64(value)
    }

    fn signed_integer(value: i64) -> Vec<u8> {
        encode_integer_i64(value)
    }

    fn octet_string(value: &[u8]) -> Vec<u8> {
        encode_tlv(0x04, value)
    }

    fn null() -> Vec<u8> {
        encode_tlv(0x05, &[])
    }

    fn opaque(value: &[u8]) -> Vec<u8> {
        encode_tlv(0x44, value)
    }

    fn high_tag_application(tag: u32, value: &[u8]) -> Vec<u8> {
        let mut encoded = Vec::new();
        encode_identifier(1, false, tag, &mut encoded);
        encode_length(value.len(), &mut encoded);
        encoded.extend(value);
        encoded
    }

    fn varbind(oid_arcs: &[u64], value: Vec<u8>) -> Vec<u8> {
        let mut content = Vec::new();
        content.extend(oid_value(oid_arcs));
        content.extend(value);
        encode_sequence(&content)
    }

    fn v2c_message(pdu_type: PduType, request_id: u32, varbinds: Vec<Vec<u8>>) -> Bytes {
        v2c_message_with_request_id(
            pdu_type,
            encode_integer_u64(request_id as u64),
            b"public",
            varbinds,
        )
    }

    fn v2c_message_with_request_id(
        pdu_type: PduType,
        request_id: Vec<u8>,
        community: &[u8],
        varbinds: Vec<Vec<u8>>,
    ) -> Bytes {
        let pdu = v2c_pdu(pdu_type, request_id, varbinds);

        let mut message = Vec::new();
        message.extend(encode_integer_u64(1));
        message.extend(encode_tlv(0x04, community));
        message.extend(pdu);

        Bytes::from(encode_sequence(&message))
    }

    fn v2c_pdu(pdu_type: PduType, request_id: Vec<u8>, varbinds: Vec<Vec<u8>>) -> Vec<u8> {
        let mut varbind_list = Vec::new();
        for varbind in varbinds {
            varbind_list.extend(varbind);
        }

        let mut pdu = Vec::new();
        pdu.extend(request_id);
        pdu.extend(encode_integer_u64(0));
        pdu.extend(encode_integer_u64(0));
        pdu.extend(encode_sequence(&varbind_list));

        encode_tlv(0xa0 | pdu_type.0 as u8, &pdu)
    }

    fn v2c_notification(pdu_type: PduType) -> Bytes {
        v2c_message(pdu_type, 42, notification_varbinds())
    }

    fn notification_varbinds() -> Vec<Vec<u8>> {
        let mut varbinds = required_notification_varbinds();
        varbinds.push(varbind(&[1, 3, 6, 1, 4, 1, 8072, 2, 4, 1, 0], integer(7)));
        varbinds
    }

    fn required_notification_varbinds() -> Vec<Vec<u8>> {
        vec![
            varbind(&[1, 3, 6, 1, 2, 1, 1, 3, 0], timeticks(123_456)),
            varbind(
                &[1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0],
                oid_value(&[1, 3, 6, 1, 4, 1, 8072, 2, 3, 0, 1]),
            ),
        ]
    }

    fn v1_trap() -> Bytes {
        v1_trap_with_generic_trap(integer(6))
    }

    fn v1_trap_with_generic_trap(generic_trap: Vec<u8>) -> Bytes {
        let mut pdu = Vec::new();
        pdu.extend(oid_value(&[1, 3, 6, 1, 4, 1, 8072, 2, 3, 0, 1]));
        pdu.extend(encode_tlv(0x40, &[192, 168, 1, 100]));
        pdu.extend(generic_trap);
        pdu.extend(encode_integer_u64(1));
        pdu.extend(timeticks(123_456));
        pdu.extend(encode_sequence(&[]));

        let mut message = Vec::new();
        message.extend(encode_integer_u64(0));
        message.extend(encode_tlv(0x04, b"public"));
        message.extend(encode_tlv(0xa4, &pdu));

        Bytes::from(encode_sequence(&message))
    }

    fn v3_trap() -> Bytes {
        let mut header = Vec::new();
        header.extend(integer(1));
        header.extend(integer(MAX_SNMP_MESSAGE_SIZE as u64));
        header.extend(octet_string(&[0]));
        header.extend(integer(1));

        let mut scoped_pdu = Vec::new();
        scoped_pdu.extend(octet_string(&[]));
        scoped_pdu.extend(octet_string(&[]));
        scoped_pdu.extend(v2c_pdu(
            PduType::TrapV2,
            integer(42),
            vec![
                varbind(&[1, 3, 6, 1, 2, 1, 1, 3, 0], timeticks(123_456)),
                varbind(
                    &[1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0],
                    oid_value(&[1, 3, 6, 1, 6, 3, 1, 1, 5, 1]),
                ),
            ],
        ));

        let mut message = Vec::new();
        message.extend(integer(3));
        message.extend(encode_sequence(&header));
        message.extend(octet_string(&[]));
        message.extend(encode_sequence(&scoped_pdu));

        Bytes::from(encode_sequence(&message))
    }

    #[test]
    fn test_format_object_value() {
        assert_eq!(
            format_object_value(&ObjectSyntax::String(b"test")),
            FormattedVarbindValue {
                value_type: "octet_string",
                value: "test".to_string(),
                value_bytes_hex: Some("74657374".to_string()),
            }
        );
        assert_eq!(
            format_object_value(&ObjectSyntax::Counter32(100)),
            formatted_value("counter32", "100")
        );
        assert_eq!(
            format_object_value(&ObjectSyntax::Gauge32(200)),
            formatted_value("gauge32", "200")
        );
        assert_eq!(
            format_object_value(&ObjectSyntax::TimeTicks(300)),
            formatted_value("timeticks", "300")
        );
        assert_eq!(
            format_object_value(&ObjectSyntax::Counter64(400)),
            formatted_value("counter64", "400")
        );
        assert_eq!(
            format_object_value(&ObjectSyntax::UInteger32(500)),
            formatted_value("unsigned32", "500")
        );
        assert_eq!(
            format_object_value(&ObjectSyntax::Empty),
            formatted_value("empty", "empty")
        );
        assert_eq!(
            format_object_value(&ObjectSyntax::IpAddress(NetworkAddress::IPv4(
                Ipv4Addr::new(192, 168, 1, 1)
            ))),
            formatted_value("ip_address", "192.168.1.1")
        );
    }

    #[test]
    fn test_parse_v1_trap() {
        let parsed = parse_snmp_trap(&v1_trap(), source_addr(), &mib_resolver()).unwrap();
        assert!(parsed.response.is_none());

        let log = parsed.events[0].as_log();
        assert_eq!(log["snmp_version"], Value::from("1"));
        assert_eq!(log["pdu_type"], Value::from("trap_v1"));
        assert_eq!(
            log["enterprise_oid"],
            Value::from("1.3.6.1.4.1.8072.2.3.0.1")
        );
        assert_eq!(log["agent_address"], Value::from("192.168.1.100"));
        assert_eq!(log["generic_trap"], Value::from(6));
        assert_eq!(log["generic_trap_name"], Value::from("enterpriseSpecific"));
        assert_eq!(log["uptime"], Value::from(123_456));
    }

    #[test]
    fn test_parse_v1_trap_rejects_unknown_generic_trap() {
        let result = parse_snmp_trap(
            &v1_trap_with_generic_trap(integer(7)),
            source_addr(),
            &mib_resolver(),
        );
        assert!(matches!(result, Err(ParseError::InvalidV1Trap(_))));
    }

    #[test]
    fn test_parse_v1_trap_rejects_wrapped_generic_trap() {
        let result = parse_snmp_trap(
            &v1_trap_with_generic_trap(integer(256)),
            source_addr(),
            &mib_resolver(),
        );
        assert!(matches!(result, Err(ParseError::InvalidV1Trap(_))));
    }

    #[test]
    fn test_parse_v1_trap_with_mib_resolution() {
        let resolver = MibResolver::from_str(TEST_MIB);
        let parsed = parse_snmp_trap(&v1_trap(), source_addr(), &resolver).unwrap();

        let log = parsed.events[0].as_log();
        assert_eq!(
            log["enterprise_oid_name"],
            Value::from("TEST-MIB::testTrap")
        );
        assert_eq!(log["enterprise_oid_module"], Value::from("TEST-MIB"));
        assert_eq!(log["enterprise_oid_symbol"], Value::from("testTrap"));
    }

    #[test]
    fn test_parse_v2c_trap() {
        let parsed = parse_snmp_trap(
            &v2c_notification(PduType::TrapV2),
            source_addr(),
            &mib_resolver(),
        )
        .unwrap();
        assert!(parsed.response.is_none());

        let log = parsed.events[0].as_log();
        assert_eq!(log["snmp_version"], Value::from("2c"));
        assert_eq!(log["pdu_type"], Value::from("trap_v2"));
        assert_eq!(log["request_id"], Value::from(42));
        assert_eq!(log["uptime"], Value::from(123_456));
        assert_eq!(log["trap_oid"], Value::from("1.3.6.1.4.1.8072.2.3.0.1"));
        assert!(log.get("trap_oid_name").is_none());

        let varbinds = log["varbinds"].as_array().unwrap();
        assert_eq!(varbinds.len(), 3);
        assert_eq!(varbinds[0].get("type").unwrap(), &Value::from("timeticks"));
        assert_eq!(varbinds[2].get("type").unwrap(), &Value::from("integer"));
    }

    #[test]
    fn test_parse_v2c_trap_with_mib_resolution() {
        let resolver = MibResolver::from_str(TEST_MIB);
        let parsed =
            parse_snmp_trap(&v2c_notification(PduType::TrapV2), source_addr(), &resolver).unwrap();

        let log = parsed.events[0].as_log();
        assert_eq!(log["trap_oid_name"], Value::from("TEST-MIB::testTrap"));
        assert_eq!(log["trap_oid_module"], Value::from("TEST-MIB"));
        assert_eq!(log["trap_oid_symbol"], Value::from("testTrap"));

        let varbinds = log["varbinds"].as_array().unwrap();
        assert_eq!(
            varbinds[0].get("oid_name").unwrap(),
            &Value::from("SNMPv2-MIB::sysUpTime.0")
        );
        assert_eq!(
            varbinds[1].get("value_oid_name").unwrap(),
            &Value::from("TEST-MIB::testTrap")
        );
        assert_eq!(
            varbinds[2].get("oid_name").unwrap(),
            &Value::from("TEST-MIB::testValue.0")
        );
        assert_eq!(varbinds[2].get("oid_instance").unwrap(), &Value::from("0"));
    }

    #[test]
    fn test_parse_v2c_inform_builds_response() {
        let parsed = parse_snmp_trap(
            &v2c_notification(PduType::InformRequest),
            source_addr(),
            &mib_resolver(),
        )
        .unwrap();
        let response = parsed.response.expect("inform should produce a response");

        let (_, response) = parse_snmp_v2c(&response).unwrap();
        assert_eq!(response.community, "public");
        match response.pdu {
            SnmpPdu::Generic(pdu) => {
                assert_eq!(pdu.pdu_type, PduType::Response);
                assert_eq!(pdu.req_id, 42);
                assert_eq!(pdu.err, ErrorStatus::NoError);
                assert_eq!(pdu.err_index, 0);
                assert_eq!(pdu.var.len(), 3);
            }
            other => panic!("expected response PDU, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_v2c_inform_preserves_negative_request_id() {
        let parsed = parse_snmp_trap(
            &v2c_message_with_request_id(
                PduType::InformRequest,
                signed_integer(-1),
                b"public",
                notification_varbinds(),
            ),
            source_addr(),
            &mib_resolver(),
        )
        .unwrap();

        assert_eq!(parsed.events[0].as_log()["request_id"], Value::from(-1));
        let response = parsed.response.expect("inform should produce a response");
        assert!(
            response
                .windows([0x02, 0x01, 0xff].len())
                .any(|window| window == [0x02, 0x01, 0xff]),
            "response should echo request-id -1 using the original signed BER integer"
        );
    }

    #[test]
    fn test_parse_v2c_inform_rejects_positive_request_id_outside_integer32() {
        let result = parse_snmp_trap(
            &v2c_message_with_request_id(
                PduType::InformRequest,
                encode_tlv(0x02, &[0x00, 0x80, 0x00, 0x00, 0x00]),
                b"public",
                notification_varbinds(),
            ),
            source_addr(),
            &mib_resolver(),
        );
        assert!(matches!(result, Err(ParseError::InvalidRequestId(_))));
    }

    #[test]
    fn test_parse_v2c_inform_too_big_response() {
        let oversized_value = vec![b'x'; MAX_SNMP_MESSAGE_SIZE];
        let parsed = parse_snmp_trap(
            &v2c_message(
                PduType::InformRequest,
                42,
                vec![
                    varbind(&[1, 3, 6, 1, 2, 1, 1, 3, 0], timeticks(123_456)),
                    varbind(
                        &[1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0],
                        oid_value(&[1, 3, 6, 1, 4, 1, 8072, 2, 3, 0, 1]),
                    ),
                    varbind(
                        &[1, 3, 6, 1, 4, 1, 8072, 2, 4, 1, 0],
                        octet_string(&oversized_value),
                    ),
                ],
            ),
            source_addr(),
            &mib_resolver(),
        )
        .unwrap();
        let response = parsed
            .response
            .expect("inform should produce a tooBig response");

        let (_, response) = parse_snmp_v2c(&response).unwrap();
        match response.pdu {
            SnmpPdu::Generic(pdu) => {
                assert_eq!(pdu.pdu_type, PduType::Response);
                assert_eq!(pdu.req_id, 42);
                assert_eq!(pdu.err, ErrorStatus::TooBig);
                assert_eq!(pdu.err_index, 0);
                assert!(pdu.var.is_empty());
            }
            other => panic!("expected response PDU, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_v2c_inform_drops_too_big_response_when_alternate_is_too_large() {
        let community = vec![b'x'; MAX_SNMP_MESSAGE_SIZE];
        let parsed = parse_snmp_trap(
            &v2c_message_with_request_id(
                PduType::InformRequest,
                integer(42),
                &community,
                required_notification_varbinds(),
            ),
            source_addr(),
            &mib_resolver(),
        )
        .unwrap();

        assert!(parsed.response.is_none());
    }

    #[test]
    fn test_parse_v2c_exception_varbind_values() {
        let parsed = parse_snmp_trap(
            &v2c_message(
                PduType::TrapV2,
                42,
                vec![
                    varbind(&[1, 3, 6, 1, 2, 1, 1, 3, 0], timeticks(123_456)),
                    varbind(
                        &[1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0],
                        oid_value(&[1, 3, 6, 1, 6, 3, 1, 1, 5, 1]),
                    ),
                    varbind(&[1, 3, 6, 1, 2, 1, 1, 99, 0], encode_tlv(0x80, &[])),
                    varbind(&[1, 3, 6, 1, 2, 1, 1, 100, 0], encode_tlv(0x81, &[])),
                    varbind(&[1, 3, 6, 1, 2, 1, 1, 101, 0], encode_tlv(0x82, &[])),
                ],
            ),
            source_addr(),
            &mib_resolver(),
        )
        .unwrap();

        let varbinds = parsed.events[0].as_log()["varbinds"].as_array().unwrap();
        assert_eq!(
            varbinds[2].get("type").unwrap(),
            &Value::from("no_such_object")
        );
        assert_eq!(
            varbinds[3].get("type").unwrap(),
            &Value::from("no_such_instance")
        );
        assert_eq!(
            varbinds[4].get("type").unwrap(),
            &Value::from("end_of_mib_view")
        );
    }

    #[test]
    fn test_parse_v2c_binary_values_include_hex() {
        let parsed = parse_snmp_trap(
            &v2c_message(
                PduType::TrapV2,
                42,
                vec![
                    varbind(&[1, 3, 6, 1, 2, 1, 1, 3, 0], timeticks(123_456)),
                    varbind(
                        &[1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0],
                        oid_value(&[1, 3, 6, 1, 6, 3, 1, 1, 5, 1]),
                    ),
                    varbind(
                        &[1, 3, 6, 1, 2, 1, 2, 2, 1, 6, 1],
                        octet_string(&[0, 0x11, 0x22, 0xaa, 0xbb, 0xcc]),
                    ),
                    varbind(&[1, 3, 6, 1, 2, 1, 1, 102, 0], opaque(&[0xde, 0xad])),
                ],
            ),
            source_addr(),
            &mib_resolver(),
        )
        .unwrap();

        let varbinds = parsed.events[0].as_log()["varbinds"].as_array().unwrap();
        assert_eq!(
            varbinds[2].get("value").unwrap(),
            &Value::from("001122aabbcc")
        );
        assert_eq!(
            varbinds[2].get("value_bytes_hex").unwrap(),
            &Value::from("001122aabbcc")
        );
        assert_eq!(varbinds[3].get("value").unwrap(), &Value::from("dead"));
        assert_eq!(
            varbinds[3].get("value_bytes_hex").unwrap(),
            &Value::from("dead")
        );
    }

    #[test]
    fn test_parse_v2c_requires_notification_oids() {
        let result = parse_snmp_trap(
            &v2c_message(
                PduType::TrapV2,
                42,
                vec![varbind(&[1, 3, 6, 1, 4, 1, 8072, 2, 4, 1, 0], integer(7))],
            ),
            source_addr(),
            &mib_resolver(),
        );
        assert!(matches!(
            result,
            Err(ParseError::InvalidV2cNotification(
                "first varbind must be sysUpTime.0"
            ))
        ));
    }

    #[test]
    fn test_parse_v2c_rejects_wrong_notification_oid_order() {
        let result = parse_snmp_trap(
            &v2c_message(
                PduType::InformRequest,
                42,
                vec![
                    varbind(
                        &[1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0],
                        oid_value(&[1, 3, 6, 1, 6, 3, 1, 1, 5, 1]),
                    ),
                    varbind(&[1, 3, 6, 1, 2, 1, 1, 3, 0], timeticks(123_456)),
                ],
            ),
            source_addr(),
            &mib_resolver(),
        );
        assert!(matches!(
            result,
            Err(ParseError::InvalidV2cNotification(
                "first varbind must be sysUpTime.0"
            ))
        ));
    }

    #[test]
    fn test_parse_v2c_rejects_wrong_notification_value_types() {
        let result = parse_snmp_trap(
            &v2c_message(
                PduType::TrapV2,
                42,
                vec![
                    varbind(&[1, 3, 6, 1, 2, 1, 1, 3, 0], integer(123_456)),
                    varbind(
                        &[1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0],
                        oid_value(&[1, 3, 6, 1, 6, 3, 1, 1, 5, 1]),
                    ),
                ],
            ),
            source_addr(),
            &mib_resolver(),
        );
        assert!(matches!(
            result,
            Err(ParseError::InvalidV2cNotification(
                "sysUpTime.0 varbind must contain TimeTicks"
            ))
        ));
    }

    #[test]
    fn test_parse_v2c_inform_preserves_high_tag_unknown_varbinds() {
        let parsed = parse_snmp_trap(
            &v2c_message(
                PduType::InformRequest,
                42,
                vec![
                    varbind(&[1, 3, 6, 1, 2, 1, 1, 3, 0], timeticks(123_456)),
                    varbind(
                        &[1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0],
                        oid_value(&[1, 3, 6, 1, 6, 3, 1, 1, 5, 1]),
                    ),
                    varbind(
                        &[1, 3, 6, 1, 2, 1, 1, 103, 0],
                        high_tag_application(31, &[0xab, 0xcd]),
                    ),
                ],
            ),
            source_addr(),
            &mib_resolver(),
        )
        .unwrap();

        let response = parsed.response.expect("inform should produce a response");
        assert!(
            response
                .windows([0x5f, 0x1f, 0x02, 0xab, 0xcd].len())
                .any(|window| window == [0x5f, 0x1f, 0x02, 0xab, 0xcd])
        );
    }

    #[test]
    fn test_parse_v2c_get_request_rejected() {
        let result = parse_snmp_trap(
            &v2c_message(
                PduType::GetRequest,
                42,
                vec![varbind(&[1, 3, 6, 1, 2, 1, 1, 1, 0], null())],
            ),
            source_addr(),
            &mib_resolver(),
        );
        assert!(matches!(
            result,
            Err(ParseError::InvalidPduType(PduType::GetRequest))
        ));
    }

    #[test]
    fn test_parse_trailing_data_rejected() {
        let mut data = v2c_notification(PduType::TrapV2).to_vec();
        data.push(0);
        let result = parse_snmp_trap(&Bytes::from(data), source_addr(), &mib_resolver());
        assert!(matches!(result, Err(ParseError::TrailingData(1))));
    }

    #[test]
    fn test_parse_v3_rejected() {
        let error = parse_snmp_trap(&v3_trap(), source_addr(), &mib_resolver()).unwrap_err();
        assert!(matches!(error, ParseError::UnsupportedVersion(_)));
        assert_eq!(error.error_code(), "unsupported_version");
    }

    #[test]
    fn test_parse_invalid_data() {
        let data = Bytes::from("invalid data");
        let result = parse_snmp_trap(&data, source_addr(), &mib_resolver());
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_empty_data() {
        let data = Bytes::from("");
        let result = parse_snmp_trap(&data, source_addr(), &mib_resolver());
        assert!(result.is_err());
    }

    const TEST_MIB: &str = r#"
TEST-MIB DEFINITIONS ::= BEGIN

IMPORTS
    enterprises, OBJECT-TYPE, NOTIFICATION-TYPE
        FROM SNMPv2-SMI;

testRoot OBJECT IDENTIFIER ::= { enterprises 8072 }
testNotifications OBJECT IDENTIFIER ::= { testRoot 2 }
testNotificationPrefix OBJECT IDENTIFIER ::= { testNotifications 3 }
testSpecificNotifications OBJECT IDENTIFIER ::= { testNotificationPrefix 0 }

testTrap NOTIFICATION-TYPE
    OBJECTS { testValue }
    STATUS current
    DESCRIPTION "A test notification."
    ::= { testSpecificNotifications 1 }

testObjects OBJECT IDENTIFIER ::= { testNotifications 4 }
testValue OBJECT-TYPE
    SYNTAX Integer32
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "A test value."
    ::= { testObjects 1 }

END
"#;
}
