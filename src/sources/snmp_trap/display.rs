//! Renders variable binding values the way Net-SNMP's `snmptrapd` prints them, using the MIB
//! syntax of the object when it is known.

use snmp_parser::snmp::{NetworkAddress, ObjectSyntax, VarBindValue};

use super::mib::MibResolver;

/// The base ASN.1 or SMI type that a MIB object's `SYNTAX` ultimately refers to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BaseSyntax {
    Integer,
    Unsigned,
    Counter,
    TimeTicks,
    IpAddress,
    /// The SMIv1 `NetworkAddress` type, which Net-SNMP shows as colon-separated hexadecimal.
    NetworkAddress,
    OctetString,
    ObjectIdentifier,
    Bits,
    Opaque,
}

/// The syntax of a MIB object after resolving textual conventions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ValueSyntax {
    pub base: BaseSyntax,
    /// The labels of an enumerated INTEGER or of the bits of a BITS value.
    pub named_numbers: Vec<(i64, String)>,
    /// The RFC 2579 `DISPLAY-HINT` of the textual convention, if any.
    pub display_hint: Option<String>,
    /// The object's `UNITS`, appended to numeric values.
    pub units: Option<String>,
}

/// Formats a value like the text `snmptrapd` prints after the value's type label, for example
/// `down(2)`, `0:1a:2b:3c:4d:5e`, or `(123456) 0:20:34.56`.
pub(super) fn display_value(
    value: &VarBindValue<'_>,
    syntax: Option<&ValueSyntax>,
    resolver: &MibResolver,
) -> String {
    match value {
        VarBindValue::Value(value) => display_object(value, syntax, resolver),
        VarBindValue::Unspecified => "NULL".to_string(),
        VarBindValue::NoSuchObject => {
            "No Such Object available on this agent at this OID".to_string()
        }
        VarBindValue::NoSuchInstance => "No Such Instance currently exists at this OID".to_string(),
        VarBindValue::EndOfMibView => {
            "No more variables left in this MIB View (It is past the end of the MIB tree)"
                .to_string()
        }
    }
}

/// Formats raw bytes as hexadecimal the way Net-SNMP prints a `Hex-STRING`: a space after every
/// octet and a line break after every 16 octets when more follow.
pub(super) fn display_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 3 + bytes.len() / 16);
    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 && index % 16 == 0 {
            output.push('\n');
        }
        output.push_str(&format!("{byte:02X} "));
    }
    output
}

fn display_object(
    value: &ObjectSyntax<'_>,
    syntax: Option<&ValueSyntax>,
    resolver: &MibResolver,
) -> String {
    let with_units = |text: String| match syntax.and_then(|syntax| syntax.units.as_deref()) {
        Some(units) => format!("{text} {units}"),
        None => text,
    };

    match value {
        ObjectSyntax::Number(number) => with_units(display_integer(
            i64::from(*number),
            syntax.filter(|syntax| syntax.base == BaseSyntax::Integer),
        )),
        ObjectSyntax::Gauge32(number) | ObjectSyntax::UInteger32(number) => {
            with_units(display_integer(
                i64::from(*number),
                syntax.filter(|syntax| syntax.base == BaseSyntax::Unsigned),
            ))
        }
        ObjectSyntax::Counter32(number) => with_units(number.to_string()),
        ObjectSyntax::Counter64(number) => with_units(number.to_string()),
        ObjectSyntax::TimeTicks(ticks) => with_units(display_timeticks(*ticks)),
        ObjectSyntax::IpAddress(NetworkAddress::IPv4(address)) => match syntax {
            Some(syntax) if syntax.base == BaseSyntax::NetworkAddress => address
                .octets()
                .iter()
                .map(|octet| format!("{octet:02X}"))
                .collect::<Vec<_>>()
                .join(":"),
            _ => address.to_string(),
        },
        ObjectSyntax::Object(oid) => {
            let oid = oid.to_string();
            resolver
                .resolve(&oid)
                .map_or(oid, |resolution| resolution.name)
        }
        ObjectSyntax::String(bytes) => match syntax {
            Some(syntax) if syntax.base == BaseSyntax::Bits => {
                display_bits(bytes, &syntax.named_numbers)
            }
            Some(ValueSyntax {
                base: BaseSyntax::OctetString,
                display_hint: Some(hint),
                ..
            }) => display_hinted_octets(bytes, hint).unwrap_or_else(|| display_octets(bytes)),
            _ => display_octets(bytes),
        },
        ObjectSyntax::Empty => "NULL".to_string(),
        ObjectSyntax::Opaque(bytes) | ObjectSyntax::NsapAddress(bytes) => display_hex(bytes),
        ObjectSyntax::BitString(bits) => display_hex(bits.data.as_ref()),
        ObjectSyntax::UnknownSimple(value) | ObjectSyntax::UnknownApplication(value) => {
            display_hex(value.as_bytes())
        }
    }
}

fn display_integer(value: i64, syntax: Option<&ValueSyntax>) -> String {
    let Some(syntax) = syntax else {
        return value.to_string();
    };

    if !syntax.named_numbers.is_empty() {
        return syntax
            .named_numbers
            .iter()
            .find(|(number, _)| *number == value)
            .map_or_else(
                || value.to_string(),
                |(_, label)| format!("{label}({value})"),
            );
    }

    syntax
        .display_hint
        .as_deref()
        .and_then(|hint| display_hinted_integer(value, hint))
        .unwrap_or_else(|| value.to_string())
}

/// Applies an RFC 2579 integer display hint (`d`, `d-N`, `x`, `o`, or `b`) the way Net-SNMP does:
/// `d-2` shows 5 as `.05`, and `b` shows 32 binary digits.
fn display_hinted_integer(value: i64, hint: &str) -> Option<String> {
    let mut chars = hint.chars();
    let format = chars.next()?;
    let rest = chars.as_str();
    match format {
        'd' if rest.is_empty() => Some(value.to_string()),
        'd' => {
            let decimals: usize = rest.strip_prefix('-')?.parse().ok()?;
            if decimals == 0 {
                return Some(value.to_string());
            }
            let digits = value.unsigned_abs().to_string();
            let (whole, fraction) = if digits.len() > decimals {
                let (whole, fraction) = digits.split_at(digits.len() - decimals);
                (whole.to_string(), fraction.to_string())
            } else {
                (String::new(), format!("{digits:0>decimals$}"))
            };
            let sign = if value < 0 { "-" } else { "" };
            Some(format!("{sign}{whole}.{fraction}"))
        }
        'x' if rest.is_empty() => Some(format!("{value:x}")),
        'o' if rest.is_empty() => Some(format!("{value:o}")),
        'b' if rest.is_empty() => Some(format!("{:032b}", value as u32)),
        _ => None,
    }
}

fn display_timeticks(ticks: u32) -> String {
    let centiseconds = ticks % 100;
    let seconds = ticks / 100;
    let days = seconds / 86_400;
    let hours = (seconds / 3_600) % 24;
    let minutes = (seconds / 60) % 60;
    let seconds = seconds % 60;
    let time = format!("{hours}:{minutes:02}:{seconds:02}.{centiseconds:02}");
    match days {
        0 => format!("({ticks}) {time}"),
        1 => format!("({ticks}) 1 day, {time}"),
        days => format!("({ticks}) {days} days, {time}"),
    }
}

/// Formats an OCTET STRING without a display hint: printable text is quoted, anything else is
/// shown as hexadecimal.
fn display_octets(bytes: &[u8]) -> String {
    let printable = bytes.iter().all(|byte| {
        byte.is_ascii_graphic() || matches!(byte, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
    });
    if !printable {
        return display_hex(bytes);
    }

    let mut output = String::with_capacity(bytes.len() + 2);
    output.push('"');
    push_escaped(&mut output, &String::from_utf8_lossy(bytes));
    output.push('"');
    output
}

/// Escapes `"` and `\` like Net-SNMP does in quoted text.
fn push_escaped(output: &mut String, text: &str) {
    for character in text.chars() {
        if matches!(character, '"' | '\\') {
            output.push('\\');
        }
        output.push(character);
    }
}

/// Formats BITS as hexadecimal followed by each set bit, labeled when the MIB names it, for
/// example `92 01 sunday(0) wednesday(3) 15 `.
fn display_bits(bytes: &[u8], labels: &[(i64, String)]) -> String {
    let mut output = display_hex(bytes);
    for (byte_index, byte) in bytes.iter().enumerate() {
        for bit in 0..8 {
            if byte & (0x80 >> bit) == 0 {
                continue;
            }
            let position = (byte_index * 8 + bit) as i64;
            match labels.iter().find(|(number, _)| *number == position) {
                Some((_, label)) => output.push_str(&format!("{label}({position}) ")),
                None => output.push_str(&format!("{position} ")),
            }
        }
    }
    output
}

/// One octet-format specification of an RFC 2579 display hint.
#[derive(Debug, PartialEq, Eq)]
struct OctetFormat {
    repeat: bool,
    length: usize,
    format: char,
    separator: Option<char>,
    terminator: Option<char>,
}

fn parse_octet_hint(hint: &str) -> Option<Vec<OctetFormat>> {
    let chars: Vec<char> = hint.chars().collect();
    let mut formats = Vec::new();
    let mut index = 0;
    let is_delimiter = |character: char| !character.is_ascii_digit() && character != '*';

    while index < chars.len() {
        let repeat = chars[index] == '*';
        if repeat {
            index += 1;
        }

        let start = index;
        while chars.get(index).is_some_and(char::is_ascii_digit) {
            index += 1;
        }
        let length: usize = chars[start..index]
            .iter()
            .collect::<String>()
            .parse()
            .ok()?;

        let format = *chars.get(index)?;
        if !matches!(format, 'a' | 'd' | 'o' | 't' | 'x') {
            return None;
        }
        index += 1;

        let separator = chars.get(index).copied().filter(|c| is_delimiter(*c));
        if separator.is_some() {
            index += 1;
        }
        let terminator = if repeat {
            let terminator = chars.get(index).copied().filter(|c| is_delimiter(*c));
            if terminator.is_some() {
                index += 1;
            }
            terminator
        } else {
            None
        };

        formats.push(OctetFormat {
            repeat,
            // Net-SNMP displays at least one octet per field, even for a zero length.
            length: length.max(1),
            format,
            separator,
            terminator,
        });
    }

    (!formats.is_empty()).then_some(formats)
}

/// Applies an RFC 2579 octet-string display hint the way Net-SNMP does. The last format is reused
/// until the value is exhausted, and separators and terminators are only written while octets
/// remain.
fn display_hinted_octets(bytes: &[u8], hint: &str) -> Option<String> {
    let formats = parse_octet_hint(hint)?;
    let mut output = String::new();
    let mut position = 0;
    let mut format_index = 0;

    while position < bytes.len() {
        let format = &formats[format_index.min(formats.len() - 1)];
        format_index += 1;

        let repetitions = if format.repeat {
            let count = usize::from(bytes[position]);
            position += 1;
            count
        } else {
            1
        };

        for _ in 0..repetitions {
            if position >= bytes.len() {
                break;
            }
            let end = (position + format.length).min(bytes.len());
            let chunk = &bytes[position..end];
            position = end;

            match format.format {
                'a' | 't' => output.push_str(&String::from_utf8_lossy(chunk)),
                format_char => {
                    // Like Net-SNMP, a field that runs past the end of the value is completed
                    // with zero octets.
                    let missing = format.length.saturating_sub(chunk.len()).min(16);
                    let number = chunk
                        .iter()
                        .fold(0u128, |number, byte| (number << 8) | u128::from(*byte))
                        .checked_shl(8 * missing as u32)
                        .unwrap_or_default();
                    match format_char {
                        'd' => output.push_str(&number.to_string()),
                        'o' => output.push_str(&format!("{number:o}")),
                        _ => output.push_str(&format!("{number:x}")),
                    }
                }
            }

            if let Some(separator) = format.separator
                && position < bytes.len()
            {
                output.push(separator);
            }
        }

        if let Some(terminator) = format.terminator
            && position < bytes.len()
        {
            output.push(terminator);
        }
    }

    Some(output)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn syntax(base: BaseSyntax) -> ValueSyntax {
        ValueSyntax {
            base,
            named_numbers: Vec::new(),
            display_hint: None,
            units: None,
        }
    }

    fn octet_syntax(hint: &str) -> ValueSyntax {
        ValueSyntax {
            display_hint: Some(hint.to_string()),
            ..syntax(BaseSyntax::OctetString)
        }
    }

    fn string_value(bytes: &[u8]) -> VarBindValue<'_> {
        VarBindValue::Value(ObjectSyntax::String(bytes))
    }

    fn number(value: i32) -> VarBindValue<'static> {
        VarBindValue::Value(ObjectSyntax::Number(value))
    }

    fn display(value: &VarBindValue<'_>, syntax: Option<&ValueSyntax>) -> String {
        display_value(value, syntax, &MibResolver::with_builtin_symbols())
    }

    #[test]
    fn displays_like_snmptrapd_without_mib_syntax() {
        for (value, expected) in [
            (string_value(b"hello world"), "\"hello world\""),
            (string_value(b"say \"hi\""), "\"say \\\"hi\\\"\""),
            (string_value(b"back\\slash"), "\"back\\\\slash\""),
            (string_value(b"hello\n"), "\"hello\n\""),
            (string_value(b""), "\"\""),
            (
                string_value(&[0xde, 0xad, 0xbe, 0xef, 0x00]),
                "DE AD BE EF 00 ",
            ),
            (
                string_value(&[0xff; 17]),
                "FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF \nFF ",
            ),
            (VarBindValue::Value(ObjectSyntax::Counter32(42)), "42"),
            (VarBindValue::Value(ObjectSyntax::Gauge32(7)), "7"),
            (number(-5), "-5"),
            (
                VarBindValue::Value(ObjectSyntax::Counter64(u64::MAX)),
                "18446744073709551615",
            ),
            (
                VarBindValue::Value(ObjectSyntax::TimeTicks(0)),
                "(0) 0:00:00.00",
            ),
            (
                VarBindValue::Value(ObjectSyntax::TimeTicks(123_456)),
                "(123456) 0:20:34.56",
            ),
            (
                VarBindValue::Value(ObjectSyntax::TimeTicks(8_640_123)),
                "(8640123) 1 day, 0:00:01.23",
            ),
            (
                VarBindValue::Value(ObjectSyntax::TimeTicks(17_280_000)),
                "(17280000) 2 days, 0:00:00.00",
            ),
            (
                VarBindValue::Value(ObjectSyntax::IpAddress(NetworkAddress::IPv4(
                    Ipv4Addr::new(10, 0, 0, 1),
                ))),
                "10.0.0.1",
            ),
            (VarBindValue::Unspecified, "NULL"),
            (VarBindValue::Value(ObjectSyntax::Empty), "NULL"),
            (
                VarBindValue::NoSuchObject,
                "No Such Object available on this agent at this OID",
            ),
            (
                VarBindValue::NoSuchInstance,
                "No Such Instance currently exists at this OID",
            ),
            (
                VarBindValue::EndOfMibView,
                "No more variables left in this MIB View (It is past the end of the MIB tree)",
            ),
        ] {
            assert_eq!(display(&value, None), expected);
        }
    }

    #[test]
    fn displays_enumerations_and_integer_hints() {
        let enumeration = ValueSyntax {
            named_numbers: vec![(1, "up".to_string()), (2, "down".to_string())],
            ..syntax(BaseSyntax::Integer)
        };
        assert_eq!(display(&number(2), Some(&enumeration)), "down(2)");
        assert_eq!(display(&number(9), Some(&enumeration)), "9");

        let hinted = |hint: &str| ValueSyntax {
            display_hint: Some(hint.to_string()),
            ..syntax(BaseSyntax::Integer)
        };
        assert_eq!(display(&number(42), Some(&hinted("d"))), "42");
        assert_eq!(display(&number(42), Some(&hinted("d-0"))), "42");
        for invalid in ["x1", "o2", "b3", "q", "d2", "d-x"] {
            assert_eq!(
                display(&number(42), Some(&hinted(invalid))),
                "42",
                "hint {invalid}"
            );
        }
    }

    #[test]
    fn syntax_is_ignored_when_the_value_has_another_type() {
        let enumeration = ValueSyntax {
            named_numbers: vec![(1, "up".to_string())],
            ..syntax(BaseSyntax::Integer)
        };
        assert_eq!(display(&string_value(b"up"), Some(&enumeration)), "\"up\"");
        assert_eq!(display(&number(1), Some(&octet_syntax("1x:"))), "1");
    }

    #[test]
    fn displays_bits_with_labels() {
        let bits = ValueSyntax {
            named_numbers: vec![
                (0, "sunday".to_string()),
                (3, "wednesday".to_string()),
                (6, "saturday".to_string()),
            ],
            ..syntax(BaseSyntax::Bits)
        };
        assert_eq!(
            display(&string_value(&[0x80]), Some(&bits)),
            "80 sunday(0) "
        );
        assert_eq!(
            display(&string_value(&[0x92, 0x01]), Some(&bits)),
            "92 01 sunday(0) wednesday(3) saturday(6) 15 "
        );
    }

    #[test]
    fn appends_units_to_numeric_values() {
        let with_units = |base| ValueSyntax {
            units: Some("seconds".to_string()),
            ..syntax(base)
        };
        assert_eq!(
            display(&number(42), Some(&with_units(BaseSyntax::Integer))),
            "42 seconds"
        );
        assert_eq!(
            display(
                &VarBindValue::Value(ObjectSyntax::Counter32(7)),
                Some(&with_units(BaseSyntax::Counter))
            ),
            "7 seconds"
        );
        assert_eq!(
            display(
                &VarBindValue::Value(ObjectSyntax::TimeTicks(0)),
                Some(&with_units(BaseSyntax::TimeTicks))
            ),
            "(0) 0:00:00.00 seconds"
        );
    }

    #[test]
    fn displays_network_addresses_as_hex() {
        let value = VarBindValue::Value(ObjectSyntax::IpAddress(NetworkAddress::IPv4(
            Ipv4Addr::new(10, 1, 2, 3),
        )));
        assert_eq!(
            display(&value, Some(&syntax(BaseSyntax::NetworkAddress))),
            "0A:01:02:03"
        );
        assert_eq!(display(&value, None), "10.1.2.3");
    }

    #[test]
    fn applies_octet_display_hints() {
        for (hint, bytes, expected) in [
            (
                "1x:",
                &[0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e][..],
                "0:1a:2b:3c:4d:5e",
            ),
            ("255a", b"eth0", "eth0"),
            ("255a", b"a \"b\" \\c", "a \"b\" \\c"),
            ("1d.1d.1d.1d", &[10, 0, 0, 1], "10.0.0.1"),
            (
                "2d-1d-1d,1d:1d:1d.1d,1a1d:1d",
                &[0x07, 0xe9, 9, 26, 12, 30, 45, 0],
                "2025-9-26,12:30:45.0",
            ),
            (
                "2d-1d-1d,1d:1d:1d.1d,1a1d:1d",
                &[0x07, 0xe9, 9, 26, 12, 30, 45, 0, b'+', 5, 30],
                "2025-9-26,12:30:45.0,+5:30",
            ),
            ("*1x:/1x:", &[2, 0xaa, 0xbb, 0xcc], "aa:bb:/cc"),
            ("2d", &[0x41], "16640"),
            ("2x:", &[0xc0, 0x05, 0xd8], "c005:d800"),
            (
                "1d.1d.1d.1d%4d",
                &[192, 168, 0, 1, 0, 0, 0, 3],
                "192.168.0.1%3",
            ),
        ] {
            assert_eq!(
                display(&string_value(bytes), Some(&octet_syntax(hint))),
                expected,
                "hint {hint}"
            );
        }
    }

    /// Outputs recorded from Net-SNMP 5.9.4's `snmptrapd` for objects using these hints.
    #[test]
    fn matches_net_snmp_hint_rendering() {
        let bracket = "0a[2x:2x:2x:2x:2x:2x:2x:2x]0a:2d";
        let address = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
        let with_port = [&address[..], &[0x00, 0x50]].concat();
        let with_extra = [&with_port[..], &[0xaa]].concat();
        for (hint, bytes, expected) in [
            (bracket, &address[..], "\u{fffd}[8000:0:0:0:0:0:0:100"),
            (bracket, &with_port[..], "\u{fffd}[8000:0:0:0:0:0:0:100]P"),
            (
                bracket,
                &with_extra[..],
                "\u{fffd}[8000:0:0:0:0:0:0:100]P:43520",
            ),
            (bracket, &[0xfe, 0x80][..], "\u{fffd}[8000"),
            ("*1x:/1x:", &[2, 0xaa, 0xbb, 0xcc][..], "aa:bb:/cc"),
            ("*1x:/1x:", &[2, 0xaa, 0xbb][..], "aa:bb"),
            ("*1x:/1x:", &[5, 0xaa][..], "aa"),
            ("*1x:/1x:", &[0, 0xaa, 0xbb][..], "/aa:bb"),
            ("*1x:/1x:", &[1, 0xaa, 0xbb, 0xcc][..], "aa:/bb:cc"),
            ("1o-", &[0x0a, 0x1b, 0xff][..], "12-33-377"),
            (
                "1d.1d.1d.1d%4d",
                &[192, 168, 0, 1, 0, 0, 0, 3][..],
                "192.168.0.1%3",
            ),
            ("1d.1d.1d.1d%4d", &[192, 168, 0, 1][..], "192.168.0.1"),
            ("1d.1d.1d.1d%4d", &[192, 168, 0, 1, 0][..], "192.168.0.1%0"),
        ] {
            assert_eq!(
                display(&string_value(bytes), Some(&octet_syntax(hint))),
                expected,
                "hint {hint} on {bytes:02x?}"
            );
        }

        let hinted = |hint: &str| ValueSyntax {
            display_hint: Some(hint.to_string()),
            ..syntax(BaseSyntax::Integer)
        };
        for (hint, value, expected) in [
            ("d-2", 0, ".00"),
            ("d-2", 5, ".05"),
            ("d-2", -5, "-.05"),
            ("d-2", 1234, "12.34"),
            ("d-2", -1234, "-12.34"),
            ("d-1", 1234, "123.4"),
            ("d-1", -7, "-.7"),
            ("d-1", 0, ".0"),
            ("d-3", 5, ".005"),
            ("d-3", 123_456, "123.456"),
            ("x", 255, "ff"),
            ("x", -1, "ffffffffffffffff"),
            ("o", 8, "10"),
            ("b", 5, "00000000000000000000000000000101"),
            ("b", -2, "11111111111111111111111111111110"),
        ] {
            assert_eq!(
                display(&number(value), Some(&hinted(hint))),
                expected,
                "hint {hint} on {value}"
            );
        }

        let unsigned = ValueSyntax {
            display_hint: Some("d-2".to_string()),
            units: Some("volts".to_string()),
            ..syntax(BaseSyntax::Unsigned)
        };
        let gauge = |value| VarBindValue::Value(ObjectSyntax::Gauge32(value));
        assert_eq!(display(&gauge(1234), Some(&unsigned)), "12.34 volts");
        assert_eq!(display(&gauge(0), Some(&unsigned)), ".00 volts");
        let widgets = ValueSyntax {
            units: Some("widgets".to_string()),
            ..syntax(BaseSyntax::Unsigned)
        };
        assert_eq!(display(&gauge(7), Some(&widgets)), "7 widgets");
        // An integer syntax does not apply to unsigned values.
        assert_eq!(display(&gauge(1234), Some(&hinted("d-2"))), "1234");
    }

    #[test]
    fn displays_timeticks_with_hours_and_minutes() {
        assert_eq!(
            display(
                &VarBindValue::Value(ObjectSyntax::TimeTicks(4_000_000)),
                None
            ),
            "(4000000) 11:06:40.00"
        );
    }

    #[test]
    fn invalid_hints_fall_back_to_default_formatting() {
        assert_eq!(
            display(&string_value(b"abc"), Some(&octet_syntax("1q"))),
            "\"abc\""
        );
        assert_eq!(
            display(&string_value(b"abc"), Some(&octet_syntax(""))),
            "\"abc\""
        );
    }
}
