use crate::proto::certificate_validator::parse::parse_chain_to_x509_attributes;

pub fn get_aki_for_pem_chain(pem_chain: &[u8]) -> Option<Vec<u8>> {
    parse_chain_to_x509_attributes(pem_chain)
        .ok()
        .and_then(|attrs| {
            attrs
                .extensions
                .into_iter()
                .find(|ext| ext.oid == "2.5.29.35")
                .map(|ext| ext.value)
        })
        .and_then(|ext_value| {
            ext_value
                .split("\n")
                .filter_map(|entry| entry.strip_prefix("Key ID: "))
                .next()
                .and_then(parse_serial)
        })
}

// x509-parser has a format_serial() function, but no associated parse_serial(),
// so we have to implement it ourselves.
/// Parses a string in "xx:xx:xx" format (sequence of hex-encoded bytes)
/// into a vector of raw byte values.
fn parse_serial(value: &str) -> Option<Vec<u8>> {
    let mut result: Vec<u8> = Vec::with_capacity(1 + value.len() / 3);
    for part in value.split(":") {
        match u8::from_str_radix(part, 16) {
            Ok(value) => result.push(value),
            Err(_) => return None,
        }
    }
    Some(result)
}
