use anyhow::Context;
use ct_codecs::{Base64, Decoder, Encoder};
use x509_parser::prelude::Pem;

pub(crate) fn pem_chain_into_x5c(pem_chain: &str) -> anyhow::Result<Vec<String>> {
    Pem::iter_from_buffer(pem_chain.as_bytes())
        .map(|pem| {
            let pem = pem.context("failed to parse x509 certificate")?;
            let encoded = Base64::encode_to_string(pem.contents)
                .context("failed to encode x509 certificate")?;
            Ok(encoded)
        })
        .collect()
}

pub(crate) fn x5c_into_pem_chain(x5c: &[String]) -> anyhow::Result<String> {
    use pem::{EncodeConfig, LineEnding, Pem, encode_many_config};
    let pems: Vec<Pem> = x5c.iter().try_fold(Vec::new(), |mut aggr, item| {
        let der = Base64::decode_to_vec(item, None).context("failed to decode x5c")?;
        aggr.push(pem::Pem::new("CERTIFICATE", der));
        Ok::<_, anyhow::Error>(aggr)
    })?;
    Ok(encode_many_config(
        &pems,
        EncodeConfig::new().set_line_ending(LineEnding::LF),
    ))
}

pub(crate) fn is_dns_name_matching(dns_def: &str, target_domain: &str) -> bool {
    // https://datatracker.ietf.org/doc/html/rfc1034#section-4.3.3
    if let Some(wildcard_domain) = dns_def.strip_prefix("*") {
        target_domain.ends_with(wildcard_domain)
    } else {
        // simple case
        dns_def == target_domain
    }
}
