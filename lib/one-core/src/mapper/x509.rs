use anyhow::Context;
use ct_codecs::{Base64, Decoder, Encoder};
use x509_parser::pem::Pem;

use crate::util::x509;

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

/// For each certificate in the chain, retrieve the authority key identifier.
pub(crate) fn pem_chain_to_authority_key_identifiers(
    pem_chain: &str,
) -> anyhow::Result<Vec<String>> {
    Pem::iter_from_buffer(pem_chain.as_bytes())
        .map(|pem| {
            let pem = pem.context("failed to parse x509 certificate")?;
            let cert = pem
                .parse_x509()
                .context("failed to parse x509 certificate")?;
            let key_identifier = x509::authority_key_identifier(&cert)
                .context("failed to parse authority key identifier")?;
            Ok(key_identifier)
        })
        // If the chain goes up to the CA (which is self-signed) then the last entry might not have an authority key identifier
        // hence filter out the empty values.
        .filter_map(Result::transpose)
        .collect()
}

pub(crate) fn x5c_into_pem_chain(x5c: &[String]) -> anyhow::Result<String> {
    let der_chain = x5c.iter().try_fold(Vec::new(), |mut aggr, item| {
        aggr.push(Base64::decode_to_vec(item, None).context("failed to decode x5c")?);
        Ok::<_, anyhow::Error>(aggr)
    })?;
    der_chain_into_pem_chain(der_chain)
}

pub(crate) fn der_chain_into_pem_chain(der_chain: Vec<Vec<u8>>) -> anyhow::Result<String> {
    use pem::{EncodeConfig, LineEnding, Pem, encode_many_config};
    let pems = der_chain
        .into_iter()
        .map(|der| Pem::new("CERTIFICATE", der))
        .collect::<Vec<_>>();
    Ok(encode_many_config(
        &pems,
        EncodeConfig::new().set_line_ending(LineEnding::LF),
    ))
}
