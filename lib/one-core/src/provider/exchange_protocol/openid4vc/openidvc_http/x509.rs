use ct_codecs::{Base64, Base64UrlSafeNoPadding, Decoder, Encoder};
use shared_types::DidValue;
use x509_parser::certificate::X509Certificate;
use x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME;

use crate::provider::did_method::mdl::parse_x509_from_der;
use crate::provider::exchange_protocol::error::ExchangeProtocolError;

enum Certificate {
    Der(Vec<u8>),
}

pub(crate) fn extract_x5c_san_dns(
    x5c: &[String],
    client_id: &str,
    x509_ca_certificate: &str,
) -> Result<DidValue, ExchangeProtocolError> {
    if x5c.is_empty() {
        return Err(ExchangeProtocolError::Failed("x5c empty".to_string()));
    }

    let mut chain: Vec<Certificate> = x5c.iter().try_fold(Vec::new(), |mut aggr, item| {
        let der = Base64::decode_to_vec(item, None)
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;
        aggr.push(Certificate::Der(der));
        Ok(aggr)
    })?;

    // CA certificate as the last item in the chain
    let x509_ca_certificate = Base64UrlSafeNoPadding::decode_to_vec(x509_ca_certificate, None)
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;
    chain.push(Certificate::Der(x509_ca_certificate));

    let mut previous: Option<&Certificate> = None;
    for certificate in chain.iter() {
        let current = parse_x509(certificate)?;
        if !current.validity().is_valid() {
            return Err(ExchangeProtocolError::Failed(
                "certificate expired".to_string(),
            ));
        }

        if let Some(previous) = previous {
            // parent entry in the chain, validate signature
            let previous = parse_x509(previous)?;
            previous
                .verify_signature(Some(current.public_key()))
                .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;
        } else {
            // first in chain, check client_id match
            let dns_names = current
                .subject()
                .iter_by_oid(&OID_X509_EXT_SUBJECT_ALT_NAME)
                .try_fold(Vec::new(), |mut aggr, entry| {
                    if let Ok(cn) = entry.as_str() {
                        aggr.push(cn.to_string());
                    }
                    Ok(aggr)
                })?;

            if !dns_names
                .iter()
                .any(|dns_name| is_dns_name_matching(dns_name, client_id))
            {
                return Err(ExchangeProtocolError::Failed(format!(
                    "dNSName mismatch client_id: '{client_id}'"
                )));
            }
        }

        previous = Some(certificate);
    }

    // construct DidValue from the first (leaf) entry
    // https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.6
    let Some(Certificate::Der(der)) = chain.first() else {
        return Err(ExchangeProtocolError::Failed(
            "invalid certificate".to_string(),
        ));
    };

    let did_mdl = Base64UrlSafeNoPadding::encode_to_string(der)
        .map(|cert| format!("did:mdl:certificate:{cert}"))
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

    did_mdl
        .parse()
        .map_err(|e: anyhow::Error| ExchangeProtocolError::Failed(e.to_string()))
}

fn parse_x509(certificate: &Certificate) -> Result<X509Certificate, ExchangeProtocolError> {
    match certificate {
        Certificate::Der(der) => parse_x509_from_der(der),
    }
    .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))
}

fn is_dns_name_matching(dns_name: &str, client_id: &str) -> bool {
    // https://datatracker.ietf.org/doc/html/rfc1034#section-4.3.3
    if let Some(wildcard_domain) = dns_name.strip_prefix("*") {
        client_id.ends_with(wildcard_domain)
    } else {
        // simple case
        dns_name == client_id
    }
}
