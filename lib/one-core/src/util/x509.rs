use std::sync::Arc;

use anyhow::{Context, bail};
use ct_codecs::{Base64, Base64UrlSafeNoPadding, Decoder, Encoder};
use x509_parser::certificate::X509Certificate;
use x509_parser::oid_registry::{
    OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY, OID_SIG_ED25519, OID_X509_EXT_SUBJECT_ALT_NAME,
};
use x509_parser::prelude::{GeneralName, ParsedExtension, Pem};

use crate::config::core_config::KeyAlgorithmType;
use crate::model::key::PublicKeyJwk;
use crate::provider::did_method::error::DidMethodError;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;

#[derive(PartialEq, Eq, Debug, Clone)]
pub(crate) enum Certificate {
    Der(Vec<u8>),
}

impl Certificate {
    pub(crate) fn from_base64_url_safe_no_padding(base64: &str) -> anyhow::Result<Self> {
        let der = Base64UrlSafeNoPadding::decode_to_vec(base64, None)
            .context("failed to decode certificate")?;
        Ok(Self::Der(der))
    }

    pub(crate) fn as_base64_url_safe_no_padding(&self) -> anyhow::Result<String> {
        let Certificate::Der(der) = self;
        Base64UrlSafeNoPadding::encode_to_string(der).context("failed to encode certificate")
    }
}

pub(crate) fn extract_leaf_certificate_from_verified_chain(
    x5c: &[String],
    client_id: &str,
    x509_ca_certificate: Option<&Certificate>,
) -> anyhow::Result<Certificate> {
    if x5c.is_empty() {
        bail!("x5c empty");
    }

    let mut chain: Vec<Certificate> = x5c.iter().try_fold(Vec::new(), |mut aggr, item| {
        let der = Base64::decode_to_vec(item, None).context("failed to decode x5c")?;
        aggr.push(Certificate::Der(der));
        Ok::<_, anyhow::Error>(aggr)
    })?;

    // CA certificate as the last item in the chain
    if let Some(x509_ca_certificate) = x509_ca_certificate {
        if !chain.contains(x509_ca_certificate) {
            chain.push(x509_ca_certificate.clone());
        }
    };

    let mut previous: Option<&Certificate> = None;
    for certificate in chain.iter() {
        let current = parse_x509(certificate)?;
        if !current.validity().is_valid() {
            bail!("certificate expired");
        }

        if let Some(previous) = previous {
            // parent entry in the chain, validate signature
            let previous = parse_x509(previous)?;
            previous
                .verify_signature(Some(current.public_key()))
                .context("failed to verify certificate signature")?;
        } else {
            // first in chain, check client_id match
            let dns_names = current
                .iter_extensions()
                .filter(|extension| extension.oid == OID_X509_EXT_SUBJECT_ALT_NAME)
                .try_fold(Vec::new(), |mut aggr, entry| {
                    if let ParsedExtension::SubjectAlternativeName(san) = entry.parsed_extension() {
                        for name in &san.general_names {
                            if let GeneralName::DNSName(dns) = name {
                                aggr.push(dns.to_string());
                            }
                        }
                    }
                    Ok::<_, anyhow::Error>(aggr)
                })?;

            if !dns_names
                .iter()
                .any(|dns_name| is_dns_name_matching(dns_name, client_id))
            {
                bail!("dNSName mismatch client_id: '{client_id}'");
            }
        }

        previous = Some(certificate);
    }

    chain
        .into_iter()
        .next()
        .context("no leaf certificate found in chain")
}

pub(crate) fn extract_jwk_from_der(
    certificate: &str,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
) -> anyhow::Result<PublicKeyJwk> {
    let certificate = Base64UrlSafeNoPadding::decode_to_vec(certificate, None)
        .context("failed to decode certificate")?;

    let x509 = parse_x509_from_der(&certificate).context("failed to parse certificate")?;

    let key_algorithm = match &x509.subject_pki.algorithm.algorithm {
        alg if alg == &OID_SIG_ED25519 => key_algorithm_provider
            .key_algorithm_from_type(KeyAlgorithmType::Eddsa)
            .ok_or(DidMethodError::KeyAlgorithmNotFound)?,

        alg if alg == &OID_KEY_TYPE_EC_PUBLIC_KEY => {
            let curve_oid = x509
                .subject_pki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.as_oid().ok())
                .context("Invalid did:mdl:certificate: EC algorithm missing curve information")?;

            if curve_oid != OID_EC_P256 {
                bail!("did:mdl:certificate EC algorithm with unsupported curve. oid: {curve_oid}");
            }

            key_algorithm_provider
                .key_algorithm_from_type(KeyAlgorithmType::Ecdsa)
                .ok_or(DidMethodError::KeyAlgorithmNotFound)?
        }
        other => {
            bail!("certificate with unsupported algorithm. oid: {other}");
        }
    };

    key_algorithm
        .parse_raw(x509.subject_pki.raw)
        .context("failed to parse certificate public key")?
        .public_key_as_jwk()
        .context("failed to create public key JWK from certificate")
}

fn parse_x509(certificate: &Certificate) -> anyhow::Result<X509Certificate> {
    match certificate {
        Certificate::Der(der) => parse_x509_from_der(der),
    }
    .context("failed to parse x509 certificate")
}

fn parse_x509_from_der(certificate: &[u8]) -> Result<X509Certificate, DidMethodError> {
    let (_leftover, certificate) =
        x509_parser::parse_x509_certificate(certificate).map_err(|err| {
            DidMethodError::CouldNotCreate(format!(
                "Error parsing x509 certificate from DER format: {err}"
            ))
        })?;

    Ok(certificate)
}

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
