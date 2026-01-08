use x509_parser::extensions::ParsedExtension;
use x509_parser::pem::Pem;

use crate::service::error::ValidationError;

#[derive(Eq, PartialEq)]
pub struct AuthorityKeyIdentifier(pub Vec<u8>);

pub fn get_akis_for_pem_chain(
    pem_chain: &[u8],
) -> Result<Vec<AuthorityKeyIdentifier>, ValidationError> {
    Pem::iter_from_buffer(pem_chain)
        .filter_map(|item| match item {
            Ok(pem) => match pem.parse_x509() {
                Ok(x509_cert) => x509_cert
                    .extensions()
                    .iter()
                    .filter_map(|ext| match ext.parsed_extension() {
                        ParsedExtension::AuthorityKeyIdentifier(aki) => Some(aki),
                        _ => None,
                    })
                    .filter_map(|aki| aki.key_identifier.as_ref())
                    .map(|key_id| AuthorityKeyIdentifier(key_id.0.to_owned()))
                    .next() // RFC 5280 disallows more than 1 instance of an extension
                    .map(Ok),
                Err(e) => Some(Err(ValidationError::CertificateParsingFailed(
                    e.to_string(),
                ))),
            },
            Err(e) => Some(Err(ValidationError::CertificateParsingFailed(
                e.to_string(),
            ))),
        })
        .collect()
}
