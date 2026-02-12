use std::sync::Arc;

use anyhow::Context;
use ct_codecs::{Base64, Decoder, Encoder};
use one_crypto::signer::ecdsa::ECDSASigner;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::ParsedExtension;
use x509_parser::oid_registry::{
    OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER, OID_X509_EXT_SUBJECT_KEY_IDENTIFIER,
};
use x509_parser::pem::Pem;

use crate::config::core_config::KeyAlgorithmType;
use crate::error::{ErrorCode, ErrorCodeMixin};
use crate::model::key::Key;
use crate::provider::key_storage::KeyStorage;

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
            let key_identifier = authority_key_identifier(&cert)
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

#[derive(Debug, thiserror::Error)]
pub enum CertificateParsingError {
    #[error("Unexpected extension")]
    UnexpectedExtension,
    #[error("Missing authority key identifier")]
    MissingAuthorityKeyIdentifier,

    #[error("PEM error: `{0}`")]
    PEMError(#[from] x509_parser::error::PEMError),
    #[error("X509 nom error: `{0}`")]
    X509NomError(#[from] x509_parser::nom::Err<x509_parser::error::X509Error>),
    #[error("X509 error: `{0}`")]
    X509ParserError(#[from] x509_parser::error::X509Error),
}

impl ErrorCodeMixin for CertificateParsingError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::MissingAuthorityKeyIdentifier => ErrorCode::BR_0243,
            _ => ErrorCode::BR_0224,
        }
    }
}

pub(crate) fn subject_key_identifier(
    cert: &X509Certificate,
) -> Result<Option<String>, CertificateParsingError> {
    Ok(cert
        .get_extension_unique(&OID_X509_EXT_SUBJECT_KEY_IDENTIFIER)?
        .map(|ext| ext.parsed_extension())
        .map(|ext| match ext {
            ParsedExtension::SubjectKeyIdentifier(key_identifier) => Ok(key_identifier),
            _ => Err(CertificateParsingError::UnexpectedExtension),
        })
        .transpose()?
        .map(|key_id| format!("{key_id:x}")))
}

pub(crate) fn authority_key_identifier(
    cert: &X509Certificate,
) -> Result<Option<String>, CertificateParsingError> {
    Ok(cert
        .get_extension_unique(&OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER)?
        .map(|ext| ext.parsed_extension())
        .map(|ext| match ext {
            ParsedExtension::AuthorityKeyIdentifier(key_identifier) => Ok(key_identifier),
            _ => Err(CertificateParsingError::UnexpectedExtension),
        })
        .transpose()?
        .map(|key_identifier| {
            key_identifier
                .key_identifier
                .as_ref()
                .ok_or(CertificateParsingError::MissingAuthorityKeyIdentifier)
        })
        .transpose()?
        .map(|key_id| format!("{key_id:x}")))
}

#[derive(Eq, PartialEq)]
pub struct AuthorityKeyIdentifier(pub Vec<u8>);

pub fn get_akis_for_pem_chain(
    pem_chain: &[u8],
) -> Result<Vec<AuthorityKeyIdentifier>, CertificateParsingError> {
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
                Err(e) => Some(Err(e.into())),
            },
            Err(e) => Some(Err(e.into())),
        })
        .collect()
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum RcgenSigningError {
    #[error("Unsupported key type `{0}`")]
    UnsupportedKeyType(String),
    #[error("Mapping error: {0}")]
    MappingError(String),
    #[error(transparent)]
    CryptoError(#[from] one_crypto::SignerError),
}

impl ErrorCodeMixin for RcgenSigningError {
    fn error_code(&self) -> ErrorCode {
        ErrorCode::BR_0329
    }
}

/// adapter for use with the `rcgen` crate
pub(crate) struct SigningKeyAdapter {
    key: Key,
    public_key: Vec<u8>,
    key_storage: Arc<dyn KeyStorage>,
    algorithm: &'static rcgen::SignatureAlgorithm,
    handle: tokio::runtime::Handle,
}

impl SigningKeyAdapter {
    pub(crate) fn new(
        key: Key,
        key_storage: Arc<dyn KeyStorage>,
        handle: tokio::runtime::Handle,
    ) -> Result<SigningKeyAdapter, RcgenSigningError> {
        let algorithm = match key.key_algorithm_type() {
            Some(KeyAlgorithmType::Ecdsa) => &rcgen::PKCS_ECDSA_P256_SHA256,
            Some(KeyAlgorithmType::Eddsa) => &rcgen::PKCS_ED25519,
            Some(other) => return Err(RcgenSigningError::UnsupportedKeyType(other.to_string())),
            None => {
                return Err(RcgenSigningError::MappingError(format!(
                    "missing key type on key {}",
                    key.id
                )));
            }
        };

        let public_key = if algorithm == &rcgen::PKCS_ECDSA_P256_SHA256 {
            ECDSASigner::parse_public_key(&key.public_key, false)?
        } else {
            key.public_key.to_owned()
        };

        Ok(Self {
            key,
            key_storage,
            algorithm,
            handle,
            public_key,
        })
    }
}

impl rcgen::PublicKeyData for SigningKeyAdapter {
    fn der_bytes(&self) -> &[u8] {
        self.public_key.as_ref()
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        self.algorithm
    }
}

impl rcgen::SigningKey for SigningKeyAdapter {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let handle = self.handle.clone();
        let key_storage = self.key_storage.clone();
        let key = self.key.clone();
        let msg = msg.to_vec();
        let algorithm = self.algorithm;

        std::thread::spawn(move || {
            let _guard = handle.enter();
            let handle = tokio::spawn(async move {
                let mut signature = key_storage
                    .key_handle(&key)
                    .map_err(|error| {
                        tracing::warn!(%error, "Failed to sign X509 - key handle failure");
                        rcgen::Error::RemoteKeyError
                    })?
                    .sign(&msg)
                    .await
                    .map_err(|error| {
                        tracing::warn!(%error, "Failed to sign X509");
                        rcgen::Error::RemoteKeyError
                    })?;

                // P256 signature must be ASN.1 encoded
                if algorithm == &rcgen::PKCS_ECDSA_P256_SHA256 {
                    use asn1_rs::{Integer, SequenceOf, ToDer};

                    let s: [u8; 32] = signature.split_off(32).try_into().map_err(|_| {
                        tracing::warn!("Failed to convert generated signature");
                        rcgen::Error::RemoteKeyError
                    })?;
                    let r: [u8; 32] = signature.try_into().map_err(|_| {
                        tracing::warn!("Failed to convert generated signature");
                        rcgen::Error::RemoteKeyError
                    })?;

                    let r = Integer::from_const_array(r);
                    let s = Integer::from_const_array(s);
                    let seq = SequenceOf::from_iter([r, s]);
                    signature = seq.to_der_vec().map_err(|error| {
                        tracing::warn!(%error, "Failed to serialize P256 signature");
                        rcgen::Error::RemoteKeyError
                    })?;
                }

                Ok(signature)
            });
            futures::executor::block_on(handle).map_err(|_| {
                tracing::warn!("Failed to join X509 task");
                rcgen::Error::RemoteKeyError
            })?
        })
        .join()
        .map_err(|_| {
            tracing::warn!("Failed to join X509 thread");
            rcgen::Error::RemoteKeyError
        })?
    }
}

#[cfg(test)]
mod tests {
    use similar_asserts::assert_eq;
    use x509_parser::pem::parse_x509_pem;

    use super::*;

    #[test]
    fn test_authority_key_identifier() {
        let pem = "-----BEGIN CERTIFICATE-----
MIIBODCB66ADAgECAhQjDWW20goQ5ZYZHnUYjgEAtpYAxjAFBgMrZXAwEjEQMA4G
A1UEAwwHQ0EgY2VydDAeFw0yMzA3MjgxMzA5MDhaFw0zNTAxMjYxMzA5MDhaMBIx
EDAOBgNVBAMMB0NBIGNlcnQwKjAFBgMrZXADIQBKBEnJk+6LyU8tcMSYIw8mvo06
E2W4JVTSZRP1JavvX6NTMFEwHwYDVR0jBBgwFoAUYSDrfq7B9LW8JqFf8Goypix1
9fswHQYDVR0OBBYEFGEg636uwfS1vCahX/BqMqYsdfX7MA8GA1UdEwEB/wQFMAMB
Af8wBQYDK2VwA0EAia2OnNqDv08Y8X6r1e7iBsgYsEa6V2Df65WDMKd/8LHCuhvL
GsPNAYTwQu1egNMnoBk0k0cwNJCBJmS3zEGaDw==
-----END CERTIFICATE-----";

        let (_, pem) = parse_x509_pem(pem.as_bytes()).unwrap();
        let cert = pem.parse_x509().unwrap();
        let identifier = authority_key_identifier(&cert).unwrap().unwrap();
        assert_eq!(
            identifier,
            "61:20:eb:7e:ae:c1:f4:b5:bc:26:a1:5f:f0:6a:32:a6:2c:75:f5:fb"
        );
    }
}
