use std::sync::Arc;

use asn1_rs::Oid;
use ct_codecs::{Base64, Decoder, Encoder};
use futures::executor::block_on;
use one_crypto::signer::ecdsa::ECDSASigner;
use standardized_types::x509::KeyIdentifier;
use tokio::task::block_in_place;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::ParsedExtension;
use x509_parser::oid_registry::{
    OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER, OID_X509_EXT_SUBJECT_KEY_IDENTIFIER,
};
use x509_parser::pem::Pem;

use crate::config::core_config::KeyAlgorithmType;
use crate::error::{ContextWithErrorCode, ErrorCode, ErrorCodeMixin, NestedError};
use crate::model::key::Key;
use crate::provider::key_storage::KeyStorage;

/// Converts the arc-slice OID constants of [`standardized_types::x509::oid`] into the
/// representation the certificate parser works with.
///
/// The builder side (`rcgen` / `yasna`) consumes those constants directly.
pub(crate) fn parse_oid(arcs: &[u64]) -> Result<Oid<'static>, CertificateParsingError> {
    Ok(Oid::from(arcs)?)
}

pub fn pem_chain_into_x5c(pem_chain: &str) -> Result<Vec<String>, CertificateParsingError> {
    Pem::iter_from_buffer(pem_chain.as_bytes())
        .map(|pem| {
            let encoded = Base64::encode_to_string(pem?.contents)?;
            Ok(encoded)
        })
        .collect()
}

pub(crate) fn x5c_into_pem_chain(x5c: &[String]) -> Result<String, CertificateParsingError> {
    let der_chain = x5c.iter().try_fold(Vec::new(), |mut aggr, item| {
        // base64 cert content may be line-wrapped (XML-DSig X509Certificate); ignore whitespace.
        aggr.push(Base64::decode_to_vec(item, Some(b"\n\r\t "))?);
        Ok::<_, CertificateParsingError>(aggr)
    })?;
    Ok(der_chain_into_pem_chain(der_chain))
}

pub(crate) fn der_chain_into_pem_chain(der_chain: Vec<Vec<u8>>) -> String {
    use pem::{EncodeConfig, LineEnding, Pem, encode_many_config};
    let pems = der_chain
        .into_iter()
        .map(|der| Pem::new("CERTIFICATE", der))
        .collect::<Vec<_>>();
    encode_many_config(&pems, EncodeConfig::new().set_line_ending(LineEnding::LF))
}

pub(crate) fn pem_chain_into_der_chain(
    pem_chain: &str,
) -> Result<Vec<Vec<u8>>, CertificateParsingError> {
    Pem::iter_from_buffer(pem_chain.as_bytes())
        .map(|pem| Ok(pem?.contents))
        .collect()
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
    #[error("Encoding error: `{0}`")]
    Encoding(#[from] ct_codecs::Error),
    #[error("OID error: `{0}`")]
    Oid(#[from] asn1_rs::OidParseError),
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
) -> Result<Option<KeyIdentifier>, CertificateParsingError> {
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
        .map(|key_id| KeyIdentifier::from(key_id.0.to_owned())))
}

/// For each certificate in the chain, retrieve the authority key identifier.
pub fn pem_chain_to_authority_key_identifiers(
    pem_chain: &str,
) -> Result<Vec<KeyIdentifier>, CertificateParsingError> {
    Pem::iter_from_buffer(pem_chain.as_bytes())
        .map(|pem| {
            let pem = pem?;
            let cert = pem.parse_x509()?;
            let key_identifier = authority_key_identifier(&cert)?;
            Ok(key_identifier)
        })
        // If the chain goes up to the CA (which is self-signed) then the last entry might not have an authority key identifier
        // hence filter out the empty values.
        .filter_map(Result::transpose)
        .collect()
}

/// Extracts the Subject key identifier from the leaf certificate (if any)
/// Consumes either PEM chain or a single PEM certificate
pub fn pem_to_subject_key_identifier(
    pem: &str,
) -> Result<Option<KeyIdentifier>, CertificateParsingError> {
    let leaf = Pem::iter_from_buffer(pem.as_bytes()).next();
    let Some(leaf) = leaf else {
        return Ok(None);
    };

    let pem = leaf?;
    let cert = pem.parse_x509()?;
    let Some(ski) = cert
        .get_extension_unique(&OID_X509_EXT_SUBJECT_KEY_IDENTIFIER)?
        .map(|ext| ext.parsed_extension())
        .map(|ext| match ext {
            ParsedExtension::SubjectKeyIdentifier(key_identifier) => Ok(key_identifier),
            _ => Err(CertificateParsingError::UnexpectedExtension),
        })
        .transpose()?
    else {
        return Ok(None);
    };

    Ok(Some(ski.0.to_vec().into()))
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum RcgenSigningError {
    #[error("Unsupported key type `{0}`")]
    UnsupportedKeyType(KeyAlgorithmType),
    #[error(transparent)]
    CryptoError(#[from] one_crypto::SignerError),
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for RcgenSigningError {
    fn error_code(&self) -> ErrorCode {
        match self {
            RcgenSigningError::Nested(nested) => nested.error_code(),
            _ => ErrorCode::BR_0329,
        }
    }
}

/// adapter for use with the `rcgen` crate
pub(crate) struct SigningKeyAdapter {
    key: Key,
    public_key: Vec<u8>,
    key_storage: Arc<dyn KeyStorage>,
    algorithm: &'static rcgen::SignatureAlgorithm,
}

impl SigningKeyAdapter {
    pub(crate) fn new(
        key: Key,
        key_storage: Arc<dyn KeyStorage>,
    ) -> Result<SigningKeyAdapter, RcgenSigningError> {
        let algorithm = match key
            .key_algorithm_type()
            .error_while("getting key algorithm type")?
        {
            KeyAlgorithmType::Ecdsa => &rcgen::PKCS_ECDSA_P256_SHA256,
            KeyAlgorithmType::Eddsa => &rcgen::PKCS_ED25519,
            other => return Err(RcgenSigningError::UnsupportedKeyType(other)),
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
        let key_storage = self.key_storage.clone();
        let key = self.key.clone();
        let msg = msg.to_vec();
        let algorithm = self.algorithm;

        // block_in_place keeps the runtime workers available to drive the
        // HTTP futures of remote key storages while this thread blocks;
        // requires a multi-thread runtime (tests need the multi_thread flavor)
        block_in_place(|| {
            block_on(async move {
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
            })
        })
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
            format!("{identifier:x}"),
            "61:20:eb:7e:ae:c1:f4:b5:bc:26:a1:5f:f0:6a:32:a6:2c:75:f5:fb"
        );
    }
}
