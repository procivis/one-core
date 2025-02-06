use x509_parser::certificate::X509Certificate;
use x509_parser::error::X509Error;

use super::DidMdl;
use crate::model::key::Key;
use crate::provider::key_algorithm::error::KeyAlgorithmError;

#[derive(Debug, thiserror::Error)]
pub enum DidMdlValidationError {
    #[error("Signature verification of provided certificate failed: {0}")]
    CertificateSignatureVerificationFailed(X509Error),

    #[error("Certificate expired")]
    CertificateExpired,

    #[error("Certificate subject public key doesn't match provided key")]
    SubjectPublicKeyNotMatching,

    #[error("Provided key type `{0}` is not supported")]
    KeyTypeNotSupported(String),

    #[error("Cannot parse certificate subject public key: {0}")]
    SubjectPublicKeyInvalidDer(KeyAlgorithmError),
}

#[cfg_attr(test, mockall::automock)]
pub trait DidMdlValidator: Send + Sync {
    #[allow(clippy::needless_lifetimes)]
    fn validate_certificate<'cert>(
        &self,
        certificate: &X509Certificate<'cert>,
    ) -> Result<(), DidMdlValidationError>;

    #[allow(clippy::needless_lifetimes)]
    fn validate_subject_public_key<'cert>(
        &self,
        certificate: &X509Certificate<'cert>,
        key: &Key,
    ) -> Result<(), DidMdlValidationError>;
}

impl DidMdlValidator for DidMdl {
    fn validate_certificate(
        &self,
        certificate: &X509Certificate,
    ) -> Result<(), DidMdlValidationError> {
        check_is_valid_now(certificate)?;

        let signer_public_key = self.params.with_iaca_certificate(|cert| cert.public_key());

        certificate
            .verify_signature(Some(signer_public_key))
            .map_err(DidMdlValidationError::CertificateSignatureVerificationFailed)
    }

    fn validate_subject_public_key(
        &self,
        certificate: &X509Certificate<'_>,
        key: &Key,
    ) -> Result<(), DidMdlValidationError> {
        check_is_valid_now(certificate)?;

        let key_algorithm = self
            .key_algorithm_provider
            .key_algorithm_from_name(&key.key_type)
            .ok_or(DidMdlValidationError::KeyTypeNotSupported(
                key.key_type.to_string(),
            ))?;

        let subject_public_key = key_algorithm
            .parse_raw(certificate.subject_pki.raw)
            .map_err(DidMdlValidationError::SubjectPublicKeyInvalidDer)?;

        let subject_raw_public_key = subject_public_key.public_key_as_raw();

        if key.public_key != subject_raw_public_key {
            return Err(DidMdlValidationError::SubjectPublicKeyNotMatching);
        }

        Ok(())
    }
}

fn check_is_valid_now(certificate: &X509Certificate<'_>) -> Result<(), DidMdlValidationError> {
    if !certificate.validity().is_valid() {
        return Err(DidMdlValidationError::CertificateExpired);
    }

    Ok(())
}
