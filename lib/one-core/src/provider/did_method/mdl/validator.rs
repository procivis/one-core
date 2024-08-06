use one_providers::common_models::key::OpenKey;
use one_providers::key_algorithm::error::KeyAlgorithmError;
use x509_parser::{certificate::X509Certificate, error::X509Error};

use super::DidMdl;

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
        key: &OpenKey,
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
        key: &OpenKey,
    ) -> Result<(), DidMdlValidationError> {
        check_is_valid_now(certificate)?;

        let Some(key_algorithm) = self.key_algorithm_provider.get_key_algorithm(&key.key_type)
        else {
            return Err(DidMdlValidationError::KeyTypeNotSupported(
                key.key_type.to_string(),
            ));
        };

        let subject_public_key = key_algorithm
            .public_key_from_der(certificate.subject_pki.raw)
            .map_err(DidMdlValidationError::SubjectPublicKeyInvalidDer)?;

        if key.public_key != subject_public_key {
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
