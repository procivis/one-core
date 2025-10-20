//! A service for issuing credentials, creating and signing presentations as a holder,
//! and parsing and verifying credentials as a verifier.
//!
//! See the **/examples** directory in the [repository][repo] for an
//! example implementation.
//!
//! [repo]: https://github.com/procivis/one-open-core

use std::sync::Arc;

use one_core::model::did::KeyRole;
use one_core::model::key::Key;
use one_core::proto::certificate_validator::CertificateValidator;
use one_core::proto::key_verification::KeyVerification;
use one_core::provider::credential_formatter::model::{
    CredentialData, CredentialPresentation, DetailCredential,
};
use one_core::provider::credential_formatter::provider::CredentialFormatterProvider;
use one_core::provider::did_method::provider::DidMethodProvider;
use one_core::provider::key_algorithm::provider::KeyAlgorithmProvider;
use one_core::provider::key_storage::provider::KeyProvider;

use crate::model::CredentialFormat;
use crate::service::error::CredentialServiceError;

pub struct CredentialService {
    key_storage_provider: Arc<dyn KeyProvider>,
    credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
}

impl CredentialService {
    pub fn new(
        key_storage_provider: Arc<dyn KeyProvider>,
        credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        certificate_validator: Arc<dyn CertificateValidator>,
    ) -> Self {
        Self {
            key_storage_provider,
            credential_formatter_provider,
            key_algorithm_provider,
            did_method_provider,
            certificate_validator,
        }
    }

    pub async fn format_credential(
        &self,
        credential_data: CredentialData,
        format: CredentialFormat,
        issuer_key: Key,
    ) -> Result<String, CredentialServiceError> {
        let auth_fn = self.key_storage_provider.get_signature_provider(
            &issuer_key,
            None,
            self.key_algorithm_provider.clone(),
        )?;

        let token = self
            .credential_formatter_provider
            .get_credential_formatter(&format.to_string())
            .ok_or(CredentialServiceError::MissingFormat(format.to_string()))?
            .format_credential(credential_data, auth_fn)
            .await?;

        Ok(token)
    }

    pub async fn format_credential_presentation(
        &self,
        format: CredentialFormat,
        credential: CredentialPresentation,
    ) -> Result<String, CredentialServiceError> {
        let token = self
            .credential_formatter_provider
            .get_credential_formatter(&format.to_string())
            .ok_or(CredentialServiceError::MissingFormat(format.to_string()))?
            .format_credential_presentation(credential, None, None)
            .await?;

        Ok(token)
    }

    pub async fn extract_credential(
        &self,
        format: CredentialFormat,
        credential: &str,
    ) -> Result<DetailCredential, CredentialServiceError> {
        let key_verification = Box::new(KeyVerification {
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            did_method_provider: self.did_method_provider.clone(),
            key_role: KeyRole::AssertionMethod,
            certificate_validator: self.certificate_validator.clone(),
        });

        let details = self
            .credential_formatter_provider
            .get_credential_formatter(&format.to_string())
            .ok_or(CredentialServiceError::MissingFormat(format.to_string()))?
            .extract_credentials(credential, None, key_verification, None)
            .await?;

        Ok(details)
    }
}
