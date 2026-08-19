use std::fmt::Display;
use std::sync::Arc;

use shared_types::{
    CredentialFormat, CredentialSchemaId, OrganisationId, RevocationMethodId, SerializedCredential,
};
use time::Duration;

use super::error::FormatterError;
use super::model::{
    AuthenticationFn, CredentialData, CredentialPresentation, DetailCredential, Features,
    FormatterCapabilities, TokenVerifier,
};
use super::{CredentialFormatter, MetadataClaimSchema};
use crate::config::core_config::{KeyAlgorithmType, RevocationType};
use crate::error::ContextWithErrorCode;
use crate::model::credential::Credential;
use crate::model::credential_schema::CredentialSchema;
use crate::model::organisation::Organisation;
use crate::provider::Provider;
use crate::provider::disabled_provider::DisabledProvider;
use crate::provider::provider_directory::WithDisabledDecorator;
use crate::provider::revocation::bitstring_status_list::model::StatusPurpose;
use crate::util::key_selection::SelectedKey;

impl WithDisabledDecorator for dyn CredentialFormatter {
    fn decorate(self: Arc<dyn CredentialFormatter>) -> Arc<dyn CredentialFormatter> {
        Arc::new(DisabledProvider::new(self))
    }
}

#[async_trait::async_trait]
impl<T: Provider + CredentialFormatter + Display + ?Sized> CredentialFormatter
    for DisabledProvider<T>
{
    async fn format_credential(
        &self,
        _credential_data: CredentialData,
        _auth_fn: AuthenticationFn,
    ) -> Result<SerializedCredential, FormatterError> {
        self.disabled_error()
    }

    async fn format_status_list<'a>(
        &self,
        _revocation_list_url: String,
        _issuer: SelectedKey,
        _encoded_list: String,
        _algorithm: KeyAlgorithmType,
        _auth_fn: AuthenticationFn,
        _status_purpose: StatusPurpose,
        _status_list_type: RevocationType,
    ) -> Result<Vec<u8>, FormatterError> {
        self.disabled_error()
    }

    async fn extract_credentials<'a>(
        &self,
        credentials: &SerializedCredential,
        credential_schema: Option<&'a CredentialSchema>,
        verification: Box<dyn TokenVerifier>,
    ) -> Result<DetailCredential, FormatterError> {
        self.inner()
            .extract_credentials(credentials, credential_schema, verification)
            .await
    }

    async fn extract_credentials_unverified<'a>(
        &self,
        credential: &SerializedCredential,
        credential_schema: Option<&'a CredentialSchema>,
    ) -> Result<DetailCredential, FormatterError> {
        self.inner()
            .extract_credentials_unverified(credential, credential_schema)
            .await
    }

    async fn prepare_selective_disclosure(
        &self,
        credential: CredentialPresentation,
    ) -> Result<String, FormatterError> {
        self.inner().prepare_selective_disclosure(credential).await
    }

    fn get_leeway(&self) -> Duration {
        self.inner().get_leeway()
    }

    fn get_default_expiration(&self) -> Duration {
        self.inner().get_default_expiration()
    }

    fn get_capabilities(&self) -> FormatterCapabilities {
        self.inner().get_capabilities()
    }

    fn credential_schema_id<'a>(
        &self,
        id: CredentialSchemaId,
        organisation_id: OrganisationId,
        schema_id: Option<&'a str>,
        core_base_url: &'a str,
        format: &CredentialFormat,
    ) -> Result<String, FormatterError> {
        self.inner()
            .credential_schema_id(id, organisation_id, schema_id, core_base_url, format)
    }

    fn get_metadata_claims(&self) -> Vec<MetadataClaimSchema> {
        self.inner().get_metadata_claims()
    }

    fn user_claims_path(&self) -> Vec<String> {
        self.inner().user_claims_path()
    }

    async fn parse_credential(
        &self,
        credential: &SerializedCredential,
        organisation: Organisation,
        verification: Box<dyn TokenVerifier>,
    ) -> Result<Credential, FormatterError> {
        self.inner()
            .parse_credential(credential, organisation, verification)
            .await
    }

    fn revocation_method_id(&self) -> Option<&RevocationMethodId> {
        self.inner().revocation_method_id()
    }

    fn config_name(&self) -> &CredentialFormat {
        self.inner().config_name()
    }
}

/// Checks supported operations
pub(super) struct CapabilityChecked(pub Arc<dyn CredentialFormatter>);

impl Provider for CapabilityChecked {
    fn capabilities(&self) -> Option<serde_json::Value> {
        self.0.capabilities()
    }
}

#[async_trait::async_trait]
impl CredentialFormatter for CapabilityChecked {
    async fn format_credential(
        &self,
        credential_data: CredentialData,
        auth_fn: AuthenticationFn,
    ) -> Result<SerializedCredential, FormatterError> {
        let capabilities = self.0.get_capabilities();

        if let Some(holder_identifier) = &credential_data.holder_identifier
            && !capabilities
                .holder_identifier_types
                .contains(&holder_identifier.data.r#type().into())
        {
            return Err(FormatterError::UnsupportedIdentifierType(
                holder_identifier.data.r#type(),
            ));
        }

        let signing_key_algorithm = auth_fn
            .get_key_algorithm()
            .error_while("getting signing key algorithm")?;
        if !capabilities
            .signing_key_algorithms
            .contains(&signing_key_algorithm)
        {
            return Err(FormatterError::CouldNotFormat(format!(
                "Unsupported signing key algorithm: {signing_key_algorithm}"
            )));
        }

        self.0.format_credential(credential_data, auth_fn).await
    }

    async fn format_status_list<'a>(
        &self,
        revocation_list_url: String,
        issuer: SelectedKey,
        encoded_list: String,
        algorithm: KeyAlgorithmType,
        auth_fn: AuthenticationFn,
        status_purpose: StatusPurpose,
        status_list_type: RevocationType,
    ) -> Result<Vec<u8>, FormatterError> {
        self.0
            .format_status_list(
                revocation_list_url,
                issuer,
                encoded_list,
                algorithm,
                auth_fn,
                status_purpose,
                status_list_type,
            )
            .await
    }

    async fn extract_credentials<'a>(
        &self,
        credentials: &SerializedCredential,
        credential_schema: Option<&'a CredentialSchema>,
        verification: Box<dyn TokenVerifier>,
    ) -> Result<DetailCredential, FormatterError> {
        self.0
            .extract_credentials(credentials, credential_schema, verification)
            .await
    }

    async fn extract_credentials_unverified<'a>(
        &self,
        credential: &SerializedCredential,
        credential_schema: Option<&'a CredentialSchema>,
    ) -> Result<DetailCredential, FormatterError> {
        self.0
            .extract_credentials_unverified(credential, credential_schema)
            .await
    }

    async fn prepare_selective_disclosure(
        &self,
        credential: CredentialPresentation,
    ) -> Result<String, FormatterError> {
        self.0.prepare_selective_disclosure(credential).await
    }

    fn get_leeway(&self) -> Duration {
        self.0.get_leeway()
    }

    fn get_default_expiration(&self) -> Duration {
        self.0.get_default_expiration()
    }

    fn get_capabilities(&self) -> FormatterCapabilities {
        self.0.get_capabilities()
    }

    fn credential_schema_id<'a>(
        &self,
        id: CredentialSchemaId,
        organisation_id: OrganisationId,
        schema_id: Option<&'a str>,
        core_base_url: &'a str,
        format: &CredentialFormat,
    ) -> Result<String, FormatterError> {
        if let Some(schema_id) = schema_id {
            if schema_id.is_empty() {
                return Err(FormatterError::SchemaIdNotAllowed);
            }

            let capabilities = self.0.get_capabilities();
            if !capabilities.features.contains(&Features::SupportsSchemaId) {
                return Err(FormatterError::SchemaIdNotAllowed);
            }
        }

        self.0
            .credential_schema_id(id, organisation_id, schema_id, core_base_url, format)
    }

    fn get_metadata_claims(&self) -> Vec<MetadataClaimSchema> {
        self.0.get_metadata_claims()
    }

    fn user_claims_path(&self) -> Vec<String> {
        self.0.user_claims_path()
    }

    async fn parse_credential(
        &self,
        credential: &SerializedCredential,
        organisation: Organisation,
        verification: Box<dyn TokenVerifier>,
    ) -> Result<Credential, FormatterError> {
        self.0
            .parse_credential(credential, organisation, verification)
            .await
    }

    fn revocation_method_id(&self) -> Option<&RevocationMethodId> {
        self.0.revocation_method_id()
    }

    fn config_name(&self) -> &CredentialFormat {
        self.0.config_name()
    }
}
