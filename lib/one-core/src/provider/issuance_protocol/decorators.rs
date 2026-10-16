use std::collections::HashMap;
use std::fmt::Display;
use std::sync::Arc;

use shared_types::{
    CredentialId, CredentialSchemaFormatId, CredentialSchemaId, InteractionId, KeyId,
    SerializedCredential,
};
use standardized_types::oauth2::authorization_server_metadata::AuthorizationServerMetadata;
use standardized_types::openid4vci::CredentialIssuerMetadata;
use url::Url;

use super::dto::{ContinueIssuanceDTO, Features, IssuanceProtocolCapabilities};
use super::error::IssuanceProtocolError;
use super::model::{
    AuthorizationDpopKey, ContinueIssuanceResponseDTO, InvitationResponseEnum,
    IssuanceAcceptResult, IssuanceRefreshResponse, ShareResponse,
};
use super::{HolderBindingInput, IssuanceProtocol};
use crate::model::credential::Credential;
use crate::model::identifier::Identifier;
use crate::model::interaction::Interaction;
use crate::model::organisation::Organisation;
use crate::provider::Provider;
use crate::provider::disabled_provider::DisabledProvider;
use crate::provider::provider_directory::WithDisabledDecorator;

impl WithDisabledDecorator for dyn IssuanceProtocol {
    fn decorate(self: Arc<dyn IssuanceProtocol>) -> Arc<dyn IssuanceProtocol> {
        Arc::new(DisabledProvider::new(self))
    }
}

#[async_trait::async_trait]
impl<T: Provider + IssuanceProtocol + Display + ?Sized> IssuanceProtocol for DisabledProvider<T> {
    fn holder_can_handle(&self, _url: &Url) -> bool {
        false
    }

    async fn holder_handle_invitation<'a>(
        &self,
        _url: Url,
        _organisation: Organisation,
        _redirect_uri: Option<String>,
    ) -> Result<InvitationResponseEnum<'a>, IssuanceProtocolError> {
        self.disabled_error()
    }

    async fn holder_accept_credential(
        &self,
        _interaction: Interaction,
        _holder_binding: Option<HolderBindingInput>,
        _tx_code: Option<String>,
        _credential_configuration_ids: Vec<String>,
    ) -> Result<IssuanceAcceptResult, IssuanceProtocolError> {
        self.disabled_error()
    }

    async fn regroup_configurations(
        &self,
        interaction_id: InteractionId,
        configuration_parents: HashMap<String, CredentialId>,
    ) -> Result<(), IssuanceProtocolError> {
        self.inner()
            .regroup_configurations(interaction_id, configuration_parents)
            .await
    }

    async fn holder_reject_credential(
        &self,
        credential: Credential,
    ) -> Result<(), IssuanceProtocolError> {
        self.inner().holder_reject_credential(credential).await
    }

    async fn holder_prepare_authorization_dpop_key(
        &self,
        _organisation: &Organisation,
        _authorization_server_metadata: &AuthorizationServerMetadata,
    ) -> Result<Option<AuthorizationDpopKey>, IssuanceProtocolError> {
        self.disabled_error()
    }

    async fn holder_continue_issuance<'a>(
        &self,
        _continue_issuance_dto: ContinueIssuanceDTO,
        _organisation: Organisation,
        _dpop_key: Option<KeyId>,
    ) -> Result<ContinueIssuanceResponseDTO<'a>, IssuanceProtocolError> {
        self.disabled_error()
    }

    async fn holder_refresh_credential(
        &self,
        interaction: &Interaction,
        update_credential: Option<CredentialId>,
    ) -> Result<Vec<IssuanceRefreshResponse>, IssuanceProtocolError> {
        self.inner()
            .holder_refresh_credential(interaction, update_credential)
            .await
    }

    async fn issuer_share_credential(
        &self,
        _credential: &Credential,
    ) -> Result<ShareResponse, IssuanceProtocolError> {
        self.disabled_error()
    }

    async fn issuer_issue_credential(
        &self,
        _credential_id: &CredentialId,
        _format_id: CredentialSchemaFormatId,
        _holder_identifier: Identifier,
        _holder_key_id: String,
    ) -> Result<SerializedCredential, IssuanceProtocolError> {
        self.disabled_error()
    }

    async fn issuer_metadata(
        &self,
        protocol_id: &str,
        credential_schema_id: &CredentialSchemaId,
        issuer_identifier: &Identifier,
    ) -> Result<CredentialIssuerMetadata, IssuanceProtocolError> {
        self.inner()
            .issuer_metadata(protocol_id, credential_schema_id, issuer_identifier)
            .await
    }

    fn get_capabilities(&self) -> IssuanceProtocolCapabilities {
        self.inner().get_capabilities()
    }

    fn protocol_base_url(&self) -> Option<String> {
        self.inner().protocol_base_url()
    }

    fn config_name(&self) -> &str {
        self.inner().config_name()
    }
}

/// Checks supported operations
pub(super) struct CapabilityChecked(pub Arc<dyn IssuanceProtocol>);

impl Provider for CapabilityChecked {
    fn capabilities(&self) -> Option<serde_json::Value> {
        self.0.capabilities()
    }
}

#[async_trait::async_trait]
impl IssuanceProtocol for CapabilityChecked {
    fn holder_can_handle(&self, url: &Url) -> bool {
        self.0.holder_can_handle(url)
    }

    async fn holder_handle_invitation<'a>(
        &self,
        url: Url,
        organisation: Organisation,
        redirect_uri: Option<String>,
    ) -> Result<InvitationResponseEnum<'a>, IssuanceProtocolError> {
        self.0
            .holder_handle_invitation(url, organisation, redirect_uri)
            .await
    }

    async fn holder_accept_credential(
        &self,
        interaction: Interaction,
        holder_binding: Option<HolderBindingInput>,
        tx_code: Option<String>,
        credential_configuration_ids: Vec<String>,
    ) -> Result<IssuanceAcceptResult, IssuanceProtocolError> {
        self.0
            .holder_accept_credential(
                interaction,
                holder_binding,
                tx_code,
                credential_configuration_ids,
            )
            .await
    }

    async fn regroup_configurations(
        &self,
        interaction_id: InteractionId,
        configuration_parents: HashMap<String, CredentialId>,
    ) -> Result<(), IssuanceProtocolError> {
        self.0
            .regroup_configurations(interaction_id, configuration_parents)
            .await
    }

    async fn holder_reject_credential(
        &self,
        credential: Credential,
    ) -> Result<(), IssuanceProtocolError> {
        if !self
            .0
            .get_capabilities()
            .features
            .contains(&Features::SupportsRejection)
        {
            return Err(IssuanceProtocolError::RejectionNotSupported);
        }

        self.0.holder_reject_credential(credential).await
    }

    async fn holder_prepare_authorization_dpop_key(
        &self,
        organisation: &Organisation,
        authorization_server_metadata: &AuthorizationServerMetadata,
    ) -> Result<Option<AuthorizationDpopKey>, IssuanceProtocolError> {
        self.0
            .holder_prepare_authorization_dpop_key(organisation, authorization_server_metadata)
            .await
    }

    async fn holder_continue_issuance<'a>(
        &self,
        continue_issuance_dto: ContinueIssuanceDTO,
        organisation: Organisation,
        dpop_key: Option<KeyId>,
    ) -> Result<ContinueIssuanceResponseDTO<'a>, IssuanceProtocolError> {
        self.0
            .holder_continue_issuance(continue_issuance_dto, organisation, dpop_key)
            .await
    }

    async fn holder_refresh_credential(
        &self,
        interaction: &Interaction,
        update_credential: Option<CredentialId>,
    ) -> Result<Vec<IssuanceRefreshResponse>, IssuanceProtocolError> {
        self.0
            .holder_refresh_credential(interaction, update_credential)
            .await
    }

    async fn issuer_share_credential(
        &self,
        credential: &Credential,
    ) -> Result<ShareResponse, IssuanceProtocolError> {
        self.0.issuer_share_credential(credential).await
    }

    async fn issuer_issue_credential(
        &self,
        credential_id: &CredentialId,
        format_id: CredentialSchemaFormatId,
        holder_identifier: Identifier,
        holder_key_id: String,
    ) -> Result<SerializedCredential, IssuanceProtocolError> {
        self.0
            .issuer_issue_credential(credential_id, format_id, holder_identifier, holder_key_id)
            .await
    }

    async fn issuer_metadata(
        &self,
        protocol_id: &str,
        credential_schema_id: &CredentialSchemaId,
        issuer_identifier: &Identifier,
    ) -> Result<CredentialIssuerMetadata, IssuanceProtocolError> {
        self.0
            .issuer_metadata(protocol_id, credential_schema_id, issuer_identifier)
            .await
    }

    fn get_capabilities(&self) -> IssuanceProtocolCapabilities {
        self.0.get_capabilities()
    }

    fn protocol_base_url(&self) -> Option<String> {
        self.0.protocol_base_url()
    }

    fn config_name(&self) -> &str {
        self.0.config_name()
    }
}
