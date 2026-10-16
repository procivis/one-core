use std::collections::HashMap;
use std::fmt::{Display, Formatter};

use dto::IssuanceProtocolCapabilities;
use error::IssuanceProtocolError;
use proc_macros::provider_mock;
use serde::Serialize;
use serde::de::Deserialize;
use shared_types::{
    CredentialId, CredentialSchemaFormatId, CredentialSchemaId, InteractionId, KeyId,
    SerializedCredential,
};
use standardized_types::oauth2::authorization_server_metadata::AuthorizationServerMetadata;
use standardized_types::openid4vci::CredentialIssuerMetadata;
use url::Url;

use crate::model::credential::Credential;
use crate::model::identifier::Identifier;
use crate::model::interaction::Interaction;
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::provider::Provider;
use crate::provider::issuance_protocol::dto::ContinueIssuanceDTO;
use crate::provider::issuance_protocol::model::InvitationResponseEnum;

mod decorators;
pub mod dto;
pub mod error;
mod mapper;
pub mod model;
pub mod openid4vci_final1_0;
pub(crate) mod provider;
use model::{
    AuthorizationDpopKey, ContinueIssuanceResponseDTO, IssuanceAcceptResponse,
    IssuanceAcceptResult, IssuanceRefreshResponse, ShareResponse,
};

pub(crate) fn deserialize_interaction_data<DataDTO: for<'a> Deserialize<'a>>(
    data: Option<&Vec<u8>>,
) -> Result<DataDTO, IssuanceProtocolError> {
    let data = data.ok_or(IssuanceProtocolError::Failed(
        "interaction data is missing".to_string(),
    ))?;
    Ok(serde_json::from_slice(data)?)
}

pub(crate) fn serialize_interaction_data<DataDTO: ?Sized + Serialize>(
    dto: &DataDTO,
) -> Result<Vec<u8>, IssuanceProtocolError> {
    Ok(serde_json::to_vec(&dto)?)
}

#[derive(Debug, Clone)]
#[cfg_attr(test, derive(PartialEq))]
pub(crate) struct HolderBindingInput {
    pub identifier: Identifier,
    pub key: Key,
}

/// This trait contains methods for exchanging credentials between issuers and holders
#[provider_mock]
#[async_trait::async_trait]
pub(crate) trait IssuanceProtocol: Provider + Send + Sync {
    // Holder methods:
    /// Check if the holder can handle the invitation URL.
    ///
    /// Protocols that share a URL scheme are told apart by what the issuer advertises in its
    /// metadata, so answering this may take fetching that metadata; the fetch is cached and
    /// repeated by whichever protocol then handles the invitation.
    async fn holder_can_handle(&self, url: &Url) -> bool;

    /// For handling credential issuance, this method
    /// saves the offer information coming in.
    async fn holder_handle_invitation<'a>(
        &self,
        url: Url,
        organisation: Organisation,
        redirect_uri: Option<String>,
    ) -> Result<InvitationResponseEnum<'a>, IssuanceProtocolError>;

    /// Accepts the offered credentials, one result per requested credential configuration.
    async fn holder_accept_credential(
        &self,
        interaction: Interaction,
        holder_binding: Option<HolderBindingInput>,
        tx_code: Option<String>,
        credential_configuration_ids: Vec<String>,
    ) -> Result<IssuanceAcceptResult, IssuanceProtocolError>;

    /// Reassigns accepted configurations to batch parents selected by the holder service.
    async fn regroup_configurations(
        &self,
        interaction_id: InteractionId,
        configuration_parents: HashMap<String, CredentialId>,
    ) -> Result<(), IssuanceProtocolError>;

    /// Rejects a previously-accepted credential offer.
    async fn holder_reject_credential(
        &self,
        credential: Credential,
    ) -> Result<(), IssuanceProtocolError>;

    /// Prepares the DPoP key the authorization code of an authorization code flow is bound to.
    /// `None` if the authorization server does not support DPoP.
    async fn holder_prepare_authorization_dpop_key(
        &self,
        organisation: &Organisation,
        authorization_server_metadata: &AuthorizationServerMetadata,
    ) -> Result<Option<AuthorizationDpopKey>, IssuanceProtocolError>;

    /// Continues an authorization code flow once the authorization code was received.
    /// `dpop_key` is the key the authorization code is bound to, if any.
    async fn holder_continue_issuance<'a>(
        &self,
        continue_issuance_dto: ContinueIssuanceDTO,
        organisation: Organisation,
        dpop_key: Option<KeyId>,
    ) -> Result<ContinueIssuanceResponseDTO<'a>, IssuanceProtocolError>;

    /// Refreshes a credential or requests new batch.
    async fn holder_refresh_credential(
        &self,
        interaction: &Interaction,
        update_credential: Option<CredentialId>,
    ) -> Result<Vec<IssuanceRefreshResponse>, IssuanceProtocolError>;

    /// Generates QR-code content to start the credential issuance flow.
    async fn issuer_share_credential(
        &self,
        credential: &Credential,
    ) -> Result<ShareResponse, IssuanceProtocolError>;

    /// Creates a newly issued credential
    async fn issuer_issue_credential(
        &self,
        credential_id: &CredentialId,
        format_id: CredentialSchemaFormatId,
        holder_identifier: Identifier,
        holder_key_id: String,
    ) -> Result<SerializedCredential, IssuanceProtocolError>;

    async fn issuer_metadata(
        &self,
        protocol_id: &str,
        credential_schema_id: &CredentialSchemaId,
        issuer_identifier: &Identifier,
    ) -> Result<CredentialIssuerMetadata, IssuanceProtocolError>;

    fn get_capabilities(&self) -> IssuanceProtocolCapabilities;

    /// Base URL under which this protocol instance serves its issuer endpoints,
    /// or `None` when no core base URL is configured.
    fn protocol_base_url(&self) -> Option<String>;

    fn config_name(&self) -> &str;
}

impl Display for dyn IssuanceProtocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Issuance protocol `{}`", self.config_name())
    }
}
