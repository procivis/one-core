use dto::IssuanceProtocolCapabilities;
use error::IssuanceProtocolError;
use serde::Serialize;
use serde::de::Deserialize;
use shared_types::{CredentialId, HolderWalletUnitId};
use url::Url;

use crate::model::credential::Credential;
use crate::model::identifier::Identifier;
use crate::model::interaction::Interaction;
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::provider::issuance_protocol::dto::ContinueIssuanceDTO;
use crate::provider::issuance_protocol::model::InvitationResponseEnum;
use crate::service::storage_proxy::StorageAccess;

pub mod dto;
pub mod error;
mod mapper;
pub mod model;
pub mod openid4vci_draft13;
pub mod openid4vci_draft13_swiyu;
pub mod openid4vci_final1_0;
pub(crate) mod provider;
use model::{ContinueIssuanceResponseDTO, ShareResponse, SubmitIssuerResponse, UpdateResponse};

pub(crate) fn deserialize_interaction_data<DataDTO: for<'a> Deserialize<'a>>(
    data: Option<&Vec<u8>>,
) -> Result<DataDTO, IssuanceProtocolError> {
    let data = data.ok_or(IssuanceProtocolError::Failed(
        "interaction data is missing".to_string(),
    ))?;
    serde_json::from_slice(data).map_err(IssuanceProtocolError::JsonError)
}

pub(crate) fn serialize_interaction_data<DataDTO: ?Sized + Serialize>(
    dto: &DataDTO,
) -> Result<Vec<u8>, IssuanceProtocolError> {
    serde_json::to_vec(&dto).map_err(IssuanceProtocolError::JsonError)
}

#[derive(Debug)]
pub(crate) struct BasicSchemaData {
    pub id: String,
    pub offer_id: String,
}

#[derive(Debug, Clone)]
pub(crate) struct HolderBindingInput {
    pub identifier: Identifier,
    pub key: Key,
}

/// This trait contains methods for exchanging credentials between issuers and holders
#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub(crate) trait IssuanceProtocol: Send + Sync {
    // Holder methods:
    /// Check if the holder can handle the invitation URL.
    async fn holder_can_handle(&self, url: &Url) -> bool;

    /// For handling credential issuance, this method
    /// saves the offer information coming in.
    async fn holder_handle_invitation(
        &self,
        url: Url,
        organisation: Organisation,
        storage_access: &StorageAccess,
        redirect_uri: Option<String>,
    ) -> Result<InvitationResponseEnum, IssuanceProtocolError>;

    /// Accepts an offered credential.
    async fn holder_accept_credential(
        &self,
        interaction: Interaction,
        holder_binding: Option<HolderBindingInput>,
        storage_access: &StorageAccess,
        tx_code: Option<String>,
        holder_wallet_unit_id: Option<HolderWalletUnitId>,
    ) -> Result<UpdateResponse, IssuanceProtocolError>;

    /// Rejects a previously-accepted credential offer.
    async fn holder_reject_credential(
        &self,
        credential: Credential,
        storage_access: &StorageAccess,
    ) -> Result<(), IssuanceProtocolError>;

    /// Generates QR-code content to start the credential issuance flow.
    async fn issuer_share_credential(
        &self,
        credential: &Credential,
    ) -> Result<ShareResponse, IssuanceProtocolError>;

    /// Creates a newly issued credential
    async fn issuer_issue_credential(
        &self,
        credential_id: &CredentialId,
        holder_identifier: Identifier,
        holder_key_id: String,
    ) -> Result<SubmitIssuerResponse, IssuanceProtocolError>;

    async fn holder_continue_issuance(
        &self,
        continue_issuance_dto: ContinueIssuanceDTO,
        organisation: Organisation,
        storage_access: &StorageAccess,
    ) -> Result<ContinueIssuanceResponseDTO, IssuanceProtocolError>;

    fn get_capabilities(&self) -> IssuanceProtocolCapabilities;
}
