//! Implementation of OpenID4VCI.
//! https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html

use async_trait::async_trait;
use openidvc_http::OpenID4VP20HTTP;
use serde_json::json;
use shared_types::CredentialId;
use url::Url;

use super::dto::IssuanceProtocolCapabilities;
use super::{
    HandleInvitationOperationsAccess, IssuanceProtocol, IssuanceProtocolError, StorageAccess,
};
use crate::config::core_config::DidType;
use crate::model::credential::Credential;
use crate::model::did::Did;
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::provider::issuance_protocol::openid4vci_draft13::model::{
    InvitationResponseDTO, ShareResponse, SubmitIssuerResponse, UpdateResponse,
};

pub mod error;
pub mod handle_invitation_operations;
pub(crate) mod mapper;
pub mod model;
pub mod openidvc_http;
pub mod proof_formatter;
pub mod service;
pub mod validator;

pub(crate) struct OpenID4VC {
    openid_http: OpenID4VP20HTTP,
}

impl OpenID4VC {
    pub fn new(openid_http: OpenID4VP20HTTP) -> Self {
        Self { openid_http }
    }
}

#[async_trait]
impl IssuanceProtocol for OpenID4VC {
    fn holder_can_handle(&self, url: &Url) -> bool {
        self.openid_http.can_handle(url)
    }

    async fn holder_handle_invitation(
        &self,
        url: Url,
        organisation: Organisation,
        storage_access: &StorageAccess,
        handle_invitation_operations: &HandleInvitationOperationsAccess,
    ) -> Result<InvitationResponseDTO, IssuanceProtocolError> {
        if self.openid_http.can_handle(&url) {
            return self
                .openid_http
                .holder_handle_invitation(
                    url,
                    organisation,
                    storage_access,
                    handle_invitation_operations,
                )
                .await;
        }

        Err(IssuanceProtocolError::Failed(
            "No OpenID4VC query params detected".to_string(),
        ))
    }

    async fn holder_accept_credential(
        &self,
        credential: &Credential,
        holder_did: &Did,
        key: &Key,
        jwk_key_id: Option<String>,
        format: &str,
        storage_access: &StorageAccess,
        tx_code: Option<String>,
    ) -> Result<UpdateResponse<SubmitIssuerResponse>, IssuanceProtocolError> {
        self.openid_http
            .holder_accept_credential(
                credential,
                holder_did,
                key,
                jwk_key_id,
                format,
                storage_access,
                tx_code,
            )
            .await
    }

    async fn holder_reject_credential(
        &self,
        credential: &Credential,
    ) -> Result<(), IssuanceProtocolError> {
        self.openid_http.holder_reject_credential(credential).await
    }

    async fn issuer_share_credential(
        &self,
        credential: &Credential,
        credential_format: &str,
    ) -> Result<ShareResponse<serde_json::Value>, IssuanceProtocolError> {
        self.openid_http
            .issuer_share_credential(credential, credential_format)
            .await
            .map(|context| ShareResponse {
                url: context.url,
                interaction_id: context.interaction_id,
                context: json!(context.context),
            })
    }

    async fn issuer_issue_credential(
        &self,
        credential_id: &CredentialId,
        holder_did: Did,
        holder_key_id: String,
    ) -> Result<SubmitIssuerResponse, IssuanceProtocolError> {
        self.openid_http
            .issue_credential(credential_id, holder_did, holder_key_id)
            .await
    }

    fn get_capabilities(&self) -> IssuanceProtocolCapabilities {
        IssuanceProtocolCapabilities {
            did_methods: vec![
                DidType::Key,
                DidType::Jwk,
                DidType::Web,
                DidType::MDL,
                DidType::WebVh,
            ],
        }
    }
}
