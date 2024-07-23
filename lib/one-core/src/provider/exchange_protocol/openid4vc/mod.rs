use async_trait::async_trait;
use one_providers::common_models::key::Key;
use one_providers::credential_formatter::model::DetailCredential;
use openidvc_ble::OpenID4VCBLE;
use openidvc_http::OpenID4VCHTTP;
use serde_json::json;
use url::Url;

use super::dto::{PresentedCredential, ShareResponse, SubmitIssuerResponse, UpdateResponse};
use super::{
    deserialize_interaction_data, serialize_interaction_data, ExchangeProtocol,
    ExchangeProtocolError, ExchangeProtocolImpl, StorageAccess,
};
use crate::config::core_config::TransportType;
use crate::model::credential::Credential;
use crate::model::did::Did;
use crate::model::organisation::Organisation;
use crate::model::proof::Proof;
use crate::provider::exchange_protocol::dto::PresentationDefinitionResponseDTO;
use crate::service::ssi_holder::dto::InvitationResponseDTO;

pub mod dto;
pub(crate) mod mapper;
mod mdoc;
pub mod model;
pub(crate) mod openidvc_ble;
pub(crate) mod openidvc_http;
mod validator;

pub(crate) struct OpenID4VC {
    openid_http: OpenID4VCHTTP,
    openid_ble: OpenID4VCBLE,
}

impl OpenID4VC {
    pub fn new(openid_http: OpenID4VCHTTP, openid_ble: OpenID4VCBLE) -> Self {
        Self {
            openid_http,
            openid_ble,
        }
    }
}

#[async_trait]
impl ExchangeProtocolImpl for OpenID4VC {
    type VCInteractionContext = serde_json::Value;
    type VPInteractionContext = serde_json::Value;

    fn can_handle(&self, url: &Url) -> bool {
        self.openid_http.can_handle(url) || self.openid_ble.can_handle(url)
    }

    async fn handle_invitation(
        &self,
        url: Url,
        organisation: Organisation,
        storage_access: &StorageAccess,
    ) -> Result<InvitationResponseDTO, ExchangeProtocolError> {
        if self.openid_http.can_handle(&url) {
            self.openid_http
                .handle_invitation(url, organisation, storage_access)
                .await
        } else if self.openid_ble.can_handle(&url) {
            self.openid_ble
                .handle_invitation(url, organisation, storage_access)
                .await
        } else {
            Err(ExchangeProtocolError::Failed(
                "No OpenID4VC query params detected".to_string(),
            ))
        }
    }

    async fn reject_proof(&self, proof: &Proof) -> Result<(), ExchangeProtocolError> {
        self.openid_http.reject_proof(proof).await
    }

    async fn submit_proof(
        &self,
        proof: &Proof,
        credential_presentations: Vec<PresentedCredential>,
        holder_did: &Did,
        key: &Key,
        jwk_key_id: Option<String>,
    ) -> Result<UpdateResponse<()>, ExchangeProtocolError> {
        self.openid_http
            .submit_proof(proof, credential_presentations, holder_did, key, jwk_key_id)
            .await
    }

    async fn accept_credential(
        &self,
        credential: &Credential,
        holder_did: &Did,
        key: &Key,
        jwk_key_id: Option<String>,
        storage_access: &StorageAccess,
    ) -> Result<UpdateResponse<SubmitIssuerResponse>, ExchangeProtocolError> {
        self.openid_http
            .accept_credential(credential, holder_did, key, jwk_key_id, storage_access)
            .await
    }

    async fn reject_credential(
        &self,
        credential: &Credential,
    ) -> Result<(), ExchangeProtocolError> {
        self.openid_http.reject_credential(credential).await
    }

    async fn share_credential(
        &self,
        credential: &Credential,
    ) -> Result<ShareResponse<Self::VCInteractionContext>, ExchangeProtocolError> {
        self.openid_http
            .share_credential(credential)
            .await
            .map(|context| ShareResponse {
                url: context.url,
                id: context.id,
                context: json!(context.context),
            })
    }

    async fn share_proof(
        &self,
        proof: &Proof,
    ) -> Result<ShareResponse<Self::VPInteractionContext>, ExchangeProtocolError> {
        if proof.transport == TransportType::Ble.to_string() {
            self.openid_ble
                .share_proof(proof)
                .await
                .map(|context| ShareResponse {
                    url: context.url,
                    id: context.id,
                    context: json!(context.context),
                })
        } else {
            self.openid_http
                .share_proof(proof)
                .await
                .map(|context| ShareResponse {
                    url: context.url,
                    id: context.id,
                    context: json!(context.context),
                })
        }
    }

    async fn get_presentation_definition(
        &self,
        proof: &Proof,
        interaction_data: Self::VPInteractionContext,
        storage_access: &StorageAccess,
    ) -> Result<PresentationDefinitionResponseDTO, ExchangeProtocolError> {
        if proof.transport == TransportType::Ble.to_string() {
            let interaction_data = serde_json::from_value(interaction_data)
                .map_err(ExchangeProtocolError::JsonError)?;
            self.openid_ble
                .get_presentation_definition(proof, interaction_data, storage_access)
                .await
        } else {
            let interaction_data = serde_json::from_value(interaction_data)
                .map_err(ExchangeProtocolError::JsonError)?;
            self.openid_http
                .get_presentation_definition(proof, interaction_data, storage_access)
                .await
        }
    }

    async fn verifier_handle_proof(
        &self,
        _proof: &Proof,
        _submission: &[u8],
    ) -> Result<Vec<DetailCredential>, ExchangeProtocolError> {
        unimplemented!()
    }
}

impl ExchangeProtocol for OpenID4VC {}
