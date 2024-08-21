use std::collections::HashMap;

use async_trait::async_trait;
use one_providers::common_dto::PublicKeyJwkDTO;
use one_providers::common_models::credential::OpenCredential;
use one_providers::common_models::did::OpenDid;
use one_providers::common_models::key::{KeyId, OpenKey};
use one_providers::common_models::organisation::OpenOrganisation;
use one_providers::common_models::proof::{OpenProof, OpenProofStateEnum};
use one_providers::credential_formatter::model::DetailCredential;
use one_providers::exchange_protocol::openid4vc::imp::OpenID4VCHTTP;
use one_providers::exchange_protocol::openid4vc::model::{
    DatatypeType, InvitationResponseDTO, OpenID4VPFormat, PresentationDefinitionResponseDTO,
    PresentedCredential, ShareResponse, SubmitIssuerResponse, UpdateResponse,
};
use one_providers::exchange_protocol::openid4vc::service::FnMapExternalFormatToExternalDetailed;
use one_providers::exchange_protocol::openid4vc::validator::throw_if_latest_proof_state_not_eq;
use one_providers::exchange_protocol::openid4vc::{
    FormatMapper, HandleInvitationOperationsAccess, TypeToDescriptorMapper,
};
use openidvc_ble::OpenID4VCBLE;
use serde_json::json;
use url::Url;
use uuid::Uuid;

use super::{ExchangeProtocol, ExchangeProtocolError, ExchangeProtocolImpl, StorageAccess};
use crate::config::core_config::TransportType;

pub mod dto;
pub mod handle_invitation_operations;
pub(crate) mod mapper;
pub mod model;
pub(crate) mod openidvc_ble;

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
        organisation: OpenOrganisation,
        storage_access: &StorageAccess,
        handle_invitation_operations: &HandleInvitationOperationsAccess,
    ) -> Result<InvitationResponseDTO, ExchangeProtocolError> {
        if self.openid_http.can_handle(&url) {
            self.openid_http
                .handle_invitation(
                    url,
                    organisation,
                    storage_access,
                    handle_invitation_operations,
                )
                .await
        } else if self.openid_ble.can_handle(&url) {
            self.openid_ble
                .handle_invitation(
                    url,
                    organisation,
                    storage_access,
                    handle_invitation_operations,
                )
                .await
        } else {
            Err(ExchangeProtocolError::Failed(
                "No OpenID4VC query params detected".to_string(),
            ))
        }
    }

    async fn reject_proof(&self, proof: &OpenProof) -> Result<(), ExchangeProtocolError> {
        if proof.transport == TransportType::Ble.to_string() {
            self.openid_ble.reject_proof(proof).await
        } else {
            self.openid_http.reject_proof(proof).await
        }
    }

    async fn submit_proof(
        &self,
        proof: &OpenProof,
        credential_presentations: Vec<PresentedCredential>,
        holder_did: &OpenDid,
        key: &OpenKey,
        jwk_key_id: Option<String>,
        format_map: HashMap<String, String>,
        presentation_format_map: HashMap<String, String>,
    ) -> Result<UpdateResponse<()>, ExchangeProtocolError> {
        if proof.transport == TransportType::Ble.to_string() {
            self.openid_ble
                .submit_proof(
                    proof,
                    credential_presentations,
                    holder_did,
                    key,
                    jwk_key_id,
                    format_map,
                    presentation_format_map,
                )
                .await
        } else {
            self.openid_http
                .submit_proof(
                    proof,
                    credential_presentations,
                    holder_did,
                    key,
                    jwk_key_id,
                    format_map,
                    presentation_format_map,
                )
                .await
        }
    }

    async fn accept_credential(
        &self,
        credential: &OpenCredential,
        holder_did: &OpenDid,
        key: &OpenKey,
        jwk_key_id: Option<String>,
        format: &str,
        storage_access: &StorageAccess,
        map_oidc_format_to_external: FnMapExternalFormatToExternalDetailed,
    ) -> Result<UpdateResponse<SubmitIssuerResponse>, ExchangeProtocolError> {
        self.openid_http
            .accept_credential(
                credential,
                holder_did,
                key,
                jwk_key_id,
                format,
                storage_access,
                map_oidc_format_to_external,
            )
            .await
    }

    async fn reject_credential(
        &self,
        credential: &OpenCredential,
    ) -> Result<(), ExchangeProtocolError> {
        self.openid_http.reject_credential(credential).await
    }

    async fn validate_proof_for_submission(
        &self,
        proof: &OpenProof,
    ) -> Result<(), ExchangeProtocolError> {
        throw_if_latest_proof_state_not_eq(proof, OpenProofStateEnum::Pending)
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))
    }

    async fn share_credential(
        &self,
        credential: &OpenCredential,
        credential_format: &str,
    ) -> Result<ShareResponse<Self::VCInteractionContext>, ExchangeProtocolError> {
        self.openid_http
            .share_credential(credential, credential_format)
            .await
            .map(|context| ShareResponse {
                url: context.url,
                id: context.id,
                context: json!(context.context),
            })
    }

    async fn share_proof(
        &self,
        proof: &OpenProof,
        format_to_type_mapper: FormatMapper,
        key_id: KeyId,
        encryption_key_jwk: PublicKeyJwkDTO,
        vp_formats: HashMap<String, OpenID4VPFormat>,
        type_to_descriptor: TypeToDescriptorMapper,
    ) -> Result<ShareResponse<Self::VPInteractionContext>, ExchangeProtocolError> {
        if proof.transport == TransportType::Ble.to_string() {
            self.openid_ble
                .share_proof(
                    proof,
                    format_to_type_mapper,
                    key_id,
                    encryption_key_jwk,
                    vp_formats,
                    type_to_descriptor,
                )
                .await
                .map(|context| ShareResponse {
                    url: context.url,
                    id: context.id,
                    context: json!(context.context),
                })
        } else {
            self.openid_http
                .share_proof(
                    proof,
                    format_to_type_mapper,
                    key_id,
                    encryption_key_jwk,
                    vp_formats,
                    type_to_descriptor,
                )
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
        proof: &OpenProof,
        interaction_data: Self::VPInteractionContext,
        storage_access: &StorageAccess,
        format_map: HashMap<String, String>,
        types: HashMap<String, DatatypeType>,
    ) -> Result<PresentationDefinitionResponseDTO, ExchangeProtocolError> {
        if proof.transport == TransportType::Ble.to_string() {
            let interaction_data = serde_json::from_value(interaction_data)
                .map_err(ExchangeProtocolError::JsonError)?;
            self.openid_ble
                .get_presentation_definition(
                    proof,
                    interaction_data,
                    storage_access,
                    format_map,
                    types,
                )
                .await
        } else {
            let interaction_data = serde_json::from_value(interaction_data)
                .map_err(ExchangeProtocolError::JsonError)?;
            self.openid_http
                .get_presentation_definition(
                    proof,
                    interaction_data,
                    storage_access,
                    format_map,
                    types,
                )
                .await
        }
    }

    async fn verifier_handle_proof(
        &self,
        _proof: &OpenProof,
        _submission: &[u8],
    ) -> Result<Vec<DetailCredential>, ExchangeProtocolError> {
        unimplemented!()
    }

    async fn retract_proof(
        &self,
        proof: &OpenProof,
        id: Option<Uuid>,
    ) -> Result<(), ExchangeProtocolError> {
        if proof.transport == TransportType::Ble.to_string() {
            self.openid_ble.retract_proof(proof, id).await?;
        }

        Ok(())
    }
}

impl ExchangeProtocol for OpenID4VC {}
