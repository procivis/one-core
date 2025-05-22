use async_trait::async_trait;
use shared_types::DidValue;
use url::Url;

use crate::common_mapper::DidRole;
use crate::config::core_config::{TransportType, VerificationProtocolType};
use crate::model::interaction::{InteractionId, UpdateInteractionRequest};
use crate::model::organisation::Organisation;
use crate::provider::credential_formatter::jwt::Jwt;
use crate::provider::credential_formatter::model::VerificationFn;
use crate::provider::verification_protocol::dto::{InvitationResponseDTO, UpdateResponse};
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::openid4vp::draft20::model::OpenID4VP20AuthorizationRequest;
use crate::provider::verification_protocol::openid4vp::model::{
    OpenID4VPPresentationDefinition, PresentationSubmissionMappingDTO,
};
use crate::provider::verification_protocol::openid4vp::proximity_draft00::{
    CreatePresentationParams, create_interaction_and_proof, create_presentation,
};
use crate::service::storage_proxy::StorageAccess;

#[async_trait]
pub(crate) trait ProximityHolderTransport: Send + Sync {
    type Context;

    fn can_handle(&self, url: &Url) -> bool;

    fn transport_type(&self) -> TransportType;

    async fn setup(
        &self,
        invitation_url: Url,
        interaction_id: InteractionId,
    ) -> Result<Self::Context, VerificationProtocolError>;

    async fn receive_authz_request_token(
        &self,
        context: &mut Self::Context,
    ) -> Result<String, VerificationProtocolError>;

    fn interaction_data_from_authz_request(
        &self,
        authz_request: OpenID4VP20AuthorizationRequest,
        context: Self::Context,
    ) -> Result<Vec<u8>, VerificationProtocolError>;

    fn parse_interaction_data(
        &self,
        interaction_data: serde_json::Value,
    ) -> Result<HolderCommonVPInteractionData, VerificationProtocolError>;

    async fn submit_presentation(
        &self,
        vp_token: String,
        presentation_submission: PresentationSubmissionMappingDTO,
        interaction_data: serde_json::Value,
    ) -> Result<(), VerificationProtocolError>;

    async fn reject_proof(
        &self,
        interaction_data: serde_json::Value,
    ) -> Result<(), VerificationProtocolError>;
}

pub(crate) async fn handle_invitation_with_transport<T: Send + Sync + 'static>(
    url: Url,
    organisation: Organisation,
    storage_access: &StorageAccess,
    transport: &dyn ProximityHolderTransport<Context = T>,
    verification_fn: VerificationFn,
) -> Result<InvitationResponseDTO, VerificationProtocolError> {
    let (interaction_id, mut proof) = create_interaction_and_proof(
        None,
        organisation.clone(),
        None,
        VerificationProtocolType::OpenId4VpProximityDraft00,
        transport.transport_type(),
        storage_access,
    )
    .await?;

    let mut context = transport.setup(url, interaction_id).await?;
    let authz_request_token = transport.receive_authz_request_token(&mut context).await?;
    let presentation_request = Jwt::<OpenID4VP20AuthorizationRequest>::build_from_token(
        &authz_request_token,
        Some(&verification_fn),
        None,
    )
    .await
    .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

    let did_value = DidValue::from_did_url(presentation_request.payload.custom.client_id.as_str())
        .map_err(|_| {
            VerificationProtocolError::InvalidRequest(format!(
                "invalid client_id: {}",
                presentation_request.payload.custom.client_id
            ))
        })?;
    let (_, verifier_identifier) = storage_access
        .get_or_create_did_and_identifier(
            &Some(organisation.clone()),
            &did_value,
            DidRole::Verifier,
        )
        .await
        .map_err(|_| {
            VerificationProtocolError::Failed(format!(
                "failed to resolve or create did and identifier: {}",
                presentation_request.payload.custom.client_id
            ))
        })?;
    proof.verifier_identifier = Some(verifier_identifier);

    let interaction_data = transport
        .interaction_data_from_authz_request(presentation_request.payload.custom, context)?;

    storage_access
        .update_interaction(UpdateInteractionRequest {
            id: interaction_id,
            host: None,
            data: Some(interaction_data),
            organisation: Some(organisation),
        })
        .await
        .map_err(|e| {
            VerificationProtocolError::Failed(format!("failed to update interaction data: {}", e))
        })?;

    Ok(InvitationResponseDTO {
        interaction_id,
        proof,
    })
}

pub(crate) struct HolderCommonVPInteractionData {
    pub client_id: String,
    pub presentation_definition: Option<OpenID4VPPresentationDefinition>,
    pub nonce: String,
    pub identity_request_nonce: Option<String>,
}

pub(crate) async fn submit_proof_with_transport<T: Send + Sync + 'static>(
    transport: &dyn ProximityHolderTransport<Context = T>,
    interaction_data: serde_json::Value,
    mut params: CreatePresentationParams<'_>,
) -> Result<UpdateResponse, VerificationProtocolError> {
    let parsed_interaction_data = transport.parse_interaction_data(interaction_data.clone())?;

    params.client_id = &parsed_interaction_data.client_id;
    params.identity_request_nonce = parsed_interaction_data.identity_request_nonce.as_deref();
    params.nonce = &parsed_interaction_data.nonce;
    params.presentation_definition = parsed_interaction_data.presentation_definition.as_ref();

    let (vp_token, presentation_submission) = create_presentation(params).await?;
    transport
        .submit_presentation(vp_token, presentation_submission, interaction_data)
        .await?;
    Ok(UpdateResponse { update_proof: None })
}
