use async_trait::async_trait;
use shared_types::DidValue;
use url::Url;

use crate::common_mapper::DidRole;
use crate::config::core_config::{TransportType, VerificationProtocolType};
use crate::model::interaction::{InteractionId, UpdateInteractionRequest};
use crate::model::organisation::Organisation;
use crate::provider::credential_formatter::jwt::Jwt;
use crate::provider::credential_formatter::model::VerificationFn;
use crate::provider::verification_protocol::dto::InvitationResponseDTO;
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::openid4vp::draft20::model::OpenID4VP20AuthorizationRequest;
use crate::provider::verification_protocol::openid4vp::proximity_draft00::create_interaction_and_proof;
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

    async fn receive_authorization_request_token(
        &self,
        context: &mut Self::Context,
    ) -> Result<String, VerificationProtocolError>;

    fn interaction_data(
        &self,
        authz_request: OpenID4VP20AuthorizationRequest,
        context: Self::Context,
    ) -> Result<Vec<u8>, VerificationProtocolError>;
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
    let authz_request_token = transport
        .receive_authorization_request_token(&mut context)
        .await?;
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

    let interaction_data =
        transport.interaction_data(presentation_request.payload.custom, context)?;

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
