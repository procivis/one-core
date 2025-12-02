use async_trait::async_trait;
use dcql::DcqlQuery;
use shared_types::DidValue;
use url::Url;

use crate::config::core_config::{TransportType, VerificationProtocolType};
use crate::model::interaction::UpdateInteractionRequest;
use crate::model::organisation::Organisation;
use crate::proto::identifier_creator::{IdentifierCreator, IdentifierRole};
use crate::proto::jwt::Jwt;
use crate::provider::credential_formatter::model::{IdentifierDetails, VerificationFn};
use crate::provider::verification_protocol::dto::{InvitationResponseDTO, UpdateResponse};
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::openid4vp::final1_0::mappers::decode_client_id_with_scheme;
use crate::provider::verification_protocol::openid4vp::final1_0::model::AuthorizationRequest;
use crate::provider::verification_protocol::openid4vp::model::{ClientIdScheme, DcqlSubmission};
use crate::provider::verification_protocol::openid4vp::proximity_draft00::{
    CreatePresentationParams, create_interaction_and_proof, create_presentation,
};
use crate::service::storage_proxy::StorageAccess;

#[async_trait]
pub(crate) trait ProximityHolderTransport: Send + Sync {
    type Context;

    fn can_handle(&self, url: &Url) -> bool;

    fn transport_type(&self) -> TransportType;

    async fn setup(&self, invitation_url: Url) -> Result<Self::Context, VerificationProtocolError>;

    async fn receive_authz_request_token(
        &self,
        context: &mut Self::Context,
    ) -> Result<String, VerificationProtocolError>;

    fn interaction_data_from_authz_request(
        &self,
        authz_request: AuthorizationRequest,
        context: Self::Context,
    ) -> Result<Vec<u8>, VerificationProtocolError>;

    fn parse_interaction_data(
        &self,
        interaction_data: serde_json::Value,
    ) -> Result<HolderCommonVPInteractionData, VerificationProtocolError>;

    async fn submit_presentation(
        &self,
        presenatition: DcqlSubmission,
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
    identifier_creator: &dyn IdentifierCreator,
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

    let mut context = transport.setup(url).await?;
    let authz_request_token = transport.receive_authz_request_token(&mut context).await?;
    let presentation_request = Jwt::<AuthorizationRequest>::build_from_token(
        &authz_request_token,
        Some(&verification_fn),
        None,
    )
    .await
    .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

    let (did_value, ClientIdScheme::Did) =
        decode_client_id_with_scheme(&presentation_request.payload.custom.client_id)?
    else {
        return Err(VerificationProtocolError::InvalidRequest(format!(
            "invalid client_id: {}",
            presentation_request.payload.custom.client_id
        )));
    };
    let did_value = DidValue::from_did_url(&did_value).map_err(|_| {
        VerificationProtocolError::InvalidRequest(format!("invalid client_id did: {did_value}"))
    })?;

    let (verifier_identifier, ..) = identifier_creator
        .get_or_create_remote_identifier(
            &Some(organisation),
            &IdentifierDetails::Did(did_value),
            IdentifierRole::Verifier,
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
        .update_interaction(
            interaction_id,
            UpdateInteractionRequest {
                data: Some(Some(interaction_data)),
            },
        )
        .await
        .map_err(|e| {
            VerificationProtocolError::Failed(format!("failed to update interaction data: {e}"))
        })?;

    Ok(InvitationResponseDTO {
        interaction_id,
        proof,
    })
}

pub(crate) struct HolderCommonVPInteractionData {
    pub client_id: String,
    pub dcql_query: Option<DcqlQuery>,
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
    params.dcql_query = parsed_interaction_data.dcql_query.as_ref();

    let presentation = create_presentation(params).await?;
    transport
        .submit_presentation(presentation, interaction_data)
        .await?;
    Ok(UpdateResponse { update_proof: None })
}
