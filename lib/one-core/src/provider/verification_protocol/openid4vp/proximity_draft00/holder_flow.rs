use std::borrow::Cow;

use async_trait::async_trait;
use shared_types::DidValue;
use standardized_types::openid4vp::dcql::DcqlQuery;
use standardized_types::openid4vp::{AuthorizationRequest, ClientIdPrefix, VpTokenResponse};
use url::Url;

use crate::config::core_config::{TransportType, VerificationProtocolType};
use crate::error::ContextWithErrorCode;
use crate::model::interaction::UpdateInteractionRequest;
use crate::model::organisation::Organisation;
use crate::proto::identifier_creator::{IdentifierCreator, IdentifierName, IdentifierRole};
use crate::proto::jwt::Jwt;
use crate::provider::credential_formatter::model::{IdentifierDetails, VerificationFn};
use crate::provider::ecosystem::model::ProtocolArtifact;
use crate::provider::verification_protocol::dto::{InvitationResponseDTO, UpdateResponse};
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::openid4vp::final1_0::mappers::decode_client_id_with_scheme;
use crate::provider::verification_protocol::openid4vp::proximity_draft00::{
    CreatePresentationParams, create_interaction_and_proof, create_presentation,
};
use crate::repository::interaction_repository::InteractionRepository;

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
        presenatition: VpTokenResponse,
        interaction_data: serde_json::Value,
    ) -> Result<(), VerificationProtocolError>;

    async fn reject_proof(
        &self,
        interaction_data: serde_json::Value,
    ) -> Result<(), VerificationProtocolError>;
}

pub(crate) async fn handle_invitation_with_transport<'a, T: Send + Sync + 'static>(
    url: Url,
    organisation: Organisation,
    interaction_repository: &dyn InteractionRepository,
    identifier_creator: &dyn IdentifierCreator,
    transport: &dyn ProximityHolderTransport<Context = T>,
    verification_fn: VerificationFn,
) -> Result<InvitationResponseDTO<'a>, VerificationProtocolError> {
    let (interaction_id, mut proof) = create_interaction_and_proof(
        None,
        organisation.clone(),
        None,
        VerificationProtocolType::OpenId4VpProximityDraft00,
        transport.transport_type(),
        interaction_repository,
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
    .error_while("parsing request JWT")?;

    let (did_value, ClientIdPrefix::DecentralizedIdentifier) =
        decode_client_id_with_scheme(&presentation_request.payload.custom.client_id, false)?
    else {
        return Err(VerificationProtocolError::InvalidRequest(format!(
            "invalid client_id: {}",
            presentation_request.payload.custom.client_id
        )));
    };
    let did_value = DidValue::from_did_url(&did_value).map_err(|_| {
        VerificationProtocolError::InvalidRequest(format!("invalid client_id did: {did_value}"))
    })?;

    let verifier_details = IdentifierDetails::Did(did_value);
    let (verifier_identifier, ..) = identifier_creator
        .get_or_create_remote_identifier(
            &organisation,
            &verifier_details,
            IdentifierName::PrefixForId(IdentifierRole::Verifier.to_string()),
        )
        .await
        .error_while("creating verifier identifier")?;
    proof.verifier_identifier = Some(verifier_identifier.into());

    let ecosystem_artifact = ProtocolArtifact::HolderProof {
        verifier_details: Cow::Owned(Some(verifier_details)),
        dcql_query: presentation_request.payload.custom.dcql_query.clone(),
        verifier_info: presentation_request.payload.custom.verifier_info.clone(),
        proof_id: proof.id,
    };

    let interaction_data = transport
        .interaction_data_from_authz_request(presentation_request.payload.custom, context)?;

    interaction_repository
        .update_interaction(
            interaction_id,
            UpdateInteractionRequest {
                data: Some(Some(interaction_data)),
                ..Default::default()
            },
        )
        .await
        .error_while("updating interaction")?;

    Ok(InvitationResponseDTO {
        interaction_id,
        proof,
        ecosystem_artifact,
    })
}

pub(crate) struct HolderCommonVPInteractionData {
    pub client_id: String,
    pub dcql_query: DcqlQuery,
    pub nonce: String,
}

pub(crate) async fn submit_proof_with_transport<T: Send + Sync + 'static>(
    transport: &dyn ProximityHolderTransport<Context = T>,
    interaction_data: serde_json::Value,
    mut params: CreatePresentationParams<'_>,
) -> Result<UpdateResponse, VerificationProtocolError> {
    let parsed_interaction_data = transport.parse_interaction_data(interaction_data.clone())?;

    params.client_id = &parsed_interaction_data.client_id;
    params.nonce = &parsed_interaction_data.nonce;

    let presentation = create_presentation(params).await?;
    transport
        .submit_presentation(presentation, interaction_data)
        .await?;
    Ok(UpdateResponse { update_proof: None })
}
