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
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::identifier_creator::{
    IdentifierCreator, IdentifierName, IdentifierRole, RemoteIdentifierRelation,
};
use crate::proto::jwt::Jwt;
use crate::proto::jwt::model::DecomposedJwt;
use crate::provider::credential_formatter::model::{
    IdentifierDetails, PublicKeySource, VerificationFn,
};
use crate::provider::ecosystem::model::ProtocolArtifact;
use crate::provider::verification_protocol::dto::{InvitationResponseDTO, UpdateResponse};
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::openid4vp::final1_0::mappers::decode_client_id_with_scheme;
use crate::provider::verification_protocol::openid4vp::proximity_draft00::{
    CreatePresentationParams, create_interaction_and_proof, create_presentation,
};
use crate::provider::verification_protocol::openid4vp::validator::validate_x509_hash_request_token;
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
    certificate_validator: &dyn CertificateValidator,
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
    let request_token: DecomposedJwt<AuthorizationRequest> =
        Jwt::decompose_token(&authz_request_token).error_while("parsing request JWT")?;

    let (client_id, client_id_scheme) =
        decode_client_id_with_scheme(&request_token.payload.custom.client_id, false)?;
    let verifier_details = match client_id_scheme {
        ClientIdPrefix::DecentralizedIdentifier => {
            let did_value = DidValue::from_did_url(&client_id).map_err(|_| {
                VerificationProtocolError::InvalidRequest(format!(
                    "invalid client_id did: {client_id}"
                ))
            })?;
            let public_key_source = request_token
                .public_key_source(Some(PublicKeySource::Did {
                    did: Cow::Borrowed(&did_value),
                    key_id: request_token.header.key_id.as_deref(),
                }))
                .error_while("parsing request JWT")?;
            request_token
                .verify_signature(public_key_source, &*verification_fn)
                .await
                .error_while("verifying request JWT")?;
            IdentifierDetails::Did(did_value)
        }
        ClientIdPrefix::X509Hash => IdentifierDetails::Certificate(
            validate_x509_hash_request_token(&request_token, &client_id, certificate_validator)
                .await?,
        ),
        _ => {
            return Err(VerificationProtocolError::InvalidRequest(format!(
                "invalid client_id: {}",
                request_token.payload.custom.client_id
            )));
        }
    };
    let presentation_request = request_token.payload.custom;

    let (verifier_identifier, verifier_relation) = identifier_creator
        .get_or_create_remote_identifier(
            &organisation,
            &verifier_details,
            IdentifierName::PrefixForId(IdentifierRole::Verifier.to_string()),
            true,
            None,
            None,
        )
        .await
        .error_while("creating verifier identifier")?;
    proof.verifier_identifier = Some(verifier_identifier.into());
    if let RemoteIdentifierRelation::Certificate(certificate) = verifier_relation {
        proof.verifier_certificate = Some(certificate.into());
    }

    let ecosystem_artifact = ProtocolArtifact::HolderProof {
        verifier_details: Cow::Owned(Some(verifier_details)),
        dcql_query: presentation_request.dcql_query.clone(),
        verifier_info: presentation_request.verifier_info.clone(),
        proof_id: proof.id,
    };

    let interaction_data =
        transport.interaction_data_from_authz_request(presentation_request, context)?;

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
