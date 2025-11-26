use url::Url;

use crate::mapper::oidc::determine_response_mode_openid4vp_draft;
use crate::model::interaction::InteractionId;
use crate::model::proof::Proof;
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::openid4vp::draft20::model::OpenID4VP20AuthorizationRequest;
use crate::provider::verification_protocol::openid4vp::model::{
    ClientIdScheme, OpenID4VPDraftClientMetadata, OpenID4VPPresentationDefinition,
};

#[expect(clippy::too_many_arguments)]
pub(crate) fn generate_authorization_request_params_draft20(
    proof: &Proof,
    interaction_id: &InteractionId,
    nonce: String,
    presentation_definition: OpenID4VPPresentationDefinition,
    client_id: String,
    response_uri: String,
    client_id_scheme: ClientIdScheme,
    client_metadata: OpenID4VPDraftClientMetadata,
) -> Result<OpenID4VP20AuthorizationRequest, VerificationProtocolError> {
    Ok(OpenID4VP20AuthorizationRequest {
        response_type: Some("vp_token".to_string()),
        response_mode: Some(determine_response_mode_openid4vp_draft(proof)?),
        client_id,
        client_id_scheme: Some(client_id_scheme),
        client_metadata: Some(client_metadata.into()),
        presentation_definition: Some(presentation_definition),
        response_uri: Some(
            Url::parse(&response_uri)
                .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?,
        ),
        nonce: Some(nonce),
        state: Some(interaction_id.to_string()),
        client_metadata_uri: None,
        presentation_definition_uri: None,
        redirect_uri: None,
    })
}
