use dcql::DcqlQuery;
use url::Url;

use crate::mapper::oidc::determine_response_mode_openid4vp_draft;
use crate::model::interaction::InteractionId;
use crate::model::proof::Proof;
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::openid4vp::draft25::model::OpenID4VP25AuthorizationRequest;
use crate::provider::verification_protocol::openid4vp::model::{
    OpenID4VPDraftClientMetadata, OpenID4VPPresentationDefinition,
};
use crate::provider::verification_protocol::openid4vp::service::oidc_verifier_presentation_definition;

#[allow(clippy::too_many_arguments)]
pub(crate) fn generate_authorization_request_params_draft25(
    proof: &Proof,
    interaction_id: &InteractionId,
    nonce: String,
    presentation_definition: Option<OpenID4VPPresentationDefinition>,
    dcql_query: Option<DcqlQuery>,
    client_id: String,
    response_uri: String,
    client_metadata: OpenID4VPDraftClientMetadata,
) -> Result<OpenID4VP25AuthorizationRequest, VerificationProtocolError> {
    if presentation_definition.is_some() && dcql_query.is_some() {
        return Err(
            VerificationProtocolError::InvalidDcqlQueryOrPresentationDefinition(
                "presentation_definition and dcql_query cannot be used together".to_string(),
            ),
        );
    }

    let presentation_definition = presentation_definition
        .map(|pd| {
            oidc_verifier_presentation_definition(proof, pd)
                .map_err(|e| VerificationProtocolError::Failed(e.to_string()))
        })
        .transpose()?;

    Ok(OpenID4VP25AuthorizationRequest {
        response_type: Some("vp_token".to_string()),
        response_mode: Some(determine_response_mode_openid4vp_draft(proof)?),
        client_id,
        client_metadata: Some(client_metadata.into()),
        presentation_definition,
        response_uri: Some(
            Url::parse(&response_uri)
                .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?,
        ),
        nonce: Some(nonce),
        state: Some(interaction_id.to_string()),
        presentation_definition_uri: None,
        dcql_query,
        redirect_uri: None,
    })
}
