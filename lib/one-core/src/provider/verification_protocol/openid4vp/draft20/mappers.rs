use std::collections::HashMap;
use std::sync::Arc;

use shared_types::KeyId;

use super::model::OpenID4VP20AuthorizationRequestQueryParams;
use crate::model::interaction::InteractionId;
use crate::model::proof::Proof;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::openid4vp::model::{
    ClientIdScheme, OpenID4VPVerifierInteractionContent, OpenID4Vp20Params,
    OpenID4VpPresentationFormat,
};
use crate::provider::verification_protocol::openid4vp::service::create_open_id_for_vp_client_metadata;
use crate::service::key::dto::PublicKeyJwkDTO;
use crate::service::oid4vp_draft20::proof_request::{
    generate_authorization_request_client_id_scheme_did,
    generate_authorization_request_client_id_scheme_verifier_attestation,
    generate_authorization_request_client_id_scheme_x509_san_dns,
};
use crate::util::oidc::determine_response_mode;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn create_openidvp20_authorization_request(
    base_url: &str,
    openidvc_params: &OpenID4Vp20Params,
    client_id: String,
    interaction_id: InteractionId,
    interaction_data: &OpenID4VPVerifierInteractionContent,
    nonce: String,
    proof: &Proof,
    key_id: KeyId,
    encryption_key_jwk: PublicKeyJwkDTO,
    vp_formats: HashMap<String, OpenID4VpPresentationFormat>,
    client_id_scheme: ClientIdScheme,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    key_provider: &dyn KeyProvider,
    did_method_provider: &dyn DidMethodProvider,
) -> Result<OpenID4VP20AuthorizationRequestQueryParams, VerificationProtocolError> {
    if openidvc_params.use_request_uri {
        Ok(OpenID4VP20AuthorizationRequestQueryParams {
            client_id,
            client_id_scheme: Some(client_id_scheme),
            request_uri: Some(format!(
                "{base_url}/ssi/openid4vp/draft-20/{}/client-request",
                proof.id
            )),
            ..Default::default()
        })
    } else {
        match client_id_scheme {
            ClientIdScheme::RedirectUri => get_params_for_redirect_uri(
                base_url,
                openidvc_params,
                client_id,
                interaction_id,
                nonce,
                proof,
                key_id,
                encryption_key_jwk,
                vp_formats,
                interaction_data,
            ),
            ClientIdScheme::X509SanDns => {
                let token = generate_authorization_request_client_id_scheme_x509_san_dns(
                    proof,
                    interaction_data.to_owned(),
                    &interaction_id,
                    key_algorithm_provider,
                    key_provider,
                )
                .await?;
                Ok(OpenID4VP20AuthorizationRequestQueryParams {
                    client_id,
                    request: Some(token),
                    client_id_scheme: Some(client_id_scheme),
                    ..Default::default()
                })
            }
            ClientIdScheme::VerifierAttestation => {
                let token = generate_authorization_request_client_id_scheme_verifier_attestation(
                    proof,
                    interaction_data.to_owned(),
                    &interaction_id,
                    key_algorithm_provider,
                    key_provider,
                    did_method_provider,
                )
                .await?;

                Ok(OpenID4VP20AuthorizationRequestQueryParams {
                    client_id,
                    request: Some(token),
                    client_id_scheme: Some(client_id_scheme),
                    ..Default::default()
                })
            }
            ClientIdScheme::Did => {
                let token = generate_authorization_request_client_id_scheme_did(
                    proof,
                    interaction_data.to_owned(),
                    &interaction_id,
                    key_algorithm_provider,
                    key_provider,
                    did_method_provider,
                )
                .await?;

                Ok(OpenID4VP20AuthorizationRequestQueryParams {
                    client_id,
                    request: Some(token),
                    client_id_scheme: Some(client_id_scheme),
                    ..Default::default()
                })
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn get_params_for_redirect_uri(
    base_url: &str,
    openidvc_params: &OpenID4Vp20Params,
    client_id: String,
    interaction_id: InteractionId,
    nonce: String,
    proof: &Proof,
    key_id: KeyId,
    encryption_key_jwk: PublicKeyJwkDTO,
    vp_formats: HashMap<String, OpenID4VpPresentationFormat>,
    interaction_data: &OpenID4VPVerifierInteractionContent,
) -> Result<OpenID4VP20AuthorizationRequestQueryParams, VerificationProtocolError> {
    let mut presentation_definition = None;
    let mut presentation_definition_uri = None;
    if openidvc_params.presentation_definition_by_value {
        let pd = serde_json::to_string(&interaction_data.presentation_definition)
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

        presentation_definition = Some(pd);
    } else {
        presentation_definition_uri = Some(format!(
            "{base_url}/ssi/openid4vp/draft-20/{}/presentation-definition",
            proof.id
        ));
    }

    let mut client_metadata = None;
    let mut client_metadata_uri = None;
    if openidvc_params.client_metadata_by_value {
        let metadata = serde_json::to_string(&create_open_id_for_vp_client_metadata(
            key_id,
            encryption_key_jwk,
            vp_formats,
        ))
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

        client_metadata = Some(metadata);
    } else {
        client_metadata_uri = Some(format!(
            "{base_url}/ssi/openid4vp/draft-20/{}/client-metadata",
            proof.id
        ));
    }

    Ok(OpenID4VP20AuthorizationRequestQueryParams {
        client_id: client_id.clone(),
        client_id_scheme: Some(ClientIdScheme::RedirectUri),
        response_type: Some("vp_token".to_string()),
        state: Some(interaction_id.to_string()),
        response_mode: Some(determine_response_mode(proof)?),
        client_metadata,
        client_metadata_uri,
        response_uri: Some(client_id),
        nonce: Some(nonce),
        presentation_definition,
        presentation_definition_uri,
        request: None,
        request_uri: None,
        redirect_uri: None,
    })
}
