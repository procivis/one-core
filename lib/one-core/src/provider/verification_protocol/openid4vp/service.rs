use std::collections::HashMap;

use anyhow::Context;
use time::{Duration, OffsetDateTime};

use super::error::OpenID4VCError;
use super::model::{
    AuthorizationEncryptedResponseAlgorithm,
    AuthorizationEncryptedResponseContentEncryptionAlgorithm, EncryptionInfo,
    OpenID4VPClientMetadata, OpenID4VPClientMetadataJwkDTO, OpenID4VPClientMetadataJwks,
    OpenID4VPHolderInteractionData, OpenID4VpPresentationFormat,
};
use crate::mapper::PublicKeyWithJwk;
use crate::model::proof::Proof;
use crate::proto::http_client::HttpClient;
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::openid4vp::jwe_presentation::ec_key_from_metadata;
use crate::provider::verification_protocol::openid4vp::model::{
    OpenID4VPDraftClientMetadata, OpenID4VPPresentationDefinition,
};

pub(crate) fn create_open_id_for_vp_client_metadata_draft(
    jwk: Option<PublicKeyWithJwk>,
    vp_formats: HashMap<String, OpenID4VpPresentationFormat>,
) -> OpenID4VPDraftClientMetadata {
    let mut metadata = OpenID4VPDraftClientMetadata {
        vp_formats,
        ..Default::default()
    };
    if let Some(jwk) = jwk {
        metadata.jwks = Some(OpenID4VPClientMetadataJwks {
            keys: vec![OpenID4VPClientMetadataJwkDTO {
                key_id: jwk.key_id.to_string(),
                jwk: jwk.jwk.into(),
            }],
        });
        metadata.authorization_encrypted_response_alg =
            Some(AuthorizationEncryptedResponseAlgorithm::EcdhEs);
        metadata.authorization_encrypted_response_enc =
            Some(AuthorizationEncryptedResponseContentEncryptionAlgorithm::A256GCM);
    }

    metadata
}

pub(crate) fn oidc_verifier_presentation_definition(
    proof: &Proof,
    mut presentation_definition: OpenID4VPPresentationDefinition,
) -> Result<OpenID4VPPresentationDefinition, OpenID4VCError> {
    let proof_schema = proof.schema.as_ref().ok_or(OpenID4VCError::MappingError(
        "missing proof schema".to_string(),
    ))?;

    let proof_schema_inputs = match proof_schema.input_schemas.as_ref() {
        Some(input_schemas) if !input_schemas.is_empty() => input_schemas.to_vec(),
        _ => {
            return Err(OpenID4VCError::MappingError(
                "input_schemas are missing".to_string(),
            ));
        }
    };

    if proof_schema_inputs.len() != presentation_definition.input_descriptors.len() {
        return Err(OpenID4VCError::Other(
            "Proof schema inputs length doesn't match interaction data input descriptors length"
                .to_owned(),
        ));
    }

    let now = OffsetDateTime::now_utc();
    for (input_descriptor, proof_schema_input) in presentation_definition
        .input_descriptors
        .iter_mut()
        .zip(proof_schema_inputs)
    {
        if let Some(validity_constraint) = proof_schema_input.validity_constraint {
            input_descriptor.constraints.validity_credential_nbf =
                Some(now - Duration::seconds(validity_constraint));
        }
    }

    Ok(presentation_definition)
}

pub(crate) async fn encryption_info_from_metadata(
    client: &dyn HttpClient,
    interaction_data: &OpenID4VPHolderInteractionData,
) -> Result<Option<EncryptionInfo>, VerificationProtocolError> {
    let Some(OpenID4VPClientMetadata::Draft(mut client_metadata)) =
        interaction_data.client_metadata.clone()
    else {
        // metadata_uri (if any) has been resolved before, no need to check
        return Ok(None);
    };

    if !matches!(
        client_metadata.authorization_encrypted_response_alg,
        Some(AuthorizationEncryptedResponseAlgorithm::EcdhEs)
    ) {
        // Encrypted presentations not supported
        return Ok(None);
    }

    let encryption_alg = match client_metadata.authorization_encrypted_response_enc.clone() {
        // Encrypted presentations not supported
        None => return Ok(None),
        Some(alg) => alg,
    };

    if client_metadata
        .jwks
        .as_ref()
        .map(|jwks| jwks.keys.is_empty())
        .unwrap_or(true)
        && let Some(ref uri) = client_metadata.jwks_uri
    {
        let jwks = client
            .get(uri)
            .send()
            .await
            .context("send error")
            .map_err(VerificationProtocolError::Transport)?
            .error_for_status()
            .context("status error")
            .map_err(VerificationProtocolError::Transport)?;

        client_metadata.jwks = jwks
            .json()
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;
    }
    let Some(verifier_key) = ec_key_from_metadata(client_metadata.into()) else {
        return Ok(None);
    };
    Ok(Some(EncryptionInfo {
        verifier_key,
        alg: encryption_alg,
    }))
}
