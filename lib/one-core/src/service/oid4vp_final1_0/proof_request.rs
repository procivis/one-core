use std::collections::HashMap;

use shared_types::InteractionId;
use standardized_types::jwk::PublicJwk;
use standardized_types::openid4vp::dcql::DcqlQuery;
use standardized_types::openid4vp::{
    AuthorizationRequest, ClientMetadata, MdocAlgs, PresentationFormat, ResponseMode, SdJwtVcAlgs,
    VerifierInfoAttestation, W3CJwtAlgs, W3CLdpAlgs,
};
use url::Url;

use crate::model::proof::Proof;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::util::key_agreement::key_agreement_keys;

#[expect(clippy::too_many_arguments)]
pub(crate) fn generate_authorization_request_params_final1_0(
    nonce: String,
    dcql_query: DcqlQuery,
    transaction_data: Vec<String>,
    client_id: String,
    response_uri: String,
    interaction_id: &InteractionId,
    client_metadata: ClientMetadata,
    verifier_info: Vec<VerifierInfoAttestation>,
) -> Result<AuthorizationRequest, VerificationProtocolError> {
    Ok(AuthorizationRequest {
        response_type: Some("vp_token".to_string()),
        response_mode: Some(determine_response_mode_final1_0(&client_metadata)),
        client_id,
        client_metadata: Some(client_metadata),
        response_uri: Some(
            Url::parse(&response_uri)
                .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?,
        ),
        nonce: Some(nonce),
        state: Some(interaction_id.to_string()),
        dcql_query,
        transaction_data,
        redirect_uri: None,
        verifier_info,
    })
}

fn determine_response_mode_final1_0(metadata: &ClientMetadata) -> ResponseMode {
    if metadata.encrypted_response_enc_values_supported.is_some() {
        ResponseMode::DirectPostJwt
    } else {
        ResponseMode::DirectPost
    }
}
pub(crate) fn generate_vp_formats_supported() -> HashMap<String, PresentationFormat> {
    let mut formats = HashMap::new();

    let jose_algs = vec!["EdDSA".to_owned(), "ES256".to_owned()];
    let cose_algs = vec![-7, -8, -9, -19];

    // only including the entries specified in the final standard for now
    formats.insert(
        "jwt_vc_json".to_owned(),
        PresentationFormat::W3CJwtAlgs(W3CJwtAlgs {
            alg_values: jose_algs.to_owned(),
        }),
    );
    formats.insert(
        "ldp_vc".to_owned(),
        PresentationFormat::W3CLdpAlgs(W3CLdpAlgs {
            proof_type_values: vec!["DataIntegrityProof".to_string()],
            cryptosuite_values: vec![
                "bbs-2023".to_string(),
                "ecdsa-rdfc-2019".to_string(),
                "eddsa-rdfc-2022".to_string(),
            ],
        }),
    );
    formats.insert(
        "mso_mdoc".to_owned(),
        PresentationFormat::MdocAlgs(MdocAlgs {
            issuerauth_alg_values: cose_algs.to_owned(),
            deviceauth_alg_values: cose_algs,
        }),
    );
    formats.insert(
        "dc+sd-jwt".to_owned(),
        PresentationFormat::SdJwtVcAlgs(SdJwtVcAlgs {
            sd_jwt_alg_values: jose_algs.to_owned(),
            kb_jwt_alg_values: jose_algs,
        }),
    );

    formats
}

/// Selects the JWK the verifier advertises for ECDH-ES key agreement, preferring the key the
/// proof was created with.
pub(crate) async fn select_key_agreement_key_from_proof(
    proof: &Proof,
    key_provider: &dyn KeyProvider,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> Result<Option<PublicJwk>, VerificationProtocolError> {
    let Some(verifier_identifier) = proof.verifier_identifier.as_ref() else {
        return Err(VerificationProtocolError::Failed(
            "verifier_identifier is None".to_string(),
        ));
    };
    let verifier_identifier = verifier_identifier.as_ref().await?;

    let Some(verifier_key) = proof.verifier_key.as_ref() else {
        return Err(VerificationProtocolError::Failed(
            "verifier_key is None".to_string(),
        ));
    };
    let verifier_key = verifier_key.as_ref().await?;

    let candidates = key_agreement_keys(
        &verifier_identifier,
        Some(verifier_key.id),
        key_provider,
        key_algorithm_provider,
    )
    .await?;

    if candidates.is_empty() {
        tracing::warn!(
            "Verifier identifier {} has no key usable for key agreement, response encryption is not offered",
            verifier_identifier.id
        );
    }

    Ok(candidates.into_iter().next().map(|candidate| candidate.jwk))
}
