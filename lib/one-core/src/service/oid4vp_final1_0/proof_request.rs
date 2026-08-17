use std::collections::HashMap;

use shared_types::InteractionId;
use standardized_types::jwk::{JwkUse, PublicJwk};
use standardized_types::openid4vp::dcql::DcqlQuery;
use standardized_types::openid4vp::{
    AuthorizationRequest, ClientMetadata, MdocAlgs, PresentationFormat, ResponseMode, SdJwtVcAlgs,
    VerifierInfoAttestation, W3CJwtAlgs, W3CLdpAlgs,
};
use url::Url;

use crate::config::core_config::{CoreConfig, KeyStorageType};
use crate::error::ContextWithErrorCode;
use crate::model::did::KeyRole;
use crate::model::identifier::IdentifierData;
use crate::model::proof::Proof;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::util::key_selection::KeyFilter;

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

pub(crate) async fn select_key_agreement_key_from_proof(
    proof: &Proof,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
    config: &CoreConfig,
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

    let candidate_encryption_key = match &verifier_identifier.data {
        IdentifierData::Certificate(_) | IdentifierData::Key(_) => Some(verifier_key.to_owned()),
        IdentifierData::Did(verifier_did) => {
            let verifier_did = verifier_did.as_ref().await?;

            let key_agreement_key_filter = KeyFilter::did_role(KeyRole::KeyAgreement);
            // We ensure the specified key is a key agreement key
            let encryption_key = verifier_did
                .find_key(&verifier_key.id, &key_agreement_key_filter)
                .await;
            match encryption_key {
                Ok(key) => Some(key.key),
                // If the key is not a key agreement key or not found, we try to find a matching key
                Err(_) => verifier_did
                    .find_first_matching_key(&key_agreement_key_filter)
                    .await
                    .error_while("finding agreement key")?
                    .map(|key| key.key),
            }
        }
        IdentifierData::CertificateAuthority(_) => {
            return Err(VerificationProtocolError::Failed(format!(
                "Invalid verifier identifier type {}",
                verifier_identifier.data.r#type()
            )));
        }
    };

    // If no key is found, we return None, the verifier will only support the direct_post response_mode
    let Some(candidate_encryption_key) = candidate_encryption_key else {
        return Ok(None);
    };

    let key_algorithm = key_algorithm_provider
        .key_algorithm_from_key(&candidate_encryption_key)
        .error_while("getting key algorithm")?;

    /*
     * TODO(ONE-5428): Azure vault doesn't work directly with encrypted JWE params
     * This needs more investigation and a refactor to support creating shared secret
     * through key storage
     */
    if config
        .key_storage
        .get_type(&candidate_encryption_key.storage_type)
        .error_while("getting key storage type")?
        == KeyStorageType::AzureVault
    {
        return Ok(None);
    }

    let key_agreement_jwk = key_algorithm
        .reconstruct_key(
            &candidate_encryption_key.public_key,
            None,
            Some(JwkUse::Encryption),
        )
        .error_while("reconstructing key")?
        .key_agreement()
        .map(|k| k.public().as_jwk())
        .transpose()
        .error_while("getting key agreement")?;

    if let Some(mut key_agreement_jwk) = key_agreement_jwk {
        key_agreement_jwk.set_kid(candidate_encryption_key.id.to_string());
        Ok(Some(key_agreement_jwk))
    } else {
        Ok(None)
    }
}
