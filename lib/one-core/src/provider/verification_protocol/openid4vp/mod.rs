//! Implementation of OpenID4VP.
//! https://openid.net/specs/openid-4-verifiable-presentations-1_0.html

use std::sync::Arc;

use standardized_types::openid4vp::ClientIdPrefix;

use super::VerificationProtocolError;
use crate::error::ContextWithErrorCode;
use crate::model::identifier::{Identifier, IdentifierType};
use crate::model::key::Key;
use crate::model::proof::Proof;
use crate::provider::credential_formatter::model::AuthenticationFn;
use crate::provider::key_algorithm::KeyAlgorithm;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::service::proof::dto::ShareProofRequestParamsDTO;
pub(crate) mod dcql;
pub(crate) mod disclosure_policy;
pub mod error;
pub mod final1_0;
pub mod final1_0_swiyu;
pub(crate) mod mapper;
pub(crate) mod mdoc;
pub mod model;
pub mod proximity_draft00;
pub mod validator;

fn get_client_id_scheme(
    params: Option<ShareProofRequestParamsDTO>,
    supported_client_id_schemes: &[ClientIdPrefix],
    verifier_identifier: &Identifier,
) -> Result<ClientIdPrefix, VerificationProtocolError> {
    let param_scheme = params.unwrap_or_default().client_id_scheme;

    if let Some(scheme) = param_scheme {
        return Ok(scheme);
    }

    let fallback_scheme = supported_client_id_schemes
        .iter()
        .find(|scheme| {
            get_supported_client_id_scheme_for_identifier(&verifier_identifier.data.r#type())
                .contains(scheme)
        })
        .cloned()
        .ok_or_else(|| {
            VerificationProtocolError::InvalidRequest(
                "No supported client_id_scheme for selected identifier type".to_string(),
            )
        })?;

    Ok(fallback_scheme)
}

fn get_supported_client_id_scheme_for_identifier(
    identifier: &IdentifierType,
) -> Vec<ClientIdPrefix> {
    match identifier {
        IdentifierType::Key => vec![],
        IdentifierType::Did => vec![
            ClientIdPrefix::DecentralizedIdentifier,
            ClientIdPrefix::VerifierAttestation,
            ClientIdPrefix::RedirectUri,
        ],
        IdentifierType::Certificate => vec![ClientIdPrefix::X509SanDns, ClientIdPrefix::X509Hash],
        IdentifierType::CertificateAuthority => vec![],
    }
}

struct JWTSigner {
    pub auth_fn: AuthenticationFn,
    pub verifier_key: Key,
    pub key_algorithm: Arc<dyn KeyAlgorithm>,
    pub jose_algorithm: String,
}

async fn get_jwt_signer(
    proof: &Proof,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    key_provider: &dyn KeyProvider,
) -> Result<JWTSigner, VerificationProtocolError> {
    let verifier_key = proof
        .verifier_key
        .as_ref()
        .ok_or(VerificationProtocolError::Failed(
            "verifier_key is None".to_string(),
        ))?
        .as_ref()
        .await?
        .to_owned();

    let auth_fn = key_provider.get_signature_provider(
        &verifier_key,
        None,
        key_algorithm_provider.to_owned(),
    )?;

    let key_algorithm = key_algorithm_provider
        .key_algorithm_from_key(&verifier_key)
        .error_while("getting key algorithm")?;

    let jose_algorithm = key_algorithm.issuance_jose_alg_id();
    Ok(JWTSigner {
        auth_fn,
        verifier_key,
        key_algorithm,
        jose_algorithm,
    })
}
