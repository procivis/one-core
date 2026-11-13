//! Implementation of OpenID4VP.
//! https://openid.net/specs/openid-4-verifiable-presentations-1_0.html

use standardized_types::openid4vp::ClientIdPrefix;

use super::VerificationProtocolError;
use crate::model::identifier::{Identifier, IdentifierType};
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
    params: Option<&ShareProofRequestParamsDTO>,
    supported_client_id_schemes: &[ClientIdPrefix],
    verifier_identifier: &Identifier,
) -> Result<ClientIdPrefix, VerificationProtocolError> {
    if let Some(params) = params
        && let Some(scheme) = params.client_id_scheme
    {
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
