use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use time::OffsetDateTime;

use crate::model::credential::{Credential, CredentialStateEnum};
use crate::model::identifier::IdentifierType;
use crate::model::interaction::Interaction;
use crate::provider::credential_formatter::model::{
    CertificateDetails, DetailCredential, IdentifierDetails,
};
use crate::provider::issuance_protocol::error::{
    IssuanceProtocolError, OpenID4VCIError, OpenIDIssuanceError,
};
use crate::provider::issuance_protocol::openid4vci_draft13::model::{
    OpenID4VCIIssuerInteractionDataDTO, OpenID4VCITokenRequestDTO,
};
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;

pub(crate) fn throw_if_token_request_invalid(
    request: &OpenID4VCITokenRequestDTO,
) -> Result<(), OpenIDIssuanceError> {
    match &request {
        OpenID4VCITokenRequestDTO::PreAuthorizedCode {
            pre_authorized_code,
            tx_code: _,
        } if pre_authorized_code.is_empty() => Err(OpenIDIssuanceError::OpenID4VCI(
            OpenID4VCIError::InvalidRequest,
        )),
        OpenID4VCITokenRequestDTO::RefreshToken { refresh_token } if refresh_token.is_empty() => {
            Err(OpenIDIssuanceError::OpenID4VCI(
                OpenID4VCIError::InvalidRequest,
            ))
        }

        _ => Ok(()),
    }
}

pub(crate) fn throw_if_tx_code_invalid(
    expected_code: Option<&String>,
    request: &OpenID4VCITokenRequestDTO,
) -> Result<(), OpenID4VCIError> {
    match (expected_code, request) {
        (
            Some(expected_code),
            OpenID4VCITokenRequestDTO::PreAuthorizedCode {
                pre_authorized_code: _,
                tx_code: Some(request_code),
            },
        ) => {
            if expected_code != request_code {
                tracing::info!("wrong tx_code supplied");
                return Err(OpenID4VCIError::InvalidGrant);
            }
            tracing::debug!("correct tx_code supplied");
        }
        (Some(_), _) => {
            tracing::info!("tx_code not supplied");
            return Err(OpenID4VCIError::InvalidRequest);
        }
        (
            None,
            OpenID4VCITokenRequestDTO::PreAuthorizedCode {
                pre_authorized_code: _,
                tx_code: Some(_),
            },
        ) => {
            tracing::info!("tx_code supplied while not expected");
            return Err(OpenID4VCIError::InvalidRequest);
        }
        (None, _) => {} // OK, correct handling without tx_code
    };

    Ok(())
}

pub(crate) fn throw_if_interaction_created_date(
    pre_authorization_expires_in: time::Duration,
    interaction: &Interaction,
) -> Result<(), OpenIDIssuanceError> {
    if interaction.created_date + pre_authorization_expires_in < OffsetDateTime::now_utc() {
        return Err(OpenIDIssuanceError::OpenID4VCI(
            OpenID4VCIError::InvalidGrant,
        ));
    }
    Ok(())
}

pub(crate) fn throw_if_interaction_pre_authorized_code_used(
    interaction_data: &OpenID4VCIIssuerInteractionDataDTO,
) -> Result<(), OpenIDIssuanceError> {
    if interaction_data.pre_authorized_code_used {
        return Err(OpenIDIssuanceError::OpenID4VCI(
            OpenID4VCIError::InvalidGrant,
        ));
    }
    Ok(())
}

pub(crate) fn throw_if_credential_state_not_eq(
    credential: &Credential,
    state: CredentialStateEnum,
) -> Result<(), OpenIDIssuanceError> {
    let current_state = &credential.state;
    if *current_state != state {
        return Err(OpenIDIssuanceError::InvalidCredentialState {
            state: current_state.to_owned(),
        });
    }
    Ok(())
}

pub(super) fn validate_refresh_token(
    interaction_data: &OpenID4VCIIssuerInteractionDataDTO,
    refresh_token: &str,
) -> Result<(), OpenIDIssuanceError> {
    let Some(stored_refresh_token_hash) = interaction_data.refresh_token_hash.as_ref() else {
        return Err(OpenIDIssuanceError::OpenID4VCI(
            OpenID4VCIError::InvalidRequest,
        ));
    };

    let refresh_token_hash = SHA256
        .hash(refresh_token.as_bytes())
        .map_err(|e| OpenIDIssuanceError::ValidationError(e.to_string()))?;

    if stored_refresh_token_hash != &refresh_token_hash {
        return Err(OpenIDIssuanceError::OpenID4VCI(
            OpenID4VCIError::InvalidToken,
        ));
    }

    let Some(expires_at) = interaction_data.refresh_token_expires_at.as_ref() else {
        return Err(OpenIDIssuanceError::OpenID4VCI(
            OpenID4VCIError::InvalidRequest,
        ));
    };

    if &OffsetDateTime::now_utc() > expires_at {
        return Err(OpenIDIssuanceError::OpenID4VCI(
            OpenID4VCIError::InvalidToken,
        ));
    }

    Ok(())
}

/// Check that the issued credential issuer is consistent with what was promised in the credential offer.
pub(crate) async fn validate_issuer(
    offered_credential: &Credential,
    received_credential: &DetailCredential,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> Result<(), IssuanceProtocolError> {
    let Some(offer_identifier) = &offered_credential.issuer_identifier else {
        // the offer did not make any promises about the issuer, hence consistency is given anyway
        return Ok(());
    };

    match &received_credential.issuer {
        IdentifierDetails::Did(response_did) => {
            if offer_identifier.r#type != IdentifierType::Did {
                return Err(IssuanceProtocolError::DidMismatch);
            }
            let Some(credential_offer_did) = &offer_identifier.did else {
                return Err(IssuanceProtocolError::Failed(format!(
                    "Missing did on identifier {}",
                    offer_identifier.id
                )));
            };
            if *response_did != credential_offer_did.did {
                return Err(IssuanceProtocolError::DidMismatch);
            }
        }
        IdentifierDetails::Certificate(CertificateDetails { fingerprint, .. }) => {
            if offer_identifier.r#type != IdentifierType::Certificate {
                return Err(IssuanceProtocolError::CertificateMismatch);
            }
            let Some(offer_cert) = &offered_credential.issuer_certificate else {
                return Err(IssuanceProtocolError::Failed(format!(
                    "Missing issuer_certificate on credential {} offered by issuer with certificate identifier {}",
                    offered_credential.id, offer_identifier.id
                )));
            };
            if offer_cert.fingerprint != *fingerprint {
                return Err(IssuanceProtocolError::CertificateMismatch);
            }
        }
        IdentifierDetails::Key(public_key) => {
            if offer_identifier.r#type != IdentifierType::Key {
                return Err(IssuanceProtocolError::KeyMismatch);
            }
            let Some(offer_key) = &offer_identifier.key else {
                return Err(IssuanceProtocolError::Failed(format!(
                    "Missing key on identifier {}",
                    offer_identifier.id
                )));
            };
            let pk = key_algorithm_provider.parse_jwk(public_key).map_err(|e| {
                IssuanceProtocolError::Failed(format!(
                    "Failed to parse received issuer JWK {}, cause: {e}",
                    offer_identifier.id
                ))
            })?;
            if pk.key.public_key_as_raw() != offer_key.public_key {
                return Err(IssuanceProtocolError::KeyMismatch);
            }
        }
    }
    Ok(())
}
