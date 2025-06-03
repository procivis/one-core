use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use pem::{EncodeConfig, LineEnding, Pem, encode_many_config};
use time::OffsetDateTime;

use crate::model::credential::{Credential, CredentialStateEnum};
use crate::model::interaction::Interaction;
use crate::provider::credential_formatter::model::{
    CertificateDetails, DetailCredential, IssuerDetails,
};
use crate::provider::issuance_protocol::error::IssuanceProtocolError;
use crate::provider::issuance_protocol::openid4vci_draft13::error::{
    OpenID4VCIError, OpenIDIssuanceError,
};
use crate::provider::issuance_protocol::openid4vci_draft13::model::{
    OpenID4VCIIssuerInteractionDataDTO, OpenID4VCITokenRequestDTO,
};
use crate::service::certificate::validator::{CertificateValidator, ParsedCertificate};

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

pub(crate) async fn validate_issuer(
    offered_credential: &Credential,
    received_credential: &DetailCredential,
    certificate_validator: &dyn CertificateValidator,
) -> Result<(), IssuanceProtocolError> {
    // check credential is consistent with what was offered
    match &received_credential.issuer {
        IssuerDetails::Did(response_did) => {
            if offered_credential.issuer_certificate.is_some() {
                return Err(IssuanceProtocolError::DidMismatch);
            }
            if let Some(credential_offer_did) = offered_credential
                .issuer_identifier
                .as_ref()
                .and_then(|identifier| identifier.did.as_ref())
            {
                if *response_did != credential_offer_did.did {
                    return Err(IssuanceProtocolError::DidMismatch);
                }
            }
        }
        IssuerDetails::Certificate(CertificateDetails { fingerprint, .. }) => {
            if let Some(ref identifier) = offered_credential.issuer_identifier {
                // TODO ONE-5919: did:mdl compatibility shim, remove when did method is removed
                if let Some(did) = identifier.did.as_ref().map(|did| &did.did) {
                    let der_bytes = did
                        .as_str()
                        .strip_prefix("did:mdl:certificate:")
                        .map(|s| Base64UrlSafeNoPadding::decode_to_vec(s, None))
                        .transpose()
                        .map_err(|_| IssuanceProtocolError::CertificateMismatch)?
                        .ok_or(IssuanceProtocolError::CertificateMismatch)?;
                    let chain = encode_many_config(
                        &[Pem::new("CERTIFICATE", der_bytes)],
                        EncodeConfig::new().set_line_ending(LineEnding::LF),
                    );
                    let ParsedCertificate { attributes, .. } = certificate_validator
                        .parse_pem_chain(chain.as_bytes(), true)
                        .await
                        .map_err(|_| IssuanceProtocolError::CertificateMismatch)?;
                    if attributes.fingerprint == *fingerprint {
                        return Ok(());
                    }
                }
                return Err(IssuanceProtocolError::CertificateMismatch);
            } else if let Some(credential_offer_cert) =
                offered_credential.issuer_certificate.as_ref()
            {
                if credential_offer_cert.fingerprint != *fingerprint {
                    return Err(IssuanceProtocolError::CertificateMismatch);
                }
            }
        }
    }
    Ok(())
}
