use std::str::FromStr;

use one_crypto::utilities::generate_alphanumeric;
use shared_types::{BlobId, CredentialSchemaFormatId, InteractionId};
use standardized_types::oauth2::token::TokenRequest;
use time::OffsetDateTime;
use uuid::Uuid;

use super::error::OID4VCIFinal1_0ServiceError;
use crate::model::credential::{Credential, UpdateCredentialRequest};
use crate::model::credential_schema::CredentialSchema;
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::interaction::Interaction;
use crate::proto::dpop_handler::DpopParams;
use crate::provider::issuance_protocol::error::OpenID4VCIError;
use crate::provider::issuance_protocol::openid4vci_final1_0::model::{
    FormatNotification, OpenID4VCDpopParams, OpenID4VCIIssuerInteractionDataDTO,
};
use crate::provider::issuance_protocol::openid4vci_final1_0::service::parse_refresh_token;

pub(crate) fn interaction_data_to_dto(
    interaction: &Interaction,
) -> Result<OpenID4VCIIssuerInteractionDataDTO, OID4VCIFinal1_0ServiceError> {
    let interaction_data =
        interaction
            .data
            .to_owned()
            .ok_or(OID4VCIFinal1_0ServiceError::MappingError(
                "interaction data is missing".to_string(),
            ))?;

    serde_json::from_slice(&interaction_data)
        .map_err(|e| OID4VCIFinal1_0ServiceError::MappingError(e.to_string()))
}

// interactions created before multi-format support have no selection, all schema formats are offered
pub(crate) async fn offered_formats(
    credential_schema: &CredentialSchema,
    interaction_data: &OpenID4VCIIssuerInteractionDataDTO,
) -> Result<Vec<CredentialSchemaFormat>, OID4VCIFinal1_0ServiceError> {
    let formats = credential_schema.formats.as_ref().await?;
    let Some(selected) = &interaction_data.formats else {
        return Ok(formats.to_owned());
    };

    Ok(formats
        .iter()
        .filter(|format| selected.contains(&format.id))
        .cloned()
        .collect())
}

/// One notification id per offered format, allocated when issuing the token so that the
/// credential endpoint does not need to write the interaction. Ids are kept across token refreshes.
pub(super) fn allocate_notification_ids(
    existing: Vec<FormatNotification>,
    offered_formats: &[CredentialSchemaFormat],
) -> Vec<FormatNotification> {
    offered_formats
        .iter()
        .map(|format| {
            existing
                .iter()
                .find(|entry| entry.format == Some(format.id))
                .cloned()
                .unwrap_or_else(|| FormatNotification {
                    notification_id: generate_alphanumeric(32),
                    format: Some(format.id),
                })
        })
        .collect()
}

// interactions created before multi-format support have a single entry without format
pub(super) fn notification_id_for_format(
    notification_ids: &[FormatNotification],
    format_id: CredentialSchemaFormatId,
) -> Option<&str> {
    notification_ids
        .iter()
        .find(|entry| entry.format.is_none_or(|id| id == format_id))
        .map(|entry| entry.notification_id.as_str())
}

pub(super) fn map_dpop_params(
    value: OpenID4VCDpopParams,
    base_url: Option<String>,
    swiyu_mode: bool,
) -> DpopParams {
    DpopParams {
        nonce_validity: value.nonce_validity_seconds,
        nonce_refresh_threshold: value.nonce_refresh_threshold_seconds,
        leeway: value.leeway_seconds,
        signing_key: value.signing_key,
        proof_signing_algorithms: value.signing_algorithms,
        base_url,
        swiyu_mode,
    }
}

pub(super) fn interaction_id_from_token_request(
    request: &TokenRequest,
) -> Result<InteractionId, OID4VCIFinal1_0ServiceError> {
    match &request {
        TokenRequest::PreAuthorizedCode {
            pre_authorized_code,
            tx_code: _,
        } => Uuid::from_str(pre_authorized_code)
            .map_err(|_| OpenID4VCIError::InvalidRequest.into())
            .map(Into::into),
        TokenRequest::AuthorizationCode { .. } => Err(OpenID4VCIError::InvalidGrant.into()),
        TokenRequest::RefreshToken { refresh_token } => {
            parse_refresh_token(refresh_token).map_err(Into::into)
        }
    }
}

/// Update persisting a credential issued by the issuance protocol.
pub(super) fn issued_credential_update(
    credential: &Credential,
    credential_blob_id: BlobId,
    issuance_date: OffsetDateTime,
    wallet_key_attestation_blob_id: Option<BlobId>,
) -> Result<UpdateCredentialRequest, OID4VCIFinal1_0ServiceError> {
    let issuer = credential.issuer_credential()?;
    Ok(UpdateCredentialRequest {
        state: Some(issuer.common.state),
        issuance_date: Some(issuance_date),
        holder_identifier_id: issuer.data.holder_identifier.as_ref().map(|h| h.id()),
        format: Some(issuer.data.format.id()),
        credential_blob_id: Some(credential_blob_id),
        wallet_key_attestation_blob_id,
        ..Default::default()
    })
}
