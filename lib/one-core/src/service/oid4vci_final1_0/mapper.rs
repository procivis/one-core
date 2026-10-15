use std::str::FromStr;

use shared_types::InteractionId;
use standardized_types::oauth2::token::TokenRequest;
use uuid::Uuid;

use super::error::OID4VCIFinal1_0ServiceError;
use crate::model::credential_schema::CredentialSchema;
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::interaction::Interaction;
use crate::proto::dpop_handler::DpopParams;
use crate::provider::issuance_protocol::error::OpenID4VCIError;
use crate::provider::issuance_protocol::openid4vci_final1_0::model::{
    OpenID4VCDpopParams, OpenID4VCIIssuerInteractionDataDTO,
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

pub(super) fn map_dpop_params(value: OpenID4VCDpopParams, base_url: Option<String>) -> DpopParams {
    DpopParams {
        nonce_validity: value.nonce_validity_seconds,
        nonce_refresh_threshold: value.nonce_refresh_threshold_seconds,
        leeway: value.leeway_seconds,
        signing_key: value.signing_key,
        proof_signing_algorithms: value.signing_algorithms,
        base_url,
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
