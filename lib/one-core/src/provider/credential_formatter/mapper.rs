use one_providers::credential_formatter::model::{
    CredentialData, CredentialSchemaData, CredentialStatus, ExtractPresentationCtx,
    FormatPresentationCtx,
};
use one_providers::exchange_protocol::openid4vc::model::OpenID4VPInteractionContent;
use time::OffsetDateTime;

use super::map_claims;
use crate::provider::exchange_protocol::openid4vc::dto::OpenID4VPInteractionData;
use crate::service::credential::dto::CredentialDetailResponseDTO;
use crate::service::error::ServiceError;

pub fn extract_presentation_ctx_from_interaction_content(
    content: OpenID4VPInteractionContent,
) -> ExtractPresentationCtx {
    ExtractPresentationCtx {
        nonce: Some(content.nonce),
        format_nonce: None,
        issuance_date: None,
        expiration_date: None,
    }
}

pub fn format_presentation_ctx_from_interaction_data(
    data: OpenID4VPInteractionData,
) -> FormatPresentationCtx {
    FormatPresentationCtx {
        nonce: Some(data.nonce),
        client_id: Some(data.client_id),
        response_uri: Some(data.response_uri),
        format_nonce: None,
    }
}

pub fn credential_data_from_credential_detail_response(
    credential: CredentialDetailResponseDTO,
    core_base_url: &str,
    credential_status: Vec<CredentialStatus>,
) -> Result<CredentialData, ServiceError> {
    let id = format!("{core_base_url}/ssi/credential/v1/{}", credential.id);
    let issuer_did = credential.issuer_did.map(|did| did.did).ok_or_else(|| {
        ServiceError::MappingError(format!(
            "Missing issuer DID in CredentialDetailResponseDTO for credential {id}"
        ))
    })?;

    let issuance_date = OffsetDateTime::now_utc();
    let valid_for = time::Duration::days(365 * 2);

    Ok(CredentialData {
        id,
        issuance_date,
        valid_for,
        claims: map_claims(&credential.claims, false),
        issuer_did: issuer_did.into(),
        status: credential_status,
        schema: CredentialSchemaData {
            id: Some(credential.schema.schema_id),
            r#type: Some(credential.schema.schema_type.to_string()),
            context: Some(format!(
                "{core_base_url}/ssi/context/v1/{}",
                credential.schema.id
            )),
            name: credential.schema.name,
        },
    })
}
