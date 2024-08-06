use std::collections::HashMap;

use one_providers::{
    credential_formatter::model::{
        CredentialData, CredentialSchemaData, CredentialStatus, ExtractPresentationCtx,
        FormatPresentationCtx,
    },
    exchange_protocol::openid4vc::model::OpenID4VPInteractionContent,
};
use time::OffsetDateTime;

use crate::{
    config::core_config::CoreConfig,
    provider::exchange_protocol::openid4vc::dto::OpenID4VPInteractionData,
    service::{credential::dto::CredentialDetailResponseDTO, error::ServiceError},
};

use super::map_claims;

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
    config: &CoreConfig,
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

    let mut array_order: HashMap<String, usize> = HashMap::new();

    Ok(CredentialData {
        id,
        issuance_date,
        valid_for,
        claims: map_claims(
            config,
            &credential.claims,
            &mut array_order,
            "",
            false,
            false,
        ),
        issuer_did: issuer_did.into(),
        status: credential_status,
        schema: CredentialSchemaData {
            id: Some(credential.schema.schema_id),
            r#type: Some(
                serde_json::to_string(&credential.schema.schema_type).map_err(|_| {
                    ServiceError::MappingError("Could not serialize schema type".to_string())
                })?,
            ),
            context: Some(format!(
                "{core_base_url}/ssi/context/v1/{}",
                credential.schema.id
            )),
            name: credential.schema.name,
        },
    })
}
