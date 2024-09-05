use one_providers::credential_formatter::model::{
    CredentialData, CredentialSchemaData, CredentialSchemaMetadata, CredentialStatus,
    ExtractPresentationCtx, FormatPresentationCtx,
};
use one_providers::exchange_protocol::openid4vc::model::OpenID4VPInteractionContent;
use time::OffsetDateTime;
use uuid::fmt::Urn;

use super::map_claims;
use crate::config::core_config::RevocationType;
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
        ..Default::default()
    }
}

pub fn credential_data_from_credential_detail_response(
    credential: CredentialDetailResponseDTO,
    core_base_url: &str,
    credential_status: Vec<CredentialStatus>,
) -> Result<CredentialData, ServiceError> {
    let issuer_did = credential.issuer_did.map(|did| did.did).ok_or_else(|| {
        ServiceError::MappingError(format!(
            "Missing issuer DID in CredentialDetailResponseDTO for credential {}",
            credential.id
        ))
    })?;

    let issuance_date = OffsetDateTime::now_utc();
    let valid_for = time::Duration::days(365 * 2);

    // The ID property is optional according to the VCDM. We need to include it for BBS+ due to ONE-3193
    // We also include it if LLVC credentials are used for revocation
    let id = if credential.schema.format.eq("JSON_LD_BBSPLUS")
        || credential_status
            .iter()
            .any(|status| status.r#type == RevocationType::Lvvc.to_string())
    {
        Some(Urn::from_uuid(credential.id.into()).to_string())
    } else {
        None
    };

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
            metadata: match (
                credential.schema.layout_properties,
                credential.schema.layout_type,
            ) {
                (Some(l), Some(t)) => Some(CredentialSchemaMetadata {
                    layout_properties: l.into(),
                    layout_type: t.into(),
                }),
                _ => None,
            },
        },
    })
}
