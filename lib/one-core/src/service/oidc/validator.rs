use one_crypto::hasher::sha256::SHA256;
use one_crypto::Hasher;
use time::OffsetDateTime;

use crate::config::core_config::{CoreConfig, ExchangeType};
use crate::config::ConfigValidationError;
use crate::model::credential_schema::CredentialSchema;
use crate::provider::exchange_protocol::openid4vc::error::OpenID4VCIError;
use crate::provider::exchange_protocol::openid4vc::model::{
    OpenID4VCICredentialRequestDTO, OpenID4VCIIssuerInteractionDataDTO,
};
use crate::service::error::ServiceError;
use crate::util::oidc::map_from_oidc_format_to_core;

pub(crate) fn throw_if_credential_request_invalid(
    schema: &CredentialSchema,
    request: &OpenID4VCICredentialRequestDTO,
) -> Result<(), ServiceError> {
    let requested_format = map_from_oidc_format_to_core(&request.format)?;

    if !schema.format.starts_with(&requested_format) {
        return Err(ServiceError::OpenID4VCIError(
            OpenID4VCIError::UnsupportedCredentialFormat,
        ));
    }

    match requested_format.as_str() {
        "MDOC" => {
            if let Some(doctype) = &request.doctype {
                if &schema.schema_id != doctype {
                    return Err(ServiceError::OpenID4VCIError(
                        OpenID4VCIError::UnsupportedCredentialType,
                    ));
                }
            } else {
                return Err(ServiceError::OpenID4VCIError(
                    OpenID4VCIError::InvalidRequest,
                ));
            }
        }
        _ => {
            if !request
                .credential_definition
                .as_ref()
                .ok_or(ServiceError::OpenID4VCIError(
                    OpenID4VCIError::InvalidRequest,
                ))?
                .r#type
                .contains(&"VerifiableCredential".to_string())
            {
                return Err(ServiceError::OpenID4VCIError(
                    OpenID4VCIError::UnsupportedCredentialType,
                ));
            }
        }
    };

    Ok(())
}

fn is_access_token_valid(
    interaction_data: &OpenID4VCIIssuerInteractionDataDTO,
    access_token: &str,
) -> bool {
    interaction_data.pre_authorized_code_used
        && SHA256
            .hash(access_token.as_bytes())
            .is_ok_and(|hash| hash == interaction_data.access_token_hash)
        && interaction_data
            .access_token_expires_at
            .is_some_and(|expires_at| expires_at > OffsetDateTime::now_utc())
}

pub(crate) fn throw_if_access_token_invalid(
    interaction_data: &OpenID4VCIIssuerInteractionDataDTO,
    access_token: &str,
) -> Result<(), ServiceError> {
    if !is_access_token_valid(interaction_data, access_token) {
        return Err(ServiceError::OpenID4VCIError(OpenID4VCIError::InvalidToken));
    }
    Ok(())
}

pub(super) fn validate_config_entity_presence(
    config: &CoreConfig,
) -> Result<(), ConfigValidationError> {
    if !config
        .exchange
        .iter()
        .any(|(_, v)| v.r#type == ExchangeType::OpenId4Vc)
    {
        Err(ConfigValidationError::EntryNotFound(
            "No exchange method with type OPENID4VC".to_string(),
        ))
    } else {
        Ok(())
    }
}
