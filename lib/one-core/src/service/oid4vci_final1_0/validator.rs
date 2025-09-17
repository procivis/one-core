use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use time::OffsetDateTime;

use crate::config::ConfigValidationError;
use crate::config::core_config::{CoreConfig, IssuanceProtocolType};
use crate::model::credential_schema::CredentialSchema;
use crate::provider::issuance_protocol::error::OpenID4VCIError;
use crate::provider::issuance_protocol::openid4vci_final1_0::model::{
    OpenID4VCICredentialRequestDTO, OpenID4VCIIssuerInteractionDataDTO,
};
use crate::service::error::ServiceError;

pub(crate) fn throw_if_credential_request_invalid(
    schema: &CredentialSchema,
    request: &OpenID4VCICredentialRequestDTO,
) -> Result<(), ServiceError> {
    if let Some(credential_configuration_id) = &request.credential_configuration_id {
        if &schema.schema_id != credential_configuration_id {
            return Err(ServiceError::OpenID4VCIError(
                OpenID4VCIError::UnsupportedCredentialType,
            ));
        }
    } else {
        return Err(ServiceError::OpenID4VCIError(
            OpenID4VCIError::InvalidRequest,
        ));
    }

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
        .issuance_protocol
        .iter()
        .any(|(_, v)| v.r#type == IssuanceProtocolType::OpenId4VciFinal1_0)
    {
        Err(ConfigValidationError::EntryNotFound(
            "No exchange method with type OPENID4VCI_FINAL1".to_string(),
        ))
    } else {
        Ok(())
    }
}

pub(super) fn validate_config_entity(
    config: &CoreConfig,
    protocol_id: &str,
) -> Result<(), ConfigValidationError> {
    let fields = config.issuance_protocol.get_fields(protocol_id)?;
    if fields.r#type != IssuanceProtocolType::OpenId4VciFinal1_0 {
        return Err(ConfigValidationError::InvalidType(
            IssuanceProtocolType::OpenId4VciFinal1_0.to_string(),
            fields.r#type.to_string(),
        ));
    }

    Ok(())
}
