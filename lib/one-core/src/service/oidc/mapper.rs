use crate::model::credential_schema::CredentialSchema;
use crate::model::interaction::{Interaction, InteractionId};
use crate::service::error::ServiceError;
use crate::service::oidc::dto::{
    DurationSeconds, OpenID4VCIDiscoveryResponseDTO, OpenID4VCIError, OpenID4VCIInteractionDataDTO,
    OpenID4VCIIssuerMetadataCredentialDefinitionResponseDTO,
    OpenID4VCIIssuerMetadataCredentialSupportedResponseDTO, OpenID4VCIIssuerMetadataResponseDTO,
    OpenID4VCITokenResponseDTO,
};
use crate::util::oidc::map_core_to_oidc_format;
use std::str::FromStr;
use uuid::Uuid;

use super::dto::OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO;

pub(super) fn create_issuer_metadata_response(
    base_url: String,
    schema: CredentialSchema,
) -> Result<OpenID4VCIIssuerMetadataResponseDTO, ServiceError> {
    Ok(OpenID4VCIIssuerMetadataResponseDTO {
        credential_issuer: base_url.to_owned(),
        credential_endpoint: format!("{base_url}/credential"),
        credentials_supported: vec![OpenID4VCIIssuerMetadataCredentialSupportedResponseDTO {
            format: map_core_to_oidc_format(&schema.format).map_err(ServiceError::from)?,
            credential_definition: OpenID4VCIIssuerMetadataCredentialDefinitionResponseDTO {
                r#type: vec!["VerifiableCredential".to_string()],
            },
            display: Some(vec![
                OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO { name: schema.name },
            ]),
        }],
    })
}

pub(super) fn create_service_discovery_response(
    base_url: String,
) -> Result<OpenID4VCIDiscoveryResponseDTO, ServiceError> {
    Ok(OpenID4VCIDiscoveryResponseDTO {
        issuer: base_url.to_owned(),
        authorization_endpoint: format!("{base_url}/authorize"),
        token_endpoint: format!("{base_url}/token"),
        jwks_uri: format!("{base_url}/jwks"),
        response_types_supported: vec!["token".to_string()],
        grant_types_supported: vec![
            "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string()
        ],
        subject_types_supported: vec!["public".to_string()],
        id_token_signing_alg_values_supported: vec![],
    })
}

impl TryFrom<OpenID4VCIInteractionDataDTO> for OpenID4VCITokenResponseDTO {
    type Error = ServiceError;
    fn try_from(value: OpenID4VCIInteractionDataDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            access_token: value.access_token.to_string(),
            token_type: "bearer".to_string(),
            expires_in: DurationSeconds(
                value
                    .access_token_expires_at
                    .ok_or(ServiceError::MappingError(
                        "access_token_expires_at missing".to_string(),
                    ))?
                    .unix_timestamp(),
            ),
        })
    }
}

pub(super) fn parse_access_token(access_token: &str) -> Result<InteractionId, ServiceError> {
    let mut splitted_token = access_token.split('.');
    if splitted_token.to_owned().count() != 2 {
        return Err(ServiceError::OpenID4VCError(OpenID4VCIError::InvalidToken));
    }

    let interaction_id = Uuid::from_str(
        splitted_token
            .next()
            .ok_or(ServiceError::OpenID4VCError(OpenID4VCIError::InvalidToken))?,
    )
    .map_err(|_| ServiceError::MappingError("Not a uuid".to_string()))?;
    Ok(interaction_id)
}

pub(crate) fn interaction_data_to_dto(
    interaction: &Interaction,
) -> Result<OpenID4VCIInteractionDataDTO, ServiceError> {
    let interaction_data = interaction
        .data
        .to_owned()
        .ok_or(ServiceError::MappingError(
            "interaction data is missing".to_string(),
        ))?;
    let json_data = String::from_utf8(interaction_data)
        .map_err(|e| ServiceError::MappingError(e.to_string()))?;

    let interaction_data_parsed: OpenID4VCIInteractionDataDTO =
        serde_json::from_str(&json_data).map_err(|e| ServiceError::MappingError(e.to_string()))?;
    Ok(interaction_data_parsed)
}

pub(crate) fn vec_last_position_from_token_path(path: &str) -> Result<usize, ServiceError> {
    // Find the position of '[' and ']'
    if let Some(open_bracket) = path.rfind('[') {
        if let Some(close_bracket) = path.rfind(']') {
            // Extract the substring between '[' and ']'
            let value = &path[open_bracket + 1..close_bracket];

            let parsed_value = value.parse().map_err(|_| {
                ServiceError::MappingError("Could not parse vec position".to_string())
            })?;

            Ok(parsed_value)
        } else {
            Err(ServiceError::MappingError(
                "Credential path is incorrect".to_string(),
            ))
        }
    } else {
        Ok(0)
    }
}
