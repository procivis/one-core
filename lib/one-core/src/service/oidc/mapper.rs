use crate::common_mapper::{remove_first_nesting_layer, NESTED_CLAIM_MARKER};
use crate::config::core_config::{CoreConfig, FormatType};
use crate::model::credential_schema::{CredentialSchema, CredentialSchemaClaim};
use crate::model::interaction::{Interaction, InteractionId};
use crate::service::error::ServiceError;
use crate::service::oidc::{
    dto::{
        DurationSeconds, OpenID4VCIDiscoveryResponseDTO, OpenID4VCIError,
        OpenID4VCIInteractionDataDTO, OpenID4VCIIssuerMetadataCredentialDefinitionResponseDTO,
        OpenID4VCIIssuerMetadataCredentialSupportedResponseDTO,
        OpenID4VCIIssuerMetadataResponseDTO, OpenID4VCITokenResponseDTO,
    },
    model::OpenID4VPInteractionContent,
};
use crate::util::oidc::map_core_to_oidc_format;
use std::collections::HashMap;
use std::str::FromStr;
use uuid::Uuid;

use super::dto::{
    OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO,
    OpenID4VCIIssuerMetadataMdocClaimsResponseDTO, OpenID4VCIIssuerMetadataMdocClaimsValuesDTO,
};

pub(super) fn create_issuer_metadata_response(
    base_url: String,
    schema: CredentialSchema,
    config: &CoreConfig,
) -> Result<OpenID4VCIIssuerMetadataResponseDTO, ServiceError> {
    let format = config.format.get_fields(&schema.format)?;

    let credentials_supported = match format.r#type {
        FormatType::Mdoc => credentials_supported_mdoc(schema),
        _ => credentials_supported_others(schema),
    }?;

    Ok(OpenID4VCIIssuerMetadataResponseDTO {
        credential_issuer: base_url.to_owned(),
        credential_endpoint: format!("{base_url}/credential"),
        credentials_supported,
    })
}

fn credentials_supported_mdoc(
    schema: CredentialSchema,
) -> Result<Vec<OpenID4VCIIssuerMetadataCredentialSupportedResponseDTO>, ServiceError> {
    let claim_schema_values = schemas_to_values(schema.claim_schemas.ok_or(
        ServiceError::MappingError("claim_schemas is None".to_string()),
    )?)?;

    Ok(vec![
        OpenID4VCIIssuerMetadataCredentialSupportedResponseDTO {
            wallet_storage_type: schema.wallet_storage_type,
            format: map_core_to_oidc_format(&schema.format).map_err(ServiceError::from)?,
            claims: Some(OpenID4VCIIssuerMetadataMdocClaimsResponseDTO {
                values: claim_schema_values,
            }),
            credential_definition: None,
            doctype: Some(schema.schema_id),
            display: Some(vec![
                OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO { name: schema.name },
            ]),
        },
    ])
}

fn nest_schemas(
    schemas: HashMap<String, OpenID4VCIIssuerMetadataMdocClaimsValuesDTO>,
) -> Result<HashMap<String, OpenID4VCIIssuerMetadataMdocClaimsValuesDTO>, ServiceError> {
    // Copy non-nested schemas to new buffer
    let mut result: HashMap<String, OpenID4VCIIssuerMetadataMdocClaimsValuesDTO> = schemas
        .iter()
        .filter_map(|(key, value)| {
            if key.find(NESTED_CLAIM_MARKER).is_some() {
                None
            } else {
                Some((key.to_owned(), value.to_owned()))
            }
        })
        .collect();

    // Assign nested schemas to mentioned buffer
    schemas.iter().try_for_each(|(key, value)| {
        if let Some(index) = key.find(NESTED_CLAIM_MARKER) {
            let prefix = &key[0..index];
            let entry = result.get_mut(prefix).ok_or(ServiceError::MappingError(
                "failed to find parent claim schema".to_string(),
            ))?;
            entry
                .value
                .insert(remove_first_nesting_layer(key), value.to_owned());
        }

        Ok::<(), ServiceError>(())
    })?;

    // Redo for every nesting
    result
        .into_iter()
        .map(|(key, value)| {
            Ok((
                key,
                OpenID4VCIIssuerMetadataMdocClaimsValuesDTO {
                    value: nest_schemas(value.value)?,
                    value_type: value.value_type,
                },
            ))
        })
        .collect::<Result<_, ServiceError>>()
}

fn schemas_to_values(
    schemas: Vec<CredentialSchemaClaim>,
) -> Result<HashMap<String, OpenID4VCIIssuerMetadataMdocClaimsValuesDTO>, ServiceError> {
    let result = schemas
        .into_iter()
        .map(|schema| {
            (
                schema.schema.key.to_owned(),
                OpenID4VCIIssuerMetadataMdocClaimsValuesDTO {
                    value: Default::default(),
                    value_type: schema.schema.data_type,
                },
            )
        })
        .collect();

    nest_schemas(result)
}

fn credentials_supported_others(
    schema: CredentialSchema,
) -> Result<Vec<OpenID4VCIIssuerMetadataCredentialSupportedResponseDTO>, ServiceError> {
    Ok(vec![
        OpenID4VCIIssuerMetadataCredentialSupportedResponseDTO {
            wallet_storage_type: schema.wallet_storage_type,
            format: map_core_to_oidc_format(&schema.format).map_err(ServiceError::from)?,
            claims: None,
            credential_definition: Some(OpenID4VCIIssuerMetadataCredentialDefinitionResponseDTO {
                r#type: vec!["VerifiableCredential".to_string()],
            }),
            doctype: None,
            display: Some(vec![
                OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO { name: schema.name },
            ]),
        },
    ])
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
    )?;
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

pub(super) fn parse_interaction_content(
    data: Option<&Vec<u8>>,
) -> Result<OpenID4VPInteractionContent, ServiceError> {
    if let Some(interaction_data) = data {
        serde_json::from_slice(interaction_data)
            .map_err(|e| ServiceError::MappingError(e.to_string()))
    } else {
        Err(ServiceError::MappingError(
            "Interaction data is missing or incorrect".to_string(),
        ))
    }
}
