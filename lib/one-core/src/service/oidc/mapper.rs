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
    OpenID4VCIIssuerMetadataCredentialSchemaResponseDTO,
    OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO,
    OpenID4VCIIssuerMetadataMdocClaimsValuesDTO,
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
    let claim_schemas = schema.claim_schemas.ok_or(ServiceError::MappingError(
        "claim_schemas is None".to_string(),
    ))?;

    // order of namespaces and elements inside MDOC schema as defined in OpenID4VCI mdoc spec: `{namespace}~{element}`
    let element_order: Vec<String> = claim_schemas
        .iter()
        .filter(|claim| {
            claim
                .schema
                .key
                .chars()
                .filter(|c| *c == NESTED_CLAIM_MARKER)
                .count()
                == 1
        })
        .map(|element| element.schema.key.replace(NESTED_CLAIM_MARKER, "~"))
        .collect();

    let claim_schema_values = schemas_to_mdoc_values(claim_schemas)?;
    let claims = claim_schema_values
        .into_iter()
        .map(|(namespace, elements)| (namespace, elements.value))
        .collect();

    Ok(vec![
        OpenID4VCIIssuerMetadataCredentialSupportedResponseDTO {
            wallet_storage_type: schema.wallet_storage_type,
            format: map_core_to_oidc_format(&schema.format).map_err(ServiceError::from)?,
            claims: Some(claims),
            order: if element_order.len() > 1 {
                Some(element_order)
            } else {
                None
            },
            credential_definition: None,
            doctype: Some(schema.schema_id),
            display: Some(vec![
                OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO { name: schema.name },
            ]),
        },
    ])
}

fn schemas_to_mdoc_values(
    schemas: Vec<CredentialSchemaClaim>,
) -> Result<HashMap<String, OpenID4VCIIssuerMetadataMdocClaimsValuesDTO>, ServiceError> {
    let mdoc_claims = nest_mdoc_claims(
        schemas
            .into_iter()
            .map(|claim| MdocClaimSchema {
                key: claim.schema.key.to_owned(),
                schema: claim,
                claims: vec![],
            })
            .collect(),
    )?;

    Ok(order_mdoc_claims(mdoc_claims))
}

#[derive(Clone, Debug)]
struct MdocClaimSchema {
    pub schema: CredentialSchemaClaim,
    pub key: String,
    pub claims: Vec<MdocClaimSchema>,
}

fn nest_mdoc_claims(schemas: Vec<MdocClaimSchema>) -> Result<Vec<MdocClaimSchema>, ServiceError> {
    // split nested and non-nested
    let (mut root, nested): (Vec<_>, Vec<_>) = schemas
        .into_iter()
        .partition(|claim| claim.key.find(NESTED_CLAIM_MARKER).is_none());

    // Assign nested schemas to mentioned root
    nested.into_iter().try_for_each(|claim| {
        let key = &claim.key;
        let delimiter_index = key.find(NESTED_CLAIM_MARKER).ok_or_else(|| {
            ServiceError::MappingError(format!("Invalid nested claim schema key `{key}`"))
        })?;
        let parent = &key[0..delimiter_index];
        let parent_entry = root
            .iter_mut()
            .find(|claim| claim.key == parent)
            .ok_or_else(|| {
                ServiceError::MappingError(format!("failed to find parent claim schema `{parent}`"))
            })?;
        parent_entry.claims.push(MdocClaimSchema {
            key: remove_first_nesting_layer(key),
            ..claim
        });

        Ok::<(), ServiceError>(())
    })?;

    // Redo for all sub-levels
    root.into_iter()
        .map(|claim| {
            Ok(MdocClaimSchema {
                claims: nest_mdoc_claims(claim.claims)?,
                ..claim
            })
        })
        .collect::<Result<_, ServiceError>>()
}

fn order_mdoc_claims(
    schemas: Vec<MdocClaimSchema>,
) -> HashMap<String, OpenID4VCIIssuerMetadataMdocClaimsValuesDTO> {
    schemas
        .into_iter()
        .map(|claim| {
            let order = if claim.claims.len() > 1 {
                Some(
                    claim
                        .claims
                        .iter()
                        .map(|claim| claim.key.to_owned())
                        .collect(),
                )
            } else {
                None
            };

            (
                claim.key,
                OpenID4VCIIssuerMetadataMdocClaimsValuesDTO {
                    value: order_mdoc_claims(claim.claims),
                    value_type: claim.schema.schema.data_type,
                    mandatory: Some(claim.schema.required),
                    order,
                },
            )
        })
        .collect()
}

fn credentials_supported_others(
    schema: CredentialSchema,
) -> Result<Vec<OpenID4VCIIssuerMetadataCredentialSupportedResponseDTO>, ServiceError> {
    Ok(vec![
        OpenID4VCIIssuerMetadataCredentialSupportedResponseDTO {
            wallet_storage_type: schema.wallet_storage_type,
            format: map_core_to_oidc_format(&schema.format).map_err(ServiceError::from)?,
            claims: None,
            order: None,
            credential_definition: Some(OpenID4VCIIssuerMetadataCredentialDefinitionResponseDTO {
                r#type: vec!["VerifiableCredential".to_string()],
                credential_schema: Some(OpenID4VCIIssuerMetadataCredentialSchemaResponseDTO {
                    id: schema.schema_id,
                    r#type: schema.schema_type.into(),
                }),
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
            "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
            "refresh_token".to_string(),
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
            refresh_token: value.refresh_token,
            refresh_token_expires_in: value
                .refresh_token_expires_at
                .map(|dt| DurationSeconds(dt.unix_timestamp())),
        })
    }
}

pub(super) fn parse_refresh_token(token: &str) -> Result<InteractionId, ServiceError> {
    parse_access_token(token)
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
