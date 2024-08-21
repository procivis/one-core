use std::collections::HashMap;

use dto_mapper::{convert_inner, convert_inner_of_inner};
use one_providers::exchange_protocol::openid4vc::model::{
    OpenID4VCIInteractionDataDTO, OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO,
    OpenID4VCIIssuerMetadataCredentialSupportedResponseDTO,
    OpenID4VCIIssuerMetadataMdocClaimsValuesDTO, OpenID4VCIIssuerMetadataResponseDTO,
    OpenID4VPInteractionContent, ProvedCredential,
};

use crate::common_mapper::{get_or_create_did, remove_first_nesting_layer, NESTED_CLAIM_MARKER};
use crate::model::credential::Credential;
use crate::model::credential_schema::{CredentialSchema, CredentialSchemaClaim};
use crate::model::interaction::Interaction;
use crate::model::organisation::Organisation;
use crate::repository::did_repository::DidRepository;
use crate::service::error::ServiceError;
use crate::util::oidc::map_core_to_oidc_format;

pub(super) async fn credentials_supported_mdoc(
    base_url: &str,
    schema: CredentialSchema,
) -> Result<OpenID4VCIIssuerMetadataResponseDTO, ServiceError> {
    let claim_schemas = schema.claim_schemas.get().await?;

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

    let credentials_supported = vec![OpenID4VCIIssuerMetadataCredentialSupportedResponseDTO {
        wallet_storage_type: schema.wallet_storage_type.map(Into::into),
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
    }];

    Ok(OpenID4VCIIssuerMetadataResponseDTO {
        credential_issuer: base_url.to_owned(),
        credential_endpoint: format!("{base_url}/credential"),
        credentials_supported,
    })
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

pub(super) async fn credential_from_proved(
    proved_credential: ProvedCredential,
    organisation: &Organisation,
    did_repository: &dyn DidRepository,
) -> Result<Credential, ServiceError> {
    let issuer_did = get_or_create_did(
        did_repository,
        &Some(organisation.to_owned()),
        &proved_credential.issuer_did_value.into(),
    )
    .await?;
    let holder_did = get_or_create_did(
        did_repository,
        &Some(organisation.to_owned()),
        &proved_credential.holder_did_value.into(),
    )
    .await?;

    Ok(Credential {
        id: proved_credential.credential.id.into(),
        created_date: proved_credential.credential.created_date,
        issuance_date: proved_credential.credential.issuance_date,
        last_modified: proved_credential.credential.last_modified,
        deleted_at: proved_credential.credential.deleted_at,
        credential: proved_credential.credential.credential,
        exchange: proved_credential.credential.exchange,
        redirect_uri: proved_credential.credential.redirect_uri,
        role: proved_credential.credential.role.into(),
        state: convert_inner_of_inner(proved_credential.credential.state),
        claims: convert_inner_of_inner(proved_credential.credential.claims),
        issuer_did: Some(issuer_did),
        holder_did: Some(holder_did),
        schema: proved_credential
            .credential
            .schema
            .map(|schema| from_provider_schema(schema, organisation.to_owned())),
        interaction: None,
        revocation_list: None,
        key: proved_credential.credential.key,
    })
}

fn from_provider_schema(
    schema: one_providers::common_models::credential_schema::OpenCredentialSchema,
    organisation: Organisation,
) -> CredentialSchema {
    let claim_schemas: Vec<CredentialSchemaClaim> =
        convert_inner(schema.claim_schemas.unwrap_or_default());
    CredentialSchema {
        id: schema.id.into(),
        deleted_at: schema.deleted_at,
        created_date: schema.created_date,
        last_modified: schema.last_modified,
        name: schema.name,
        format: schema.format,
        revocation_method: schema.revocation_method,
        wallet_storage_type: convert_inner(schema.wallet_storage_type),
        layout_type: schema.layout_type.into(),
        layout_properties: convert_inner(schema.layout_properties),
        schema_id: schema.schema_id,
        schema_type: schema.schema_type.into(),
        claim_schemas: claim_schemas.into(),
        organisation: organisation.into(),
    }
}
