use std::collections::HashMap;

use dto_mapper::convert_inner;
use shared_types::{CredentialSchemaId, OrganisationId, ProofSchemaId};
use time::OffsetDateTime;
use uuid::Uuid;

use super::dto::{
    CreateProofSchemaRequestDTO, GetProofSchemaResponseDTO, ImportProofSchemaClaimSchemaDTO,
    ImportProofSchemaInputSchemaDTO, ProofClaimSchemaResponseDTO, ProofInputSchemaResponseDTO,
};
use crate::common_mapper::{remove_first_nesting_layer, NESTED_CLAIM_MARKER};
use crate::config::core_config::{DatatypeConfig, DatatypeType};
use crate::model::claim_schema::ClaimSchema;
use crate::model::common::ExactColumn;
use crate::model::credential_schema::{CredentialSchema, CredentialSchemaClaim};
use crate::model::history::{History, HistoryAction, HistoryEntityType};
use crate::model::organisation::Organisation;
use crate::model::proof_schema::{ProofInputClaimSchema, ProofInputSchema, ProofSchema};
use crate::service::error::{BusinessLogicError, ServiceError};
use crate::service::proof_schema::dto::GetProofSchemaQueryDTO;

pub(super) async fn convert_proof_schema_to_response(
    value: ProofSchema,
    datatype_config: &DatatypeConfig,
) -> Result<GetProofSchemaResponseDTO, ServiceError> {
    let mut proof_input_schemas: Vec<ProofInputSchemaResponseDTO> = vec![];
    for value in value.input_schemas.ok_or(ServiceError::MappingError(
        "proof_input_schemas is None".to_string(),
    ))? {
        proof_input_schemas.push(convert_input_schema_to_response(value, datatype_config).await?);
    }

    Ok(GetProofSchemaResponseDTO {
        id: value.id,
        created_date: value.created_date,
        last_modified: value.last_modified,
        name: value.name,
        organisation_id: *value.organisation.id(),
        expire_duration: value.expire_duration,
        proof_input_schemas,
    })
}

pub(super) fn credential_schema_from_proof_input_schema(
    input_schema: &ImportProofSchemaInputSchemaDTO,
    organisation: Organisation,
    now: OffsetDateTime,
) -> CredentialSchema {
    let claims: Vec<_> = unnest_proof_claim_schemas(&input_schema.claim_schemas, "".into())
        .into_iter()
        .map(|imported_schema| CredentialSchemaClaim {
            schema: ClaimSchema {
                id: imported_schema.id,
                key: imported_schema.key,
                data_type: imported_schema.data_type,
                created_date: now,
                last_modified: now,
                array: imported_schema.array,
            },
            required: imported_schema.required,
        })
        .collect();

    CredentialSchema {
        id: input_schema.credential_schema.id,
        deleted_at: None,
        created_date: now,
        last_modified: now,
        name: input_schema.credential_schema.name.clone(),
        format: input_schema.credential_schema.format.clone(),
        revocation_method: input_schema.credential_schema.revocation_method.clone(),
        wallet_storage_type: input_schema.credential_schema.wallet_storage_type.clone(),
        layout_type: input_schema
            .credential_schema
            .layout_type
            .clone()
            .unwrap_or(crate::model::credential_schema::LayoutType::Card),
        layout_properties: input_schema
            .credential_schema
            .layout_properties
            .clone()
            .map(Into::into),
        schema_id: input_schema.credential_schema.schema_id.clone(),
        schema_type: input_schema.credential_schema.schema_type.clone().into(),
        claim_schemas: claims.into(),
        organisation: organisation.into(),
    }
}

pub(super) async fn proof_input_from_import_request(
    input_schema: &ImportProofSchemaInputSchemaDTO,
    credential_schema: CredentialSchema,
) -> Result<ProofInputSchema, ServiceError> {
    let claim_schemas = credential_schema.claim_schemas.get().await?;

    let proof_claim_schemas = input_schema
        .claim_schemas
        .iter()
        .enumerate()
        .map(|(i, input_claim_schema)| {
            let claim_schema = claim_schemas
                .iter()
                .find(|claim_schema| claim_schema.schema.key == input_claim_schema.key)
                .ok_or_else(|| ServiceError::MappingError("claim_schema missing".to_string()))?;

            Ok(ProofInputClaimSchema {
                schema: claim_schema.schema.to_owned(),
                required: input_claim_schema.required,
                order: i as u32,
            })
        })
        .collect::<Result<_, ServiceError>>()?;

    Ok(ProofInputSchema {
        validity_constraint: input_schema.validity_constraint,
        claim_schemas: Some(proof_claim_schemas),
        credential_schema: Some(credential_schema),
    })
}

fn unnest_proof_claim_schemas(
    claim_schemas: &Vec<ImportProofSchemaClaimSchemaDTO>,
    prefix: String,
) -> Vec<ProofClaimSchemaResponseDTO> {
    let mut result = vec![];

    for claim_schema in claim_schemas {
        let key = format!("{prefix}{}", claim_schema.key);

        let nested =
            unnest_proof_claim_schemas(&claim_schema.claims, format!("{key}{NESTED_CLAIM_MARKER}"));

        result.push(ProofClaimSchemaResponseDTO {
            id: claim_schema.id,
            required: claim_schema.required,
            key,
            data_type: claim_schema.data_type.clone(),
            claims: vec![],
            array: claim_schema.array,
        });

        result.extend(nested);
    }

    result
}

async fn convert_input_schema_to_response(
    value: ProofInputSchema,
    datatype_config: &DatatypeConfig,
) -> Result<ProofInputSchemaResponseDTO, ServiceError> {
    let claim_schemas = value.claim_schemas.ok_or(ServiceError::MappingError(
        "claim_schemas is None".to_string(),
    ))?;
    let credential_schema = value.credential_schema.ok_or(ServiceError::MappingError(
        "credential_schema is None".to_string(),
    ))?;

    let credential_schema_claims = credential_schema.claim_schemas.get().await?;

    Ok(ProofInputSchemaResponseDTO {
        claim_schemas: nest_claim_schemas(
            append_object_claim_schemas(
                convert_inner(claim_schemas),
                &credential_schema_claims,
                datatype_config,
            )?,
            datatype_config,
        )?,
        credential_schema: credential_schema.into(),
        validity_constraint: value.validity_constraint,
    })
}

fn append_object_claim_schemas(
    mut claim_schemas: Vec<ProofClaimSchemaResponseDTO>,
    credential_claim_schemas: &[CredentialSchemaClaim],
    datatype_config: &DatatypeConfig,
) -> Result<Vec<ProofClaimSchemaResponseDTO>, ServiceError> {
    let mut nested_claim_schemas: Vec<_> = claim_schemas
        .iter()
        // todo: can arrays be root objects
        .filter(|cs| is_object(&cs.data_type, datatype_config).unwrap_or(false))
        .flat_map(|os| {
            // Add all nested claims for object
            credential_claim_schemas
                .iter()
                .filter(|claim| {
                    claim
                        .schema
                        .key
                        .starts_with(&format!("{}{NESTED_CLAIM_MARKER}", os.key))
                })
                .map(|child_claim| ProofClaimSchemaResponseDTO {
                    id: child_claim.schema.id,
                    required: child_claim.required,
                    key: child_claim.schema.key.to_owned(),
                    data_type: child_claim.schema.data_type.to_owned(),
                    claims: vec![],
                    array: child_claim.schema.array,
                })
                .collect::<Vec<_>>()
        })
        .collect();

    claim_schemas.append(&mut nested_claim_schemas);

    credential_claim_schemas.iter().try_for_each(|value| {
        if is_object(&value.schema.data_type, datatype_config)? {
            claim_schemas.push(ProofClaimSchemaResponseDTO {
                id: value.schema.id,
                required: value.required,
                key: value.schema.key.to_owned(),
                data_type: value.schema.data_type.to_owned(),
                claims: vec![],
                array: value.schema.array,
            });
        }

        Ok::<(), ServiceError>(())
    })?;

    Ok(claim_schemas)
}

fn nest_claim_schemas(
    claim_schemas: Vec<ProofClaimSchemaResponseDTO>,
    datatype_config: &DatatypeConfig,
) -> Result<Vec<ProofClaimSchemaResponseDTO>, ServiceError> {
    let mut result: Vec<ProofClaimSchemaResponseDTO> = vec![];

    // Iterate over all and copy all unnested claim schemas to new vec
    for claim_schema in claim_schemas.iter() {
        if claim_schema.key.find(NESTED_CLAIM_MARKER).is_none()
        // Ignore duplicates - if a child claim is requested along with it's parent
            && !result.iter().any(|c| c.key == claim_schema.key)
        {
            result.push(claim_schema.to_owned());
        }
    }

    // Find all nested claims and move them to related entries in result vec
    for mut claim_schema in claim_schemas.into_iter() {
        if claim_schema.key.find(NESTED_CLAIM_MARKER).is_some() {
            let matching_entry = result
                .iter_mut()
                .find(|result_schema| {
                    claim_schema
                        .key
                        .starts_with(&format!("{}{NESTED_CLAIM_MARKER}", result_schema.key))
                })
                .ok_or(ServiceError::BusinessLogic(
                    BusinessLogicError::MissingParentClaimSchema {
                        claim_schema_id: claim_schema.id,
                    },
                ))?;
            claim_schema.key = remove_first_nesting_layer(&claim_schema.key);

            matching_entry.claims.push(claim_schema);
        }
    }

    // Repeat for all claims to nest all subclaims
    let mut nested = result
        .into_iter()
        .map(|mut claim_schema| {
            claim_schema.claims = nest_claim_schemas(claim_schema.claims, datatype_config)?;
            Ok(claim_schema)
        })
        .collect::<Result<Vec<ProofClaimSchemaResponseDTO>, ServiceError>>()?;

    // Remove empty object claims
    nested.retain(|element| {
        let is_empty_object_claim = is_object(&element.data_type, datatype_config).unwrap_or(false)
            && element.claims.is_empty();
        !is_empty_object_claim
    });

    Ok(nested)
}

fn is_object(data_type: &str, datatype_config: &DatatypeConfig) -> Result<bool, ServiceError> {
    Ok(datatype_config.get_fields(data_type)?.r#type == DatatypeType::Object)
}

impl From<ProofInputClaimSchema> for ProofClaimSchemaResponseDTO {
    fn from(value: ProofInputClaimSchema) -> Self {
        Self {
            id: value.schema.id,
            required: value.required,
            key: value.schema.key,
            data_type: value.schema.data_type,
            claims: vec![],
            array: value.schema.array,
        }
    }
}

impl From<CredentialSchemaClaim> for ProofClaimSchemaResponseDTO {
    fn from(value: CredentialSchemaClaim) -> Self {
        Self {
            id: value.schema.id,
            required: value.required,
            key: value.schema.key,
            data_type: value.schema.data_type,
            claims: vec![],
            array: value.schema.array,
        }
    }
}

pub fn create_unique_name_check_request(
    name: &str,
    organisation_id: OrganisationId,
) -> Result<GetProofSchemaQueryDTO, ServiceError> {
    Ok(GetProofSchemaQueryDTO {
        page: 0,
        page_size: 1,
        sort: None,
        sort_direction: None,
        exact: Some(vec![ExactColumn::Name]),
        name: Some(name.to_string()),
        organisation_id,
        ids: None,
    })
}

pub fn proof_schema_from_create_request(
    request: CreateProofSchemaRequestDTO,
    now: OffsetDateTime,
    claim_schemas: Vec<ClaimSchema>,
    credential_schemas: Vec<CredentialSchema>,
    organisation: Organisation,
) -> Result<ProofSchema, BusinessLogicError> {
    let mut proof_schema_claims: HashMap<CredentialSchemaId, Vec<ProofInputClaimSchema>> =
        HashMap::new();
    for proof_input_schema in &request.proof_input_schemas {
        let credential_schema_id = proof_input_schema.credential_schema_id;
        for proof_input_claim_schema in &proof_input_schema.claim_schemas {
            for (order, claim_schema) in claim_schemas.iter().enumerate() {
                if claim_schema.id == proof_input_claim_schema.id {
                    let claim = ProofInputClaimSchema {
                        schema: claim_schema.clone(),
                        required: proof_input_claim_schema.required,
                        order: order as u32,
                    };

                    proof_schema_claims
                        .entry(credential_schema_id)
                        .or_default()
                        .push(claim);
                }
            }
        }
    }

    let input_schemas = request
        .proof_input_schemas
        .into_iter()
        .map(|proof_input_schema| {
            let credential_schema_id = proof_input_schema.credential_schema_id;
            let credential_schema = credential_schemas
                .iter()
                .find(|c| c.id == credential_schema_id)
                .cloned()
                .ok_or(BusinessLogicError::MissingCredentialSchema)?;

            let proof_input_schema = ProofInputSchema {
                validity_constraint: proof_input_schema.validity_constraint,
                claim_schemas: proof_schema_claims.get(&credential_schema_id).cloned(),
                credential_schema: Some(credential_schema),
            };

            Ok::<_, BusinessLogicError>(proof_input_schema)
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(ProofSchema {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        name: request.name,
        expire_duration: request.expire_duration,
        organisation: organisation.into(),
        deleted_at: None,
        input_schemas: Some(input_schemas),
    })
}

pub(super) fn proof_schema_created_history_event(
    id: ProofSchemaId,
    organisation: Organisation,
) -> History {
    History {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        action: HistoryAction::Created,
        entity_id: Some(id.into()),
        entity_type: HistoryEntityType::ProofSchema,
        metadata: None,
        organisation: Some(organisation),
    }
}

pub(super) fn proof_schema_history_event(
    proof_schema_id: ProofSchemaId,
    organisation: Option<Organisation>,
    action: HistoryAction,
) -> History {
    History {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        action,
        entity_id: Some(proof_schema_id.into()),
        entity_type: HistoryEntityType::ProofSchema,
        metadata: None,
        organisation,
    }
}
