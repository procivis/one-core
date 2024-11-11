use std::collections::HashMap;

use one_dto_mapper::convert_inner;
use shared_types::{CredentialSchemaId, OrganisationId};
use time::OffsetDateTime;
use uuid::Uuid;

use super::dto::{
    CreateProofSchemaRequestDTO, GetProofSchemaResponseDTO, ImportProofSchemaClaimSchemaDTO,
    ImportProofSchemaInputSchemaDTO, ProofClaimSchemaResponseDTO, ProofInputSchemaResponseDTO,
    ProofSchemaFilterValue,
};
use crate::common_mapper::{remove_first_nesting_layer, NESTED_CLAIM_MARKER};
use crate::config::core_config::{DatatypeConfig, DatatypeType};
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential_schema::{CredentialSchema, CredentialSchemaClaim};
use crate::model::list_filter::{ListFilterValue, StringMatch};
use crate::model::list_query::ListPagination;
use crate::model::organisation::Organisation;
use crate::model::proof_schema::{ProofInputClaimSchema, ProofInputSchema, ProofSchema};
use crate::service::error::{BusinessLogicError, ServiceError};
use crate::service::proof_schema::dto::GetProofSchemaQueryDTO;

pub(super) fn convert_proof_schema_to_response(
    value: ProofSchema,
    datatype_config: &DatatypeConfig,
) -> Result<GetProofSchemaResponseDTO, ServiceError> {
    Ok(GetProofSchemaResponseDTO {
        id: value.id,
        created_date: value.created_date,
        last_modified: value.last_modified,
        name: value.name,
        imported_source_url: value.imported_source_url,
        organisation_id: value
            .organisation
            .ok_or(ServiceError::MappingError(
                "organisation is None".to_string(),
            ))?
            .id,
        expire_duration: value.expire_duration,
        proof_input_schemas: value
            .input_schemas
            .ok_or(ServiceError::MappingError(
                "proof_input_schemas is None".to_string(),
            ))?
            .into_iter()
            .map(|value| convert_input_schema_to_response(value, datatype_config))
            .collect::<Result<Vec<_>, _>>()?,
    })
}

pub(super) fn proof_input_from_import_request(
    input_schema: ImportProofSchemaInputSchemaDTO,
    credential_schema: CredentialSchema,
) -> Result<ProofInputSchema, ServiceError> {
    let credential_schema_claims = credential_schema
        .claim_schemas
        .as_ref()
        .ok_or_else(|| ServiceError::MappingError("claim_schemas is None".to_string()))?;

    let proof_input_claim_schemas =
        extract_proof_input_claim_schemas(input_schema.claim_schemas, credential_schema_claims)?;

    Ok(ProofInputSchema {
        validity_constraint: input_schema.validity_constraint,
        claim_schemas: Some(proof_input_claim_schemas),
        credential_schema: Some(credential_schema),
    })
}

fn extract_proof_input_claim_schemas(
    proof_schema_claims: Vec<ImportProofSchemaClaimSchemaDTO>,
    credential_schema_claims: &[CredentialSchemaClaim],
) -> Result<Vec<ProofInputClaimSchema>, ServiceError> {
    let proof_input_claim_schemas = extract_proof_input_claim_schemas_nested(
        proof_schema_claims,
        credential_schema_claims,
        None,
    )?;

    let result = proof_input_claim_schemas
        .into_iter()
        .enumerate()
        .map(|(i, input)| ProofInputClaimSchema {
            order: i as u32,
            ..input
        })
        .collect();

    Ok(result)
}

fn extract_proof_input_claim_schemas_nested(
    proof_schema_claims: Vec<ImportProofSchemaClaimSchemaDTO>,
    credential_schema_claims: &[CredentialSchemaClaim],
    parent_path_prefix: Option<String>,
) -> Result<Vec<ProofInputClaimSchema>, ServiceError> {
    let mut result: Vec<ProofInputClaimSchema> = vec![];

    for proof_schema_claim in proof_schema_claims {
        let path = if let Some(parent_path) = &parent_path_prefix {
            format!(
                "{parent_path}{NESTED_CLAIM_MARKER}{}",
                proof_schema_claim.key
            )
        } else {
            proof_schema_claim.key
        };

        if proof_schema_claim.requested {
            let claim_schema = credential_schema_claims
                .iter()
                .find(|credential_schema_claim| credential_schema_claim.schema.key == path)
                .ok_or_else(|| {
                    ServiceError::MappingError(format!("claim_schema for path '{path}' missing"))
                })?;

            result.push(ProofInputClaimSchema {
                schema: claim_schema.schema.to_owned(),
                required: proof_schema_claim.required,
                order: 0, // ordering is done once all claim schemas have been collected in `extract_proof_input_claim_schemas`
            });
        } else {
            result.extend(extract_proof_input_claim_schemas_nested(
                proof_schema_claim.claims,
                credential_schema_claims,
                Some(path),
            )?);
        }
    }

    Ok(result)
}

fn convert_input_schema_to_response(
    value: ProofInputSchema,
    datatype_config: &DatatypeConfig,
) -> Result<ProofInputSchemaResponseDTO, ServiceError> {
    let claim_schemas = value.claim_schemas.ok_or(ServiceError::MappingError(
        "claim_schemas is None".to_string(),
    ))?;
    let credential_schema = value.credential_schema.ok_or(ServiceError::MappingError(
        "credential_schema is None".to_string(),
    ))?;

    let credential_schema_claims =
        credential_schema
            .claim_schemas
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "claim_schemas is None".to_string(),
            ))?;

    Ok(ProofInputSchemaResponseDTO {
        claim_schemas: nest_claim_schemas(
            append_object_claim_schemas(
                convert_inner(claim_schemas),
                credential_schema_claims,
                datatype_config,
            )?,
            datatype_config,
        )?,
        credential_schema: credential_schema.into(),
        validity_constraint: value.validity_constraint,
    })
}

fn append_object_claim_schemas(
    mut proof_claim_schemas: Vec<ProofClaimSchemaResponseDTO>,
    credential_claim_schemas: &[CredentialSchemaClaim],
    datatype_config: &DatatypeConfig,
) -> Result<Vec<ProofClaimSchemaResponseDTO>, ServiceError> {
    let mut nested_claim_schemas: Vec<_> = proof_claim_schemas
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
                    requested: false,
                    required: os.required,
                    key: child_claim.schema.key.to_owned(),
                    data_type: child_claim.schema.data_type.to_owned(),
                    claims: vec![],
                    array: child_claim.schema.array,
                })
                .collect::<Vec<_>>()
        })
        .collect();

    proof_claim_schemas.append(&mut nested_claim_schemas);

    credential_claim_schemas.iter().try_for_each(|value| {
        if is_object(&value.schema.data_type, datatype_config)?
            && !proof_claim_schemas.iter().any(|c| c.id == value.schema.id)
        {
            proof_claim_schemas.push(ProofClaimSchemaResponseDTO {
                id: value.schema.id,
                requested: false,
                required: false,
                key: value.schema.key.to_owned(),
                data_type: value.schema.data_type.to_owned(),
                claims: vec![],
                array: value.schema.array,
            });
        }

        Ok::<(), ServiceError>(())
    })?;

    Ok(proof_claim_schemas)
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
            requested: true,
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
            // TODO: unknown requested and required values
            requested: true,
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
        pagination: Some(ListPagination {
            page: 0,
            page_size: 1,
        }),
        filtering: Some(
            ProofSchemaFilterValue::OrganisationId(organisation_id).condition()
                & ProofSchemaFilterValue::Name(StringMatch::equals(name.to_string())),
        ),
        ..Default::default()
    })
}

pub fn proof_schema_from_create_request(
    request: CreateProofSchemaRequestDTO,
    now: OffsetDateTime,
    claim_schemas: Vec<ClaimSchema>,
    credential_schemas: Vec<CredentialSchema>,
    organisation: Organisation,
    base_url: Option<&str>,
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
    let id = Uuid::new_v4().into();
    Ok(ProofSchema {
        id,
        created_date: now,
        last_modified: now,
        imported_source_url: base_url.map(|url| format!("{url}/ssi/proof-schema/v1/{id}")),
        name: request.name,
        expire_duration: request.expire_duration.unwrap_or(0),
        organisation: Some(organisation),
        deleted_at: None,
        input_schemas: Some(input_schemas),
    })
}
