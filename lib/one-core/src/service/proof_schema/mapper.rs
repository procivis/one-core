use std::collections::HashMap;

use super::dto::{
    CreateProofSchemaRequestDTO, GetProofSchemaResponseDTO, ProofClaimSchemaResponseDTO,
    ProofInputSchemaResponseDTO, ProofSchemaId,
};
use crate::common_mapper::{remove_first_nesting_layer, NESTED_CLAIM_MARKER};
use crate::config::core_config::{DatatypeConfig, DatatypeType};
use crate::model::claim_schema::ClaimSchema;
use crate::model::common::ExactColumn;
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaClaim, CredentialSchemaId,
};
use crate::model::history::{History, HistoryAction, HistoryEntityType};
use crate::model::proof_schema::{ProofInputClaimSchema, ProofInputSchema};
use crate::service::error::BusinessLogicError;
use crate::service::proof_schema::dto::GetProofSchemaQueryDTO;
use crate::{
    model::{organisation::Organisation, proof_schema::ProofSchema},
    service::error::ServiceError,
};
use dto_mapper::convert_inner;
use shared_types::OrganisationId;
use time::OffsetDateTime;
use uuid::Uuid;

pub(super) fn convert_proof_schema_to_response(
    value: ProofSchema,
    datatype_config: &DatatypeConfig,
) -> Result<GetProofSchemaResponseDTO, ServiceError> {
    Ok(GetProofSchemaResponseDTO {
        id: value.id,
        created_date: value.created_date,
        last_modified: value.last_modified,
        name: value.name,
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

pub(super) fn convert_input_schema_to_response(
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
            .to_owned()
            .claim_schemas
            .ok_or(ServiceError::MappingError(
                "claim_schemas is None".to_string(),
            ))?;

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
    credential_claim_schemas.iter().try_for_each(|value| {
        if is_object(&value.schema.data_type, datatype_config)? {
            claim_schemas.push(ProofClaimSchemaResponseDTO {
                id: value.schema.id,
                required: value.required,
                key: value.schema.key.to_owned(),
                data_type: value.schema.data_type.to_owned(),
                claims: vec![],
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
    let mut result = vec![];

    // Iterate over all and copy all unnested claim schemas to new vec
    for claim_schema in claim_schemas.iter() {
        if claim_schema.key.find(NESTED_CLAIM_MARKER).is_none() {
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

    proof_schema_claims
        .values()
        .try_for_each(|credential_claims| {
            credential_claims.iter().try_for_each(|claim| {
                let Some((prefix, _)) = claim.schema.key.rsplit_once(NESTED_CLAIM_MARKER) else {
                    return Ok(());
                };

                credential_claims
                    .iter()
                    .find(|other_claim| other_claim.schema.key == prefix)
                    .map(|_| ())
                    .ok_or(BusinessLogicError::MissingParentClaimSchema {
                        claim_schema_id: claim.schema.id,
                    })
            })
        })?;

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
        id: Uuid::new_v4(),
        created_date: now,
        last_modified: now,
        name: request.name,
        expire_duration: request.expire_duration,
        organisation: Some(organisation),
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

pub(super) fn proof_schema_deleted_history_event(proof_schema: ProofSchema) -> History {
    History {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        action: HistoryAction::Deleted,
        entity_id: Some(proof_schema.id.into()),
        entity_type: HistoryEntityType::ProofSchema,
        metadata: None,
        organisation: proof_schema.organisation,
    }
}
