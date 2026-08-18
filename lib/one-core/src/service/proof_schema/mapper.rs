use std::collections::HashMap;

use one_dto_mapper::convert_inner;
use shared_types::CredentialSchemaId;
use time::OffsetDateTime;
use uuid::Uuid;

use super::dto::{
    CreateProofSchemaRequestDTO, GetProofSchemaResponseDTO, ProofClaimSchemaResponseDTO,
    ProofInputSchemaResponseDTO, ProofSchemaFilterParamsDTO, ProofSchemaFilterValue,
};
use super::error::ProofSchemaServiceError;
use crate::config::core_config::{DatatypeConfig, DatatypeType};
use crate::error::{ContextWithErrorCode, NestedError};
use crate::mapper::{NESTED_CLAIM_MARKER, remove_first_nesting_layer};
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential_schema::CredentialSchema;
use crate::model::list_filter::{
    ComparisonType, ListFilterCondition, ListFilterValue, StringMatch, StringMatchType,
    ValueComparison,
};
use crate::model::organisation::Organisation;
use crate::model::proof_schema::{
    ExactProofSchemaFilterColumn, ProofInputClaimSchema, ProofInputSchema, ProofSchema,
};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::service::credential_schema::mapper::to_credential_schema_list_response;

pub(super) async fn convert_proof_schema_to_response(
    value: ProofSchema,
    datatype_config: &DatatypeConfig,
    formatter_provider: &dyn CredentialFormatterProvider,
) -> Result<GetProofSchemaResponseDTO, ProofSchemaServiceError> {
    let mut proof_input_schemas = vec![];

    let input_schemas = value.input_schemas.as_ref().await?;
    for input_schema in &input_schemas {
        proof_input_schemas.push(
            convert_input_schema_to_response(input_schema, datatype_config, formatter_provider)
                .await?,
        );
    }

    Ok(GetProofSchemaResponseDTO {
        id: value.id,
        created_date: value.created_date,
        last_modified: value.last_modified,
        name: value.name,
        imported_source_url: value.imported_source_url,
        organisation_id: value.organisation.id(),
        expire_duration: value.expire_duration,
        proof_input_schemas,
        ecosystem: value.ecosystem,
    })
}

async fn convert_input_schema_to_response(
    value: &ProofInputSchema,
    datatype_config: &DatatypeConfig,
    formatter_provider: &dyn CredentialFormatterProvider,
) -> Result<ProofInputSchemaResponseDTO, ProofSchemaServiceError> {
    let credential_schema = value.credential_schema.as_ref().await?.to_owned();

    let claim_schemas = {
        let claim_schemas = value.claim_schemas.as_ref().await?.to_owned();

        let credential_schema_claims = credential_schema.claim_schemas.as_ref().await?;
        nest_claim_schemas(
            append_object_claim_schemas(
                convert_inner(claim_schemas),
                &credential_schema_claims,
                datatype_config,
            )?,
            datatype_config,
        )?
    };

    Ok(ProofInputSchemaResponseDTO {
        claim_schemas,
        credential_schema: to_credential_schema_list_response(
            credential_schema,
            false,
            formatter_provider,
        )
        .await
        .map_err(|e: NestedError| ProofSchemaServiceError::MappingError(e.to_string()))?,
    })
}

fn append_object_claim_schemas(
    mut proof_claim_schemas: Vec<ProofClaimSchemaResponseDTO>,
    credential_claim_schemas: &[ClaimSchema],
    datatype_config: &DatatypeConfig,
) -> Result<Vec<ProofClaimSchemaResponseDTO>, ProofSchemaServiceError> {
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
                        .key
                        .starts_with(&format!("{}{NESTED_CLAIM_MARKER}", os.key))
                })
                .map(|child_claim| ProofClaimSchemaResponseDTO {
                    id: child_claim.id,
                    requested: false,
                    required: os.required && child_claim.required,
                    key: child_claim.key.to_owned(),
                    data_type: child_claim.data_type.to_owned(),
                    claims: vec![],
                    array: child_claim.array,
                })
                .collect::<Vec<_>>()
        })
        .collect();

    proof_claim_schemas.append(&mut nested_claim_schemas);

    // Blanket add all object claims so that the parent object claims of nested requested claims
    // are definitely included when going into `nest_claim_schemas`.
    credential_claim_schemas.iter().try_for_each(|value| {
        if is_object(&value.data_type, datatype_config)?
            && !proof_claim_schemas.iter().any(|c| c.id == value.id)
        {
            proof_claim_schemas.push(ProofClaimSchemaResponseDTO {
                id: value.id,
                requested: false,
                required: false,
                key: value.key.to_owned(),
                data_type: value.data_type.to_owned(),
                claims: vec![],
                array: value.array,
            });
        }

        Ok::<(), ProofSchemaServiceError>(())
    })?;

    Ok(proof_claim_schemas)
}

fn nest_claim_schemas(
    claim_schemas: Vec<ProofClaimSchemaResponseDTO>,
    datatype_config: &DatatypeConfig,
) -> Result<Vec<ProofClaimSchemaResponseDTO>, ProofSchemaServiceError> {
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
                .ok_or(ProofSchemaServiceError::MissingParentClaimSchema(
                    claim_schema.id,
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
        .collect::<Result<Vec<ProofClaimSchemaResponseDTO>, ProofSchemaServiceError>>()?;

    // Remove empty object claims
    nested.retain(|element| {
        let is_empty_object_claim = is_object(&element.data_type, datatype_config).unwrap_or(false)
            && element.claims.is_empty();
        !is_empty_object_claim
    });

    Ok(nested)
}

fn is_object(
    data_type: &str,
    datatype_config: &DatatypeConfig,
) -> Result<bool, ProofSchemaServiceError> {
    Ok(datatype_config
        .get_fields(data_type)
        .error_while("getting datatype config")?
        .r#type
        == DatatypeType::Object)
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

pub fn proof_schema_from_create_request(
    request: CreateProofSchemaRequestDTO,
    now: OffsetDateTime,
    claim_schemas: Vec<ClaimSchema>,
    credential_schemas: Vec<CredentialSchema>,
    organisation: Organisation,
    base_url: Option<&str>,
) -> Result<ProofSchema, ProofSchemaServiceError> {
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
                .ok_or(ProofSchemaServiceError::MissingCredentialSchema)?;

            let proof_input_schema = ProofInputSchema {
                claim_schemas: proof_schema_claims
                    .get(&credential_schema_id)
                    .cloned()
                    .unwrap_or_default()
                    .into(),
                credential_schema: credential_schema.into(),
            };

            Ok::<_, ProofSchemaServiceError>(proof_input_schema)
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
        organisation: organisation.into(),
        deleted_at: None,
        input_schemas: input_schemas.into(),
        ecosystem: request.ecosystem,
    })
}

impl From<ProofSchemaFilterParamsDTO> for ListFilterCondition<ProofSchemaFilterValue> {
    fn from(value: ProofSchemaFilterParamsDTO) -> Self {
        let exact = value.exact.unwrap_or_default();
        let get_string_match_type = |column| {
            if exact.contains(&column) {
                StringMatchType::Equals
            } else {
                StringMatchType::StartsWith
            }
        };

        let organisation_id =
            ProofSchemaFilterValue::OrganisationId(value.organisation_id).condition();

        let name = value.name.map(|name| {
            ProofSchemaFilterValue::Name(StringMatch {
                r#match: get_string_match_type(ExactProofSchemaFilterColumn::Name),
                value: name,
            })
        });

        let proof_schema_ids = value.ids.map(ProofSchemaFilterValue::ProofSchemaIds);

        let formats = value.formats.map(ProofSchemaFilterValue::Formats);

        let ecosystems = value.ecosystems.map(ProofSchemaFilterValue::Ecosystems);

        let created_date_after = value.created_date_after.map(|date| {
            ProofSchemaFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });

        let created_date_before = value.created_date_before.map(|date| {
            ProofSchemaFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        let last_modified_after = value.last_modified_after.map(|date| {
            ProofSchemaFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });

        let last_modified_before = value.last_modified_before.map(|date| {
            ProofSchemaFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        organisation_id
            & name
            & proof_schema_ids
            & formats
            & ecosystems
            & created_date_after
            & created_date_before
            & last_modified_after
            & last_modified_before
    }
}
