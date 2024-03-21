use crate::common_mapper::NESTED_CLAIM_MARKER;
use crate::{
    model::{
        claim_schema::ClaimSchema,
        common::ExactColumn,
        credential_schema::{CredentialSchema, CredentialSchemaClaim},
        history::{History, HistoryAction, HistoryEntityType},
        organisation::Organisation,
    },
    service::{
        credential_schema::dto::{
            CreateCredentialSchemaRequestDTO, CredentialClaimSchemaDTO,
            CredentialClaimSchemaRequestDTO, CredentialSchemaDetailResponseDTO,
            GetCredentialSchemaQueryDTO,
        },
        error::{BusinessLogicError, ServiceError},
    },
};
use dto_mapper::convert_inner;
use shared_types::OrganisationId;
use time::OffsetDateTime;
use uuid::Uuid;

impl TryFrom<CredentialSchema> for CredentialSchemaDetailResponseDTO {
    type Error = ServiceError;

    fn try_from(value: CredentialSchema) -> Result<Self, Self::Error> {
        let claim_schemas =
            renest_claim_schemas(convert_inner(value.claim_schemas.unwrap_or_default()))?;

        let organisation_id = match value.organisation {
            None => Err(ServiceError::MappingError(
                "Organisation has not been fetched".to_string(),
            )),
            Some(value) => Ok(value.id),
        }?;

        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            format: value.format,
            revocation_method: value.revocation_method,
            organisation_id,
            claims: claim_schemas,
            wallet_storage_type: value.wallet_storage_type,
        })
    }
}

impl From<CredentialSchemaClaim> for CredentialClaimSchemaDTO {
    fn from(value: CredentialSchemaClaim) -> Self {
        Self {
            id: value.schema.id,
            created_date: value.schema.created_date,
            last_modified: value.schema.last_modified,
            key: value.schema.key,
            datatype: value.schema.data_type,
            required: value.required,
            claims: vec![],
        }
    }
}

pub(super) fn create_unique_name_check_request(
    name: &str,
    organisation_id: OrganisationId,
) -> Result<GetCredentialSchemaQueryDTO, ServiceError> {
    Ok(GetCredentialSchemaQueryDTO {
        page: 0,
        page_size: 1,
        sort: None,
        sort_direction: None,
        name: Some(name.to_string()),
        exact: Some(vec![ExactColumn::Name]),
        organisation_id,
        ids: None,
    })
}

pub(super) fn from_create_request(
    request: CreateCredentialSchemaRequestDTO,
    organisation: Organisation,
) -> Result<CredentialSchema, ServiceError> {
    if request.claims.is_empty() {
        return Err(ServiceError::ValidationError(
            "Claim schemas cannot be empty".to_string(),
        ));
    }

    let now = OffsetDateTime::now_utc();

    let claim_schemas = unnest_claim_schemas(request.claims);

    Ok(CredentialSchema {
        id: Uuid::new_v4(),
        deleted_at: None,
        created_date: now,
        last_modified: now,
        name: request.name,
        format: request.format,
        wallet_storage_type: request.wallet_storage_type,
        revocation_method: request.revocation_method,
        claim_schemas: Some(
            claim_schemas
                .into_iter()
                .map(|claim_schema| from_jwt_request_claim_schema(claim_schema, now))
                .collect(),
        ),
        organisation: Some(organisation),
    })
}

pub(super) fn schema_create_history_event(schema: CredentialSchema) -> History {
    history_event(schema, HistoryAction::Created)
}

pub(super) fn schema_delete_history_event(schema: CredentialSchema) -> History {
    history_event(schema, HistoryAction::Deleted)
}

fn history_event(schema: CredentialSchema, action: HistoryAction) -> History {
    History {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        action,
        entity_id: Some(schema.id.into()),
        entity_type: HistoryEntityType::CredentialSchema,
        metadata: None,
        organisation: schema.organisation,
    }
}

fn from_jwt_request_claim_schema(
    claim_schema: CredentialClaimSchemaRequestDTO,
    now: OffsetDateTime,
) -> CredentialSchemaClaim {
    CredentialSchemaClaim {
        schema: ClaimSchema {
            id: Uuid::new_v4().into(),
            key: claim_schema.key,
            data_type: claim_schema.datatype,
            created_date: now,
            last_modified: now,
        },
        required: claim_schema.required,
    }
}

fn remove_first_nesting_layer(name: &str) -> String {
    match name.find(NESTED_CLAIM_MARKER) {
        Some(marker_pos) => name[marker_pos + 1..].to_string(),
        None => name.to_string(),
    }
}

pub(super) fn renest_claim_schemas(
    claim_schemas: Vec<CredentialClaimSchemaDTO>,
) -> Result<Vec<CredentialClaimSchemaDTO>, ServiceError> {
    let mut result = vec![];

    // Iterate over all and copy all unnested claims to new vec
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
    result
        .into_iter()
        .map(|mut claim_schema| {
            claim_schema.claims = renest_claim_schemas(claim_schema.claims)?;
            Ok(claim_schema)
        })
        .collect::<Result<Vec<CredentialClaimSchemaDTO>, _>>()
}

pub(super) fn unnest_claim_schemas(
    claim_schemas: Vec<CredentialClaimSchemaRequestDTO>,
) -> Vec<CredentialClaimSchemaRequestDTO> {
    unnest_claim_schemas_inner(claim_schemas, "".to_string())
}

fn unnest_claim_schemas_inner(
    mut claim_schemas: Vec<CredentialClaimSchemaRequestDTO>,
    prefix: String,
) -> Vec<CredentialClaimSchemaRequestDTO> {
    let nested_claims = claim_schemas
        .iter()
        .map(|claim_schema| {
            unnest_claim_schemas_inner(
                claim_schema.claims.to_owned(),
                format!("{prefix}{}/", claim_schema.key),
            )
        })
        .collect::<Vec<Vec<CredentialClaimSchemaRequestDTO>>>()
        .into_iter()
        .flatten()
        .collect::<Vec<CredentialClaimSchemaRequestDTO>>();

    for claim_schema in claim_schemas.iter_mut() {
        claim_schema.key = format!("{prefix}{}", claim_schema.key);
        claim_schema.claims = vec![];
    }

    claim_schemas.extend(nested_claims);

    claim_schemas
}
