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
        error::ServiceError,
    },
};
use dto_mapper::convert_inner;
use shared_types::OrganisationId;
use time::OffsetDateTime;
use uuid::Uuid;

impl TryFrom<CredentialSchema> for CredentialSchemaDetailResponseDTO {
    type Error = ServiceError;

    fn try_from(value: CredentialSchema) -> Result<Self, Self::Error> {
        let claim_schemas = convert_inner(value.claim_schemas.unwrap_or_default());

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
            request
                .claims
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
