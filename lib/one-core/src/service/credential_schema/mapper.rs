use crate::{
    model::{
        claim_schema::ClaimSchema,
        credential_schema::{CredentialSchema, CredentialSchemaClaim, GetCredentialSchemaList},
        organisation::Organisation,
    },
    service::{
        credential_schema::dto::{
            CreateCredentialSchemaRequestDTO, CredentialClaimSchemaDTO,
            CredentialClaimSchemaRequestDTO, GetCredentialSchemaListResponseDTO,
            GetCredentialSchemaListValueResponseDTO, GetCredentialSchemaResponseDTO,
        },
        error::ServiceError,
    },
};
use time::OffsetDateTime;
use uuid::Uuid;

impl TryFrom<CredentialSchema> for GetCredentialSchemaListValueResponseDTO {
    type Error = ServiceError;

    fn try_from(value: CredentialSchema) -> Result<Self, Self::Error> {
        Ok(GetCredentialSchemaListValueResponseDTO {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            format: value.format,
            revocation_method: value.revocation_method,
        })
    }
}

impl TryFrom<CredentialSchema> for GetCredentialSchemaResponseDTO {
    type Error = ServiceError;

    fn try_from(value: CredentialSchema) -> Result<Self, Self::Error> {
        let claim_schemas: Vec<CredentialClaimSchemaDTO> = match value.claim_schemas {
            None => vec![],
            Some(claim_schemas) => claim_schemas.into_iter().map(|c| c.into()).collect(),
        };

        let organisation_id = match value.organisation {
            None => Err(ServiceError::MappingError(
                "Organisation has not been fetched".to_string(),
            )),
            Some(value) => Ok(value.id),
        }?;

        Ok(GetCredentialSchemaResponseDTO {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            format: value.format,
            revocation_method: value.revocation_method,
            organisation_id,
            claims: claim_schemas,
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

impl TryFrom<GetCredentialSchemaList> for GetCredentialSchemaListResponseDTO {
    type Error = ServiceError;

    fn try_from(value: GetCredentialSchemaList) -> Result<Self, Self::Error> {
        let values: Result<Vec<_>, _> = value
            .values
            .into_iter()
            .map(|item| item.try_into())
            .collect();

        Ok(Self {
            values: values?,
            total_pages: value.total_pages,
            total_items: value.total_items,
        })
    }
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

fn from_jwt_request_claim_schema(
    claim_schema: CredentialClaimSchemaRequestDTO,
    now: OffsetDateTime,
) -> CredentialSchemaClaim {
    CredentialSchemaClaim {
        schema: ClaimSchema {
            id: Uuid::new_v4(),
            key: claim_schema.key,
            data_type: claim_schema.datatype,
            created_date: now,
            last_modified: now,
        },
        required: claim_schema.required,
    }
}
