use crate::model::claim_schema::ClaimSchema;
use crate::model::credential_schema::{CredentialSchema, GetCredentialSchemaList};
use crate::model::organisation::Organisation;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::service::credential_schema::dto::{
    CreateCredentialSchemaRequestWithIds, CreateCredentialSchemaRequestWithoutIds,
    CredentialClaimSchemaDTO, CredentialClaimSchemaWithIds, CredentialClaimSchemaWithoutIds,
    GetCredentialSchemaListResponseDTO, GetCredentialSchemaListValueResponseDTO,
};
use crate::service::error::ServiceError;

use super::dto::GetCredentialSchemaResponseDTO;

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

impl From<ClaimSchema> for CredentialClaimSchemaDTO {
    fn from(value: ClaimSchema) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            key: value.key,
            datatype: value.data_type,
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
    request: CreateCredentialSchemaRequestWithIds,
    organisation: Organisation,
) -> Result<CredentialSchema, ServiceError> {
    if request.claims.is_empty() {
        return Err(ServiceError::ValidationError(
            "Claim schemas cannot be empty".to_string(),
        ));
    }

    let now = OffsetDateTime::now_utc();

    Ok(CredentialSchema {
        id: request.id,
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
    claim_schema: CredentialClaimSchemaWithIds,
    now: OffsetDateTime,
) -> ClaimSchema {
    ClaimSchema {
        id: claim_schema.id,
        key: claim_schema.key,
        data_type: claim_schema.datatype,
        created_date: now,
        last_modified: now,
    }
}

impl From<CreateCredentialSchemaRequestWithoutIds> for CreateCredentialSchemaRequestWithIds {
    fn from(
        value: CreateCredentialSchemaRequestWithoutIds,
    ) -> CreateCredentialSchemaRequestWithIds {
        CreateCredentialSchemaRequestWithIds {
            id: Uuid::new_v4(),
            name: value.name,
            format: value.format,
            revocation_method: value.revocation_method,
            organisation_id: value.organisation_id,
            claims: value
                .claims
                .into_iter()
                .map(|claim_schema| claim_schema.into())
                .collect(),
        }
    }
}

impl From<CredentialClaimSchemaWithoutIds> for CredentialClaimSchemaWithIds {
    fn from(value: CredentialClaimSchemaWithoutIds) -> CredentialClaimSchemaWithIds {
        CredentialClaimSchemaWithIds {
            id: Uuid::new_v4(),
            key: value.key,
            datatype: value.datatype,
        }
    }
}
