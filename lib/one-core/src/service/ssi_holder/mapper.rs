use crate::{
    model::{
        claim_schema::ClaimSchema,
        credential_schema::{CredentialSchema, CredentialSchemaClaim},
    },
    provider::{
        credential_formatter::model::VCCredentialClaimSchemaResponse,
        transport_protocol::dto::ProofCredentialSchema,
    },
    service::{
        credential::dto::DetailCredentialSchemaResponseDTO,
        credential_schema::dto::{CredentialClaimSchemaDTO, CredentialSchemaListItemResponseDTO},
        error::ServiceError,
    },
};
use std::str::FromStr;
use time::OffsetDateTime;
use uuid::Uuid;

impl TryFrom<VCCredentialClaimSchemaResponse> for CredentialSchemaClaim {
    type Error = ServiceError;
    fn try_from(value: VCCredentialClaimSchemaResponse) -> Result<Self, Self::Error> {
        let now = OffsetDateTime::now_utc();
        Ok(Self {
            schema: ClaimSchema {
                id: string_to_uuid(&value.id)?,
                key: value.key,
                data_type: value.datatype,
                created_date: now,
                last_modified: now,
            },
            required: value.required,
        })
    }
}

pub fn string_to_uuid(value: &str) -> Result<Uuid, ServiceError> {
    Uuid::from_str(value).map_err(|e| ServiceError::MappingError(e.to_string()))
}

impl TryFrom<ProofCredentialSchema> for CredentialSchemaListItemResponseDTO {
    type Error = ServiceError;

    fn try_from(value: ProofCredentialSchema) -> Result<Self, Self::Error> {
        Ok(Self {
            id: string_to_uuid(&value.id)?,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            format: value.format,
            revocation_method: value.revocation_method,
        })
    }
}

impl From<DetailCredentialSchemaResponseDTO> for CredentialSchema {
    fn from(value: DetailCredentialSchemaResponseDTO) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            format: value.format,
            revocation_method: value.revocation_method,
            deleted_at: None,
            claim_schemas: None,
            organisation: None, // response organisation is intentionally ignored (holder sets its local organisation)
        }
    }
}

impl From<CredentialClaimSchemaDTO> for CredentialSchemaClaim {
    fn from(value: CredentialClaimSchemaDTO) -> Self {
        Self {
            schema: ClaimSchema {
                id: value.id,
                key: value.key,
                data_type: value.datatype,
                created_date: value.created_date,
                last_modified: value.last_modified,
            },
            required: value.required,
        }
    }
}
