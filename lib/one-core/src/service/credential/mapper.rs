use crate::model;
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{
    Credential, CredentialState, CredentialStateEnum, GetCredentialList,
};
use crate::model::credential_schema::CredentialSchema;
use crate::model::did::Did;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::service::credential::dto::{
    CreateCredentialFromJwtRequestDTO, CreateCredentialRequestDTO, CredentialListItemResponseDTO,
    CredentialRequestClaimDTO, CredentialSchemaResponseDTO, DetailCredentialClaimResponseDTO,
    GetCredentialListResponseDTO,
};
use crate::service::credential_schema::dto::CredentialClaimSchemaDTO;
use crate::service::error::ServiceError;

use super::dto::CredentialResponseDTO;

impl TryFrom<Credential> for CredentialResponseDTO {
    type Error = ServiceError;

    fn try_from(value: Credential) -> Result<Self, ServiceError> {
        let schema = value.schema.ok_or(ServiceError::MappingError(
            "credential_schema is None".to_string(),
        ))?;
        let claims = value
            .claims
            .ok_or(ServiceError::MappingError("claims is None".to_string()))?;
        let issuer_did_value = match value.issuer_did {
            None => None,
            Some(issuer_did) => Some(issuer_did.did),
        };
        let states = value
            .state
            .ok_or(ServiceError::MappingError("state is None".to_string()))?;
        let latest_state = states.get(0).ok_or(ServiceError::NotFound)?.to_owned();

        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            issuance_date: value.issuance_date,
            state: latest_state.state.into(),
            last_modified: value.last_modified,
            schema: schema.try_into()?,
            issuer_did: issuer_did_value,
            claims: from_vec_claim(claims)?,
            credential: value.credential,
        })
    }
}

fn from_vec_claim(
    claims: Vec<Claim>,
) -> Result<Vec<DetailCredentialClaimResponseDTO>, ServiceError> {
    claims
        .into_iter()
        .map(|claim| {
            let schema = claim
                .schema
                .ok_or(ServiceError::MappingError(
                    "claim_schema is None".to_string(),
                ))?
                .into();
            Ok::<DetailCredentialClaimResponseDTO, ServiceError>(DetailCredentialClaimResponseDTO {
                schema,
                value: claim.value,
            })
        })
        .collect::<Result<Vec<_>, _>>()
}

impl From<model::credential::CredentialStateEnum> for super::dto::CredentialStateEnum {
    fn from(value: CredentialStateEnum) -> Self {
        match value {
            model::credential::CredentialStateEnum::Created => {
                super::dto::CredentialStateEnum::Created
            }
            model::credential::CredentialStateEnum::Pending => {
                super::dto::CredentialStateEnum::Pending
            }
            model::credential::CredentialStateEnum::Offered => {
                super::dto::CredentialStateEnum::Offered
            }
            model::credential::CredentialStateEnum::Accepted => {
                super::dto::CredentialStateEnum::Accepted
            }
            model::credential::CredentialStateEnum::Rejected => {
                super::dto::CredentialStateEnum::Rejected
            }
            model::credential::CredentialStateEnum::Revoked => {
                super::dto::CredentialStateEnum::Revoked
            }
            model::credential::CredentialStateEnum::Error => super::dto::CredentialStateEnum::Error,
        }
    }
}

impl TryFrom<model::credential_schema::CredentialSchema> for CredentialSchemaResponseDTO {
    type Error = ServiceError;

    fn try_from(value: CredentialSchema) -> Result<Self, Self::Error> {
        let organisation = value.organisation.ok_or(ServiceError::MappingError(
            "organisation is none".to_string(),
        ))?;

        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            format: value.format,
            revocation_method: value.revocation_method,
            organisation_id: organisation.id,
        })
    }
}

impl TryFrom<model::claim::Claim> for DetailCredentialClaimResponseDTO {
    type Error = ServiceError;

    fn try_from(value: Claim) -> Result<Self, ServiceError> {
        let schema = value.schema.ok_or(ServiceError::MappingError(
            "claim schema is none".to_string(),
        ))?;

        Ok(Self {
            schema: CredentialClaimSchemaDTO {
                id: schema.id,
                created_date: schema.created_date,
                last_modified: schema.last_modified,
                key: schema.key,
                datatype: schema.data_type,
            },
            value: value.value,
        })
    }
}

impl TryFrom<GetCredentialList> for GetCredentialListResponseDTO {
    type Error = ServiceError;

    fn try_from(value: GetCredentialList) -> Result<Self, ServiceError> {
        Ok(Self {
            values: value
                .values
                .into_iter()
                .map(|credential| credential.try_into())
                .collect::<Result<Vec<_>, _>>()?,
            total_pages: value.total_pages,
            total_items: value.total_items,
        })
    }
}

impl TryFrom<Credential> for CredentialListItemResponseDTO {
    type Error = ServiceError;

    fn try_from(value: Credential) -> Result<Self, ServiceError> {
        let issuer_did_value = match value.issuer_did {
            None => None,
            Some(issuer_did) => Some(issuer_did.did),
        };

        let schema = value.schema.ok_or(ServiceError::MappingError(
            "credential_schema is None".to_string(),
        ))?;

        let states = value
            .state
            .ok_or(ServiceError::MappingError("state is None".to_string()))?;
        let latest_state = states.get(0).ok_or(ServiceError::NotFound)?.to_owned();

        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            issuance_date: value.issuance_date,
            state: latest_state.state.into(),
            last_modified: value.last_modified,
            schema: schema.try_into()?,
            issuer_did: issuer_did_value,
            credential: value.credential,
        })
    }
}

pub(super) fn from_create_request(
    request: CreateCredentialRequestDTO,
    claims: Vec<Claim>,
    issuer_did: Did,
    schema: CredentialSchema,
) -> Credential {
    let now = OffsetDateTime::now_utc();

    Credential {
        id: Uuid::new_v4(),
        created_date: now,
        issuance_date: now,
        state: Some(vec![CredentialState {
            created_date: now,
            state: CredentialStateEnum::Created,
        }]),
        last_modified: now,
        credential: vec![],
        transport: request.transport,
        claims: Some(claims),
        issuer_did: Some(issuer_did),
        receiver_did: None,
        schema: Some(schema),
    }
}

pub(super) fn from_jwt_create_request(
    request: CreateCredentialFromJwtRequestDTO,
    claims: Vec<Claim>,
    receiver_did: Option<Did>,
    issuer_did: Did,
    schema: CredentialSchema,
) -> Credential {
    let now = OffsetDateTime::now_utc();
    let credential = match request.credential {
        None => vec![],
        Some(value) => value,
    };

    Credential {
        id: request.id,
        created_date: now,
        issuance_date: now,
        state: Some(vec![CredentialState {
            created_date: now,
            state: CredentialStateEnum::Created,
        }]),
        last_modified: now,
        credential,
        transport: request.transport,
        claims: Some(claims),
        issuer_did: Some(issuer_did),
        receiver_did,
        schema: Some(schema),
    }
}

pub(super) fn claims_from_create_request(
    claims: Vec<CredentialRequestClaimDTO>,
    claim_schemas: &[ClaimSchema],
) -> Result<Vec<Claim>, ServiceError> {
    let now = OffsetDateTime::now_utc();

    claims
        .into_iter()
        .map(|claim| {
            let schema = claim_schemas
                .iter()
                .find(|schema| schema.id == claim.claim_schema_id)
                .ok_or(ServiceError::NotFound)?;
            Ok(Claim {
                id: Uuid::new_v4(),
                created_date: now,
                last_modified: now,
                value: claim.value,
                schema: Some(schema.clone()),
            })
        })
        .collect::<Result<Vec<_>, _>>()
}
