use crate::model::{
    self,
    claim::Claim,
    credential::{Credential, CredentialState, CredentialStateEnum},
    credential_schema::{CredentialSchema, CredentialSchemaClaim},
    did::Did,
};
use crate::service::{
    credential::dto::{
        CreateCredentialRequestDTO, CredentialDetailResponseDTO, CredentialListItemResponseDTO,
        CredentialRequestClaimDTO, DetailCredentialClaimResponseDTO,
        DetailCredentialSchemaResponseDTO,
    },
    error::ServiceError,
};
use time::OffsetDateTime;
use uuid::Uuid;

impl TryFrom<Credential> for CredentialDetailResponseDTO {
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
        let latest_state = states
            .get(0)
            .ok_or(ServiceError::MappingError(
                "latest state not found".to_string(),
            ))?
            .to_owned();

        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            issuance_date: value.issuance_date,
            state: latest_state.state.into(),
            last_modified: value.last_modified,
            claims: from_vec_claim(claims, &schema)?,
            schema: schema.try_into()?,
            issuer_did: issuer_did_value,
        })
    }
}

impl TryFrom<CredentialSchema> for DetailCredentialSchemaResponseDTO {
    type Error = ServiceError;

    fn try_from(value: CredentialSchema) -> Result<Self, Self::Error> {
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
        })
    }
}

fn from_vec_claim(
    claims: Vec<Claim>,
    credential_schema: &CredentialSchema,
) -> Result<Vec<DetailCredentialClaimResponseDTO>, ServiceError> {
    claims
        .into_iter()
        .map(|claim| {
            let claim_schema_id = claim
                .schema
                .ok_or(ServiceError::MappingError(
                    "claim_schema is None".to_string(),
                ))?
                .id;
            let credential_claim_schema = credential_schema
                .claim_schemas
                .as_ref()
                .ok_or(ServiceError::MappingError(
                    "claim_schemas is None".to_string(),
                ))?
                .iter()
                .find(|claim_schema| claim_schema.schema.id == claim_schema_id)
                .ok_or(ServiceError::MappingError(
                    "claim_schema missing".to_string(),
                ))?;
            Ok::<DetailCredentialClaimResponseDTO, ServiceError>(DetailCredentialClaimResponseDTO {
                schema: credential_claim_schema.to_owned().into(),
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
        let latest_state = states
            .get(0)
            .ok_or(ServiceError::MappingError(
                "latest state not found".to_string(),
            ))?
            .to_owned();

        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            issuance_date: value.issuance_date,
            state: latest_state.state.into(),
            last_modified: value.last_modified,
            schema: schema.into(),
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
        holder_did: None,
        schema: Some(schema),
        interaction: None,
    }
}

pub(super) fn claims_from_create_request(
    claims: Vec<CredentialRequestClaimDTO>,
    claim_schemas: &[CredentialSchemaClaim],
) -> Result<Vec<Claim>, ServiceError> {
    let now = OffsetDateTime::now_utc();

    claims
        .into_iter()
        .map(|claim| {
            let schema = claim_schemas
                .iter()
                .find(|schema| schema.schema.id == claim.claim_schema_id)
                .ok_or(ServiceError::NotFound)?;
            Ok(Claim {
                id: Uuid::new_v4(),
                created_date: now,
                last_modified: now,
                value: claim.value,
                schema: Some(schema.schema.clone()),
            })
        })
        .collect::<Result<Vec<_>, _>>()
}
