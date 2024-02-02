use dto_mapper::convert_inner;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    model::{
        claim::Claim,
        credential::{
            Credential, CredentialId, CredentialRole, CredentialState, CredentialStateEnum,
        },
        credential_schema::{CredentialSchema, CredentialSchemaClaim},
        did::Did,
        history::{History, HistoryAction, HistoryEntityType},
        organisation::Organisation,
    },
    service::{
        credential::dto::{
            CreateCredentialRequestDTO, CredentialDetailResponseDTO, CredentialListItemResponseDTO,
            CredentialRequestClaimDTO, DetailCredentialClaimResponseDTO,
            DetailCredentialSchemaResponseDTO,
        },
        error::{BusinessLogicError, ServiceError},
    },
};

impl TryFrom<Credential> for CredentialDetailResponseDTO {
    type Error = ServiceError;

    fn try_from(value: Credential) -> Result<Self, ServiceError> {
        let schema = value.schema.ok_or(ServiceError::MappingError(
            "credential_schema is None".to_string(),
        ))?;
        let claims = value
            .claims
            .ok_or(ServiceError::MappingError("claims is None".to_string()))?;
        let states = value
            .state
            .ok_or(ServiceError::MappingError("state is None".to_string()))?;
        let latest_state = states
            .first()
            .ok_or(ServiceError::MappingError(
                "latest state not found".to_string(),
            ))?
            .to_owned();

        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            issuance_date: value.issuance_date,
            revocation_date: get_revocation_date(&latest_state),
            state: latest_state.state.into(),
            last_modified: value.last_modified,
            claims: from_vec_claim(claims, &schema)?,
            schema: schema.try_into()?,
            issuer_did: convert_inner(value.issuer_did),
            redirect_uri: value.redirect_uri,
            role: value.role.into(),
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
            deleted_at: value.deleted_at,
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

impl TryFrom<Credential> for CredentialListItemResponseDTO {
    type Error = ServiceError;

    fn try_from(value: Credential) -> Result<Self, ServiceError> {
        let schema = value.schema.ok_or(ServiceError::MappingError(
            "credential_schema is None".to_string(),
        ))?;

        let states = value
            .state
            .ok_or(ServiceError::MappingError("state is None".to_string()))?;
        let latest_state = states
            .first()
            .ok_or(ServiceError::MappingError(
                "latest state not found".to_string(),
            ))?
            .to_owned();

        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            issuance_date: value.issuance_date,
            revocation_date: get_revocation_date(&latest_state),
            state: latest_state.state.into(),
            last_modified: value.last_modified,
            schema: schema.into(),
            issuer_did: convert_inner(value.issuer_did),
            credential: value.credential,
            role: value.role.into(),
        })
    }
}

fn get_revocation_date(latest_state: &CredentialState) -> Option<OffsetDateTime> {
    if latest_state.state == CredentialStateEnum::Revoked {
        Some(latest_state.created_date)
    } else {
        None
    }
}

pub(super) fn from_create_request(
    request: CreateCredentialRequestDTO,
    credential_id: CredentialId,
    claims: Vec<Claim>,
    issuer_did: Did,
    schema: CredentialSchema,
) -> Credential {
    let now = OffsetDateTime::now_utc();

    Credential {
        id: credential_id,
        created_date: now,
        issuance_date: now,
        state: Some(vec![CredentialState {
            created_date: now,
            state: CredentialStateEnum::Created,
        }]),
        last_modified: now,
        deleted_at: None,
        credential: vec![],
        transport: request.transport,
        claims: Some(claims),
        issuer_did: Some(issuer_did),
        holder_did: None,
        schema: Some(schema),
        interaction: None,
        revocation_list: None,
        key: None,
        redirect_uri: request.redirect_uri,
        role: CredentialRole::Issuer,
    }
}

pub(super) fn claims_from_create_request(
    credential_id: CredentialId,
    claims: Vec<CredentialRequestClaimDTO>,
    claim_schemas: &[CredentialSchemaClaim],
) -> Result<Vec<Claim>, ServiceError> {
    let now = OffsetDateTime::now_utc();

    claims
        .into_iter()
        .map(|claim| {
            let claim_schema_id = claim.claim_schema_id;
            let schema = claim_schemas
                .iter()
                .find(|schema| schema.schema.id == claim_schema_id)
                .ok_or(BusinessLogicError::MissingClaimSchema { claim_schema_id })?;
            Ok(Claim {
                id: Uuid::new_v4(),
                credential_id,
                created_date: now,
                last_modified: now,
                value: claim.value,
                schema: Some(schema.schema.clone()),
            })
        })
        .collect::<Result<Vec<_>, _>>()
}

pub(super) fn credential_created_history_event(
    credential: Credential,
) -> Result<History, ServiceError> {
    Ok(History {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        action: HistoryAction::Issued,
        entity_id: credential.id.into(),
        entity_type: HistoryEntityType::Credential,
        organisation: credential
            .schema
            .ok_or(ServiceError::MappingError(
                "organisation is None".to_string(),
            ))?
            .organisation,
    })
}

pub(super) fn credential_offered_history_event(credential: Credential) -> History {
    History {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        action: HistoryAction::Offered,
        entity_id: credential.id.into(),
        entity_type: HistoryEntityType::Credential,
        organisation: credential.schema.and_then(|c| c.organisation),
    }
}

pub(super) fn credential_revoked_history_event(
    id: CredentialId,
    organisation: Option<Organisation>,
) -> History {
    History {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        action: HistoryAction::Revoked,
        entity_id: id.into(),
        entity_type: HistoryEntityType::Credential,
        organisation,
    }
}
