use dto_mapper::convert_inner;
use shared_types::CredentialId;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::common_mapper::{remove_first_nesting_layer, NESTED_CLAIM_MARKER};
use crate::provider::revocation::CredentialRevocationState;
use crate::service::credential::dto::DetailCredentialClaimValueResponseDTO;
use crate::{
    model::{
        claim::Claim,
        credential::{Credential, CredentialRole, CredentialState, CredentialStateEnum},
        credential_schema::{CredentialSchema, CredentialSchemaClaim},
        did::Did,
        history::{History, HistoryAction, HistoryEntityType},
        key::Key,
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
            lvvc_issuance_date: None,
            suspend_end_date: latest_state.suspend_end_date,
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
            wallet_storage_type: value.wallet_storage_type,
            organisation_id,
            schema_type: value.schema_type.into(),
            schema_id: value.schema_id,
            layout_type: value.layout_type.into(),
            layout_properties: convert_inner(value.layout_properties),
        })
    }
}

pub(super) fn renest_claims(
    claims: Vec<DetailCredentialClaimResponseDTO>,
) -> Result<Vec<DetailCredentialClaimResponseDTO>, ServiceError> {
    let mut result = vec![];

    // Iterate over all and copy all unnested claims to new vec
    for claim in claims.iter() {
        if claim.schema.key.find(NESTED_CLAIM_MARKER).is_none() {
            result.push(claim.to_owned());
        }
    }

    // Find all nested claims and move them to related entries in result vec
    for mut claim in claims.into_iter() {
        if claim.schema.key.find(NESTED_CLAIM_MARKER).is_some() {
            let matching_entry = result
                .iter_mut()
                .find(|result_schema| {
                    claim.schema.key.starts_with(&format!(
                        "{}{NESTED_CLAIM_MARKER}",
                        result_schema.schema.key
                    ))
                })
                .ok_or(ServiceError::BusinessLogic(
                    BusinessLogicError::MissingParentClaimSchema {
                        claim_schema_id: claim.schema.id,
                    },
                ))?;
            claim.schema.key = remove_first_nesting_layer(&claim.schema.key);

            match &mut matching_entry.value {
                DetailCredentialClaimValueResponseDTO::String(_value) => {
                    matching_entry.value =
                        DetailCredentialClaimValueResponseDTO::Nested(vec![claim]);
                }
                DetailCredentialClaimValueResponseDTO::Nested(nested) => {
                    nested.push(claim);
                }
            }
        }
    }

    // Repeat for all claims to nest all subclaims
    let mut nested = result
        .into_iter()
        .map(|mut claim_schema| {
            match &claim_schema.value {
                DetailCredentialClaimValueResponseDTO::String(_value) => {}
                DetailCredentialClaimValueResponseDTO::Nested(nested) => {
                    claim_schema.value = DetailCredentialClaimValueResponseDTO::Nested(
                        renest_claims(nested.to_owned())?,
                    );
                }
            }
            Ok(claim_schema)
        })
        .collect::<Result<Vec<DetailCredentialClaimResponseDTO>, ServiceError>>()?;

    // Remove empty non-required object claims
    nested.retain(|element| match &element.value {
        DetailCredentialClaimValueResponseDTO::Nested(value) => {
            element.schema.required || !value.is_empty()
        }
        _ => true,
    });

    Ok(nested)
}

fn from_vec_claim(
    claims: Vec<Claim>,
    credential_schema: &CredentialSchema,
) -> Result<Vec<DetailCredentialClaimResponseDTO>, ServiceError> {
    let claim_schemas =
        credential_schema
            .claim_schemas
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "claim_schemas is None".to_string(),
            ))?;
    let result = claim_schemas
        .iter()
        .map(|claim_schema| {
            let claim = claims.iter().find(|claim| {
                let schema = claim.schema.as_ref().ok_or(ServiceError::MappingError(
                    "claim_schema is None".to_string(),
                ));
                if let Ok(schema) = schema {
                    schema.id == claim_schema.schema.id
                } else {
                    false
                }
            });

            match claim {
                None => Ok(DetailCredentialClaimResponseDTO {
                    schema: claim_schema.to_owned().into(),
                    value: DetailCredentialClaimValueResponseDTO::Nested(vec![]),
                }),
                Some(claim) => Ok(DetailCredentialClaimResponseDTO {
                    schema: claim_schema.to_owned().into(),
                    value: DetailCredentialClaimValueResponseDTO::String(claim.value.to_owned()),
                }),
            }
        })
        .collect::<Result<Vec<_>, ServiceError>>()?;

    let nested = renest_claims(result)?;
    Ok(nested)
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
            suspend_end_date: latest_state.suspend_end_date,
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
    key: Key,
) -> Credential {
    let now = OffsetDateTime::now_utc();

    Credential {
        id: credential_id,
        created_date: now,
        issuance_date: now,
        state: Some(vec![CredentialState {
            created_date: now,
            state: CredentialStateEnum::Created,
            suspend_end_date: None,
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
        key: Some(key),
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
        entity_id: Some(credential.id.into()),
        entity_type: HistoryEntityType::Credential,
        metadata: None,
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
        entity_id: Some(credential.id.into()),
        entity_type: HistoryEntityType::Credential,
        metadata: None,
        organisation: credential.schema.and_then(|c| c.organisation),
    }
}

pub(crate) fn credential_revocation_history_event(
    id: CredentialId,
    new_state: CredentialRevocationState,
    organisation: Option<Organisation>,
) -> History {
    let action = match new_state {
        CredentialRevocationState::Revoked => HistoryAction::Revoked,
        CredentialRevocationState::Valid => HistoryAction::Reactivated,
        CredentialRevocationState::Suspended { .. } => HistoryAction::Suspended,
    };

    History {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        action,
        entity_id: Some(id.into()),
        entity_type: HistoryEntityType::Credential,
        metadata: None,
        organisation,
    }
}

pub(super) fn credential_revocation_state_to_model_state(
    revocation_state: CredentialRevocationState,
) -> CredentialStateEnum {
    match revocation_state {
        CredentialRevocationState::Revoked => CredentialStateEnum::Revoked,
        CredentialRevocationState::Valid => CredentialStateEnum::Accepted,
        CredentialRevocationState::Suspended { .. } => CredentialStateEnum::Suspended,
    }
}
