use time::OffsetDateTime;
use uuid::Uuid;

use super::dto::{
    CreateTrustEntityFromDidPublisherRequestDTO, CreateTrustEntityRequestDTO,
    GetTrustEntityResponseDTO, UpdateTrustEntityActionFromDidRequestDTO,
    UpdateTrustEntityFromDidRequestDTO,
};
use crate::model::did::Did;
use crate::model::trust_anchor::TrustAnchor;
use crate::model::trust_entity::{TrustEntity, TrustEntityState, UpdateTrustEntityRequest};
use crate::service::error::{ServiceError, ValidationError};

pub(super) fn trust_entity_from_request(
    request: CreateTrustEntityRequestDTO,
    trust_anchor: TrustAnchor,
    did: Did,
) -> TrustEntity {
    let id = Uuid::new_v4().into();
    let now = OffsetDateTime::now_utc();

    TrustEntity {
        id,
        created_date: now,
        last_modified: now,
        name: request.name,
        logo: request.logo,
        website: request.website,
        terms_url: request.terms_url,
        privacy_url: request.privacy_url,
        role: request.role,
        state: request.state,
        trust_anchor: Some(trust_anchor),
        did: Some(did),
    }
}

pub(super) fn trust_entity_from_did_request(
    request: CreateTrustEntityFromDidPublisherRequestDTO,
    trust_anchor: TrustAnchor,
    did: Did,
) -> TrustEntity {
    let id = Uuid::new_v4().into();
    let now = OffsetDateTime::now_utc();

    TrustEntity {
        id,
        created_date: now,
        last_modified: now,
        name: request.name,
        logo: request.logo,
        website: request.website,
        terms_url: request.terms_url,
        privacy_url: request.privacy_url,
        role: request.role,
        state: TrustEntityState::Active,
        trust_anchor: Some(trust_anchor),
        did: Some(did),
    }
}

impl TryFrom<TrustEntity> for GetTrustEntityResponseDTO {
    type Error = ServiceError;

    fn try_from(value: TrustEntity) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            logo: value.logo,
            website: value.website,
            terms_url: value.terms_url,
            privacy_url: value.privacy_url,
            role: value.role,
            trust_anchor: value
                .trust_anchor
                .map(Into::into)
                .ok_or(ServiceError::MappingError(format!(
                    "missing trust_anchor for trust entity {}",
                    value.id
                )))?,
            state: value.state,
            did: value
                .did
                .map(Into::into)
                .ok_or(ServiceError::MappingError(format!(
                    "missing did for trust entity {}",
                    value.id
                )))?,
        })
    }
}

pub(super) fn update_request_from_dto(
    state: TrustEntityState,
    request: UpdateTrustEntityFromDidRequestDTO,
) -> Result<UpdateTrustEntityRequest, ServiceError> {
    let new_state = match (request.action, state) {
        (UpdateTrustEntityActionFromDidRequestDTO::Activate, TrustEntityState::Withdrawn) => {
            Ok(TrustEntityState::Active)
        }
        (
            UpdateTrustEntityActionFromDidRequestDTO::Activate,
            TrustEntityState::RemovedAndWithdrawn,
        ) => Ok(TrustEntityState::Removed),
        (UpdateTrustEntityActionFromDidRequestDTO::Withdraw, TrustEntityState::Active) => {
            Ok(TrustEntityState::Withdrawn)
        }
        (UpdateTrustEntityActionFromDidRequestDTO::Withdraw, TrustEntityState::Removed) => {
            Ok(TrustEntityState::RemovedAndWithdrawn)
        }
        _ => Err(ValidationError::InvalidUpdateRequest),
    }?;

    Ok(UpdateTrustEntityRequest {
        state: Some(new_state),
        logo: request.logo,
        privacy_url: request.privacy_url,
        website: request.website,
        name: request.name,
        terms_url: request.terms_url,
        role: request.role,
    })
}
