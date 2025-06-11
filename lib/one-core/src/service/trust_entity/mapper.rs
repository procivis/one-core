use one_dto_mapper::{convert_inner, convert_inner_of_inner};
use time::OffsetDateTime;
use uuid::Uuid;

use super::dto::{
    CreateTrustEntityFromDidPublisherRequestDTO, CreateTrustEntityRequestDTO,
    GetTrustEntityResponseDTO, UpdateTrustEntityActionFromDidRequestDTO,
    UpdateTrustEntityFromDidRequestDTO,
};
use crate::model::did::Did;
use crate::model::trust_anchor::TrustAnchor;
use crate::model::trust_entity::{
    TrustEntity, TrustEntityState, TrustEntityType, UpdateTrustEntityRequest,
};
use crate::provider::trust_management::model::TrustEntityByDid;
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
        deactivated_at: None,
        name: request.name,
        logo: convert_inner(request.logo),
        website: request.website,
        terms_url: request.terms_url,
        privacy_url: request.privacy_url,
        role: request.role,
        state: TrustEntityState::Active,
        r#type: TrustEntityType::Did,
        entity_key: did.did.to_string(),
        trust_anchor: Some(trust_anchor),
        content: None,
        organisation: did.organisation,
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
        deactivated_at: None,
        name: request.name,
        logo: convert_inner(request.logo),
        website: request.website,
        terms_url: request.terms_url,
        privacy_url: request.privacy_url,
        role: request.role,
        state: TrustEntityState::Active,
        r#type: TrustEntityType::Did,
        entity_key: did.did.to_string(),
        trust_anchor: Some(trust_anchor),
        content: None,
        organisation: did.organisation,
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
            organisation_id: value.organisation.map(|organisation| organisation.id),
            did: None,
        })
    }
}

pub(super) fn get_detail_trust_entity_response(
    trust_entity: TrustEntity,
    did: Did,
) -> Result<GetTrustEntityResponseDTO, ServiceError> {
    Ok(GetTrustEntityResponseDTO {
        id: trust_entity.id,
        created_date: trust_entity.created_date,
        last_modified: trust_entity.last_modified,
        name: trust_entity.name,
        logo: trust_entity.logo,
        website: trust_entity.website,
        terms_url: trust_entity.terms_url,
        privacy_url: trust_entity.privacy_url,
        role: trust_entity.role,
        trust_anchor: trust_entity
            .trust_anchor
            .map(Into::into)
            .ok_or_else(|| ServiceError::MappingError("Missing trust anchor".to_string()))?,
        state: trust_entity.state,
        organisation_id: did
            .organisation
            .as_ref()
            .map(|organisation| organisation.id),
        did: Some(did.into()),
    })
}

pub(super) fn update_request_from_dto(
    current_state: TrustEntityState,
    request: UpdateTrustEntityFromDidRequestDTO,
) -> Result<UpdateTrustEntityRequest, ServiceError> {
    let new_state = match (request.action, current_state) {
        (Some(UpdateTrustEntityActionFromDidRequestDTO::Activate), TrustEntityState::Withdrawn) => {
            Some(TrustEntityState::Active)
        }
        (
            Some(UpdateTrustEntityActionFromDidRequestDTO::Activate),
            TrustEntityState::RemovedAndWithdrawn,
        ) => Some(TrustEntityState::Removed),

        (
            Some(UpdateTrustEntityActionFromDidRequestDTO::AdminActivate),
            TrustEntityState::Removed,
        ) => Some(TrustEntityState::Active),
        (
            Some(UpdateTrustEntityActionFromDidRequestDTO::AdminActivate),
            TrustEntityState::RemovedAndWithdrawn,
        ) => Some(TrustEntityState::Withdrawn),

        (Some(UpdateTrustEntityActionFromDidRequestDTO::Withdraw), TrustEntityState::Active) => {
            Some(TrustEntityState::Withdrawn)
        }
        (Some(UpdateTrustEntityActionFromDidRequestDTO::Withdraw), TrustEntityState::Removed) => {
            Some(TrustEntityState::RemovedAndWithdrawn)
        }

        (Some(UpdateTrustEntityActionFromDidRequestDTO::Remove), TrustEntityState::Active) => {
            Some(TrustEntityState::Removed)
        }
        (Some(UpdateTrustEntityActionFromDidRequestDTO::Remove), TrustEntityState::Withdrawn) => {
            Some(TrustEntityState::RemovedAndWithdrawn)
        }

        (None, _) => None,
        _ => {
            return Err(ValidationError::InvalidUpdateRequest.into());
        }
    };

    Ok(UpdateTrustEntityRequest {
        state: new_state,
        logo: convert_inner_of_inner(request.logo),
        privacy_url: request.privacy_url,
        website: request.website,
        name: request.name,
        terms_url: request.terms_url,
        role: request.role,
    })
}

pub(super) fn trust_entity_from_partial_and_did_and_anchor(
    trust_entity: TrustEntityByDid,
    did: Did,
    trust_anchor: TrustAnchor,
) -> Result<GetTrustEntityResponseDTO, ServiceError> {
    Ok(GetTrustEntityResponseDTO {
        id: trust_entity.id,
        organisation_id: did
            .organisation
            .as_ref()
            .map(|organisation| organisation.id),
        name: trust_entity.name,
        created_date: trust_entity.created_date,
        last_modified: trust_entity.last_modified,
        logo: trust_entity.logo,
        website: trust_entity.website,
        terms_url: trust_entity.terms_url,
        privacy_url: trust_entity.privacy_url,
        role: trust_entity.role,
        state: trust_entity.state,
        did: Some(did.into()),
        trust_anchor: trust_anchor.into(),
    })
}
