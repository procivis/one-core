use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    model::{trust_anchor::TrustAnchor, trust_entity::TrustEntity},
    service::error::ServiceError,
};

use super::dto::{CreateTrustEntityRequestDTO, GetTrustEntityResponseDTO};

pub(super) fn trust_entity_from_request(
    request: CreateTrustEntityRequestDTO,
    trust_anchor: TrustAnchor,
) -> TrustEntity {
    let id = Uuid::new_v4().into();
    let now = OffsetDateTime::now_utc();

    TrustEntity {
        id,
        created_date: now,
        last_modified: now,
        entity_id: request.entity_id,
        name: request.name,
        logo: request.logo,
        website: request.website,
        terms_url: request.terms_url,
        privacy_url: request.privacy_url,
        role: request.role,
        trust_anchor: Some(trust_anchor),
    }
}

impl TryFrom<TrustEntity> for GetTrustEntityResponseDTO {
    type Error = ServiceError;
    fn try_from(value: TrustEntity) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            entity_id: value.entity_id,
            name: value.name,
            logo: value.logo,
            website: value.website,
            terms_url: value.terms_url,
            privacy_url: value.privacy_url,
            role: value.role,
            trust_anchor: value.trust_anchor.and_then(|anchor| anchor.try_into().ok()),
        })
    }
}
