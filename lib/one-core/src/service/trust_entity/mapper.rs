use time::OffsetDateTime;
use uuid::Uuid;

use super::dto::{CreateTrustEntityRequestDTO, GetTrustEntityResponseDTO};
use crate::model::did::Did;
use crate::model::trust_anchor::TrustAnchor;
use crate::model::trust_entity::TrustEntity;

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

impl From<TrustEntity> for GetTrustEntityResponseDTO {
    fn from(value: TrustEntity) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            logo: value.logo,
            website: value.website,
            terms_url: value.terms_url,
            privacy_url: value.privacy_url,
            role: value.role,
            trust_anchor: value.trust_anchor.map(Into::into),
            state: value.state,
        }
    }
}
