use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::trust_entity::TrustEntity;

use super::dto::CreateTrustEntityRequestDTO;

impl From<CreateTrustEntityRequestDTO> for TrustEntity {
    fn from(value: CreateTrustEntityRequestDTO) -> Self {
        let id = Uuid::new_v4().into();
        let now = OffsetDateTime::now_utc();

        Self {
            id,
            created_date: now,
            last_modified: now,
            entity_id: value.entity_id,
            name: value.name,
            logo: value.logo,
            website: value.website,
            terms_url: value.terms_url,
            privacy_url: value.privacy_url,
            role: value.role,
            trust_anchor_id: value.trust_anchor_id,
        }
    }
}
