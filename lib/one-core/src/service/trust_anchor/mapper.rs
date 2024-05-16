use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::trust_anchor::TrustAnchor;

use super::dto::CreateTrustAnchorRequestDTO;

impl From<CreateTrustAnchorRequestDTO> for TrustAnchor {
    fn from(value: CreateTrustAnchorRequestDTO) -> Self {
        let id = Uuid::new_v4().into();
        let now = OffsetDateTime::now_utc();

        Self {
            id,
            name: value.name,
            created_date: now,
            last_modified: now,
            type_field: value.type_,
            publisher_reference: value.publisher_reference,
            role: value.role,
            priority: value.priority,
            organisation_id: value.organisation_id,
        }
    }
}
