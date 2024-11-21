use time::OffsetDateTime;
use uuid::Uuid;

use super::dto::{CreateTrustAnchorRequestDTO, GetTrustAnchorDetailResponseDTO};
use crate::model::trust_anchor::TrustAnchor;

pub(super) fn trust_anchor_from_request(
    request: CreateTrustAnchorRequestDTO,
    core_base_url: &String,
) -> TrustAnchor {
    let id = Uuid::new_v4().into();
    let now = OffsetDateTime::now_utc();

    TrustAnchor {
        id,
        name: request.name,
        created_date: now,
        last_modified: now,
        type_field: request.r#type,
        publisher_reference: Some(format!("{}/ssi/trust/v1/{}", core_base_url, id)),
        role: request.role,
    }
}

impl From<TrustAnchor> for GetTrustAnchorDetailResponseDTO {
    fn from(value: TrustAnchor) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            r#type: value.type_field,
            publisher_reference: value.publisher_reference,
            role: value.role,
        }
    }
}
