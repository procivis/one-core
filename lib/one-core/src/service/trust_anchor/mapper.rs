use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    model::{organisation::Organisation, trust_anchor::TrustAnchor},
    service::error::ServiceError,
};

use super::dto::{CreateTrustAnchorRequestDTO, GetTrustAnchorDetailResponseDTO};

pub(super) fn trust_anchor_from_request(
    request: CreateTrustAnchorRequestDTO,
    organisation: Organisation,
) -> TrustAnchor {
    let id = Uuid::new_v4().into();
    let now = OffsetDateTime::now_utc();

    TrustAnchor {
        id,
        name: request.name,
        created_date: now,
        last_modified: now,
        type_field: request.r#type,
        publisher_reference: request.publisher_reference,
        role: request.role,
        priority: request.priority,
        organisation: Some(organisation),
    }
}

impl TryFrom<TrustAnchor> for GetTrustAnchorDetailResponseDTO {
    type Error = ServiceError;

    fn try_from(value: TrustAnchor) -> Result<Self, Self::Error> {
        let organisation = value.organisation.ok_or(ServiceError::MappingError(
            "Missing organisation".to_owned(),
        ))?;

        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            r#type: value.type_field,
            publisher_reference: value.publisher_reference,
            role: value.role,
            priority: value.priority,
            organisation_id: organisation.id,
        })
    }
}
