use time::OffsetDateTime;
use uuid::Uuid;

use super::dto::{CreateTrustAnchorRequestDTO, TrustAnchorsListItemResponseDTO};
use crate::model::trust_anchor::TrustAnchor;
use crate::service::error::ServiceError;

pub(super) fn trust_anchor_from_request(
    request: CreateTrustAnchorRequestDTO,
    core_base_url: Option<&String>,
) -> Result<TrustAnchor, ServiceError> {
    let id = Uuid::new_v4().into();
    let now = OffsetDateTime::now_utc();
    let publisher_reference = if let Some(publisher_reference) = request.publisher_reference {
        publisher_reference
    } else {
        format!(
            "{}/ssi/trust/v1/{id}",
            core_base_url
                .as_ref()
                .ok_or_else(|| ServiceError::Other("Missing core_base_url".to_string()))?,
        )
    };

    Ok(TrustAnchor {
        id,
        name: request.name,
        created_date: now,
        last_modified: now,
        r#type: request.r#type,
        is_publisher: request.is_publisher.unwrap_or(false),
        publisher_reference,
    })
}

impl From<TrustAnchorsListItemResponseDTO> for TrustAnchor {
    fn from(value: TrustAnchorsListItemResponseDTO) -> Self {
        Self {
            id: value.id,
            name: value.name,
            created_date: value.created_date,
            last_modified: value.last_modified,
            r#type: value.r#type,
            publisher_reference: value.publisher_reference,
            is_publisher: value.is_publisher,
        }
    }
}
