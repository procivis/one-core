use shared_types::DidValue;
use time::OffsetDateTime;
use uuid::Uuid;

use super::dto::{CreateTrustAnchorRequestDTO, GetTrustAnchorEntityListResponseDTO};
use crate::model::trust_anchor::TrustAnchor;
use crate::model::trust_entity::{TrustEntity, TrustEntityType};
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

impl TryFrom<TrustEntity> for GetTrustAnchorEntityListResponseDTO {
    type Error = ServiceError;

    fn try_from(value: TrustEntity) -> Result<Self, Self::Error> {
        let did = if value.r#type == TrustEntityType::Did {
            Some(DidValue::from_did_url(value.entity_key).map_err(|err| {
                ServiceError::MappingError(format!(
                    "Invalid entity_key on trust entity of type DID: {err}"
                ))
            })?)
        } else {
            None
        };
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
            state: value.state,
            did,
        })
    }
}
