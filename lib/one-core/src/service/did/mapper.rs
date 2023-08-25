use time::OffsetDateTime;
use uuid::Uuid;

use super::dto::{CreateDidRequestDTO, GetDidListResponseDTO, GetDidResponseDTO};
use crate::model::did::{Did, GetDidList};

impl From<Did> for GetDidResponseDTO {
    fn from(value: Did) -> Self {
        GetDidResponseDTO {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            organisation_id: value.organisation_id,
            did: value.did,
            did_type: value.did_type,
            did_method: value.did_method,
        }
    }
}

impl From<GetDidList> for GetDidListResponseDTO {
    fn from(value: GetDidList) -> Self {
        Self {
            values: value.values.into_iter().map(|item| item.into()).collect(),
            total_pages: value.total_pages,
            total_items: value.total_items,
        }
    }
}

pub(crate) fn did_from_did_request(request: CreateDidRequestDTO, now: OffsetDateTime) -> Did {
    Did {
        id: Uuid::new_v4(),
        created_date: now,
        last_modified: now,
        name: request.name,
        organisation_id: request.organisation_id,
        did: request.did,
        did_type: request.did_type,
        did_method: request.did_method,
    }
}
