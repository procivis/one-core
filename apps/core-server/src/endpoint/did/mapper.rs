use one_core::{
    model::did::DidType,
    service::did::dto::{CreateDidRequestDTO, GetDidResponseDTO},
};

use super::dto::{CreateDidRequestRestDTO, GetDidResponseRestDTO};

impl From<GetDidResponseDTO> for GetDidResponseRestDTO {
    fn from(value: GetDidResponseDTO) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            organisation_id: value.organisation_id,
            did: value.did,
            did_type: value.did_type.into(),
            did_method: value.did_method,
        }
    }
}

impl From<CreateDidRequestRestDTO> for CreateDidRequestDTO {
    fn from(value: CreateDidRequestRestDTO) -> Self {
        Self {
            name: value.name,
            organisation_id: value.organisation_id,
            did: value.did,
            did_method: value.method,
            did_type: DidType::Local,
        }
    }
}
