use super::dto::{
    CreateDidRequestRestDTO, DidType, GetDidResponseRestDTO, SortableDidColumnRestDTO,
};
use one_core::service::did::dto::{CreateDidRequestDTO, GetDidResponseDTO};

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
            did_type: one_core::model::did::DidType::Local,
        }
    }
}

impl From<DidType> for one_core::model::did::DidType {
    fn from(value: DidType) -> Self {
        match value {
            DidType::Remote => one_core::model::did::DidType::Remote,
            DidType::Local => one_core::model::did::DidType::Local,
        }
    }
}

impl From<one_core::model::did::DidType> for DidType {
    fn from(value: one_core::model::did::DidType) -> Self {
        match value {
            one_core::model::did::DidType::Remote => DidType::Remote,
            one_core::model::did::DidType::Local => DidType::Local,
        }
    }
}

impl From<SortableDidColumnRestDTO> for one_core::model::did::SortableDidColumn {
    fn from(value: SortableDidColumnRestDTO) -> Self {
        match value {
            SortableDidColumnRestDTO::Name => one_core::model::did::SortableDidColumn::Name,
            SortableDidColumnRestDTO::CreatedDate => {
                one_core::model::did::SortableDidColumn::CreatedDate
            }
        }
    }
}