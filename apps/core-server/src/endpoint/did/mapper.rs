use super::dto::{CreateDidRequestRestDTO, DidResponseKeysRestDTO, DidResponseRestDTO};
use crate::mapper::MapperError;
use one_core::{
    common_mapper::vector_try_into,
    service::did::dto::{CreateDidRequestDTO, DidResponseDTO, DidResponseKeysDTO},
};

impl TryFrom<DidResponseDTO> for DidResponseRestDTO {
    type Error = MapperError;

    fn try_from(value: DidResponseDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            organisation_id: value.organisation_id,
            did: value.did,
            did_type: value.did_type.into(),
            did_method: value.did_method,
            keys: value.keys.try_into()?,
        })
    }
}

impl TryFrom<DidResponseKeysDTO> for DidResponseKeysRestDTO {
    type Error = MapperError;

    fn try_from(value: DidResponseKeysDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            authentication: vector_try_into(value.authentication)?,
            assertion: vector_try_into(value.assertion)?,
            key_agreement: vector_try_into(value.key_agreement)?,
            capability_invocation: vector_try_into(value.capability_invocation)?,
            capability_delegation: vector_try_into(value.capability_delegation)?,
        })
    }
}

impl From<CreateDidRequestRestDTO> for CreateDidRequestDTO {
    fn from(value: CreateDidRequestRestDTO) -> Self {
        Self {
            name: value.name,
            organisation_id: value.organisation_id,
            did_method: value.method,
            did_type: one_core::model::did::DidType::Local,
            keys: value.keys.into(),
            params: value.params,
        }
    }
}
