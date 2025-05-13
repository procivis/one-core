use one_dto_mapper::convert_inner;
use shared_types::OrganisationId;

use super::dto::{
    CreateIdentifierDidRequestDTO, GetIdentifierListItemResponseDTO, GetIdentifierListResponseDTO,
    GetIdentifierResponseDTO,
};
use crate::model::identifier::{GetIdentifierList, Identifier, IdentifierType};
use crate::service::did::dto::CreateDidRequestDTO;
use crate::service::error::ServiceError;

impl TryFrom<Identifier> for GetIdentifierResponseDTO {
    type Error = ServiceError;
    fn try_from(value: Identifier) -> Result<Self, Self::Error> {
        let organisation_id = value.organisation.map(|org| org.id);

        match value.r#type {
            IdentifierType::Did => {
                if value.did.is_none() {
                    return Err(ServiceError::MappingError(
                        "DID is required for identifier type Did".to_string(),
                    ));
                }
            }
            IdentifierType::Key => {
                if value.key.is_none() {
                    return Err(ServiceError::MappingError(
                        "Key is required for identifier type Key".to_string(),
                    ));
                }
            }
            IdentifierType::Certificate => {}
        }

        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            organisation_id,
            r#type: value.r#type,
            is_remote: value.is_remote,
            state: value.state,
            did: value.did.map(TryInto::try_into).transpose()?,
            key: value.key.map(TryInto::try_into).transpose()?,
        })
    }
}

impl From<Identifier> for GetIdentifierListItemResponseDTO {
    fn from(value: Identifier) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            r#type: value.r#type,
            is_remote: value.is_remote,
            state: value.state,
            organisation_id: value.organisation.map(|org| org.id),
        }
    }
}

impl From<GetIdentifierList> for GetIdentifierListResponseDTO {
    fn from(value: GetIdentifierList) -> Self {
        Self {
            values: convert_inner(value.values),
            total_pages: value.total_pages,
            total_items: value.total_items,
        }
    }
}

pub(super) fn to_create_did_request(
    identifier_name: &str,
    request: CreateIdentifierDidRequestDTO,
    organisation_id: OrganisationId,
) -> CreateDidRequestDTO {
    CreateDidRequestDTO {
        name: request.name.unwrap_or(identifier_name.to_string()),
        organisation_id,
        did_method: request.method,
        keys: request.keys,
        params: request.params,
    }
}
