use super::dto::{
    DidListItemResponseDTO, DidResponseDTO, DidResponseKeysDTO, GetDidListResponseDTO,
};
use crate::{
    common_mapper::vector_into,
    model::did::{Did, GetDidList, KeyRole},
    service::{error::ServiceError, key::dto::KeyListItemResponseDTO},
};

impl TryFrom<Did> for DidResponseDTO {
    type Error = ServiceError;
    fn try_from(value: Did) -> Result<Self, Self::Error> {
        let organisation = value.organisation.ok_or(ServiceError::MappingError(
            "organisation is None".to_string(),
        ))?;

        let keys = value
            .keys
            .ok_or(ServiceError::MappingError("keys is None".to_string()))?;
        let filter_keys = |role: KeyRole| -> Vec<KeyListItemResponseDTO> {
            keys.iter()
                .filter(|key| key.role == role)
                .map(|key| key.key.to_owned().into())
                .collect()
        };

        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            organisation_id: organisation.id,
            did: value.did,
            did_type: value.did_type,
            did_method: value.did_method,
            keys: DidResponseKeysDTO {
                authentication: filter_keys(KeyRole::Authentication),
                assertion: filter_keys(KeyRole::AssertionMethod),
                key_agreement: filter_keys(KeyRole::KeyAgreement),
                capability_invocation: filter_keys(KeyRole::CapabilityInvocation),
                capability_delegation: filter_keys(KeyRole::CapabilityDelegation),
            },
        })
    }
}

impl From<Did> for DidListItemResponseDTO {
    fn from(value: Did) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            did: value.did,
            did_type: value.did_type,
            did_method: value.did_method,
        }
    }
}

impl From<GetDidList> for GetDidListResponseDTO {
    fn from(value: GetDidList) -> Self {
        Self {
            values: vector_into(value.values),
            total_pages: value.total_pages,
            total_items: value.total_items,
        }
    }
}
