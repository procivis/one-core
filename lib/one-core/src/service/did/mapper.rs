use shared_types::{DidId, DidValue};
use time::OffsetDateTime;

use super::dto::{CreateDidRequestDTO, DidResponseDTO, DidResponseKeysDTO, GetDidListResponseDTO};
use crate::{
    common_mapper::vector_into,
    model::{
        did::{Did, GetDidList, KeyRole, RelatedKey},
        key::{Key, KeyId},
        organisation::Organisation,
    },
    provider::did_method::DidMethodError,
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
            deactivated: value.deactivated,
        })
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

pub(super) fn did_from_did_request(
    did_id: DidId,
    request: CreateDidRequestDTO,
    organisation: Organisation,
    did_value: DidValue,
    key: Key,
    now: OffsetDateTime,
) -> Result<Did, DidMethodError> {
    let mut keys: Vec<RelatedKey> = vec![];
    let mut add_keys = |key_ids: Vec<KeyId>, role: KeyRole| {
        for _ in key_ids {
            keys.push(RelatedKey {
                role: role.to_owned(),
                key: key.to_owned(),
            });
        }
    };

    add_keys(request.keys.authentication, KeyRole::Authentication);
    add_keys(request.keys.assertion, KeyRole::AssertionMethod);
    add_keys(request.keys.key_agreement, KeyRole::KeyAgreement);
    add_keys(
        request.keys.capability_invocation,
        KeyRole::CapabilityInvocation,
    );
    add_keys(
        request.keys.capability_delegation,
        KeyRole::CapabilityDelegation,
    );

    Ok(Did {
        id: did_id,
        created_date: now,
        last_modified: now,
        name: request.name,
        organisation: Some(organisation),
        did: did_value,
        did_type: request.did_type,
        did_method: request.did_method,
        keys: Some(keys),
        deactivated: false,
    })
}
