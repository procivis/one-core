use std::collections::HashMap;

use time::OffsetDateTime;
use uuid::Uuid;

use super::dto::{
    CreateDidRequestDTO, DidListItemResponseDTO, DidResponseDTO, GetDidListResponseDTO,
};
use crate::{
    common_mapper::vector_into,
    model::{
        did::{Did, GetDidList, KeyRole, RelatedKey},
        key::{Key, KeyId},
        organisation::Organisation,
    },
    service::error::ServiceError,
};

impl TryFrom<Did> for DidResponseDTO {
    type Error = ServiceError;
    fn try_from(value: Did) -> Result<Self, Self::Error> {
        let organisation = value.organisation.ok_or(ServiceError::MappingError(
            "organisation is None".to_string(),
        ))?;
        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            organisation_id: organisation.id,
            did: value.did,
            did_type: value.did_type,
            did_method: value.did_method,
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

pub(crate) fn did_from_did_request(
    request: CreateDidRequestDTO,
    organisation: Organisation,
    key_map: HashMap<KeyId, Key>,
    now: OffsetDateTime,
) -> Result<Did, ServiceError> {
    let mut keys: Vec<RelatedKey> = vec![];
    let mut add_keys = |key_ids: Vec<KeyId>, role: KeyRole| {
        for key_id in key_ids {
            keys.push(RelatedKey {
                role: role.to_owned(),
                key: key_map[&key_id].to_owned(),
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
        id: Uuid::new_v4(),
        created_date: now,
        last_modified: now,
        name: request.name,
        organisation: Some(organisation),
        did: request.did,
        did_type: request.did_type,
        did_method: request.did_method,
        keys: Some(keys),
    })
}
