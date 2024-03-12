use dto_mapper::convert_inner;
use shared_types::{DidId, DidValue, KeyId};
use time::OffsetDateTime;

use super::dto::{CreateDidRequestDTO, DidResponseDTO, DidResponseKeysDTO, GetDidListResponseDTO};

use crate::model::history::{History, HistoryAction, HistoryEntityType};
use crate::provider::did_method::dto::{DidDocumentDTO, DidVerificationMethodDTO, PublicKeyJwkDTO};
use crate::service::error::EntityNotFoundError;
use crate::{
    model::{
        did::{Did, GetDidList, KeyRole, RelatedKey},
        key::Key,
        organisation::Organisation,
    },
    service::{error::ServiceError, key::dto::KeyListItemResponseDTO},
};
use std::collections::HashMap;
use uuid::Uuid;

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
                assertion_method: filter_keys(KeyRole::AssertionMethod),
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
            values: convert_inner(value.values),
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
    found_keys: Vec<Key>,
    now: OffsetDateTime,
) -> Result<Did, EntityNotFoundError> {
    let mut keys: Vec<RelatedKey> = vec![];
    let mut add_keys = |key_ids: Vec<KeyId>, role: KeyRole| {
        for key_id in key_ids {
            keys.push(RelatedKey {
                role: role.to_owned(),
                key: found_keys
                    .iter()
                    .find(|key| key.id == key_id)
                    .ok_or(EntityNotFoundError::Key(key_id))?
                    .clone(),
            });
        }
        Ok(())
    };

    add_keys(request.keys.authentication, KeyRole::Authentication)?;
    add_keys(request.keys.assertion_method, KeyRole::AssertionMethod)?;
    add_keys(request.keys.key_agreement, KeyRole::KeyAgreement)?;
    add_keys(
        request.keys.capability_invocation,
        KeyRole::CapabilityInvocation,
    )?;
    add_keys(
        request.keys.capability_delegation,
        KeyRole::CapabilityDelegation,
    )?;

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

pub(super) fn map_did_model_to_did_web_response(
    did: &Did,
    keys: &[RelatedKey],
    grouped_key: &HashMap<KeyId, DidVerificationMethodDTO>,
) -> Result<DidDocumentDTO, ServiceError> {
    Ok(DidDocumentDTO {
        context: serde_json::json!([
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
        ]),
        id: did.did.clone(),
        verification_method: grouped_key.values().cloned().collect(),
        authentication: get_key_id_by_role(KeyRole::Authentication, keys, grouped_key)?.into(),
        assertion_method: get_key_id_by_role(KeyRole::AssertionMethod, keys, grouped_key)?.into(),
        key_agreement: get_key_id_by_role(KeyRole::KeyAgreement, keys, grouped_key)?.into(),
        capability_invocation: get_key_id_by_role(
            KeyRole::CapabilityInvocation,
            keys,
            grouped_key,
        )?
        .into(),
        capability_delegation: get_key_id_by_role(
            KeyRole::CapabilityDelegation,
            keys,
            grouped_key,
        )?
        .into(),
        rest: Default::default(),
    })
}

pub(super) fn get_key_id_by_role(
    role: KeyRole,
    keys: &[RelatedKey],
    group: &HashMap<KeyId, DidVerificationMethodDTO>,
) -> Result<Vec<String>, ServiceError> {
    keys.iter()
        .filter(|key| key.role == role)
        .map(|key| {
            Ok(group
                .get(&key.key.id)
                .ok_or(ServiceError::MappingError("Missing key".to_string()))?
                .id
                .to_string())
        })
        .collect::<Result<Vec<_>, _>>()
}

pub(super) fn map_key_to_verification_method(
    did: &Did,
    public_key_jwk: PublicKeyJwkDTO,
) -> Result<DidVerificationMethodDTO, ServiceError> {
    let assertion_method_key = did.find_key_by_role(KeyRole::AssertionMethod)?;
    Ok(DidVerificationMethodDTO {
        id: format!("{}#key-{}", did.did, assertion_method_key.id),
        r#type: "JsonWebKey2020".to_string(),
        controller: did.did.as_str().to_string(),
        public_key_jwk,
    })
}

pub(super) fn did_create_history_event(did: Did) -> History {
    history_event(did, HistoryAction::Created)
}

pub(super) fn did_deactivated_history_event(did: Did) -> History {
    history_event(did, HistoryAction::Deactivated)
}

fn history_event(did: Did, action: HistoryAction) -> History {
    History {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        action,
        entity_id: Some(did.id.into()),
        entity_type: HistoryEntityType::Did,
        metadata: None,
        organisation: did.organisation,
    }
}
