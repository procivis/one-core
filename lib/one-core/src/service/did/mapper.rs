use std::collections::HashMap;

use dto_mapper::convert_inner;
use one_providers::common_models::key::{Key, KeyId};
use one_providers::common_models::PublicKeyJwk;
use one_providers::did::model::{DidDocument, DidVerificationMethod};
use shared_types::{DidId, DidValue};
use time::OffsetDateTime;
use uuid::Uuid;

use super::dto::{
    CreateDidRequestDTO, DidListItemResponseDTO, DidResponseDTO, DidResponseKeysDTO,
    GetDidListResponseDTO,
};
use crate::model::did::{Did, GetDidList, KeyRole, RelatedKey};
use crate::model::history::{History, HistoryAction, HistoryEntityType};
use crate::model::organisation::Organisation;
use crate::service::error::{EntityNotFoundError, ServiceError};
use crate::service::key::dto::KeyListItemResponseDTO;

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
                    .ok_or(EntityNotFoundError::Key(key_id.into()))?
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
    grouped_key: &HashMap<KeyId, DidVerificationMethod>,
) -> Result<DidDocument, ServiceError> {
    Ok(DidDocument {
        context: serde_json::json!([
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
        ]),
        id: did.did.clone().into(),
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
    group: &HashMap<KeyId, DidVerificationMethod>,
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
    did_value: &DidValue,
    public_key_id: &KeyId,
    public_key_jwk: PublicKeyJwk,
) -> Result<DidVerificationMethod, ServiceError> {
    Ok(DidVerificationMethod {
        id: format!("{}#key-{}", did_value, public_key_id),
        r#type: "JsonWebKey2020".to_string(),
        controller: did_value.to_string(),
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

impl From<one_providers::exchange_protocol::openid4vc::model::DidListItemResponseDTO>
    for DidListItemResponseDTO
{
    fn from(
        value: one_providers::exchange_protocol::openid4vc::model::DidListItemResponseDTO,
    ) -> Self {
        Self {
            id: Uuid::from(value.id).into(),
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            did: value.did.into(),
            did_type: value.did_type.into(),
            did_method: value.did_method,
            deactivated: value.deactivated,
        }
    }
}

impl From<DidListItemResponseDTO>
    for one_providers::exchange_protocol::openid4vc::model::DidListItemResponseDTO
{
    fn from(value: DidListItemResponseDTO) -> Self {
        Self {
            id: Uuid::from(value.id).into(),
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            did: value.did.into(),
            did_type: value.did_type.into(),
            did_method: value.did_method,
            deactivated: value.deactivated,
        }
    }
}
