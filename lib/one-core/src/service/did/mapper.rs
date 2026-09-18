use std::collections::HashMap;

use one_dto_mapper::convert_inner;
use shared_types::{DidId, DidValue, KeyId};
use time::OffsetDateTime;

use super::dto::{
    CreateDidRequestDTO, DidFilterParamsDTO, DidListItemResponseDTO, DidResponseDTO,
    DidResponseKeysDTO, GetDidListResponseDTO,
};
use super::error::DidServiceError;
use crate::model::did::{
    Did, DidFilterValue, DidType, ExactDidFilterColumn, GetDidList, KeyRole, RelatedKey,
    UpdateDidRequest,
};
use crate::model::key::Key;
use crate::model::list_filter::{
    ListFilterCondition, ListFilterValue, StringMatch, StringMatchType,
};
use crate::model::organisation::Organisation;
use crate::provider::did_method::dto::{DidDocumentDTO, DidVerificationMethodDTO};
use crate::provider::did_method::{DidCreated, DidKeys, DidUpdate};
use crate::service::key::dto::KeyListItemResponseDTO;

pub(crate) async fn response_from_did(value: Did) -> Result<DidResponseDTO, DidServiceError> {
    let keys = value.keys.as_ref().await?;
    let filter_keys = |role: KeyRole| -> Vec<KeyListItemResponseDTO> {
        keys.iter()
            .filter(|key| key.role == role)
            .map(|key| key.key.to_owned().into())
            .collect()
    };

    Ok(DidResponseDTO {
        id: value.id,
        created_date: value.created_date,
        last_modified: value.last_modified,
        name: value.name,
        organisation_id: Some(value.organisation.id()),
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

impl From<GetDidList<u64>> for GetDidListResponseDTO {
    fn from(value: GetDidList<u64>) -> Self {
        Self {
            values: convert_inner(value.values),
            total_pages: value.total_pages,
            total_items: value.total_items,
        }
    }
}

pub(crate) fn did_from_did_request(
    did_id: DidId,
    request: CreateDidRequestDTO,
    organisation: Organisation,
    did_create: DidCreated,
    found_keys: DidKeys,
    now: OffsetDateTime,
    key_reference_mapping: HashMap<KeyId, String>,
) -> Result<Did, DidServiceError> {
    struct KeyEntry {
        role: KeyRole,
        key: Key,
    }

    let update_keys = found_keys.update_keys.into_iter().flat_map(|keys| {
        keys.into_iter().map(|key| KeyEntry {
            role: KeyRole::UpdateKey,
            key,
        })
    });

    let keys: Vec<_> = [
        (KeyRole::Authentication, found_keys.authentication),
        (KeyRole::AssertionMethod, found_keys.assertion_method),
        (KeyRole::KeyAgreement, found_keys.key_agreement),
        (
            KeyRole::CapabilityDelegation,
            found_keys.capability_delegation,
        ),
        (
            KeyRole::CapabilityInvocation,
            found_keys.capability_invocation,
        ),
    ]
    .into_iter()
    .flat_map(|(role, keys)| keys.into_iter().map(move |key| KeyEntry { role, key }))
    .chain(update_keys)
    .collect();

    let keys = keys
        .into_iter()
        .map(|KeyEntry { role, key }| {
            Ok::<_, DidServiceError>(RelatedKey {
                role,
                reference: key_reference_mapping
                    .get(&key.id)
                    .ok_or(DidServiceError::MappingError(
                        "key reference not found".to_string(),
                    ))?
                    .to_owned(),
                key,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Did {
        id: did_id,
        created_date: now,
        last_modified: now,
        deleted_at: None,
        name: request.name,
        organisation: organisation.into(),
        did: did_create.did,
        did_type: DidType::Local,
        did_method: request.did_method,
        keys: keys.into(),
        deactivated: false,
        log: did_create.log,
    })
}

pub(super) fn map_did_model_to_did_web_response(
    did: &Did,
    keys: &[RelatedKey],
    grouped_key: &HashMap<KeyId, DidVerificationMethodDTO>,
) -> Result<DidDocumentDTO, DidServiceError> {
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
        also_known_as: None,
        service: None,
    })
}

pub(super) fn get_key_id_by_role(
    role: KeyRole,
    keys: &[RelatedKey],
    group: &HashMap<KeyId, DidVerificationMethodDTO>,
) -> Result<Vec<String>, DidServiceError> {
    keys.iter()
        .filter(|key| key.role == role)
        .map(|key| {
            Ok(group
                .get(&key.key.id)
                .ok_or(DidServiceError::MappingError("Missing key".to_string()))?
                .id
                .to_string())
        })
        .collect::<Result<Vec<_>, _>>()
}

impl From<DidListItemResponseDTO> for DidValue {
    fn from(value: DidListItemResponseDTO) -> Self {
        value.did
    }
}

pub(super) async fn map_did_to_did_keys(did: &Did) -> Result<DidKeys, DidServiceError> {
    let related_keys = did.keys.as_ref().await?;
    let mut did_keys = DidKeys::default();
    for related_key in &related_keys {
        let key = related_key.key.to_owned();
        match related_key.role {
            KeyRole::Authentication => did_keys.authentication.push(key),
            KeyRole::AssertionMethod => did_keys.assertion_method.push(key),
            KeyRole::KeyAgreement => did_keys.key_agreement.push(key),
            KeyRole::CapabilityInvocation => did_keys.capability_invocation.push(key),
            KeyRole::CapabilityDelegation => did_keys.capability_delegation.push(key),
            KeyRole::UpdateKey => did_keys.update_keys.get_or_insert_default().push(key),
        }
    }
    Ok(did_keys)
}

pub(super) fn did_update_to_update_request(did_update: DidUpdate) -> UpdateDidRequest {
    UpdateDidRequest {
        deactivated: did_update.deactivated,
        log: did_update.log.map(Some),
    }
}

impl From<DidFilterParamsDTO> for ListFilterCondition<DidFilterValue> {
    fn from(value: DidFilterParamsDTO) -> Self {
        let exact = value.exact.unwrap_or_default();
        let get_string_match_type = |column| {
            if exact.contains(&column) {
                StringMatchType::Equals
            } else {
                StringMatchType::StartsWith
            }
        };
        let organisation_id = DidFilterValue::OrganisationId(value.organisation_id).condition();

        let name: ListFilterCondition<DidFilterValue> = value
            .name
            .map(|name| {
                DidFilterValue::Name(StringMatch {
                    r#match: get_string_match_type(ExactDidFilterColumn::Name),
                    value: name,
                })
            })
            .into();

        let did_value = value.did.map(|did| {
            DidFilterValue::Did(StringMatch {
                r#match: get_string_match_type(ExactDidFilterColumn::Did),
                value: did,
            })
        });

        let r#type = value.r#type.map(DidFilterValue::Type);
        let deactivated = value.deactivated.map(DidFilterValue::Deactivated);

        let key_algorithms = value.key_algorithms.map(|values| {
            DidFilterValue::KeyAlgorithms(
                values.into_iter().filter(|key| !key.is_empty()).collect(),
            )
        });

        let key_roles = value.key_roles.map(DidFilterValue::KeyRoles);

        let key_storages = value.key_storages.map(|values| {
            DidFilterValue::KeyStorages(values.into_iter().filter(|key| !key.is_empty()).collect())
        });

        let did_methods = value.did_methods.map(DidFilterValue::DidMethods);
        let key_ids = value.key_ids.map(DidFilterValue::KeyIds);

        organisation_id
            & r#type
            & (name | did_value)
            & deactivated
            & key_algorithms
            & key_roles
            & key_storages
            & did_methods
            & key_ids
    }
}
