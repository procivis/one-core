use shared_types::{DidId, DidValue};
use time::OffsetDateTime;

use super::dto::{CreateDidRequestDTO, DidResponseDTO, DidResponseKeysDTO, GetDidListResponseDTO};
use crate::provider::did_method::dto::PublicKeyJwkDTO;
use crate::service::did::dto::{
    DidWebResponseDTO, DidWebVerificationMethodResponseDTO, PublicKeyJwkResponseDTO,
};
use crate::{
    common_mapper::convert_inner,
    model::{
        did::{Did, GetDidList, KeyRole, RelatedKey},
        key::{Key, KeyId},
        organisation::Organisation,
    },
    service::{error::ServiceError, key::dto::KeyListItemResponseDTO},
};
use std::collections::HashMap;
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
    key: Key,
    now: OffsetDateTime,
) -> Did {
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

    Did {
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
    }
}

pub(super) fn map_did_model_to_did_web_response(
    did: &Did,
    keys: &[RelatedKey],
    grouped_key: &HashMap<KeyId, DidWebVerificationMethodResponseDTO>,
) -> Result<DidWebResponseDTO, ServiceError> {
    Ok(DidWebResponseDTO {
        context: vec![
            "https://www.w3.org/ns/did/v1".to_string(),
            "https://w3id.org/security/suites/jws-2020/v1".to_string(),
        ],
        id: did.did.clone(),
        verification_method: grouped_key.values().cloned().collect(),
        authentication: get_key_id_by_role(KeyRole::Authentication, keys, grouped_key)?,
        assertion_method: get_key_id_by_role(KeyRole::AssertionMethod, keys, grouped_key)?,
        key_agreement: get_key_id_by_role(KeyRole::KeyAgreement, keys, grouped_key)?,
        capability_invocation: get_key_id_by_role(
            KeyRole::CapabilityInvocation,
            keys,
            grouped_key,
        )?,
        capability_delegation: get_key_id_by_role(
            KeyRole::CapabilityDelegation,
            keys,
            grouped_key,
        )?,
    })
}

pub(super) fn get_key_id_by_role(
    role: KeyRole,
    keys: &[RelatedKey],
    group: &HashMap<KeyId, DidWebVerificationMethodResponseDTO>,
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
    index: usize,
    did: &DidValue,
    public_key_jwk: PublicKeyJwkResponseDTO,
) -> Result<DidWebVerificationMethodResponseDTO, ServiceError> {
    Ok(DidWebVerificationMethodResponseDTO {
        id: format!("{}#key-{}", did, index),
        r#type: "JsonWebKey2020".to_string(),
        controller: did.clone(),
        public_key_jwk,
    })
}

impl TryFrom<PublicKeyJwkDTO> for PublicKeyJwkResponseDTO {
    type Error = ServiceError;

    fn try_from(value: PublicKeyJwkDTO) -> Result<Self, Self::Error> {
        match value {
            PublicKeyJwkDTO::Ec(data) => Ok(PublicKeyJwkResponseDTO {
                kty: "EC".to_string(),
                crv: data.crv,
                x: data.x,
                y: data.y,
            }),
            PublicKeyJwkDTO::Okp(data) => Ok(PublicKeyJwkResponseDTO {
                kty: "OKP".to_string(),
                crv: data.crv,
                x: data.x,
                y: data.y,
            }),
            _ => Err(ServiceError::GeneralRuntimeError(
                "Only EC and OKP did algorithms are supported.".to_string(),
            )),
        }
    }
}
