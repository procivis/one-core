use time::OffsetDateTime;
use uuid::Uuid;

use shared_types::{DidId, DidValue};

use crate::{
    model::{
        did::{Did, KeyRole, RelatedKey},
        key::{Key, KeyId},
        organisation::Organisation,
    },
    provider::did_method::DidMethodError,
    service::did::dto::CreateDidRequestDTO,
};

pub(super) enum DidKeyType {
    Eddsa,
    Es256,
}

pub(super) fn categorize_did(did: &DidValue) -> Result<DidKeyType, DidMethodError> {
    if did.as_str().starts_with("did:key:z6Mk") {
        return Ok(DidKeyType::Eddsa);
    }
    if did.as_str().starts_with("did:key:zDn") {
        return Ok(DidKeyType::Es256);
    }

    Err(DidMethodError::ResolutionError(
        "Unsupported key algorithm".to_string(),
    ))
}

pub(super) fn did_from_did_request(
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
        id: DidId::from(Uuid::new_v4()),
        created_date: now,
        last_modified: now,
        name: request.name,
        organisation: Some(organisation),
        did: did_value,
        did_type: request.did_type,
        did_method: request.did_method,
        keys: Some(keys),
    })
}
