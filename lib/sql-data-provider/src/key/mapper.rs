use std::str::FromStr;
use uuid::Uuid;

use crate::entity;
use crate::entity::key_did;
use one_core::model::credential::Credential;
use one_core::model::key::{self, Key, RelatedDid};
use one_core::model::organisation::Organisation;
use one_core::repository::error::DataLayerError;

pub(super) fn from_model_and_relations(
    value: entity::key::Model,
    credential: Option<Credential>,
    dids: Option<Vec<RelatedDid>>,
    organisation: Option<Organisation>,
) -> Result<Key, DataLayerError> {
    let id = Uuid::from_str(&value.id).map_err(|_| DataLayerError::MappingError)?;

    Ok(Key {
        id,
        created_date: value.created_date,
        last_modified: value.last_modified,
        public_key: value.public_key,
        name: value.name,
        private_key: value.private_key,
        storage_type: value.storage_type,
        key_type: value.key_type,
        credential,
        dids,
        organisation,
    })
}

impl From<key_did::KeyRole> for key::KeyRole {
    fn from(value: key_did::KeyRole) -> Self {
        match value {
            key_did::KeyRole::Authentication => key::KeyRole::Authentication,
            key_did::KeyRole::AssertionMethod => key::KeyRole::AssertionMethod,
            key_did::KeyRole::KeyAgreement => key::KeyRole::KeyAgreement,
            key_did::KeyRole::CapabilityInvocation => key::KeyRole::CapabilityInvocation,
            key_did::KeyRole::CapabilityDelegation => key::KeyRole::CapabilityDelegation,
        }
    }
}
