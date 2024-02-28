use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    macros::{impls_for_seaorm_newtype, impls_for_uuid_newtype},
    CredentialId, DidId, KeyId,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(transparent)]
#[repr(transparent)]
pub struct EntityId(Uuid);

impls_for_uuid_newtype!(EntityId);

#[cfg(feature = "sea-orm")]
impls_for_seaorm_newtype!(EntityId);

impl From<DidId> for EntityId {
    fn from(value: DidId) -> Self {
        EntityId(value.into())
    }
}

impl From<KeyId> for EntityId {
    fn from(value: KeyId) -> Self {
        EntityId(value.into())
    }
}

impl From<CredentialId> for EntityId {
    fn from(value: CredentialId) -> Self {
        EntityId(value.into())
    }
}
