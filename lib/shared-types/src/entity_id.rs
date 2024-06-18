use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    macros::{impls_for_seaorm_newtype, impls_for_uuid_newtype},
    CredentialId, CredentialSchemaId, DidId, KeyId, OrganisationId, ProofSchemaId, TrustAnchorId,
    TrustEntityId,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(transparent)]
#[repr(transparent)]
pub struct EntityId(Uuid);

impls_for_uuid_newtype!(EntityId);

#[cfg(feature = "sea-orm")]
impls_for_seaorm_newtype!(EntityId);

macro_rules! impl_from_other_type {
    ($other: ty) => {
        impl std::convert::From<$other> for EntityId {
            fn from(value: $other) -> Self {
                Self(value.into())
            }
        }
    };
}

impl_from_other_type!(CredentialId);
impl_from_other_type!(CredentialSchemaId);
impl_from_other_type!(DidId);
impl_from_other_type!(KeyId);
impl_from_other_type!(OrganisationId);
impl_from_other_type!(TrustAnchorId);
impl_from_other_type!(TrustEntityId);
impl_from_other_type!(ProofSchemaId);
