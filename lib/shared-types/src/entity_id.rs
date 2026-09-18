use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::macros::impls_for_uuid_newtype;
use crate::{
    CertificateId, ClaimSchemaId, CredentialId, CredentialSchemaId, DidId, IdentifierId,
    InstanceId, KeyId, ManagedInstanceId, NotificationId, OrganisationId, ProofId, ProofSchemaId,
    TrustListPublicationId, TrustListSubscriptionId,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(transparent)]
#[repr(transparent)]
pub struct EntityId(Uuid);

impls_for_uuid_newtype!(EntityId);

#[cfg(feature = "sea-orm")]
use crate::macros::impls_for_seaorm_newtype;
use crate::trust_collection_id::TrustCollectionId;

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
impl_from_other_type!(ClaimSchemaId);
impl_from_other_type!(DidId);
impl_from_other_type!(CertificateId);
impl_from_other_type!(IdentifierId);
impl_from_other_type!(KeyId);
impl_from_other_type!(OrganisationId);
impl_from_other_type!(ProofSchemaId);
impl_from_other_type!(ProofId);
impl_from_other_type!(ManagedInstanceId);
impl_from_other_type!(InstanceId);
impl_from_other_type!(NotificationId);
impl_from_other_type!(TrustListPublicationId);
impl_from_other_type!(TrustCollectionId);
impl_from_other_type!(TrustListSubscriptionId);
