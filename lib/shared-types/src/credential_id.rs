use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::macros::{
    impl_from_unnamed, impl_into, impls_for_seaorm_newtype, impls_for_uuid_newtype,
};

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(transparent)]
#[repr(transparent)]
pub struct CredentialId(Uuid);

impls_for_uuid_newtype!(CredentialId);

#[cfg(feature = "sea-orm")]
impls_for_seaorm_newtype!(CredentialId);

impl_from_unnamed!(CredentialId; one_providers::common_models::credential::CredentialId);
impl_into!(CredentialId; one_providers::common_models::credential::CredentialId);
