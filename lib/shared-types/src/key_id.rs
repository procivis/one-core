use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::macros::{
    impl_from_unnamed, impl_into_unnamed, impls_for_seaorm_newtype, impls_for_uuid_newtype,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(transparent)]
#[repr(transparent)]
pub struct KeyId(Uuid);

impl_from_unnamed!(KeyId; one_providers::common_models::key::KeyId);
impl_into_unnamed!(KeyId; one_providers::common_models::key::KeyId);

impls_for_uuid_newtype!(KeyId);

#[cfg(feature = "sea-orm")]
impls_for_seaorm_newtype!(KeyId);
