use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::macros::{
    impl_from_unnamed, impl_into_unnamed, impls_for_seaorm_newtype, impls_for_uuid_newtype,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(transparent)]
#[repr(transparent)]
pub struct DidId(Uuid);

impls_for_uuid_newtype!(DidId);

#[cfg(feature = "sea-orm")]
impls_for_seaorm_newtype!(DidId);

impl_from_unnamed!(DidId; one_providers::common_models::did::DidId);
impl_into_unnamed!(DidId; one_providers::common_models::did::DidId);
