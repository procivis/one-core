use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::macros::{
    impl_from_unnamed, impl_into, impls_for_seaorm_newtype, impls_for_uuid_newtype,
};

#[derive(Debug, Default, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(transparent)]
#[repr(transparent)]
pub struct ProofId(Uuid);

impls_for_uuid_newtype!(ProofId);

#[cfg(feature = "sea-orm")]
impls_for_seaorm_newtype!(ProofId);

impl_from_unnamed!(ProofId; one_providers::common_models::proof::ProofId);
impl_into!(ProofId; one_providers::common_models::proof::ProofId);
