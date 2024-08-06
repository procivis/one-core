use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::macros::{
    impl_from_unnamed, impl_into, impls_for_seaorm_newtype, impls_for_uuid_newtype,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(transparent)]
#[repr(transparent)]
pub struct ClaimSchemaId(Uuid);

impls_for_uuid_newtype!(ClaimSchemaId);

#[cfg(feature = "sea-orm")]
impls_for_seaorm_newtype!(ClaimSchemaId);

impl_from_unnamed!(ClaimSchemaId; one_providers::common_models::claim_schema::ClaimSchemaId);
impl_into!(ClaimSchemaId; one_providers::common_models::claim_schema::ClaimSchemaId);
