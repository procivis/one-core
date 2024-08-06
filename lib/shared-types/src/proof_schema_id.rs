use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::macros::{
    impl_from_unnamed, impl_into, impls_for_seaorm_newtype, impls_for_uuid_newtype,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(transparent)]
#[repr(transparent)]
pub struct ProofSchemaId(Uuid);

impls_for_uuid_newtype!(ProofSchemaId);

#[cfg(feature = "sea-orm")]
impls_for_seaorm_newtype!(ProofSchemaId);

impl_from_unnamed!(ProofSchemaId; one_providers::common_models::proof_schema::ProofSchemaId);
impl_into!(ProofSchemaId; one_providers::common_models::proof_schema::ProofSchemaId);
