use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::macros::{
    impl_from_unnamed, impl_into_unnamed, impls_for_seaorm_newtype, impls_for_uuid_newtype,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(transparent)]
#[repr(transparent)]
pub struct OrganisationId(Uuid);

impl_from_unnamed!(OrganisationId; one_providers::common_models::organisation::OrganisationId);
impl_into_unnamed!(OrganisationId; one_providers::common_models::organisation::OrganisationId);

impls_for_uuid_newtype!(OrganisationId);

#[cfg(feature = "sea-orm")]
impls_for_seaorm_newtype!(OrganisationId);
