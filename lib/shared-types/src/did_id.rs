use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::macros::impls_for_uuid_newtype;

/// DID details. See the [DID](/api/resources/dids) guide.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(transparent)]
#[repr(transparent)]
pub struct DidId(Uuid);

impls_for_uuid_newtype!(DidId);

#[cfg(feature = "sea-orm")]
use crate::macros::impls_for_seaorm_newtype;

#[cfg(feature = "sea-orm")]
impls_for_seaorm_newtype!(DidId);
