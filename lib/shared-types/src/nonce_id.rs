use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::macros::impls_for_uuid_newtype;

/// Nonce ID for OID4VCI interactions
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(transparent)]
#[repr(transparent)]
pub struct NonceId(Uuid);

impls_for_uuid_newtype!(NonceId);

#[cfg(feature = "sea-orm")]
use crate::macros::impls_for_seaorm_newtype;

#[cfg(feature = "sea-orm")]
impls_for_seaorm_newtype!(NonceId);
