use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::macros::{impls_for_seaorm_newtype, impls_for_uuid_newtype};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(transparent)]
#[repr(transparent)]
pub struct CredentialSchemaId(Uuid);

impls_for_uuid_newtype!(CredentialSchemaId);

#[cfg(feature = "sea-orm")]
impls_for_seaorm_newtype!(CredentialSchemaId);
