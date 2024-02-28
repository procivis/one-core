use dto_mapper::{convert_inner, try_convert_inner, TryFrom};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{
    model::backup::UnexportableEntities,
    service::{
        credential::dto::CredentialDetailResponseDTO, did::dto::DidListItemResponseDTO,
        error::ServiceError, key::dto::KeyListItemResponseDTO,
    },
};

#[derive(Debug, Clone)]
pub struct BackupCreateResponseDTO {
    pub file: String,
    pub unexportable: UnexportableEntitiesResponseDTO,
}

#[derive(Debug, Clone, TryFrom)]
#[try_from(T = UnexportableEntities, Error = ServiceError)]
pub struct UnexportableEntitiesResponseDTO {
    #[try_from(with_fn = try_convert_inner)]
    pub credentials: Vec<CredentialDetailResponseDTO>,
    #[try_from(infallible, with_fn = convert_inner)]
    pub keys: Vec<KeyListItemResponseDTO>,
    #[try_from(infallible, with_fn = convert_inner)]
    pub dids: Vec<DidListItemResponseDTO>,
    #[try_from(infallible)]
    pub total_credentials: u64,
    #[try_from(infallible)]
    pub total_keys: u64,
    #[try_from(infallible)]
    pub total_dids: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct MetadataFile {
    pub(super) db_version: String,
    pub(super) db_hash: String,
    #[serde(with = "time::serde::rfc3339")]
    pub(super) created_at: OffsetDateTime,
}
