use serde::{Deserialize, Serialize};
use shared_types::HistoryId;
use time::OffsetDateTime;

use crate::service::credential::dto::{
    CredentialDetailResponseDTO, DetailCredentialClaimResponseDTO,
};
use crate::service::did::dto::DidListItemResponseDTO;
use crate::service::history::dto::HistoryResponseDTO;
use crate::service::identifier::dto::GetIdentifierListItemResponseDTO;
use crate::service::key::dto::KeyListItemResponseDTO;

#[derive(Debug, Clone)]
pub struct BackupCreateResponseDTO {
    pub history_id: HistoryId,
    pub file: String,
    pub unexportable: UnexportableEntitiesResponseDTO,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnexportableEntitiesResponseDTO {
    pub credentials: Vec<CredentialDetailResponseDTO<DetailCredentialClaimResponseDTO>>,
    pub keys: Vec<KeyListItemResponseDTO>,
    pub dids: Vec<DidListItemResponseDTO>,
    pub identifiers: Vec<GetIdentifierListItemResponseDTO>,
    pub history: Vec<HistoryResponseDTO>,
    pub total_credentials: u64,
    pub total_keys: u64,
    pub total_dids: u64,
    pub total_identifiers: u64,
    pub total_histories: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataDTO {
    pub db_version: String,
    pub db_hash: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}
