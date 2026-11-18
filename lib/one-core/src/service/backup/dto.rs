use serde::{Deserialize, Deserializer, Serialize};
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
    #[serde(deserialize_with = "deserialize_credentials")]
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

/// Persisted as part of the history metadata: the credential protocol is stored as plain string
/// and typed according to the credential role.
// TODO: decouple the persisted history metadata from the service DTOs by giving it a dedicated
// persisted model.
fn deserialize_credentials<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<CredentialDetailResponseDTO<DetailCredentialClaimResponseDTO>>, D::Error> {
    let credentials: Vec<CredentialDetailResponseDTO<DetailCredentialClaimResponseDTO, String>> =
        Vec::deserialize(deserializer)?;
    Ok(credentials
        .into_iter()
        .map(CredentialDetailResponseDTO::with_typed_protocol)
        .collect())
}
