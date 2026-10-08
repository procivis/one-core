use shared_types::CredentialId;
use time::OffsetDateTime;

use super::claim::Claim;
use super::credential::{CredentialCommon, CredentialRole, CredentialType};
use super::credential_schema_format::CredentialSchemaFormat;
use super::did::Did;
use super::identifier::Identifier;
use super::key::Key;
use super::relation::Related;
use crate::model::history::History;

#[derive(Debug, Clone)]
pub struct UnexportableEntities {
    pub credentials: Vec<UnexportableCredential>,
    pub keys: Vec<Key>,
    pub dids: Vec<Did>,
    pub identifiers: Vec<Identifier>,
    pub histories: Vec<History>,
    pub total_credentials: u64,
    pub total_keys: u64,
    pub total_dids: u64,
    pub total_identifiers: u64,
    pub total_histories: u64,
}

#[derive(Debug, Clone)]
pub struct Metadata {
    pub version: String,
}

/// A backup preview materialized from the snapshot, including its effective claims.
/// It omits issuer and holder relations, which may not be exportable.
#[derive(Debug, Clone)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct UnexportableCredential {
    pub common: CredentialCommon,
    pub claims: Vec<Claim>,
    pub role: CredentialRole,
    pub r#type: CredentialType,
    pub consumed_at: Option<OffsetDateTime>,
    pub webhook_url: Option<String>,
    pub subscriber_information: Option<String>,
    pub parent_id: Option<CredentialId>,
    pub format: Option<Related<CredentialSchemaFormat>>,
}
