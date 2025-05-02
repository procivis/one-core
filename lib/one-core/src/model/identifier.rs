use shared_types::IdentifierId;
use time::OffsetDateTime;

use super::did::{Did, DidRelations};
use super::key::{Key, KeyRelations};
use super::organisation::{Organisation, OrganisationRelations};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Identifier {
    pub id: IdentifierId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub r#type: IdentifierType,
    pub is_remote: bool,
    pub status: IdentifierStatus,
    pub deleted_at: Option<OffsetDateTime>,

    // Relations:
    pub organisation: Option<Organisation>,
    pub did: Option<Did>,
    pub key: Option<Key>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentifierType {
    Key,
    Did,
    Certificate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentifierStatus {
    Active,
    Deactivated,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct IdentifierRelations {
    pub organisation: Option<OrganisationRelations>,
    pub did: Option<DidRelations>,
    pub key: Option<KeyRelations>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UpdateIdentifierRequest {
    pub name: Option<String>,
    pub status: Option<IdentifierStatus>,
}
