use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::did::{Did, DidRelations};

pub type RevocationListId = Uuid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevocationList {
    pub id: RevocationListId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub credentials: Vec<u8>,

    // Relations:
    pub issuer_did: Option<Did>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct RevocationListRelations {
    pub issuer_did: Option<DidRelations>,
}