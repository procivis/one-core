use dto_mapper::Into;
use strum_macros::Display;
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
    pub purpose: RevocationListPurpose,

    // Relations:
    pub issuer_did: Option<Did>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct RevocationListRelations {
    pub issuer_did: Option<DidRelations>,
}

#[derive(Clone, Debug, Eq, PartialEq, Display, Into)]
#[into(one_providers::revocation::imp::bitstring_status_list::model::RevocationListPurpose)]
pub enum RevocationListPurpose {
    Revocation,
    Suspension,
}
