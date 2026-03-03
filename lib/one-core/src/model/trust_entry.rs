use serde::{Deserialize, Serialize};
use shared_types::{IdentifierId, TrustEntryId, TrustListPublicationId};
use time::OffsetDateTime;

use crate::model::identifier::{Identifier, IdentifierRelations};
use crate::model::trust_list_publication::{TrustListPublication, TrustListPublicationRelations};

#[derive(Clone, Debug)]
pub struct TrustEntry {
    pub id: TrustEntryId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub status: TrustEntryState,
    pub metadata: Vec<u8>,
    pub trust_list_publication_id: TrustListPublicationId,
    pub identifier_id: Option<IdentifierId>,

    // Relations
    pub trust_list_publication: Option<TrustListPublication>,
    pub identifier: Option<Identifier>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustEntryState {
    Active,
    Suspended,
    Removed,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct TrustEntryRelations {
    pub trust_list_publication: Option<TrustListPublicationRelations>,
    pub identifier: Option<IdentifierRelations>,
}
