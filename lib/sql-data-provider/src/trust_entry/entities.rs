use one_core::model::identifier::Identifier;
use one_core::model::trust_entry::TrustEntry;
use sea_orm::FromQueryResult;
use shared_types::{IdentifierId, OrganisationId, TrustEntryId, TrustListPublicationId};
use time::OffsetDateTime;

use crate::entity::identifier::{IdentifierState, IdentifierType};
use crate::entity::trust_entry::TrustEntryStatus;

#[derive(Clone, Debug, FromQueryResult)]
pub struct TrustEntryWithIdentifier {
    pub id: TrustEntryId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub status: TrustEntryStatus,
    pub metadata: Vec<u8>,
    pub trust_list_publication_id: TrustListPublicationId,

    pub identifier_id: IdentifierId,
    pub identifier_created_date: OffsetDateTime,
    pub identifier_last_modified: OffsetDateTime,
    pub identifier_name: String,
    pub identifier_type: IdentifierType,
    pub identifier_is_remote: bool,
    pub identifier_state: IdentifierState,
    pub identifier_deleted_at: Option<OffsetDateTime>,
    pub identifier_organisation_id: OrganisationId,
}

impl From<TrustEntryWithIdentifier> for TrustEntry {
    fn from(value: TrustEntryWithIdentifier) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            status: value.status.into(),
            metadata: value.metadata,
            trust_list_publication_id: value.trust_list_publication_id,
            identifier_id: value.identifier_id,
            trust_list_publication: None,
            identifier: Some(Identifier {
                id: value.identifier_id,
                created_date: value.identifier_created_date,
                last_modified: value.identifier_last_modified,
                name: value.identifier_name,
                r#type: value.identifier_type.into(),
                is_remote: value.identifier_is_remote,
                state: value.identifier_state.into(),
                deleted_at: value.identifier_deleted_at,
                organisation: None,
                did: None,
                key: None,
                certificates: None,
            }),
        }
    }
}
