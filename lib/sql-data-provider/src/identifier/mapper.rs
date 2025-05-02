use one_core::model::identifier::Identifier;
use sea_orm::Set;

use crate::entity::identifier::ActiveModel;

impl From<Identifier> for ActiveModel {
    fn from(identifier: Identifier) -> Self {
        let organisation_id = identifier.organisation.map(|org| org.id);
        let did_id = identifier.did.map(|did| did.id);
        let key_id = identifier.key.map(|key| key.id);

        Self {
            id: Set(identifier.id),
            created_date: Set(identifier.created_date),
            last_modified: Set(identifier.last_modified),
            name: Set(identifier.name),
            r#type: Set(identifier.r#type.into()),
            is_remote: Set(identifier.is_remote),
            status: Set(identifier.status.into()),
            organisation_id: Set(organisation_id),
            did_id: Set(did_id),
            key_id: Set(key_id),
            deleted_at: Set(identifier.deleted_at),
        }
    }
}
