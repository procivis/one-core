use one_core::model::organisation::{Organisation, UpdateOrganisationRequest};
use sea_orm::{Set, Unchanged};
use time::OffsetDateTime;

use crate::entity::organisation;

impl From<Organisation> for organisation::ActiveModel {
    fn from(value: Organisation) -> Self {
        Self {
            id: Set(value.id),
            name: Set(value.name),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            deactivated_at: Set(value.deactivated_at),
        }
    }
}

impl From<UpdateOrganisationRequest> for organisation::ActiveModel {
    fn from(value: UpdateOrganisationRequest) -> Self {
        Self {
            id: Set(value.id),
            name: match value.name {
                Some(name) => Set(name),
                None => Unchanged(Default::default()),
            },
            last_modified: Set(OffsetDateTime::now_utc()),
            deactivated_at: match value.deactivate {
                Some(true) => Set(Some(OffsetDateTime::now_utc())),
                Some(false) => Set(None),
                _ => Unchanged(Default::default()),
            },
            ..Default::default()
        }
    }
}
