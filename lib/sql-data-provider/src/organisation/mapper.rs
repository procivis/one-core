use one_core::model::organisation::{Organisation, UpdateOrganisationRequest};
use sea_orm::Set;
use time::OffsetDateTime;

use crate::entity::organisation;

impl From<Organisation> for organisation::ActiveModel {
    fn from(value: Organisation) -> Self {
        Self {
            id: Set(value.id),
            name: Set(value.name),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
        }
    }
}

impl From<UpdateOrganisationRequest> for organisation::ActiveModel {
    fn from(value: UpdateOrganisationRequest) -> Self {
        Self {
            id: Set(value.id),
            name: Set(value.name),
            last_modified: Set(OffsetDateTime::now_utc()),
            ..Default::default()
        }
    }
}
