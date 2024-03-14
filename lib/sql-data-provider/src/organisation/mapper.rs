use one_core::model::organisation::Organisation;
use sea_orm::Set;

use crate::entity::organisation;

impl From<Organisation> for organisation::ActiveModel {
    fn from(value: Organisation) -> Self {
        Self {
            id: Set(value.id),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
        }
    }
}
