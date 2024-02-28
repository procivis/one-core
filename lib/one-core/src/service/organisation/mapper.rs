use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::{
    history::{History, HistoryAction, HistoryEntityType},
    organisation::Organisation,
};

pub(super) fn create_organisation_history_event(organisation: Organisation) -> History {
    History {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        action: HistoryAction::Created,
        entity_id: Some(organisation.id.into()),
        entity_type: HistoryEntityType::Organisation,
        organisation: Some(organisation),
    }
}
