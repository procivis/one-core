use crate::model::credential::Credential;
use crate::model::did::Did;
use crate::model::history::{History, HistoryAction, HistoryEntityType};
use shared_types::EntityId;
use std::collections::HashMap;
use time::OffsetDateTime;
use uuid::Uuid;

use super::dto::JsonLDContextDTO;

impl Default for JsonLDContextDTO {
    fn default() -> Self {
        Self {
            version: 1.1,
            protected: true,
            id: "@id".to_string(),
            r#type: "@type".to_string(),
            entities: HashMap::default(),
        }
    }
}

pub(super) fn credential_rejected_history_event(credential: &Credential) -> History {
    history_event(
        credential.id.into(),
        credential.issuer_did.as_ref(),
        HistoryEntityType::Credential,
        HistoryAction::Rejected,
    )
}

fn history_event(
    entity_id: EntityId,
    issuer_did: Option<&Did>,
    entity_type: HistoryEntityType,
    action: HistoryAction,
) -> History {
    let organisation = issuer_did.and_then(|did| did.organisation.clone());

    History {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        action,
        entity_id: entity_id.into(),
        entity_type,
        metadata: None,
        organisation,
    }
}
