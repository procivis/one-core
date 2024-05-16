use shared_types::{OrganisationId, TrustAnchorId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    config::validator::trust_management::validate_trust_management,
    model::{
        history::{History, HistoryAction, HistoryEntityType},
        organisation::Organisation,
    },
    repository::error::DataLayerError,
    service::error::{BusinessLogicError, ServiceError},
};

use super::{dto::CreateTrustAnchorRequestDTO, TrustAnchorService};

impl TrustAnchorService {
    pub async fn create_trust_anchor(
        &self,
        anchor: CreateTrustAnchorRequestDTO,
    ) -> Result<(), ServiceError> {
        validate_trust_management(&anchor.type_, &self.config.trust_management)
            .map_err(|_| BusinessLogicError::UnknownTrustAnchorType)?;

        let organisation_id = anchor.organisation_id;

        let result = self.trust_anchor_repository.create(anchor.into()).await;

        match result {
            Ok(id) => {
                let _ = self
                    .history_repository
                    .create_history(create_history_event(id, organisation_id))
                    .await;
                Ok(())
            }
            Err(DataLayerError::AlreadyExists) => {
                Err(BusinessLogicError::TrustAnchorNameTaken.into())
            }
            Err(err) => Err(err.into()),
        }
    }
}

fn create_history_event(trust_id: TrustAnchorId, organisation_id: OrganisationId) -> History {
    History {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        action: HistoryAction::Created,
        entity_id: Some(trust_id.into()),
        entity_type: HistoryEntityType::TrustAnchor,
        metadata: None,
        organisation: Some(Organisation {
            id: organisation_id,
            created_date: OffsetDateTime::UNIX_EPOCH,
            last_modified: OffsetDateTime::UNIX_EPOCH,
        }),
    }
}
