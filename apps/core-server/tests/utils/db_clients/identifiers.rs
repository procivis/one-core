use std::sync::Arc;

use one_core::model::identifier::{Identifier, IdentifierState, IdentifierType};
use one_core::model::organisation::Organisation;
use one_core::repository::identifier_repository::IdentifierRepository;
use shared_types::IdentifierId;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::fixtures::{TestingIdentifierParams, unwrap_or_random};

pub struct IdentifiersDB {
    repository: Arc<dyn IdentifierRepository>,
}

impl IdentifiersDB {
    pub fn new(repository: Arc<dyn IdentifierRepository>) -> Self {
        Self { repository }
    }

    pub async fn create(
        &self,
        organisation: &Organisation,
        params: TestingIdentifierParams,
    ) -> Identifier {
        let now = OffsetDateTime::now_utc();

        let id = params.id.unwrap_or(IdentifierId::from(Uuid::new_v4()));
        let identifier = Identifier {
            id: id.to_owned(),
            created_date: params.created_date.unwrap_or(now),
            last_modified: params.last_modified.unwrap_or(now),
            name: unwrap_or_random(params.name),
            organisation: Some(organisation.clone()),
            did: params.did,
            key: params.key,
            certificates: params.certificates,
            state: params.state.unwrap_or(IdentifierState::Active),
            r#type: params.r#type.unwrap_or(IdentifierType::Did),
            is_remote: params.is_remote.unwrap_or_default(),
            deleted_at: params.deleted_at,
        };

        let _ = self.repository.create(identifier.clone()).await.unwrap();

        identifier
    }
}
