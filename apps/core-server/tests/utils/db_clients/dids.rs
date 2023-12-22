use std::str::FromStr;
use std::sync::Arc;

use one_core::model::did::{Did, DidType};
use one_core::model::organisation::Organisation;
use one_core::repository::did_repository::DidRepository;
use shared_types::{DidId, DidValue};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::fixtures::TestingDidParams;

pub struct DidsDB {
    repository: Arc<dyn DidRepository>,
}

impl DidsDB {
    pub fn new(repository: Arc<dyn DidRepository>) -> Self {
        Self { repository }
    }

    pub async fn create(&self, organisation: &Organisation, params: TestingDidParams) -> Did {
        let now = OffsetDateTime::now_utc();

        let did_id = params.id.unwrap_or(DidId::from(Uuid::new_v4()));
        let did = Did {
            id: did_id.to_owned(),
            created_date: params.created_date.unwrap_or(now),
            last_modified: params.last_modified.unwrap_or(now),
            name: params.name.unwrap_or_default(),
            organisation: Some(organisation.clone()),
            did: params
                .did
                .unwrap_or(DidValue::from_str(&format!("did:test:{did_id}")).unwrap()),
            did_type: params.did_type.unwrap_or(DidType::Local),
            did_method: params.did_method.unwrap_or("TEST".to_string()),
            deactivated: params.deactivated.unwrap_or(false),
            keys: params.keys,
        };

        self.repository.create_did(did.clone()).await.unwrap();

        did
    }
}
