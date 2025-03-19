use std::str::FromStr;
use std::sync::Arc;

use one_core::model::did::{Did, DidRelations, DidType};
use one_core::model::key::KeyRelations;
use one_core::model::organisation::Organisation;
use one_core::repository::did_repository::DidRepository;
use shared_types::{DidId, DidValue};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::fixtures::{unwrap_or_random, TestingDidParams};

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
            name: unwrap_or_random(params.name),
            organisation: Some(organisation.clone()),
            did: params
                .did
                .unwrap_or(DidValue::from_str(&format!("did:test:{did_id}")).unwrap()),
            did_type: params.did_type.unwrap_or(DidType::Local),
            did_method: params.did_method.unwrap_or("KEY".to_string()),
            deactivated: params.deactivated.unwrap_or(false),
            keys: params.keys,
        };

        let id = self.repository.create_did(did.clone()).await.unwrap();

        self.get(&id).await
    }

    pub async fn get(&self, did_id: &DidId) -> Did {
        self.repository
            .get_did(
                did_id,
                &DidRelations {
                    keys: Some(KeyRelations::default()),
                    organisation: Some(Default::default()),
                },
            )
            .await
            .unwrap()
            .unwrap()
    }

    pub async fn get_did_by_value(&self, did: &DidValue) -> Did {
        self.repository
            .get_did_by_value(
                did,
                &DidRelations {
                    keys: Some(KeyRelations::default()),
                    ..Default::default()
                },
            )
            .await
            .unwrap()
            .unwrap()
    }
}
