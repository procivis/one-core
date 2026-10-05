use std::str::FromStr;
use std::sync::Arc;

use one_core::model::did::{Did, DidType};
use one_core::model::organisation::Organisation;
use one_core::repository::did_repository::DidRepository;
use shared_types::{DidId, DidValue};
use uuid::Uuid;

use crate::fixtures::{TestingDidParams, unwrap_or_random};

pub struct DidsDB {
    repository: Arc<dyn DidRepository>,
}

impl DidsDB {
    pub fn new(repository: Arc<dyn DidRepository>) -> Self {
        Self { repository }
    }

    pub async fn create(&self, organisation: Organisation, params: TestingDidParams) -> Did {
        let now = one_core::clock::now_utc();

        let did_id = params.id.unwrap_or(DidId::from(Uuid::new_v4()));
        let did = Did {
            deleted_at: None,
            id: did_id.to_owned(),
            created_date: params.created_date.unwrap_or(now),
            last_modified: params.last_modified.unwrap_or(now),
            name: unwrap_or_random(params.name),
            organisation: organisation.into(),
            did: params
                .did
                .unwrap_or(DidValue::from_str(&format!("did:test:{did_id}")).unwrap()),
            did_type: params.did_type.unwrap_or(DidType::Local),
            did_method: params.did_method.unwrap_or("KEY".into()),
            deactivated: params.deactivated.unwrap_or(false),
            keys: params.keys.unwrap_or_default().into(),
            log: params.log,
        };

        let id = self.repository.create_did(did.clone()).await.unwrap();

        self.get(&id).await
    }

    pub async fn get(&self, did_id: &DidId) -> Did {
        self.repository.get_did(did_id, None).await.unwrap()
    }
}
