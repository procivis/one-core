use std::sync::Arc;

use one_core::model::organisation::Organisation;
use one_core::model::verifier_instance::{VerifierInstance, VerifierInstanceRelations};
use one_core::repository::verifier_instance_repository::VerifierInstanceRepository;
use shared_types::VerifierInstanceId;
use uuid::Uuid;

pub struct VerifierInstancesDB {
    repository: Arc<dyn VerifierInstanceRepository>,
}

#[derive(Default)]
pub struct TestVerifierInstanceParams {
    pub id: Option<VerifierInstanceId>,
    pub provider_type: Option<String>,
    pub provider_name: Option<String>,
    pub provider_url: Option<String>,
}

impl VerifierInstancesDB {
    pub fn new(repository: Arc<dyn VerifierInstanceRepository>) -> Self {
        Self { repository }
    }

    pub async fn create(
        &self,
        organisation: Organisation,
        params: TestVerifierInstanceParams,
    ) -> VerifierInstance {
        let verifier_instance = VerifierInstance {
            id: params.id.unwrap_or(Uuid::new_v4().into()),
            created_date: one_core::clock::now_utc(),
            last_modified: one_core::clock::now_utc(),
            provider_type: params.provider_type.unwrap_or("PROCIVIS_ONE".to_string()),
            provider_name: params.provider_name.unwrap_or("provider-name".to_string()),
            provider_url: params
                .provider_url
                .unwrap_or("http://provider.url".to_string()),
            organisation: Some(organisation),
        };

        self.repository
            .create(verifier_instance.clone())
            .await
            .unwrap();

        verifier_instance
    }

    pub async fn get(
        &self,
        id: impl Into<VerifierInstanceId>,
        relations: &VerifierInstanceRelations,
    ) -> Option<VerifierInstance> {
        self.repository.get(&id.into(), relations).await.unwrap()
    }
}
