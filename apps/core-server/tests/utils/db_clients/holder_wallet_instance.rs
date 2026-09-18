use std::sync::Arc;

use one_core::model::instance::{Instance, InstanceRole, InstanceStatus, WalletProviderType};
use one_core::model::key::Key;
use one_core::model::organisation::Organisation;
use one_core::repository::instance_repository::InstanceRepository;
use shared_types::{InstanceId, ManagedInstanceId};
use uuid::Uuid;

pub struct HolderWalletInstancesDB {
    repository: Arc<dyn InstanceRepository>,
}

#[derive(Default)]
pub struct TestHolderWalletInstanceParams {
    pub status: Option<InstanceStatus>,
    pub provider_type: Option<WalletProviderType>,
    pub provider_name: Option<String>,
    pub provider_url: Option<String>,
    pub provider_wallet_unit_id: Option<ManagedInstanceId>,
    pub role: Option<InstanceRole>,
    pub user_nonce: Option<String>,
}

impl HolderWalletInstancesDB {
    pub fn new(repository: Arc<dyn InstanceRepository>) -> Self {
        Self { repository }
    }

    pub async fn create(
        &self,
        organisation: Organisation,
        authentication_key: Option<Key>,
        test_holder_wallet_instance: TestHolderWalletInstanceParams,
    ) -> Instance {
        let now = one_core::clock::now_utc();
        let instance = Instance {
            id: Uuid::new_v4().into(),
            created_date: now,
            last_modified: now,
            status: test_holder_wallet_instance
                .status
                .unwrap_or(InstanceStatus::Active),
            role: test_holder_wallet_instance
                .role
                .unwrap_or(InstanceRole::Wallet),
            provider_type: test_holder_wallet_instance
                .provider_type
                .unwrap_or(WalletProviderType::ProcivisOne),
            provider_name: test_holder_wallet_instance
                .provider_name
                .unwrap_or("PROCIVIS_ONE".to_string()),
            provider_url: test_holder_wallet_instance
                .provider_url
                .unwrap_or("https://wallet.provider".to_string()),
            organisation: organisation.into(),
            authentication_key: authentication_key.map(|key| key.into()),
            provider_instance_id: test_holder_wallet_instance
                .provider_wallet_unit_id
                .unwrap_or(Uuid::new_v4().into()),
            nonce: None,
            user_nonce: test_holder_wallet_instance.user_nonce,
            wallet_attestations: Default::default(),
        };

        let id = self.repository.create(instance).await.unwrap();

        self.repository.get(&id).await.unwrap()
    }

    pub async fn get(&self, id: impl Into<InstanceId>) -> Instance {
        self.repository.get(&id.into()).await.unwrap()
    }
}
