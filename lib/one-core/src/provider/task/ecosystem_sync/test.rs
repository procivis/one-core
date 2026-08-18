use std::sync::Arc;

use mockall::Sequence;
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::model::common::GetListResponse;
use crate::model::instance::{Instance, InstanceRole, InstanceStatus, WalletProviderType};
use crate::proto::ecosystem_sync::MockEcosystemSync;
use crate::provider::task::Task;
use crate::provider::task::ecosystem_sync::EcosystemSyncTask;
use crate::repository::instance_repository::MockInstanceRepository;
use crate::service::test_utilities::dummy_organisation;

/// The task walks every page of instances and reports what the sync did across all of them.
#[tokio::test]
async fn test_syncs_every_instance() {
    let mut seq = Sequence::new();
    let mut instance_repository = MockInstanceRepository::new();
    instance_repository
        .expect_list()
        .once()
        .returning(|_| {
            Ok(GetListResponse::one_page_of(vec![
                dummy_instance(),
                dummy_instance(),
            ]))
        })
        .in_sequence(&mut seq);
    instance_repository
        .expect_list()
        .once()
        .returning(|_| Ok(GetListResponse::empty()))
        .in_sequence(&mut seq);

    let mut ecosystem_sync = MockEcosystemSync::new();
    ecosystem_sync
        .expect_sync_instance()
        .times(2)
        .returning(|_| Ok(3));

    let task = EcosystemSyncTask::new(Arc::new(instance_repository), Arc::new(ecosystem_sync));

    let result = task.run(None).await.unwrap();
    assert_eq!(result["syncedTrustCollectionsCount"], 6);
}

fn dummy_instance() -> Instance {
    let now = crate::clock::now_utc();
    Instance {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        provider_type: WalletProviderType::ProcivisOne,
        provider_name: "wallet-provider".to_string(),
        provider_url: "https://wallet-provider.org".to_string(),
        provider_instance_id: Uuid::new_v4().into(),
        status: InstanceStatus::Active,
        role: InstanceRole::Wallet,
        organisation: dummy_organisation(None).into(),
        authentication_key: None,
        wallet_unit_attestations: Default::default(),
        nonce: None,
        user_nonce: None,
    }
}
