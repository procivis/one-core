use std::sync::Arc;

use mockall::predicate::{always, eq};
use uuid::Uuid;

use super::SuspendCheckProvider;
use crate::model::credential::{Credential, CredentialStateEnum, GetCredentialList};
use crate::model::history::{HistoryAction, HistoryEntityType};
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::key_storage::provider::MockKeyProvider;
use crate::provider::revocation::model::{CredentialRevocationState, RevocationUpdate};
use crate::provider::revocation::provider::MockRevocationMethodProvider;
use crate::provider::revocation::MockRevocationMethod;
use crate::provider::task::suspend_check::dto::SuspendCheckResultDTO;
use crate::provider::task::Task;
use crate::repository::credential_repository::MockCredentialRepository;
use crate::repository::history_repository::MockHistoryRepository;
use crate::repository::revocation_list_repository::MockRevocationListRepository;
use crate::repository::validity_credential_repository::MockValidityCredentialRepository;
use crate::service::test_utilities::{dummy_credential, dummy_did_document};

#[derive(Default)]
struct TestDependencies {
    pub credential_repository: MockCredentialRepository,
    pub revocation_method_provider: MockRevocationMethodProvider,
    pub history_repository: MockHistoryRepository,
    pub revocation_list_repository: MockRevocationListRepository,
    pub validity_credential_repository: MockValidityCredentialRepository,
    pub formatter_provider: MockCredentialFormatterProvider,
    pub did_method_provider: MockDidMethodProvider,
    pub key_provider: MockKeyProvider,
    pub core_base_url: Option<String>,
}

fn setup(dependencies: TestDependencies) -> impl Task {
    SuspendCheckProvider::new(
        Arc::new(dependencies.credential_repository),
        Arc::new(dependencies.revocation_method_provider),
        Arc::new(dependencies.history_repository),
        Arc::new(dependencies.revocation_list_repository),
        Arc::new(dependencies.validity_credential_repository),
        Arc::new(dependencies.formatter_provider),
        Arc::new(dependencies.did_method_provider),
        Arc::new(dependencies.key_provider),
        dependencies.core_base_url,
    )
}

#[tokio::test]
async fn test_run_no_update() {
    let mut credential_repository = MockCredentialRepository::default();
    credential_repository
        .expect_get_credential_list()
        .once()
        .return_once(|_| {
            Ok(GetCredentialList {
                values: vec![],
                total_pages: 0,
                total_items: 0,
            })
        });

    let task = setup(TestDependencies {
        credential_repository,
        ..Default::default()
    });

    let result = task.run().await.unwrap();
    let result: SuspendCheckResultDTO = serde_json::from_value(result).unwrap();
    assert_eq!(0, result.updated_credential_ids.len());
    assert_eq!(0, result.total_checks);
}

#[tokio::test]
async fn test_run_one_update() {
    let credential = Credential {
        ..dummy_credential()
    };

    let mut credential_repository = MockCredentialRepository::default();
    let mut did_method_provider = MockDidMethodProvider::default();
    did_method_provider
        .expect_resolve()
        .once()
        .return_once(|did| Ok(dummy_did_document(did)));

    credential_repository
        .expect_get_credential_list()
        .once()
        .return_once({
            let clone = credential.clone();
            move |_| {
                Ok(GetCredentialList {
                    values: vec![clone],
                    total_pages: 0,
                    total_items: 1,
                })
            }
        });

    credential_repository
        .expect_get_credential()
        .once()
        .withf({
            let id = credential.id;
            move |credential_id, _| {
                assert_eq!(credential_id, &id);
                true
            }
        })
        .return_once({
            let clone = credential.clone();
            move |_, _| Ok(Some(clone))
        });

    credential_repository
        .expect_update_credential()
        .once()
        .withf({
            let id = credential.id;
            move |request| {
                assert_eq!(request.id, id);
                let state = request.state.as_ref().unwrap();
                assert_eq!(state.state, CredentialStateEnum::Accepted);
                assert_eq!(state.suspend_end_date, None);
                true
            }
        })
        .return_once(|_| Ok(()));

    let mut revocation_method = MockRevocationMethod::default();
    revocation_method
        .expect_mark_credential_as()
        .once()
        .with(
            eq(credential.clone()),
            eq(CredentialRevocationState::Valid),
            always(),
        )
        .return_once(|_, _, _| {
            Ok(RevocationUpdate {
                status_type: "NONE".to_string(),
                data: vec![],
            })
        });
    revocation_method
        .expect_get_status_type()
        .return_once(|| "NONE".to_string());

    let mut revocation_method_provider = MockRevocationMethodProvider::default();
    let revocation_method = Arc::new(revocation_method);
    revocation_method_provider
        .expect_get_revocation_method()
        .times(1)
        .returning(move |_| Some(revocation_method.clone()));

    let mut history_repository = MockHistoryRepository::default();
    history_repository
        .expect_create_history()
        .once()
        .withf({
            let id = credential.id;
            move |entry| {
                assert_eq!(entry.entity_id, Some(id.into()));
                assert_eq!(entry.entity_type, HistoryEntityType::Credential);
                assert_eq!(entry.action, HistoryAction::Reactivated);
                true
            }
        })
        .returning(|_| Ok(Uuid::new_v4().into()));

    let task = setup(TestDependencies {
        credential_repository,
        revocation_method_provider,
        did_method_provider,
        history_repository,
        ..Default::default()
    });

    let result = task.run().await.unwrap();
    let result: SuspendCheckResultDTO = serde_json::from_value(result).unwrap();
    assert_eq!(1, result.updated_credential_ids.len());
    assert_eq!(
        &credential.id,
        result.updated_credential_ids.first().unwrap()
    );
    assert_eq!(1, result.total_checks);
}
