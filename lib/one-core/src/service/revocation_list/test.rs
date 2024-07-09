use mockall::predicate::eq;
use one_providers::key_algorithm::provider::MockKeyAlgorithmProvider;
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

use one_providers::crypto::MockCryptoProvider;

use crate::model::revocation_list::RevocationListPurpose;
use crate::{
    model::revocation_list::{RevocationList, RevocationListRelations},
    provider::{
        credential_formatter::provider::MockCredentialFormatterProvider,
        did_method::provider::MockDidMethodProvider, key_storage::provider::MockKeyProvider,
        revocation::provider::MockRevocationMethodProvider,
    },
    repository::{
        credential_repository::MockCredentialRepository,
        revocation_list_repository::MockRevocationListRepository,
        validity_credential_repository::MockValidityCredentialRepository,
    },
    service::{revocation_list::RevocationListService, test_utilities::generic_config},
};

#[derive(Default)]
struct Repositories {
    pub credential_repository: MockCredentialRepository,
    pub lvvc_repository: MockValidityCredentialRepository,
    pub revocation_list_repository: MockRevocationListRepository,
    pub crypto_provider: MockCryptoProvider,
    pub did_method_provider: MockDidMethodProvider,
    pub formatter_provider: MockCredentialFormatterProvider,
    pub key_provider: MockKeyProvider,
    pub key_algorithm_provider: MockKeyAlgorithmProvider,
    pub revocation_method_provider: MockRevocationMethodProvider,
}

fn setup_service(repositories: Repositories) -> RevocationListService {
    RevocationListService::new(
        None,
        Arc::new(repositories.credential_repository),
        Arc::new(repositories.lvvc_repository),
        Arc::new(repositories.revocation_list_repository),
        Arc::new(repositories.crypto_provider),
        Arc::new(repositories.did_method_provider),
        Arc::new(repositories.formatter_provider),
        Arc::new(repositories.key_provider),
        Arc::new(repositories.key_algorithm_provider),
        Arc::new(repositories.revocation_method_provider),
        Arc::new(generic_config().core),
    )
}

#[tokio::test]
async fn test_get_revocation_list() {
    let mut revocation_list_repository = MockRevocationListRepository::default();
    let revocation_id = Uuid::new_v4();
    {
        let revocation = RevocationList {
            id: revocation_id,
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            credentials: b"revocation-list-credential".to_vec(),
            purpose: RevocationListPurpose::Revocation,
            issuer_did: None,
        };
        revocation_list_repository
            .expect_get_revocation_list()
            .times(1)
            .with(
                eq(revocation_id.to_owned()),
                eq(RevocationListRelations::default()),
            )
            .returning(move |_, _| Ok(Some(revocation.clone())));
    }

    let service = setup_service(Repositories {
        revocation_list_repository,
        ..Default::default()
    });

    let result = service
        .get_revocation_list_by_id(&revocation_id.to_owned())
        .await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result, "revocation-list-credential");
}
