use std::sync::Arc;

use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::model::identifier::Identifier;
use crate::model::revocation_list::{RevocationList, StatusListCredentialFormat};
use crate::proto::certificate_validator::MockCertificateValidator;
use crate::proto::http_client::MockHttpClient;
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_storage::provider::MockKeyProvider;
use crate::provider::remote_entity_storage::{MockRemoteEntityStorage, RemoteEntityType};
use crate::provider::revocation::RevocationMethod;
use crate::provider::revocation::bitstring_status_list::BitstringStatusList;
use crate::provider::revocation::bitstring_status_list::resolver::StatusListCachingLoader;
use crate::provider::revocation::model::CredentialRevocationInfo;
use crate::repository::revocation_list_repository::MockRevocationListRepository;
use crate::service::test_utilities::{dummy_credential, dummy_did, dummy_identifier};

#[tokio::test]
async fn test_check_revocation_status_as_issuer_suspension_allowed() {
    let status = revocation_status(true).await;

    assert!(
        status
            .iter()
            .any(|s| s.credential_status.status_purpose.as_deref() == Some("suspension"))
    );
}

#[tokio::test]
async fn test_check_revocation_status_as_issuer_suspension_forbidden() {
    let status = revocation_status(false).await;

    assert!(
        !status
            .iter()
            .any(|s| s.credential_status.status_purpose.as_deref() == Some("suspension"))
    );
}

async fn revocation_status(suspension: bool) -> Vec<CredentialRevocationInfo> {
    let key_algorithm_provider = MockKeyAlgorithmProvider::default();
    let did_method_provider = MockDidMethodProvider::default();
    let key_provider = MockKeyProvider::default();
    let storage = MockRemoteEntityStorage::default();
    let client = Arc::new(MockHttpClient::new());
    let caching_loader = StatusListCachingLoader::new(
        RemoteEntityType::StatusListCredential,
        Arc::new(storage),
        10,
        Duration::hours(1),
        Duration::hours(1),
    );
    let formatter_provider = MockCredentialFormatterProvider::default();

    let mut revocation_list_repository = MockRevocationListRepository::new();
    revocation_list_repository
        .expect_get_revocation_by_issuer_identifier_id()
        .returning(|_, purpose, r#type, _| {
            Ok(Some(RevocationList {
                id: Uuid::new_v4(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                credentials: vec![],
                format: StatusListCredentialFormat::Jwt,
                r#type,
                purpose,
                issuer_identifier: None,
            }))
        });
    revocation_list_repository
        .expect_get_max_used_index()
        .returning(|_| Ok(Some(0)));
    revocation_list_repository
        .expect_create_entry()
        .returning(|_, _, _| Ok(()));

    let revocation_list = BitstringStatusList::new(
        Some("".into()),
        Arc::new(key_algorithm_provider),
        Arc::new(did_method_provider),
        Arc::new(key_provider),
        caching_loader,
        Arc::new(formatter_provider),
        Arc::new(MockCertificateValidator::default()),
        Arc::new(revocation_list_repository),
        client,
        None,
    );

    let mut credential = dummy_credential();
    credential.issuer_identifier = Some(Identifier {
        did: Some(dummy_did()),
        ..dummy_identifier()
    });
    if let Some(ref mut schema) = credential.schema {
        schema.allow_suspension = suspension;
    }

    revocation_list
        .add_issued_credential(&credential)
        .await
        .unwrap()
}
