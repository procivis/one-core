use std::sync::Arc;

use time::Duration;
use uuid::Uuid;

use crate::model::identifier::Identifier;
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
use crate::provider::revocation::model::{CredentialAdditionalData, CredentialRevocationInfo};
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

    let revocation_list = BitstringStatusList::new(
        Some("".into()),
        Arc::new(key_algorithm_provider),
        Arc::new(did_method_provider),
        Arc::new(key_provider),
        caching_loader,
        Arc::new(formatter_provider),
        Arc::new(MockCertificateValidator::default()),
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

    let additional_data = Some(CredentialAdditionalData {
        credentials_by_issuer_identifier: vec![credential.clone()],
        revocation_list_id: Uuid::new_v4(),
        suspension_list_id: Some(Uuid::new_v4()),
    });

    let result = revocation_list
        .add_issued_credential(&credential, additional_data)
        .await
        .unwrap();

    result.1
}
