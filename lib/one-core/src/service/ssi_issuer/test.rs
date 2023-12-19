use std::sync::Arc;

use time::OffsetDateTime;
use uuid::Uuid;

use crate::provider::transport_protocol::provider::MockTransportProtocolProvider;
use crate::service::test_utilities::{dummy_credential, dummy_did};
use crate::{
    model::credential::{Credential, CredentialId, CredentialState, CredentialStateEnum},
    repository::did_repository::MockDidRepository,
    repository::mock::credential_repository::MockCredentialRepository,
    service::ssi_issuer::SSIIssuerService,
};

#[tokio::test]
async fn test_issuer_connect_succeeds() {
    let credential_id: CredentialId = Uuid::new_v4();

    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_get_credential()
        .withf(move |_credential_id, _| {
            assert_eq!(_credential_id, &credential_id);
            true
        })
        .once()
        .return_once(move |_, _| Ok(dummy_credential()));

    credential_repository
        .expect_update_credential()
        .once()
        .return_once(|_| Ok(()));

    let mut did_repository = MockDidRepository::new();
    did_repository
        .expect_get_did_by_value()
        .once()
        .return_once(move |_, _| Ok(dummy_did()));

    let service = SSIIssuerService {
        credential_repository: Arc::new(credential_repository),
        did_repository: Arc::new(did_repository),
        ..mock_ssi_issuer_service()
    };

    let holder_did_value = "holder did".parse().unwrap();

    service
        .issuer_connect(&credential_id, &holder_did_value)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_issuer_reject_succeeds() {
    let credential_id: CredentialId = Uuid::new_v4();

    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_get_credential()
        .withf(move |_credential_id, _| {
            assert_eq!(_credential_id, &credential_id);
            true
        })
        .once()
        .return_once(move |_, _| {
            Ok(Credential {
                state: Some(vec![CredentialState {
                    created_date: OffsetDateTime::now_utc(),
                    state: CredentialStateEnum::Offered,
                }]),
                ..dummy_credential()
            })
        });

    credential_repository
        .expect_update_credential()
        .once()
        .return_once(|_| Ok(()));

    let service = SSIIssuerService {
        credential_repository: Arc::new(credential_repository),
        ..mock_ssi_issuer_service()
    };

    service.issuer_reject(&credential_id).await.unwrap();
}

fn mock_ssi_issuer_service() -> SSIIssuerService {
    SSIIssuerService {
        credential_repository: Arc::new(MockCredentialRepository::new()),
        did_repository: Arc::new(MockDidRepository::new()),
        protocol_provider: Arc::new(MockTransportProtocolProvider::new()),
    }
}
