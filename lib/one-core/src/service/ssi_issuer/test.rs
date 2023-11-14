use std::sync::Arc;

use time::OffsetDateTime;
use uuid::Uuid;

use crate::provider::transport_protocol::provider::MockTransportProtocolProvider;
use crate::{
    model::{
        claim::Claim,
        claim_schema::ClaimSchema,
        credential::{Credential, CredentialId, CredentialState, CredentialStateEnum},
        credential_schema::{CredentialSchema, CredentialSchemaClaim},
        did::{Did, DidType},
        interaction::Interaction,
        organisation::Organisation,
    },
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

fn dummy_credential() -> Credential {
    let claim_schema_id = Uuid::new_v4();

    Credential {
        id: Uuid::new_v4(),
        created_date: OffsetDateTime::now_utc(),
        issuance_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        credential: b"credential".to_vec(),
        transport: "protocol".to_string(),
        state: Some(vec![CredentialState {
            created_date: OffsetDateTime::now_utc(),
            state: CredentialStateEnum::Pending,
        }]),
        claims: Some(vec![Claim {
            id: Uuid::new_v4(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            value: "claim value".to_string(),
            schema: Some(ClaimSchema {
                id: claim_schema_id,
                key: "key".to_string(),
                data_type: "data type".to_string(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
            }),
        }]),
        issuer_did: None,
        holder_did: None,
        schema: Some(CredentialSchema {
            id: Uuid::new_v4(),
            deleted_at: None,
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            name: "schema".to_string(),
            format: "format".to_string(),
            revocation_method: "revocation method".to_string(),
            claim_schemas: Some(vec![CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: claim_schema_id,
                    key: "key".to_string(),
                    data_type: "data type".to_string(),
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                },
                required: true,
            }]),
            organisation: Some(Organisation {
                id: Uuid::new_v4(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
            }),
        }),
        interaction: Some(Interaction {
            id: Uuid::new_v4(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            host: Some("http://www.host.co".parse().unwrap()),
            data: Some(b"interaction data".to_vec()),
        }),
        revocation_list: None,
        key: None,
    }
}

fn dummy_did() -> Did {
    Did {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        name: "John".to_string(),
        did: "did".parse().unwrap(),
        did_type: DidType::Local,
        did_method: "John".to_string(),
        keys: None,
        organisation: None,
    }
}
