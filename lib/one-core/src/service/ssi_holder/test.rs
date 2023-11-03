use std::{collections::HashMap, sync::Arc};

use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    config::data_structure::{
        AccessModifier, ConfigEntity, CoreConfig, KeyAlgorithmParams, Param, ParamsEnum,
        TranslatableString,
    },
    crypto::{
        signer::{MockSigner, Signer},
        Crypto,
    },
    model::{
        credential::{Credential, CredentialState, CredentialStateEnum},
        did::{Did, DidType, KeyRole, RelatedKey},
        interaction::Interaction,
        key::Key,
        organisation::Organisation,
        proof::{Proof, ProofState, ProofStateEnum},
    },
    provider::key_storage::provider::MockKeyProvider,
    provider::transport_protocol::{
        dto::SubmitIssuerResponse, provider::MockTransportProtocolProvider, MockTransportProtocol,
    },
    provider::{
        credential_formatter::{
            provider::MockCredentialFormatterProvider, MockCredentialFormatter,
        },
        key_storage::mock_key_storage::MockKeyStorage,
    },
    repository::did_repository::MockDidRepository,
    repository::mock::credential_repository::MockCredentialRepository,
    repository::mock::proof_repository::MockProofRepository,
    service::{
        error::ServiceError,
        ssi_holder::{
            dto::{PresentationSubmitCredentialRequestDTO, PresentationSubmitRequestDTO},
            SSIHolderService,
        },
    },
};

#[tokio::test]
async fn test_reject_proof_request_succeeds_and_sets_state_to_rejected_when_latest_state_is_pending(
) {
    let interaction_id = Uuid::new_v4();
    let proof_id = Uuid::new_v4();
    let protocol = "transport-protocol";

    let mut proof_repository = MockProofRepository::new();
    proof_repository
        .expect_get_proof_by_interaction_id()
        .once()
        .return_once(move |_, _| {
            Ok(Proof {
                id: proof_id,
                transport: protocol.to_string(),
                state: Some(vec![
                    ProofState {
                        created_date: OffsetDateTime::now_utc(),
                        last_modified: OffsetDateTime::now_utc(),
                        state: ProofStateEnum::Pending,
                    },
                    ProofState {
                        created_date: OffsetDateTime::now_utc(),
                        last_modified: OffsetDateTime::now_utc(),
                        state: ProofStateEnum::Created,
                    },
                ]),
                interaction: Some(Interaction {
                    id: interaction_id,
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    host: Some("http://www.host.co".parse().unwrap()),
                    data: None,
                }),
                ..dummy_proof()
            })
        });

    proof_repository
        .expect_set_proof_state()
        .withf(move |_proof_id, _proof_state| {
            assert_eq!(_proof_id, &proof_id);
            assert_eq!(_proof_state.state, ProofStateEnum::Rejected);
            true
        })
        .once()
        .return_once(move |_, _| Ok(()));

    let mut transport_protocol_mock = MockTransportProtocol::new();
    transport_protocol_mock
        .expect_reject_proof()
        .withf(move |_proof_id| {
            assert_eq!(_proof_id.id, proof_id);
            true
        })
        .once()
        .return_once(move |_| Ok(()));

    let mut protocol_provider = MockTransportProtocolProvider::new();
    protocol_provider
        .expect_get_protocol()
        .withf(move |_protocol| {
            assert_eq!(_protocol, protocol);
            true
        })
        .once()
        .return_once(move |_| Ok(Arc::new(transport_protocol_mock)));

    let service = SSIHolderService {
        proof_repository: Arc::new(proof_repository),
        protocol_provider: Arc::new(protocol_provider),
        ..mock_ssi_holder_service()
    };

    service.reject_proof_request(&interaction_id).await.unwrap();
}

#[tokio::test]
async fn test_reject_proof_request_fails_when_latest_state_is_not_pending() {
    let reject_proof_for_state = |state| async {
        let interaction_id = Uuid::new_v4();
        let proof_id = Uuid::new_v4();
        let protocol = "transport-protocol";
        let mut proof_repository = MockProofRepository::new();
        proof_repository
            .expect_get_proof_by_interaction_id()
            .once()
            .return_once(move |_, _| {
                Ok(Proof {
                    id: proof_id,
                    transport: protocol.to_string(),
                    state: Some(vec![
                        ProofState {
                            created_date: OffsetDateTime::now_utc(),
                            last_modified: OffsetDateTime::now_utc(),
                            state,
                        },
                        ProofState {
                            created_date: OffsetDateTime::now_utc(),
                            last_modified: OffsetDateTime::now_utc(),
                            state: ProofStateEnum::Pending,
                        },
                    ]),
                    interaction: Some(Interaction {
                        id: interaction_id,
                        created_date: OffsetDateTime::now_utc(),
                        last_modified: OffsetDateTime::now_utc(),
                        host: Some("http://www.host.co".parse().unwrap()),
                        data: None,
                    }),
                    ..dummy_proof()
                })
            });

        let service = SSIHolderService {
            proof_repository: Arc::new(proof_repository),
            ..mock_ssi_holder_service()
        };

        service.reject_proof_request(&interaction_id).await
    };

    for state in [
        ProofStateEnum::Created,
        ProofStateEnum::Offered,
        ProofStateEnum::Accepted,
        ProofStateEnum::Rejected,
        ProofStateEnum::Error,
    ] {
        assert2::assert!(
            let Err(ServiceError::AlreadyExists) = reject_proof_for_state(state).await
        );
    }
}

#[tokio::test]
async fn test_submit_proof_succeeds() {
    let interaction_id = Uuid::new_v4();

    let proof_id = Uuid::new_v4();
    let protocol = "protocol";

    let key_storage_type = "storage type";
    let key_type = "key_type";

    let mut proof_repository = MockProofRepository::new();
    proof_repository
        .expect_get_proof_by_interaction_id()
        .withf(move |_interaction_id: &Uuid, _| {
            assert_eq!(_interaction_id, &interaction_id);
            true
        })
        .once()
        .returning(move |_, _| {
            Ok(Proof {
                id: proof_id,
                transport: protocol.to_string(),
                state: Some(vec![
                    ProofState {
                        created_date: OffsetDateTime::now_utc(),
                        last_modified: OffsetDateTime::now_utc(),
                        state: ProofStateEnum::Pending,
                    },
                    ProofState {
                        created_date: OffsetDateTime::now_utc(),
                        last_modified: OffsetDateTime::now_utc(),
                        state: ProofStateEnum::Created,
                    },
                ]),
                holder_did: Some(Did {
                    keys: Some(vec![RelatedKey {
                        role: KeyRole::AssertionMethod,
                        key: Key {
                            id: Uuid::new_v4(),
                            created_date: OffsetDateTime::now_utc(),
                            last_modified: OffsetDateTime::now_utc(),
                            public_key: b"public_key".to_vec(),
                            name: "key name".to_string(),
                            private_key: b"public_key".to_vec(),
                            storage_type: key_storage_type.to_string(),
                            key_type: key_type.to_string(),
                            organisation: Some(Organisation {
                                id: Uuid::new_v4(),
                                created_date: OffsetDateTime::now_utc(),
                                last_modified: OffsetDateTime::now_utc(),
                            }),
                        },
                    }]),
                    ..dummy_did()
                }),
                interaction: Some(Interaction {
                    id: interaction_id,
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    host: Some("http://www.host.co".parse().unwrap()),
                    data: None,
                }),
                ..dummy_proof()
            })
        });

    proof_repository
        .expect_set_proof_claims()
        .once()
        .returning(|_, _| Ok(()));

    proof_repository
        .expect_set_proof_state()
        .once()
        .returning(|_, _| Ok(()));

    let credential_id = Uuid::new_v4();
    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_get_credential()
        .once()
        .returning(move |_, _| {
            Ok(Credential {
                id: credential_id,
                credential: b"credential data".to_vec(),
                transport: "protocol".to_string(),
                ..dummy_credential()
            })
        });

    let mut formatter = MockCredentialFormatter::new();
    formatter
        .expect_format_presentation()
        .once()
        .returning(|_, _, _, _| Ok("presentation".to_string()));

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_formatter()
        .once()
        .return_once(move |_| Ok(Arc::new(formatter)));

    let mut transport_protocol_mock = MockTransportProtocol::new();
    transport_protocol_mock
        .expect_submit_proof()
        .withf(move |_proof_id, _| {
            assert_eq!(_proof_id.id, proof_id);
            true
        })
        .once()
        .returning(|_, _| Ok(()));

    let mut protocol_provider = MockTransportProtocolProvider::new();
    protocol_provider
        .expect_get_protocol()
        .withf(move |_protocol| {
            assert_eq!(_protocol, protocol);
            true
        })
        .once()
        .return_once(move |_| Ok(Arc::new(transport_protocol_mock)));

    let mut key_storage = MockKeyStorage::new();
    key_storage
        .expect_decrypt_private_key()
        .once()
        .return_once(|_| Ok(b"decrypted private key".to_vec()));

    let mut key_provider = MockKeyProvider::new();
    key_provider
        .expect_get_key_storage()
        .once()
        .return_once(move |_| Ok(Arc::new(key_storage)));

    let signer: Arc<dyn Signer + Send + Sync> = Arc::new(MockSigner::new());

    let algorithm = algorithm_config(key_type);
    let config = CoreConfig {
        key_algorithm: HashMap::from_iter([(key_type.to_string(), algorithm)]),
        ..dummy_config()
    };

    let service = SSIHolderService {
        credential_repository: Arc::new(credential_repository),
        proof_repository: Arc::new(proof_repository),
        formatter_provider: Arc::new(formatter_provider),
        protocol_provider: Arc::new(protocol_provider),
        key_provider: Arc::new(key_provider),
        crypto: Arc::new(Crypto {
            signers: HashMap::from_iter([(key_type.to_string(), signer)]),
            ..dummy_crypto()
        }),
        config: Arc::new(config),
        ..mock_ssi_holder_service()
    };

    service
        .submit_proof(PresentationSubmitRequestDTO {
            interaction_id,
            submit_credentials: std::iter::once((
                "cred1".to_string(),
                PresentationSubmitCredentialRequestDTO {
                    credential_id,
                    submit_claims: vec![],
                },
            ))
            .collect(),
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn test_accept_credential() {
    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_get_credentials_by_interaction_id()
        .once()
        .return_once(move |_, _| Ok(vec![dummy_credential()]));
    credential_repository
        .expect_update_credential()
        .once()
        .returning(|_| Ok(()));

    let mut transport_protocol_mock = MockTransportProtocol::new();
    transport_protocol_mock
        .expect_accept_credential()
        .once()
        .returning(|_| {
            Ok(SubmitIssuerResponse {
                credential: "credential".to_string(),
                format: "credential format".to_string(),
            })
        });

    let mut protocol_provider = MockTransportProtocolProvider::new();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Ok(Arc::new(transport_protocol_mock)));

    let service = SSIHolderService {
        credential_repository: Arc::new(credential_repository),
        protocol_provider: Arc::new(protocol_provider),
        ..mock_ssi_holder_service()
    };

    let interaction_id = Uuid::new_v4();
    service.accept_credential(&interaction_id).await.unwrap();
}

#[tokio::test]
async fn test_reject_credential() {
    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_get_credentials_by_interaction_id()
        .once()
        .return_once(move |_, _| Ok(vec![dummy_credential()]));
    credential_repository
        .expect_update_credential()
        .once()
        .returning(|_| Ok(()));

    let mut transport_protocol_mock = MockTransportProtocol::new();
    transport_protocol_mock
        .expect_reject_credential()
        .once()
        .returning(|_| Ok(()));

    let mut protocol_provider = MockTransportProtocolProvider::new();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Ok(Arc::new(transport_protocol_mock)));

    let service = SSIHolderService {
        credential_repository: Arc::new(credential_repository),
        protocol_provider: Arc::new(protocol_provider),
        ..mock_ssi_holder_service()
    };

    let interaction_id = Uuid::new_v4();
    service.reject_credential(&interaction_id).await.unwrap();
}

fn mock_ssi_holder_service() -> SSIHolderService {
    SSIHolderService {
        credential_repository: Arc::new(MockCredentialRepository::new()),
        proof_repository: Arc::new(MockProofRepository::new()),
        did_repository: Arc::new(MockDidRepository::new()),
        formatter_provider: Arc::new(MockCredentialFormatterProvider::new()),
        protocol_provider: Arc::new(MockTransportProtocolProvider::new()),
        key_provider: Arc::new(MockKeyProvider::new()),
        crypto: Arc::new(dummy_crypto()),
        config: Arc::new(dummy_config()),
    }
}

fn dummy_config() -> CoreConfig {
    CoreConfig {
        format: Default::default(),
        exchange: Default::default(),
        transport: Default::default(),
        revocation: Default::default(),
        did: Default::default(),
        datatype: Default::default(),
        key_algorithm: Default::default(),
        key_storage: Default::default(),
    }
}

fn dummy_crypto() -> Crypto {
    Crypto {
        hashers: Default::default(),
        signers: Default::default(),
    }
}

fn dummy_did() -> Did {
    Did {
        id: Uuid::new_v4(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        name: "John".to_string(),
        did: "did".to_string(),
        did_type: DidType::Local,
        did_method: "John".to_string(),
        keys: None,
        organisation: None,
    }
}

fn dummy_proof() -> Proof {
    Proof {
        id: Uuid::new_v4(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        issuance_date: OffsetDateTime::now_utc(),
        transport: "protocol".to_string(),
        state: None,
        schema: None,
        claims: None,
        verifier_did: None,
        holder_did: None,
        interaction: None,
    }
}

fn dummy_credential() -> Credential {
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
        claims: None,
        issuer_did: None,
        holder_did: None,
        schema: None,
        interaction: Some(Interaction {
            id: Uuid::new_v4(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            host: Some("http://www.host.co".parse().unwrap()),
            data: Some(b"interaction data".to_vec()),
        }),
        revocation_list: None,
    }
}

fn algorithm_config(key_type: impl Into<String>) -> ConfigEntity<String, KeyAlgorithmParams> {
    ConfigEntity {
        r#type: "STRING".to_string(),
        display: TranslatableString::Key("X".to_string()),
        order: None,
        disabled: None,
        params: Some(ParamsEnum::Parsed(KeyAlgorithmParams {
            algorithm: Param {
                access: AccessModifier::Public,
                value: key_type.into(),
            },
        })),
    }
}
