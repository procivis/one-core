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
        dto::{
            ConnectVerifierResponse, InvitationResponse, ProofClaimSchema, ProofCredentialSchema,
            SubmitIssuerResponse,
        },
        provider::MockTransportProtocolProvider,
        MockTransportProtocol,
    },
    provider::{
        credential_formatter::{
            provider::MockCredentialFormatterProvider, MockCredentialFormatter,
        },
        key_storage::mock_key_storage::MockKeyStorage,
    },
    repository::mock::credential_repository::MockCredentialRepository,
    repository::mock::credential_schema_repository::MockCredentialSchemaRepository,
    repository::mock::interaction_repository::MockInteractionRepository,
    repository::mock::proof_repository::MockProofRepository,
    repository::{did_repository::MockDidRepository, error::DataLayerError},
    service::{
        credential::dto::{CredentialDetailResponseDTO, DetailCredentialSchemaResponseDTO},
        error::ServiceError,
        ssi_holder::{
            dto::{
                InvitationResponseDTO, PresentationSubmitCredentialRequestDTO,
                PresentationSubmitRequestDTO,
            },
            SSIHolderService,
        },
    },
};

#[tokio::test]
async fn test_handle_invitation_creates_credential_for_credential_invitation() {
    let protocol = "123".to_string();
    let url = format!("http://www.example.com/?protocol={protocol}");

    let holder_did_id = Uuid::new_v4();

    let mut did_repository = MockDidRepository::new();

    did_repository
        .expect_get_did()
        .withf(move |id, _| {
            assert_eq!(id, &holder_did_id);
            true
        })
        .once()
        .return_once(move |_, _| {
            Ok(Did {
                id: holder_did_id,
                organisation: Some(Organisation {
                    id: Uuid::new_v4(),
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                }),
                ..dummy_did()
            })
        });

    did_repository
        .expect_create_did()
        .once()
        .return_once(|_| Ok(Uuid::new_v4()));

    let mut transport_protocol_mock = MockTransportProtocol::new();
    transport_protocol_mock
        .expect_handle_invitation()
        .once()
        .return_once(move |_, _| {
            Ok(InvitationResponse::Credential(Box::new(
                dummy_credential_detail_response_dto(),
            )))
        });

    let mut protocol_provider = MockTransportProtocolProvider::new();
    protocol_provider
        .expect_get_protocol()
        .withf(move |expected_protocol| {
            assert_eq!(protocol, expected_protocol);
            true
        })
        .once()
        .return_once(move |_| Ok(Arc::new(transport_protocol_mock)));

    let mut credential_schema_repository = MockCredentialSchemaRepository::new();
    credential_schema_repository
        .expect_create_credential_schema()
        .once()
        .return_once(move |_| Ok(Uuid::new_v4()));

    let mut interaction_repository = MockInteractionRepository::new();
    interaction_repository
        .expect_create_interaction()
        .once()
        .return_once(move |_| Ok(Uuid::new_v4()));

    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_create_credential()
        .once()
        .return_once(move |_| Ok(Uuid::new_v4()));

    let service = SSIHolderService {
        did_repository: Arc::new(did_repository),
        protocol_provider: Arc::new(protocol_provider),
        credential_schema_repository: Arc::new(credential_schema_repository),
        interaction_repository: Arc::new(interaction_repository),
        credential_repository: Arc::new(credential_repository),
        ..mock_ssi_holder_service()
    };

    let res: crate::service::ssi_holder::dto::InvitationResponseDTO = service
        .handle_invitation(&url, &holder_did_id)
        .await
        .unwrap();

    assert2::assert!(let InvitationResponseDTO::Credential { .. } = res);
}

#[tokio::test]
async fn test_handle_proof_invitation_when_did_already_exists() {
    let protocol = "123".to_string();
    let url = format!("http://www.example.com/?protocol={protocol}");

    let holder_did_id = Uuid::new_v4();

    let mut did_repository = MockDidRepository::new();

    did_repository
        .expect_get_did()
        .withf(move |id, _| {
            assert_eq!(id, &holder_did_id);
            true
        })
        .once()
        .return_once(move |_, _| {
            Ok(Did {
                id: holder_did_id,
                organisation: Some(Organisation {
                    id: Uuid::new_v4(),
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                }),
                ..dummy_did()
            })
        });

    did_repository
        .expect_create_did()
        .once()
        .return_once(|_| Err(DataLayerError::AlreadyExists));

    did_repository
        .expect_get_did_by_value()
        .once()
        .return_once(|_, _| Ok(dummy_did()));

    let mut transport_protocol_mock = MockTransportProtocol::new();
    transport_protocol_mock
        .expect_handle_invitation()
        .once()
        .return_once(move |_, _| {
            Ok(InvitationResponse::Credential(Box::new(
                dummy_credential_detail_response_dto(),
            )))
        });

    let mut protocol_provider = MockTransportProtocolProvider::new();
    protocol_provider
        .expect_get_protocol()
        .withf(move |expected_protocol| {
            assert_eq!(protocol, expected_protocol);
            true
        })
        .once()
        .return_once(move |_| Ok(Arc::new(transport_protocol_mock)));

    let mut credential_schema_repository = MockCredentialSchemaRepository::new();
    credential_schema_repository
        .expect_create_credential_schema()
        .once()
        .return_once(move |_| Ok(Uuid::new_v4()));

    let mut interaction_repository = MockInteractionRepository::new();
    interaction_repository
        .expect_create_interaction()
        .once()
        .return_once(move |_| Ok(Uuid::new_v4()));

    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_create_credential()
        .once()
        .return_once(move |_| Ok(Uuid::new_v4()));

    let service = SSIHolderService {
        did_repository: Arc::new(did_repository),
        interaction_repository: Arc::new(interaction_repository),
        credential_repository: Arc::new(credential_repository),
        credential_schema_repository: Arc::new(credential_schema_repository),
        protocol_provider: Arc::new(protocol_provider),
        ..mock_ssi_holder_service()
    };

    let res = service
        .handle_invitation(&url, &holder_did_id)
        .await
        .unwrap();

    assert2::assert!(let InvitationResponseDTO::Credential { .. } = res);
}

#[tokio::test]
async fn test_handle_invitation_creates_proof_request_for_proof_invitation() {
    let protocol = "123".to_string();
    let url = format!("http://www.example.com/?protocol={protocol}");

    let holder_did_id = Uuid::new_v4();

    let mut did_repository = MockDidRepository::new();

    did_repository
        .expect_get_did()
        .withf(move |id, _| {
            assert_eq!(id, &holder_did_id);
            true
        })
        .once()
        .return_once(move |_, _| {
            Ok(Did {
                id: holder_did_id,
                organisation: Some(Organisation {
                    id: Uuid::new_v4(),
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                }),
                ..dummy_did()
            })
        });

    did_repository
        .expect_get_did_by_value()
        .once()
        .return_once(move |_, _| {
            Ok(Did {
                id: holder_did_id,
                organisation: Some(Organisation {
                    id: Uuid::new_v4(),
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                }),
                ..dummy_did()
            })
        });

    let mut transport_protocol_mock = MockTransportProtocol::new();
    transport_protocol_mock
        .expect_handle_invitation()
        .once()
        .return_once(move |_, _| {
            Ok(InvitationResponse::Proof {
                proof_request: ConnectVerifierResponse {
                    claims: vec![ProofClaimSchema {
                        id: "Proof claim schema id".to_string(),
                        created_date: OffsetDateTime::now_utc(),
                        last_modified: OffsetDateTime::now_utc(),
                        key: "key".to_string(),
                        datatype: "datatype".to_string(),
                        required: true,
                        credential_schema: ProofCredentialSchema {
                            id: "credential schema id".to_string(),
                            created_date: OffsetDateTime::now_utc(),
                            last_modified: OffsetDateTime::now_utc(),
                            name: "name".to_string(),
                            format: "format".to_string(),
                            revocation_method: "revocation method".to_string(),
                        },
                    }],
                    verifier_did: "Verifier did".to_string(),
                },
                proof_id: Uuid::new_v4().to_string(),
            })
        });

    let mut protocol_provider = MockTransportProtocolProvider::new();
    protocol_provider
        .expect_get_protocol()
        .withf(move |_protocol| {
            assert_eq!(_protocol, protocol);
            true
        })
        .once()
        .return_once(move |_| Ok(Arc::new(transport_protocol_mock)));

    let mut interaction_repository = MockInteractionRepository::new();
    interaction_repository
        .expect_create_interaction()
        .once()
        .return_once(move |_| Ok(Uuid::new_v4()));

    let mut proof_repository = MockProofRepository::new();
    proof_repository
        .expect_create_proof()
        .once()
        .return_once(move |_| Ok(Uuid::new_v4()));

    let service = SSIHolderService {
        did_repository: Arc::new(did_repository),
        protocol_provider: Arc::new(protocol_provider),
        interaction_repository: Arc::new(interaction_repository),
        proof_repository: Arc::new(proof_repository),
        ..mock_ssi_holder_service()
    };

    let res: crate::service::ssi_holder::dto::InvitationResponseDTO = service
        .handle_invitation(&url, &holder_did_id)
        .await
        .unwrap();

    assert2::assert!(let InvitationResponseDTO::ProofRequest { .. } = res);
}

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
                    host: Some("host".to_string()),
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
                        host: Some("host".to_string()),
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
                    host: Some("host".to_string()),
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
        credential_schema_repository: Arc::new(MockCredentialSchemaRepository::new()),
        credential_repository: Arc::new(MockCredentialRepository::new()),
        proof_repository: Arc::new(MockProofRepository::new()),
        did_repository: Arc::new(MockDidRepository::new()),
        interaction_repository: Arc::new(MockInteractionRepository::new()),
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

fn dummy_credential_detail_response_dto() -> CredentialDetailResponseDTO {
    CredentialDetailResponseDTO {
        id: Uuid::new_v4(),
        created_date: OffsetDateTime::now_utc(),
        issuance_date: OffsetDateTime::now_utc(),
        revocation_date: None,
        state: CredentialStateEnum::Created.into(),
        last_modified: OffsetDateTime::now_utc(),
        schema: DetailCredentialSchemaResponseDTO {
            id: Uuid::new_v4(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            name: "Credential schema name".to_string(),
            format: "Credential schema format".to_string(),
            revocation_method: "Credential schema revocation method".to_string(),
            organisation_id: Uuid::new_v4(),
        },
        issuer_did: Some("Issuer DID".to_string()),
        claims: vec![],
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
            host: Some("host".to_string()),
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
        params: Some(ParamsEnum::Parsed(KeyAlgorithmParams {
            algorithm: Param {
                access: AccessModifier::Public,
                value: key_type.into(),
            },
        })),
    }
}
