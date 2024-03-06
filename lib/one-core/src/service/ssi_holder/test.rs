use std::{collections::HashMap, sync::Arc};

use mockall::predicate::eq;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::credential_schema::WalletStorageTypeEnum;
use crate::{
    model::{
        claim::Claim,
        claim_schema::ClaimSchema,
        credential::{Credential, CredentialRole, CredentialState, CredentialStateEnum},
        credential_schema::CredentialSchema,
        did::{Did, DidType, KeyRole, RelatedKey},
        interaction::Interaction,
        key::Key,
        organisation::Organisation,
        proof::{Proof, ProofState, ProofStateEnum},
    },
    provider::{
        credential_formatter::{
            provider::MockCredentialFormatterProvider, MockCredentialFormatter,
        },
        key_storage::provider::MockKeyProvider,
        transport_protocol::{
            dto::{
                PresentationDefinitionFieldDTO, PresentationDefinitionRequestGroupResponseDTO,
                PresentationDefinitionRequestedCredentialResponseDTO,
                PresentationDefinitionResponseDTO, PresentationDefinitionRuleDTO,
                PresentationDefinitionRuleTypeEnum, SubmitIssuerResponse,
            },
            provider::MockTransportProtocolProvider,
            MockTransportProtocol,
        },
    },
    repository::did_repository::MockDidRepository,
    repository::mock::proof_repository::MockProofRepository,
    repository::{
        credential_repository::MockCredentialRepository, history_repository::MockHistoryRepository,
    },
    service::{
        error::{BusinessLogicError, ServiceError},
        ssi_holder::{
            dto::{PresentationSubmitCredentialRequestDTO, PresentationSubmitRequestDTO},
            SSIHolderService,
        },
        test_utilities::{dummy_did, dummy_proof, generic_config},
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
            Ok(Some(Proof {
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
            }))
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
        .return_once(move |_| Some(Arc::new(transport_protocol_mock)));

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let service = SSIHolderService {
        proof_repository: Arc::new(proof_repository),
        protocol_provider: Arc::new(protocol_provider),
        history_repository: Arc::new(history_repository),
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
                Ok(Some(Proof {
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
                }))
            });

        let service = SSIHolderService {
            proof_repository: Arc::new(proof_repository),
            ..mock_ssi_holder_service()
        };

        service.reject_proof_request(&interaction_id).await
    };

    for state in [
        ProofStateEnum::Created,
        ProofStateEnum::Requested,
        ProofStateEnum::Accepted,
        ProofStateEnum::Rejected,
        ProofStateEnum::Error,
    ] {
        assert2::assert!(
            let Err(ServiceError::BusinessLogic(BusinessLogicError::InvalidProofState { .. })) = reject_proof_for_state(state).await
        );
    }
}

#[tokio::test]
async fn test_submit_proof_succeeds() {
    let interaction_id = Uuid::new_v4();

    let proof_id = Uuid::new_v4();
    let protocol = "protocol";

    let key_storage_type = "storage type";
    let key_type = "ECDSA";

    let mut proof_repository = MockProofRepository::new();
    proof_repository
        .expect_get_proof_by_interaction_id()
        .withf(move |_interaction_id: &Uuid, _| {
            assert_eq!(_interaction_id, &interaction_id);
            true
        })
        .once()
        .returning(move |_, _| {
            Ok(Some(Proof {
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
                            id: Uuid::new_v4().into(),
                            created_date: OffsetDateTime::now_utc(),
                            last_modified: OffsetDateTime::now_utc(),
                            public_key: b"public_key".to_vec(),
                            name: "key name".to_string(),
                            key_reference: b"private_key".to_vec(),
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
            }))
        });

    proof_repository
        .expect_set_proof_claims()
        .once()
        .returning(|_, _| Ok(()));

    proof_repository
        .expect_set_proof_state()
        .once()
        .returning(|_, _| Ok(()));

    let credential_id = Uuid::new_v4().into();
    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_get_credential()
        .once()
        .returning(move |_, _| {
            Ok(Some(Credential {
                id: credential_id,
                credential: b"credential data".to_vec(),
                claims: Some(vec![]),
                ..dummy_credential()
            }))
        });

    let mut formatter = MockCredentialFormatter::new();

    formatter
        .expect_format_credential_presentation()
        .once()
        .returning(|presentation| Ok(presentation.token));

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    let formatter = Arc::new(formatter);
    formatter_provider
        .expect_get_formatter()
        .times(1)
        .returning(move |_| Some(formatter.clone()));

    let mut transport_protocol = MockTransportProtocol::new();
    transport_protocol
        .expect_get_presentation_definition()
        .withf(move |proof| {
            assert_eq!(proof.id, proof_id);
            true
        })
        .once()
        .returning(|_| {
            Ok(PresentationDefinitionResponseDTO {
                request_groups: vec![PresentationDefinitionRequestGroupResponseDTO {
                    id: "random".to_string(),
                    name: None,
                    purpose: None,
                    rule: PresentationDefinitionRuleDTO {
                        r#type: PresentationDefinitionRuleTypeEnum::All,
                        min: None,
                        max: None,
                        count: None,
                    },
                    requested_credentials: vec![
                        PresentationDefinitionRequestedCredentialResponseDTO {
                            id: "cred1".to_string(),
                            name: None,
                            purpose: None,
                            fields: vec![],
                            applicable_credentials: vec![],
                        },
                    ],
                }],
                credentials: vec![],
            })
        });

    transport_protocol
        .expect_submit_proof()
        .withf(move |proof, _| {
            assert_eq!(proof.id, proof_id);
            true
        })
        .once()
        .returning(|_, _| Ok(()));

    let mut protocol_provider = MockTransportProtocolProvider::new();
    protocol_provider
        .expect_get_protocol()
        .with(eq(protocol))
        .once()
        .return_once(move |_| Some(Arc::new(transport_protocol)));

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let service = SSIHolderService {
        credential_repository: Arc::new(credential_repository),
        proof_repository: Arc::new(proof_repository),
        formatter_provider: Arc::new(formatter_provider),
        protocol_provider: Arc::new(protocol_provider),
        history_repository: Arc::new(history_repository),
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
async fn test_submit_proof_repeating_claims() {
    let interaction_id = Uuid::new_v4();
    let proof_id = Uuid::new_v4();
    let credential_id = Uuid::new_v4().into();
    let claim_id = Uuid::new_v4();
    let protocol = "protocol";

    let mut proof_repository = MockProofRepository::new();
    proof_repository
        .expect_get_proof_by_interaction_id()
        .once()
        .returning(move |_, _| {
            Ok(Some(Proof {
                id: proof_id,
                transport: protocol.to_string(),
                state: Some(vec![ProofState {
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    state: ProofStateEnum::Pending,
                }]),
                holder_did: Some(Did {
                    keys: Some(vec![RelatedKey {
                        role: KeyRole::AssertionMethod,
                        key: Key {
                            id: Uuid::new_v4().into(),
                            created_date: OffsetDateTime::now_utc(),
                            last_modified: OffsetDateTime::now_utc(),
                            public_key: b"public_key".to_vec(),
                            name: "key name".to_string(),
                            key_reference: b"private_key".to_vec(),
                            storage_type: "storage type".to_string(),
                            key_type: "ECDSA".to_string(),
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
            }))
        });

    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_get_credential()
        .returning(move |_, _| {
            Ok(Some(Credential {
                id: credential_id,
                credential: b"credential data".to_vec(),
                claims: Some(vec![Claim {
                    id: claim_id,
                    credential_id,
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    value: "claim value".to_string(),
                    schema: Some(ClaimSchema {
                        id: claim_id,
                        key: "claim1".to_string(),
                        data_type: "STRING".to_string(),
                        created_date: OffsetDateTime::now_utc(),
                        last_modified: OffsetDateTime::now_utc(),
                    }),
                }]),
                ..dummy_credential()
            }))
        });

    let mut formatter = MockCredentialFormatter::new();
    formatter
        .expect_format_credential_presentation()
        .returning(|presentation| Ok(presentation.token));

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    let formatter = Arc::new(formatter);
    formatter_provider
        .expect_get_formatter()
        .returning(move |_| Some(formatter.clone()));

    let mut transport_protocol = MockTransportProtocol::new();
    transport_protocol
        .expect_get_presentation_definition()
        .withf(move |proof| {
            assert_eq!(proof.id, proof_id);
            true
        })
        .once()
        .returning(move |_| {
            Ok(PresentationDefinitionResponseDTO {
                request_groups: vec![PresentationDefinitionRequestGroupResponseDTO {
                    id: "random".to_string(),
                    name: None,
                    purpose: None,
                    rule: PresentationDefinitionRuleDTO {
                        r#type: PresentationDefinitionRuleTypeEnum::All,
                        min: None,
                        max: None,
                        count: None,
                    },
                    requested_credentials: vec![
                        PresentationDefinitionRequestedCredentialResponseDTO {
                            id: "cred1".to_string(),
                            name: None,
                            purpose: None,
                            fields: vec![PresentationDefinitionFieldDTO {
                                id: "claim1".to_string(),
                                name: None,
                                purpose: None,
                                required: None,
                                key_map: HashMap::from([(
                                    credential_id.to_string(),
                                    "claim1".to_string(),
                                )]),
                            }],
                            applicable_credentials: vec![],
                        },
                        PresentationDefinitionRequestedCredentialResponseDTO {
                            id: "cred2".to_string(),
                            name: None,
                            purpose: None,
                            fields: vec![PresentationDefinitionFieldDTO {
                                id: "claim1".to_string(),
                                name: None,
                                purpose: None,
                                required: None,
                                key_map: HashMap::from([(
                                    credential_id.to_string(),
                                    "claim1".to_string(),
                                )]),
                            }],
                            applicable_credentials: vec![credential_id.to_string()],
                        },
                    ],
                }],
                credentials: vec![],
            })
        });

    transport_protocol
        .expect_submit_proof()
        .withf(move |proof, _| {
            assert_eq!(proof.id, proof_id);
            true
        })
        .once()
        .returning(|_, _| Ok(()));

    let mut protocol_provider = MockTransportProtocolProvider::new();
    protocol_provider
        .expect_get_protocol()
        .with(eq(protocol))
        .once()
        .return_once(move |_| Some(Arc::new(transport_protocol)));

    proof_repository
        .expect_set_proof_claims()
        .once()
        .withf(move |_proof_id, claims| {
            assert_eq!(_proof_id, &proof_id);
            assert_eq!(claims.len(), 1);
            assert_eq!(claims[0].id, claim_id);
            true
        })
        .returning(|_, _| Ok(()));

    proof_repository
        .expect_set_proof_state()
        .once()
        .returning(|_, _| Ok(()));

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let service = SSIHolderService {
        credential_repository: Arc::new(credential_repository),
        proof_repository: Arc::new(proof_repository),
        formatter_provider: Arc::new(formatter_provider),
        protocol_provider: Arc::new(protocol_provider),
        history_repository: Arc::new(history_repository),
        ..mock_ssi_holder_service()
    };

    service
        .submit_proof(PresentationSubmitRequestDTO {
            interaction_id,
            submit_credentials: HashMap::from([
                (
                    "cred1".to_string(),
                    PresentationSubmitCredentialRequestDTO {
                        credential_id,
                        submit_claims: vec!["claim1".to_string()],
                    },
                ),
                (
                    "cred2".to_string(),
                    PresentationSubmitCredentialRequestDTO {
                        credential_id,
                        submit_claims: vec!["claim1".to_string()],
                    },
                ),
            ]),
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn test_accept_credential() {
    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .returning(|_| Ok(Uuid::new_v4().into()));

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
                redirect_uri: None,
            })
        });

    let mut protocol_provider = MockTransportProtocolProvider::new();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Some(Arc::new(transport_protocol_mock)));

    let service = SSIHolderService {
        credential_repository: Arc::new(credential_repository),
        protocol_provider: Arc::new(protocol_provider),
        history_repository: Arc::new(history_repository),
        ..mock_ssi_holder_service()
    };

    let interaction_id = Uuid::new_v4();
    service.accept_credential(&interaction_id).await.unwrap();
}

#[tokio::test]
async fn test_reject_credential() {
    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_get_credentials_by_interaction_id()
        .once()
        .return_once(move |_, _| Ok(vec![dummy_credential()]));
    credential_repository
        .expect_update_credential()
        .once()
        .returning(|_| Ok(()));

    let mut transport_protocol_mock: MockTransportProtocol = MockTransportProtocol::new();
    transport_protocol_mock
        .expect_reject_credential()
        .once()
        .returning(|_| Ok(()));

    let mut protocol_provider = MockTransportProtocolProvider::new();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Some(Arc::new(transport_protocol_mock)));

    let service = SSIHolderService {
        credential_repository: Arc::new(credential_repository),
        protocol_provider: Arc::new(protocol_provider),
        history_repository: Arc::new(history_repository),
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
        history_repository: Arc::new(MockHistoryRepository::new()),
        key_provider: Arc::new(MockKeyProvider::new()),
        formatter_provider: Arc::new(MockCredentialFormatterProvider::new()),
        protocol_provider: Arc::new(MockTransportProtocolProvider::new()),
        config: Arc::new(generic_config().core),
    }
}

fn dummy_credential() -> Credential {
    Credential {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        issuance_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        deleted_at: None,
        credential: b"credential".to_vec(),
        transport: "protocol".to_string(),
        redirect_uri: None,
        role: CredentialRole::Issuer,
        state: Some(vec![CredentialState {
            created_date: OffsetDateTime::now_utc(),
            state: CredentialStateEnum::Pending,
            suspend_end_date: None,
        }]),
        claims: None,
        issuer_did: Some(Did {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            name: "issuer_did".to_string(),
            did: "did:key:123".parse().unwrap(),
            did_type: DidType::Remote,
            did_method: "KEY".to_string(),
            keys: None,
            organisation: None,
            deactivated: false,
        }),
        holder_did: None,
        schema: Some(CredentialSchema {
            id: Uuid::new_v4(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            name: "schema".to_string(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            format: "JWT".to_string(),
            revocation_method: "NONE".to_string(),
            claim_schemas: None,
            organisation: None,
            deleted_at: None,
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
