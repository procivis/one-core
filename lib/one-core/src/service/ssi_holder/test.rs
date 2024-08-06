use std::collections::HashMap;
use std::sync::Arc;
use std::vec;

use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use mockall::predicate::eq;
use one_providers::common_models::credential_schema::WalletStorageTypeEnum;
use one_providers::common_models::{PublicKeyJwk, PublicKeyJwkEllipticData};
use one_providers::credential_formatter::provider::MockCredentialFormatterProvider;
use one_providers::credential_formatter::MockCredentialFormatter;
use one_providers::did::model::{DidDocument, DidVerificationMethod};
use one_providers::did::provider::MockDidMethodProvider;
use one_providers::exchange_protocol::imp::provider::MockExchangeProtocol;
use one_providers::exchange_protocol::openid4vc::model::{
    PresentationDefinitionFieldDTO, PresentationDefinitionRequestGroupResponseDTO,
    PresentationDefinitionRequestedCredentialResponseDTO, PresentationDefinitionResponseDTO,
    PresentationDefinitionRuleDTO, PresentationDefinitionRuleTypeEnum, SubmitIssuerResponse,
    UpdateResponse,
};
use one_providers::key_storage::model::{KeySecurity, KeyStorageCapabilities};
use one_providers::key_storage::provider::MockKeyProvider;
use one_providers::key_storage::MockKeyStorage;
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{Credential, CredentialRole, CredentialState, CredentialStateEnum};
use crate::model::credential_schema::{CredentialSchema, CredentialSchemaType, LayoutType};
use crate::model::did::{Did, DidType, KeyRole, RelatedKey};
use crate::model::interaction::Interaction;
use crate::model::proof::{Proof, ProofState, ProofStateEnum};
use crate::provider::exchange_protocol::provider::MockExchangeProtocolProviderExtra;
use crate::repository::credential_repository::MockCredentialRepository;
use crate::repository::credential_schema_repository::MockCredentialSchemaRepository;
use crate::repository::did_repository::MockDidRepository;
use crate::repository::history_repository::MockHistoryRepository;
use crate::repository::interaction_repository::MockInteractionRepository;
use crate::repository::organisation_repository::MockOrganisationRepository;
use crate::repository::proof_repository::MockProofRepository;
use crate::service::error::{BusinessLogicError, ServiceError};
use crate::service::ssi_holder::dto::{
    PresentationSubmitCredentialRequestDTO, PresentationSubmitRequestDTO,
};
use crate::service::ssi_holder::SSIHolderService;
use crate::service::test_utilities::{
    dummy_did, dummy_key, dummy_organisation, dummy_proof, generic_config,
};

#[tokio::test]
async fn test_reject_proof_request_succeeds_and_sets_state_to_rejected_when_latest_state_is_pending(
) {
    let interaction_id = Uuid::new_v4();
    let proof_id = Uuid::new_v4().into();
    let protocol = "exchange-protocol";

    let mut proof_repository = MockProofRepository::new();
    proof_repository
        .expect_get_proof_by_interaction_id()
        .once()
        .return_once(move |_, _| {
            Ok(Some(Proof {
                id: proof_id,
                exchange: protocol.to_string(),
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

    let mut exchange_protocol_mock = MockExchangeProtocol::default();
    exchange_protocol_mock
        .inner
        .expect_reject_proof()
        .withf(move |proof| {
            assert_eq!(Uuid::from(proof.id), Uuid::from(proof_id));
            true
        })
        .once()
        .return_once(move |_| Ok(()));

    let mut protocol_provider = MockExchangeProtocolProviderExtra::new();
    protocol_provider
        .expect_get_protocol()
        .withf(move |_protocol| {
            assert_eq!(_protocol, protocol);
            true
        })
        .once()
        .return_once(move |_| Some(Arc::new(exchange_protocol_mock)));

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
        let proof_id = Uuid::new_v4().into();
        let protocol = "exchange-protocol";
        let mut proof_repository = MockProofRepository::new();
        proof_repository
            .expect_get_proof_by_interaction_id()
            .once()
            .return_once(move |_, _| {
                Ok(Some(Proof {
                    id: proof_id,
                    exchange: protocol.to_string(),
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
    let did_id = Uuid::new_v4().into();
    let interaction_id = Uuid::new_v4();

    let proof_id = Uuid::new_v4().into();
    let protocol = "protocol";

    let mut did_repository = MockDidRepository::new();
    did_repository.expect_get_did().once().return_once(|_, _| {
        Ok(Some(Did {
            keys: Some(vec![RelatedKey {
                role: KeyRole::Authentication,
                key: dummy_key(),
            }]),
            ..dummy_did()
        }))
    });

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
                exchange: protocol.to_string(),
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
                    data: Some(serde_json::to_vec(&()).unwrap()),
                }),
                ..dummy_proof()
            }))
        });

    proof_repository
        .expect_set_proof_claims()
        .once()
        .returning(|_, _| Ok(()));

    proof_repository
        .expect_set_proof_holder_did()
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

    let mut exchange_protocol = MockExchangeProtocol::default();
    exchange_protocol
        .inner
        .expect_get_presentation_definition()
        .withf(move |proof, _, _, _, _, _| {
            assert_eq!(Uuid::from(proof.id), Uuid::from(proof_id));
            true
        })
        .once()
        .returning(|_, _, _, _, _, _| {
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
                            validity_credential_nbf: None,
                        },
                    ],
                }],
                credentials: vec![],
            })
        });

    exchange_protocol
        .inner
        .expect_submit_proof()
        .withf(move |proof, _, _, _, _, _, _| {
            assert_eq!(Uuid::from(proof.id), Uuid::from(proof_id));
            true
        })
        .once()
        .returning(|_, _, _, _, _, _, _| Ok(Default::default()));

    let mut protocol_provider = MockExchangeProtocolProviderExtra::new();
    protocol_provider
        .expect_get_protocol()
        .with(eq(protocol))
        .once()
        .return_once(move |_| Some(Arc::new(exchange_protocol)));

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let mut did_method_provider = MockDidMethodProvider::new();
    did_method_provider
        .expect_resolve()
        .once()
        .returning(move |_| {
            Ok(DidDocument {
                context: json!({}),
                id: dummy_did().did.into(),
                verification_method: vec![DidVerificationMethod {
                    id: "did-vm-id".to_string(),
                    r#type: "did-vm-type".to_string(),
                    controller: "did-vm-controller".to_string(),
                    public_key_jwk: PublicKeyJwk::Ec(PublicKeyJwkEllipticData {
                        r#use: None,
                        crv: "P-256".to_string(),
                        x: Base64UrlSafeNoPadding::encode_to_string("xabc").unwrap(),
                        y: Some(Base64UrlSafeNoPadding::encode_to_string("yabc").unwrap()),
                    }),
                }],
                authentication: Some(vec!["did-vm-id".to_string()]),
                assertion_method: None,
                key_agreement: None,
                capability_invocation: None,
                capability_delegation: None,
                rest: Default::default(),
            })
        });

    let service = SSIHolderService {
        credential_repository: Arc::new(credential_repository),
        proof_repository: Arc::new(proof_repository),
        formatter_provider: Arc::new(formatter_provider),
        protocol_provider: Arc::new(protocol_provider),
        history_repository: Arc::new(history_repository),
        did_repository: Arc::new(did_repository),
        did_method_provider: Arc::new(did_method_provider),
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
            did_id,
            key_id: None,
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn test_submit_proof_repeating_claims() {
    let did_id = Uuid::new_v4().into();
    let interaction_id = Uuid::new_v4();
    let proof_id = Uuid::new_v4().into();
    let credential_id = Uuid::new_v4().into();
    let claim_id = Uuid::new_v4();
    let protocol = "protocol";

    let mut did_repository = MockDidRepository::new();
    did_repository.expect_get_did().once().return_once(|_, _| {
        Ok(Some(Did {
            keys: Some(vec![RelatedKey {
                role: KeyRole::Authentication,
                key: dummy_key(),
            }]),
            ..dummy_did()
        }))
    });

    let mut proof_repository = MockProofRepository::new();
    proof_repository
        .expect_get_proof_by_interaction_id()
        .once()
        .returning(move |_, _| {
            Ok(Some(Proof {
                id: proof_id,
                exchange: protocol.to_string(),
                state: Some(vec![ProofState {
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    state: ProofStateEnum::Pending,
                }]),
                interaction: Some(Interaction {
                    id: interaction_id,
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    host: Some("http://www.host.co".parse().unwrap()),
                    data: Some(serde_json::to_vec(&()).unwrap()),
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
                    path: "claim1".to_string(),
                    schema: Some(ClaimSchema {
                        id: claim_id.into(),
                        key: "claim1".to_string(),
                        data_type: "STRING".to_string(),
                        created_date: OffsetDateTime::now_utc(),
                        last_modified: OffsetDateTime::now_utc(),
                        array: false,
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

    let mut exchange_protocol = MockExchangeProtocol::default();
    exchange_protocol
        .inner
        .expect_get_presentation_definition()
        .withf(move |proof, _, _, _, _, _| {
            assert_eq!(Uuid::from(proof.id), Uuid::from(proof_id));
            true
        })
        .once()
        .returning(move |_, _, _, _, _, _| {
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
                            validity_credential_nbf: None,
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
                            validity_credential_nbf: None,
                        },
                    ],
                }],
                credentials: vec![],
            })
        });

    exchange_protocol
        .inner
        .expect_submit_proof()
        .withf(move |proof, _, _, _, _, _, _| {
            assert_eq!(Uuid::from(proof.id), Uuid::from(proof_id));
            true
        })
        .once()
        .returning(|_, _, _, _, _, _, _| Ok(Default::default()));

    let mut protocol_provider = MockExchangeProtocolProviderExtra::new();
    protocol_provider
        .expect_get_protocol()
        .with(eq(protocol))
        .once()
        .return_once(move |_| Some(Arc::new(exchange_protocol)));

    proof_repository
        .expect_set_proof_holder_did()
        .once()
        .returning(|_, _| Ok(()));

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

    let mut did_method_provider = MockDidMethodProvider::new();
    did_method_provider
        .expect_resolve()
        .once()
        .returning(move |_| {
            Ok(DidDocument {
                context: json!({}),
                id: dummy_did().did.into(),
                verification_method: vec![DidVerificationMethod {
                    id: "did-vm-id".to_string(),
                    r#type: "did-vm-type".to_string(),
                    controller: "did-vm-controller".to_string(),
                    public_key_jwk: PublicKeyJwk::Ec(PublicKeyJwkEllipticData {
                        r#use: None,
                        crv: "P-256".to_string(),
                        x: Base64UrlSafeNoPadding::encode_to_string("xabc").unwrap(),
                        y: Some(Base64UrlSafeNoPadding::encode_to_string("yabc").unwrap()),
                    }),
                }],
                authentication: Some(vec!["did-vm-id".to_string()]),
                assertion_method: None,
                key_agreement: None,
                capability_invocation: None,
                capability_delegation: None,
                rest: Default::default(),
            })
        });

    let service = SSIHolderService {
        credential_repository: Arc::new(credential_repository),
        proof_repository: Arc::new(proof_repository),
        formatter_provider: Arc::new(formatter_provider),
        protocol_provider: Arc::new(protocol_provider),
        history_repository: Arc::new(history_repository),
        did_repository: Arc::new(did_repository),
        did_method_provider: Arc::new(did_method_provider),
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
            did_id,
            key_id: None,
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn test_accept_credential() {
    let did_id = Uuid::new_v4().into();
    let mut did_repository = MockDidRepository::new();
    did_repository.expect_get_did().once().return_once(|_, _| {
        Ok(Some(Did {
            keys: Some(vec![RelatedKey {
                role: KeyRole::Authentication,
                key: dummy_key(),
            }]),
            ..dummy_did()
        }))
    });
    let mut key_provider = MockKeyProvider::new();
    key_provider
        .expect_get_key_storage()
        .once()
        .return_once(|_| {
            let mut mock = MockKeyStorage::new();
            mock.expect_get_capabilities()
                .once()
                .return_once(|| KeyStorageCapabilities {
                    features: vec![],
                    algorithms: vec![],
                    security: vec![KeySecurity::Software],
                });

            Some(Arc::new(mock))
        });

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

    let mut exchange_protocol_mock = MockExchangeProtocol::default();
    exchange_protocol_mock
        .inner
        .expect_accept_credential()
        .once()
        .returning(|_, _, _, _, _, _| {
            Ok(UpdateResponse {
                result: SubmitIssuerResponse {
                    credential: "credential".to_string(),
                    format: "credential format".to_string(),
                    redirect_uri: None,
                },
                update_proof: None,
                create_did: None,
                update_credential: None,
                update_credential_schema: None,
            })
        });

    let mut protocol_provider = MockExchangeProtocolProviderExtra::new();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Some(Arc::new(exchange_protocol_mock)));

    let service = SSIHolderService {
        credential_repository: Arc::new(credential_repository),
        protocol_provider: Arc::new(protocol_provider),
        history_repository: Arc::new(history_repository),
        did_repository: Arc::new(did_repository),
        key_provider: Arc::new(key_provider),
        ..mock_ssi_holder_service()
    };

    let interaction_id = Uuid::new_v4();
    service
        .accept_credential(&interaction_id, did_id, None)
        .await
        .unwrap();
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

    let mut exchange_protocol_mock = MockExchangeProtocol::default();
    exchange_protocol_mock
        .inner
        .expect_reject_credential()
        .once()
        .returning(|_| Ok(()));

    let mut protocol_provider = MockExchangeProtocolProviderExtra::new();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Some(Arc::new(exchange_protocol_mock)));

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
        organisation_repository: Arc::new(MockOrganisationRepository::new()),
        interaction_repository: Arc::new(MockInteractionRepository::new()),
        credential_schema_repository: Arc::new(MockCredentialSchemaRepository::new()),
        did_repository: Arc::new(MockDidRepository::new()),
        history_repository: Arc::new(MockHistoryRepository::new()),
        key_provider: Arc::new(MockKeyProvider::new()),
        formatter_provider: Arc::new(MockCredentialFormatterProvider::new()),
        protocol_provider: Arc::new(MockExchangeProtocolProviderExtra::new()),
        did_method_provider: Arc::new(MockDidMethodProvider::new()),
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
        exchange: "protocol".to_string(),
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
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            name: "schema".to_string(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            format: "JWT".to_string(),
            revocation_method: "NONE".to_string(),
            claim_schemas: None,
            organisation: Some(dummy_organisation()),
            deleted_at: None,
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_type: CredentialSchemaType::ProcivisOneSchema2024,
            schema_id: "CredentialSchemaId".to_owned(),
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
