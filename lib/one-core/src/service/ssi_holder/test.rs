use std::collections::HashMap;
use std::sync::Arc;
use std::vec;

use mockall::predicate::eq;
use serde_json::json;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{Credential, CredentialRole, CredentialStateEnum};
use crate::model::credential_schema::{
    CredentialSchemaClaim, CredentialSchemaType, LayoutType, WalletStorageTypeEnum,
};
use crate::model::did::{Did, DidType, KeyRole, RelatedKey};
use crate::model::identifier::{Identifier, IdentifierState, IdentifierType};
use crate::model::interaction::Interaction;
use crate::model::proof::{Proof, ProofStateEnum};
use crate::provider::caching_loader::vct::{VctTypeMetadataCache, VctTypeMetadataResolver};
use crate::provider::credential_formatter::MockCredentialFormatter;
use crate::provider::credential_formatter::model::{CredentialSubject, DetailCredential};
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::http_client::reqwest_client::ReqwestClient;
use crate::provider::issuance_protocol::MockIssuanceProtocol;
use crate::provider::issuance_protocol::openid4vci_draft13::model::{
    SubmitIssuerResponse, UpdateResponse,
};
use crate::provider::issuance_protocol::provider::MockIssuanceProtocolProvider;
use crate::provider::key_algorithm::ecdsa::Ecdsa;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_storage::MockKeyStorage;
use crate::provider::key_storage::model::{KeySecurity, KeyStorageCapabilities};
use crate::provider::key_storage::provider::MockKeyProvider;
use crate::provider::remote_entity_storage::MockRemoteEntityStorage;
use crate::provider::verification_protocol::MockVerificationProtocol;
use crate::provider::verification_protocol::dto::{
    PresentationDefinitionFieldDTO, PresentationDefinitionRequestGroupResponseDTO,
    PresentationDefinitionRequestedCredentialResponseDTO, PresentationDefinitionResponseDTO,
    PresentationDefinitionRuleDTO, PresentationDefinitionRuleTypeEnum,
};
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::provider::MockVerificationProtocolProvider;
use crate::repository::credential_repository::MockCredentialRepository;
use crate::repository::credential_schema_repository::MockCredentialSchemaRepository;
use crate::repository::did_repository::MockDidRepository;
use crate::repository::history_repository::MockHistoryRepository;
use crate::repository::identifier_repository::MockIdentifierRepository;
use crate::repository::interaction_repository::MockInteractionRepository;
use crate::repository::organisation_repository::MockOrganisationRepository;
use crate::repository::proof_repository::MockProofRepository;
use crate::repository::validity_credential_repository::MockValidityCredentialRepository;
use crate::service::error::{BusinessLogicError, ServiceError};
use crate::service::ssi_holder::SSIHolderService;
use crate::service::ssi_holder::dto::{
    PresentationSubmitCredentialRequestDTO, PresentationSubmitRequestDTO,
};
use crate::service::test_utilities::{
    dummy_did, dummy_identifier, dummy_key, dummy_organisation, dummy_proof, generic_config,
    generic_formatter_capabilities,
};

#[tokio::test]
async fn test_reject_proof_request_succeeds_and_sets_state_to_rejected_when_latest_state_is_requested()
 {
    let interaction_id = Uuid::new_v4();
    let proof_id = Uuid::new_v4().into();
    let protocol = "OPENID4VP_DRAFT20";

    let mut proof_repository = MockProofRepository::new();
    proof_repository
        .expect_get_proof_by_interaction_id()
        .once()
        .return_once(move |_, _| {
            Ok(Some(Proof {
                id: proof_id,
                exchange: protocol.to_string(),
                state: ProofStateEnum::Requested,
                interaction: Some(Interaction {
                    id: interaction_id,
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    host: Some("http://www.host.co".parse().unwrap()),
                    data: None,
                    organisation: None,
                }),
                ..dummy_proof()
            }))
        });

    proof_repository
        .expect_update_proof()
        .withf(move |actual_proof_id, actual_proof_state, _| {
            assert_eq!(actual_proof_id, &proof_id);
            assert_eq!(actual_proof_state.state, Some(ProofStateEnum::Rejected));
            true
        })
        .once()
        .return_once(move |_, _, _| Ok(()));

    let mut verification_protocol_mock = MockVerificationProtocol::default();
    verification_protocol_mock
        .expect_holder_reject_proof()
        .withf(move |proof| {
            assert_eq!(Uuid::from(proof.id), Uuid::from(proof_id));
            true
        })
        .once()
        .return_once(move |_| Ok(()));

    let mut verification_protocol_provider = MockVerificationProtocolProvider::new();
    verification_protocol_provider
        .expect_get_protocol()
        .withf(move |_protocol| {
            assert_eq!(_protocol, protocol);
            true
        })
        .once()
        .return_once(move |_| Some(Arc::new(verification_protocol_mock)));

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let service = SSIHolderService {
        proof_repository: Arc::new(proof_repository),
        verification_protocol_provider: Arc::new(verification_protocol_provider),
        ..mock_ssi_holder_service()
    };

    service.reject_proof_request(&interaction_id).await.unwrap();
}

#[tokio::test]
async fn test_reject_proof_request_fails_when_latest_state_is_not_requested() {
    let reject_proof_for_state = |state| async {
        let interaction_id = Uuid::new_v4();
        let proof_id = Uuid::new_v4().into();
        let protocol = "OPENID4VP_DRAFT20";
        let mut proof_repository = MockProofRepository::new();
        proof_repository
            .expect_get_proof_by_interaction_id()
            .once()
            .return_once(move |_, _| {
                Ok(Some(Proof {
                    id: proof_id,
                    exchange: protocol.to_string(),
                    state,
                    interaction: Some(Interaction {
                        id: interaction_id,
                        created_date: OffsetDateTime::now_utc(),
                        last_modified: OffsetDateTime::now_utc(),
                        host: Some("http://www.host.co".parse().unwrap()),
                        data: None,
                        organisation: None,
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
        ProofStateEnum::Pending,
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
async fn test_reject_proof_request_suceeds_when_holder_reject_proof_errors_state_is_set_to_errored()
{
    let interaction_id = Uuid::new_v4();
    let proof_id = Uuid::new_v4().into();
    let protocol = "OPENID4VP_DRAFT20";

    let mut proof_repository = MockProofRepository::new();
    proof_repository
        .expect_get_proof_by_interaction_id()
        .once()
        .return_once(move |_, _| {
            Ok(Some(Proof {
                id: proof_id,
                exchange: protocol.to_string(),
                state: ProofStateEnum::Requested,
                interaction: Some(Interaction {
                    id: interaction_id,
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    host: Some("http://www.host.co".parse().unwrap()),
                    data: None,
                    organisation: None,
                }),
                ..dummy_proof()
            }))
        });

    proof_repository
        .expect_update_proof()
        .withf(move |actual_proof_id, actual_proof_state, _| {
            assert_eq!(actual_proof_id, &proof_id);
            assert_eq!(actual_proof_state.state, Some(ProofStateEnum::Error));
            true
        })
        .once()
        .return_once(move |_, _, _| Ok(()));

    let mut verification_protocol_mock = MockVerificationProtocol::default();
    verification_protocol_mock
        .expect_holder_reject_proof()
        .withf(move |proof| {
            assert_eq!(Uuid::from(proof.id), Uuid::from(proof_id));
            true
        })
        .once()
        .return_once(move |_| Err(VerificationProtocolError::Failed("error".to_string())));

    let mut verification_protocol_provider = MockVerificationProtocolProvider::new();
    verification_protocol_provider
        .expect_get_protocol()
        .withf(move |_protocol| {
            assert_eq!(_protocol, protocol);
            true
        })
        .once()
        .return_once(move |_| Some(Arc::new(verification_protocol_mock)));

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let service = SSIHolderService {
        proof_repository: Arc::new(proof_repository),
        verification_protocol_provider: Arc::new(verification_protocol_provider),
        ..mock_ssi_holder_service()
    };

    service.reject_proof_request(&interaction_id).await.unwrap();
}

#[tokio::test]
async fn test_submit_proof_succeeds() {
    let identifier_id = Uuid::new_v4().into();
    let interaction_id = Uuid::new_v4();

    let proof_id = Uuid::new_v4().into();
    let protocol = "protocol";

    let mut identifier_repository = MockIdentifierRepository::default();
    identifier_repository.expect_get().return_once(move |_, _| {
        Ok(Some(Identifier {
            id: identifier_id,
            did: Some(Did {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key: dummy_key(),
                }]),
                did_method: "KEY".to_string(),
                ..dummy_did()
            }),
            ..dummy_identifier()
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
                state: ProofStateEnum::Requested,
                interaction: Some(Interaction {
                    id: interaction_id,
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    host: Some("http://www.host.co".parse().unwrap()),
                    data: Some(serde_json::to_vec(&()).unwrap()),
                    organisation: None,
                }),
                ..dummy_proof()
            }))
        });

    proof_repository
        .expect_set_proof_claims()
        .once()
        .returning(|_, _| Ok(()));

    proof_repository
        .expect_update_proof()
        .once()
        .returning(|_, _, _| Ok(()));

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
        .returning(|presentation, _, _| Ok(presentation.token));

    formatter
        .expect_get_capabilities()
        .once()
        .returning(generic_formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    let formatter = Arc::new(formatter);
    formatter_provider
        .expect_get_formatter()
        .times(1)
        .returning(move |_| Some(formatter.clone()));

    let mut verification_protocol = MockVerificationProtocol::default();
    verification_protocol
        .expect_holder_get_presentation_definition()
        .withf(move |proof, _, _| {
            assert_eq!(Uuid::from(proof.id), Uuid::from(proof_id));
            true
        })
        .once()
        .returning(|_, _, _| {
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
                            inapplicable_credentials: vec![],
                            validity_credential_nbf: None,
                        },
                    ],
                }],
                credentials: vec![],
            })
        });

    verification_protocol
        .expect_holder_submit_proof()
        .withf(move |proof, _, _, _, _| {
            assert_eq!(Uuid::from(proof.id), Uuid::from(proof_id));
            true
        })
        .once()
        .returning(|_, _, _, _, _| Ok(Default::default()));

    verification_protocol
        .expect_holder_get_holder_binding_context()
        .returning(|_, _| Ok(None));

    let mut verification_protocol_provider = MockVerificationProtocolProvider::new();
    verification_protocol_provider
        .expect_get_protocol()
        .with(eq(protocol))
        .once()
        .return_once(move |_| Some(Arc::new(verification_protocol)));

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let mut did_method_provider = MockDidMethodProvider::new();
    did_method_provider
        .expect_get_verification_method_id_from_did_and_key()
        .once()
        .returning(|_, _| Ok("did:key:dummy_verification_method_id#0".to_string()));

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .once()
        .returning(|_| Some(Arc::new(Ecdsa)));

    let service = SSIHolderService {
        credential_repository: Arc::new(credential_repository),
        proof_repository: Arc::new(proof_repository),
        formatter_provider: Arc::new(formatter_provider),
        verification_protocol_provider: Arc::new(verification_protocol_provider),
        identifier_repository: Arc::new(identifier_repository),
        did_method_provider: Arc::new(did_method_provider),
        key_algorithm_provider: Arc::new(key_algorithm_provider),
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
            did_id: None,
            identifier_id: Some(identifier_id),
            key_id: None,
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn test_submit_proof_succeeds_with_did() {
    let did_id = Uuid::new_v4().into();
    let interaction_id = Uuid::new_v4();

    let proof_id = Uuid::new_v4().into();
    let protocol = "protocol";

    let mut identifier_repository = MockIdentifierRepository::default();
    identifier_repository
        .expect_get_from_did_id()
        .return_once(move |_, _| {
            Ok(Some(Identifier {
                did: Some(Did {
                    id: did_id,
                    keys: Some(vec![RelatedKey {
                        role: KeyRole::Authentication,
                        key: dummy_key(),
                    }]),
                    did_method: "KEY".to_string(),
                    ..dummy_did()
                }),
                ..dummy_identifier()
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
                state: ProofStateEnum::Requested,
                interaction: Some(Interaction {
                    id: interaction_id,
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    host: Some("http://www.host.co".parse().unwrap()),
                    data: Some(serde_json::to_vec(&()).unwrap()),
                    organisation: None,
                }),
                ..dummy_proof()
            }))
        });

    proof_repository
        .expect_set_proof_claims()
        .once()
        .returning(|_, _| Ok(()));

    proof_repository
        .expect_update_proof()
        .once()
        .returning(|_, _, _| Ok(()));

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
        .returning(|presentation, _, _| Ok(presentation.token));

    formatter
        .expect_get_capabilities()
        .once()
        .returning(generic_formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    let formatter = Arc::new(formatter);
    formatter_provider
        .expect_get_formatter()
        .times(1)
        .returning(move |_| Some(formatter.clone()));

    let mut verification_protocol = MockVerificationProtocol::default();
    verification_protocol
        .expect_holder_get_presentation_definition()
        .withf(move |proof, _, _| {
            assert_eq!(Uuid::from(proof.id), Uuid::from(proof_id));
            true
        })
        .once()
        .returning(|_, _, _| {
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
                            inapplicable_credentials: vec![],
                            validity_credential_nbf: None,
                        },
                    ],
                }],
                credentials: vec![],
            })
        });

    verification_protocol
        .expect_holder_submit_proof()
        .withf(move |proof, _, _, _, _| {
            assert_eq!(Uuid::from(proof.id), Uuid::from(proof_id));
            true
        })
        .once()
        .returning(|_, _, _, _, _| Ok(Default::default()));

    verification_protocol
        .expect_holder_get_holder_binding_context()
        .returning(|_, _| Ok(None));

    let mut verification_protocol_provider = MockVerificationProtocolProvider::new();
    verification_protocol_provider
        .expect_get_protocol()
        .with(eq(protocol))
        .once()
        .return_once(move |_| Some(Arc::new(verification_protocol)));

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let mut did_method_provider = MockDidMethodProvider::new();
    did_method_provider
        .expect_get_verification_method_id_from_did_and_key()
        .once()
        .returning(|_, _| Ok("did:key:dummy_verification_method_id#0".to_string()));

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .once()
        .returning(|_| Some(Arc::new(Ecdsa)));

    let service = SSIHolderService {
        credential_repository: Arc::new(credential_repository),
        proof_repository: Arc::new(proof_repository),
        formatter_provider: Arc::new(formatter_provider),
        verification_protocol_provider: Arc::new(verification_protocol_provider),
        identifier_repository: Arc::new(identifier_repository),
        did_method_provider: Arc::new(did_method_provider),
        key_algorithm_provider: Arc::new(key_algorithm_provider),
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
            did_id: Some(did_id),
            identifier_id: None,
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

    let mut identifier_repository = MockIdentifierRepository::default();
    identifier_repository
        .expect_get_from_did_id()
        .return_once(move |_, _| {
            Ok(Some(Identifier {
                did: Some(Did {
                    id: did_id,
                    keys: Some(vec![RelatedKey {
                        role: KeyRole::Authentication,
                        key: dummy_key(),
                    }]),
                    did_method: "KEY".to_string(),
                    ..dummy_did()
                }),
                ..dummy_identifier()
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
                state: ProofStateEnum::Requested,
                interaction: Some(Interaction {
                    id: interaction_id,
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    host: Some("http://www.host.co".parse().unwrap()),
                    data: Some(serde_json::to_vec(&()).unwrap()),
                    organisation: None,
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
        .returning(|presentation, _, _| Ok(presentation.token));

    formatter
        .expect_get_capabilities()
        .times(2)
        .returning(generic_formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    let formatter = Arc::new(formatter);
    formatter_provider
        .expect_get_formatter()
        .returning(move |_| Some(formatter.clone()));

    let mut verification_protocol = MockVerificationProtocol::default();
    verification_protocol
        .expect_holder_get_presentation_definition()
        .withf(move |proof, _, _| {
            assert_eq!(Uuid::from(proof.id), Uuid::from(proof_id));
            true
        })
        .once()
        .returning(move |_, _, _| {
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
                            inapplicable_credentials: vec![],
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
                            inapplicable_credentials: vec![],
                            validity_credential_nbf: None,
                        },
                    ],
                }],
                credentials: vec![],
            })
        });

    verification_protocol
        .expect_holder_submit_proof()
        .withf(move |proof, _, _, _, _| {
            assert_eq!(Uuid::from(proof.id), Uuid::from(proof_id));
            true
        })
        .once()
        .returning(|_, _, _, _, _| Ok(Default::default()));

    verification_protocol
        .expect_holder_get_holder_binding_context()
        .returning(|_, _| Ok(None));

    let mut verification_protocol_provider = MockVerificationProtocolProvider::new();
    verification_protocol_provider
        .expect_get_protocol()
        .with(eq(protocol))
        .once()
        .return_once(move |_| Some(Arc::new(verification_protocol)));

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
        .expect_update_proof()
        .once()
        .returning(|_, _, _| Ok(()));

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let mut did_method_provider = MockDidMethodProvider::new();
    did_method_provider
        .expect_get_verification_method_id_from_did_and_key()
        .once()
        .returning(|_, _| Ok("did:key:dummy_verification_method_id#0".to_string()));

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .times(2)
        .returning(|_| Some(Arc::new(Ecdsa)));

    let service = SSIHolderService {
        credential_repository: Arc::new(credential_repository),
        proof_repository: Arc::new(proof_repository),
        formatter_provider: Arc::new(formatter_provider),
        verification_protocol_provider: Arc::new(verification_protocol_provider),
        identifier_repository: Arc::new(identifier_repository),
        did_method_provider: Arc::new(did_method_provider),
        key_algorithm_provider: Arc::new(key_algorithm_provider),
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
            did_id: Some(did_id),
            identifier_id: None,
            key_id: None,
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn test_accept_credential() {
    let identifier_id = Uuid::new_v4().into();

    let mut identifier_repository = MockIdentifierRepository::new();
    identifier_repository.expect_get().return_once(move |_, _| {
        Ok(Some(Identifier {
            id: identifier_id,
            did: Some(Did {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key: dummy_key(),
                }]),
                did_method: "KEY".to_string(),
                ..dummy_did()
            }),
            ..dummy_identifier()
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

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .once()
        .returning(|_| Some(Arc::new(Ecdsa)));

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
        .returning(|_, _| Ok(()));

    let mut exchange_protocol_mock = MockIssuanceProtocol::default();
    exchange_protocol_mock
        .expect_holder_accept_credential()
        .once()
        .returning(|_, _, _, _, _, _, _| {
            Ok(UpdateResponse {
                result: SubmitIssuerResponse {
                    credential: "credential".to_string(),
                    redirect_uri: None,
                },
                create_did: None,
                create_identifier: None,
                update_credential: None,
                update_credential_schema: None,
            })
        });

    let mut issuance_protocol_provider = MockIssuanceProtocolProvider::new();
    issuance_protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Some(Arc::new(exchange_protocol_mock)));

    let mut formatter = MockCredentialFormatter::new();

    formatter
        .expect_extract_credentials_unverified()
        .once()
        .returning(move |_, _| {
            Ok(DetailCredential {
                id: None,
                valid_from: Some(OffsetDateTime::now_utc()),
                valid_until: Some(OffsetDateTime::now_utc() + Duration::days(10)),
                update_at: None,
                invalid_before: Some(OffsetDateTime::now_utc()),
                issuer_did: None,
                subject: None,
                claims: CredentialSubject {
                    claims: HashMap::from([("key1".to_string(), json!("key1_value"))]),
                    id: None,
                },
                status: vec![],
                credential_schema: Some(
                    crate::provider::credential_formatter::model::CredentialSchema {
                        id: "SchemaId".to_string(),
                        r#type: CredentialSchemaType::Mdoc.to_string(),
                        metadata: None,
                    },
                ),
            })
        });

    formatter
        .expect_get_capabilities()
        .once()
        .returning(generic_formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    let formatter = Arc::new(formatter);
    formatter_provider
        .expect_get_formatter()
        .times(2)
        .returning(move |_| Some(formatter.clone()));

    let service = SSIHolderService {
        credential_repository: Arc::new(credential_repository),
        issuance_protocol_provider: Arc::new(issuance_protocol_provider),
        identifier_repository: Arc::new(identifier_repository),
        key_provider: Arc::new(key_provider),
        key_algorithm_provider: Arc::new(key_algorithm_provider),
        formatter_provider: Arc::new(formatter_provider),
        ..mock_ssi_holder_service()
    };

    let interaction_id = Uuid::new_v4();
    service
        .accept_credential(&interaction_id, None, Some(identifier_id), None, None)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_accept_credential_with_did() {
    let did_id = Uuid::new_v4().into();

    let mut identifier_repository = MockIdentifierRepository::new();
    identifier_repository
        .expect_get_from_did_id()
        .return_once(move |_, _| {
            Ok(Some(Identifier {
                did: Some(Did {
                    id: did_id,
                    keys: Some(vec![RelatedKey {
                        role: KeyRole::Authentication,
                        key: dummy_key(),
                    }]),
                    did_method: "KEY".to_string(),
                    ..dummy_did()
                }),
                ..dummy_identifier()
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

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .once()
        .returning(|_| Some(Arc::new(Ecdsa)));

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
        .returning(|_, _| Ok(()));

    let mut exchange_protocol_mock = MockIssuanceProtocol::default();
    exchange_protocol_mock
        .expect_holder_accept_credential()
        .once()
        .returning(|_, _, _, _, _, _, _| {
            Ok(UpdateResponse {
                result: SubmitIssuerResponse {
                    credential: "credential".to_string(),
                    redirect_uri: None,
                },
                create_did: None,
                create_identifier: None,
                update_credential: None,
                update_credential_schema: None,
            })
        });

    let mut issuance_protocol_provider = MockIssuanceProtocolProvider::new();
    issuance_protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Some(Arc::new(exchange_protocol_mock)));

    let mut formatter = MockCredentialFormatter::new();

    formatter
        .expect_extract_credentials_unverified()
        .once()
        .returning(move |_, _| {
            Ok(DetailCredential {
                id: None,
                valid_from: Some(OffsetDateTime::now_utc()),
                valid_until: Some(OffsetDateTime::now_utc() + Duration::days(10)),
                update_at: None,
                invalid_before: Some(OffsetDateTime::now_utc()),
                issuer_did: None,
                subject: None,
                claims: CredentialSubject {
                    claims: HashMap::from([("key1".to_string(), json!("key1_value"))]),
                    id: None,
                },
                status: vec![],
                credential_schema: Some(
                    crate::provider::credential_formatter::model::CredentialSchema {
                        id: "SchemaId".to_string(),
                        r#type: CredentialSchemaType::Mdoc.to_string(),
                        metadata: None,
                    },
                ),
            })
        });

    formatter
        .expect_get_capabilities()
        .once()
        .returning(generic_formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    let formatter = Arc::new(formatter);
    formatter_provider
        .expect_get_formatter()
        .times(2)
        .returning(move |_| Some(formatter.clone()));

    let service = SSIHolderService {
        credential_repository: Arc::new(credential_repository),
        issuance_protocol_provider: Arc::new(issuance_protocol_provider),
        identifier_repository: Arc::new(identifier_repository),
        key_provider: Arc::new(key_provider),
        key_algorithm_provider: Arc::new(key_algorithm_provider),
        formatter_provider: Arc::new(formatter_provider),
        ..mock_ssi_holder_service()
    };

    let interaction_id = Uuid::new_v4();
    service
        .accept_credential(&interaction_id, Some(did_id), None, None, None)
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
        .returning(|_, _| Ok(()));

    let mut exchange_protocol_mock = MockIssuanceProtocol::default();
    exchange_protocol_mock
        .expect_holder_reject_credential()
        .once()
        .returning(|_| Ok(()));

    let mut issuance_protocol_provider = MockIssuanceProtocolProvider::new();
    issuance_protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Some(Arc::new(exchange_protocol_mock)));

    let service = SSIHolderService {
        credential_repository: Arc::new(credential_repository),
        issuance_protocol_provider: Arc::new(issuance_protocol_provider),
        ..mock_ssi_holder_service()
    };

    let interaction_id = Uuid::new_v4();
    service.reject_credential(&interaction_id).await.unwrap();
}

fn mock_ssi_holder_service() -> SSIHolderService {
    let mut did_method_provider = MockDidMethodProvider::new();
    did_method_provider
        .expect_get_verification_method_id_from_did_and_key()
        .returning(|_, _| Ok("did:key:dummy_verification_method_id#0".to_string()));

    let client = Arc::new(ReqwestClient::default());
    let remote_entity_storage = Arc::new(MockRemoteEntityStorage::new());

    SSIHolderService {
        credential_repository: Arc::new(MockCredentialRepository::new()),
        proof_repository: Arc::new(MockProofRepository::new()),
        organisation_repository: Arc::new(MockOrganisationRepository::new()),
        interaction_repository: Arc::new(MockInteractionRepository::new()),
        credential_schema_repository: Arc::new(MockCredentialSchemaRepository::new()),
        validity_credential_repository: Arc::new(MockValidityCredentialRepository::new()),
        did_repository: Arc::new(MockDidRepository::new()),
        identifier_repository: Arc::new(MockIdentifierRepository::new()),
        key_provider: Arc::new(MockKeyProvider::new()),
        key_algorithm_provider: Arc::new(MockKeyAlgorithmProvider::new()),
        formatter_provider: Arc::new(MockCredentialFormatterProvider::new()),
        issuance_protocol_provider: Arc::new(MockIssuanceProtocolProvider::new()),
        verification_protocol_provider: Arc::new(MockVerificationProtocolProvider::new()),
        did_method_provider: Arc::new(did_method_provider),
        config: Arc::new(generic_config().core),
        client: client.clone(),
        vct_type_metadata_cache: Arc::new(VctTypeMetadataCache::new(
            Arc::new(VctTypeMetadataResolver::new(client)),
            remote_entity_storage,
            0,
            Duration::seconds(60),
            Duration::seconds(60),
        )),
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
        exchange: "OPENID4VCI_DRAFT13".to_string(),
        redirect_uri: None,
        role: CredentialRole::Issuer,
        state: CredentialStateEnum::Pending,
        suspend_end_date: None,
        claims: None,
        issuer_identifier: Some(Identifier {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            name: "identifier".to_string(),
            r#type: IdentifierType::Did,
            is_remote: true,
            state: IdentifierState::Active,
            deleted_at: None,
            organisation: None,
            did: Some(Did {
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
                log: None,
            }),
            key: None,
            certificates: None,
        }),
        holder_identifier: None,
        schema: Some(crate::model::credential_schema::CredentialSchema {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            imported_source_url: "CORE_URL".to_string(),
            name: "schema".to_string(),
            external_schema: false,
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            format: "JWT".to_string(),
            revocation_method: "NONE".to_string(),
            claim_schemas: Some(vec![CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "key1".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    array: false,
                },
                required: true,
            }]),
            organisation: Some(dummy_organisation(None)),
            deleted_at: None,
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_type: CredentialSchemaType::ProcivisOneSchema2024,
            schema_id: "CredentialSchemaId".to_owned(),
            allow_suspension: true,
        }),
        interaction: Some(Interaction {
            id: Uuid::new_v4(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            host: Some("http://www.host.co".parse().unwrap()),
            data: Some(b"interaction data".to_vec()),
            organisation: None,
        }),
        revocation_list: None,
        key: None,
    }
}
