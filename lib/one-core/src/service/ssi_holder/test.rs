use std::collections::HashMap;
use std::sync::Arc;
use std::vec;

use mockall::predicate::eq;
use one_dto_mapper::try_convert_inner;
use regex::Regex;
use serde_json::json;
use shared_types::OrganisationId;
use similar_asserts::assert_eq;
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;
use wiremock::http::Method;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::config::core_config;
use crate::config::core_config::TransportType;
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{Credential, CredentialRole, CredentialStateEnum};
use crate::model::credential_schema::{CredentialSchemaClaim, KeyStorageSecurity, LayoutType};
use crate::model::did::{Did, DidType, KeyRole, RelatedKey};
use crate::model::identifier::{Identifier, IdentifierState, IdentifierType};
use crate::model::interaction::{Interaction, InteractionType};
use crate::model::proof::{Proof, ProofStateEnum};
use crate::proto::credential_schema::importer::MockCredentialSchemaImporter;
use crate::proto::http_client::reqwest_client::ReqwestClient;
use crate::proto::identifier_creator::MockIdentifierCreator;
use crate::proto::session_provider::test::StaticSessionProvider;
use crate::proto::session_provider::{NoSessionProvider, Session};
use crate::provider::blob_storage_provider::{MockBlobStorage, MockBlobStorageProvider};
use crate::provider::credential_formatter::MockCredentialFormatter;
use crate::provider::credential_formatter::model::{
    CredentialSubject, DetailCredential, IdentifierDetails, MockSignatureProvider,
};
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::issuance_protocol::MockIssuanceProtocol;
use crate::provider::issuance_protocol::dto::{Features, IssuanceProtocolCapabilities};
use crate::provider::issuance_protocol::model::{
    ContinueIssuanceResponseDTO, SubmitIssuerResponse, UpdateResponse,
};
use crate::provider::issuance_protocol::openid4vci_final1_0::model::{
    OAuthAuthorizationServerMetadata, OAuthCodeChallengeMethod,
};
use crate::provider::issuance_protocol::provider::MockIssuanceProtocolProvider;
use crate::provider::key_algorithm::ecdsa::Ecdsa;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_security_level::basic::Basic;
use crate::provider::key_security_level::dto::{HolderParams, Params};
use crate::provider::key_security_level::provider::MockKeySecurityLevelProvider;
use crate::provider::key_storage::MockKeyStorage;
use crate::provider::key_storage::model::KeyStorageCapabilities;
use crate::provider::key_storage::provider::MockKeyProvider;
use crate::provider::verification_protocol::MockVerificationProtocol;
use crate::provider::verification_protocol::dto::{
    PresentationDefinitionFieldDTO, PresentationDefinitionRequestGroupResponseDTO,
    PresentationDefinitionRequestedCredentialResponseDTO, PresentationDefinitionResponseDTO,
    PresentationDefinitionRuleDTO, PresentationDefinitionRuleTypeEnum,
    PresentationDefinitionVersion, VerificationProtocolCapabilities,
};
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::provider::MockVerificationProtocolProvider;
use crate::repository::certificate_repository::MockCertificateRepository;
use crate::repository::credential_repository::MockCredentialRepository;
use crate::repository::credential_schema_repository::MockCredentialSchemaRepository;
use crate::repository::did_repository::MockDidRepository;
use crate::repository::identifier_repository::MockIdentifierRepository;
use crate::repository::interaction_repository::MockInteractionRepository;
use crate::repository::key_repository::MockKeyRepository;
use crate::repository::organisation_repository::MockOrganisationRepository;
use crate::repository::proof_repository::MockProofRepository;
use crate::repository::validity_credential_repository::MockValidityCredentialRepository;
use crate::service::error::{BusinessLogicError, ServiceError, ValidationError};
use crate::service::ssi_holder::SSIHolderService;
use crate::service::ssi_holder::dto::{
    InitiateIssuanceAuthorizationDetailDTO, InitiateIssuanceRequestDTO,
    OpenIDAuthorizationCodeFlowInteractionData, PresentationSubmitCredentialRequestDTO,
    PresentationSubmitRequestDTO,
};
use crate::service::test_utilities::{
    dummy_blob, dummy_did, dummy_identifier, dummy_key, dummy_organisation, dummy_proof,
    generic_config, generic_formatter_capabilities, get_dummy_date,
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
                protocol: protocol.to_string(),
                state: ProofStateEnum::Requested,
                interaction: Some(Interaction {
                    id: interaction_id,
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    data: None,
                    organisation: None,
                    nonce_id: None,
                    interaction_type: InteractionType::Verification,
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

    let service = SSIHolderService {
        proof_repository: Arc::new(proof_repository),
        verification_protocol_provider: Arc::new(verification_protocol_provider),
        ..mock_ssi_holder_service()
    };

    service.reject_proof_request(&interaction_id).await.unwrap();
}

#[tokio::test]
async fn test_reject_proof_request_fails_when_latest_state_is_not_requested() {
    let reject_proof_for_state = |state| async move {
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
                    protocol: protocol.to_string(),
                    state,
                    interaction: Some(Interaction {
                        id: interaction_id,
                        created_date: OffsetDateTime::now_utc(),
                        last_modified: OffsetDateTime::now_utc(),
                        data: None,
                        organisation: None,
                        nonce_id: None,
                        interaction_type: InteractionType::Verification,
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
                protocol: protocol.to_string(),
                state: ProofStateEnum::Requested,
                interaction: Some(Interaction {
                    id: interaction_id,
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    data: None,
                    organisation: None,
                    nonce_id: None,
                    interaction_type: InteractionType::Verification,
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

    let key = dummy_key();
    let did = Did {
        keys: Some(vec![RelatedKey {
            role: KeyRole::Authentication,
            key: key.clone(),
            reference: "1".to_string(),
        }]),
        did_method: "KEY".to_string(),
        ..dummy_did()
    };
    let mut identifier_repository = MockIdentifierRepository::default();
    let did_copy = did.clone();
    identifier_repository.expect_get().return_once(move |_, _| {
        Ok(Some(Identifier {
            id: identifier_id,
            did: Some(did_copy),
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
                protocol: protocol.to_string(),
                state: ProofStateEnum::Requested,
                interaction: Some(Interaction {
                    id: interaction_id,
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    data: Some(serde_json::to_vec(&()).unwrap()),
                    organisation: None,
                    nonce_id: None,
                    interaction_type: InteractionType::Verification,
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
                claims: Some(vec![]),
                holder_identifier: Some(Identifier {
                    key: Some(key.clone()),
                    did: Some(did.clone()),
                    ..dummy_identifier()
                }),
                key: Some(key.clone()),
                ..dummy_credential(None)
            }))
        });

    let mut formatter = MockCredentialFormatter::new();

    formatter
        .expect_format_credential_presentation()
        .once()
        .returning(|presentation, _, _| Ok(presentation.token));

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    let formatter = Arc::new(formatter);
    formatter_provider
        .expect_get_credential_formatter()
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
                            multiple: None,
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
        .expect_get_capabilities()
        .times(1)
        .returning(|| VerificationProtocolCapabilities {
            supported_transports: vec![TransportType::Http],
            did_methods: vec![core_config::DidType::Key],
            verifier_identifier_types: vec![core_config::IdentifierType::Did],
            supported_presentation_definition: vec![PresentationDefinitionVersion::V1],
        });

    verification_protocol
        .expect_holder_submit_proof()
        .withf(move |proof, _| {
            assert_eq!(Uuid::from(proof.id), Uuid::from(proof_id));
            true
        })
        .once()
        .returning(|_, _| Ok(Default::default()));

    verification_protocol
        .expect_holder_get_holder_binding_context()
        .returning(|_, _| Ok(None));

    let mut verification_protocol_provider = MockVerificationProtocolProvider::new();
    verification_protocol_provider
        .expect_get_protocol()
        .with(eq(protocol))
        .once()
        .return_once(move |_| Some(Arc::new(verification_protocol)));

    let mut blob_storage = MockBlobStorage::new();
    blob_storage
        .expect_get()
        .once()
        .returning(|_| Ok(Some(dummy_blob())));
    let blob_storage = Arc::new(blob_storage);
    let mut blob_storage_provider = MockBlobStorageProvider::new();
    blob_storage_provider
        .expect_get_blob_storage()
        .once()
        .returning(move |_| Some(blob_storage.clone()));

    let mut key_provider = MockKeyProvider::new();
    key_provider
        .expect_get_signature_provider()
        .returning(move |_, _, _| {
            let mut mock_signature_provider = MockSignatureProvider::new();
            mock_signature_provider
                .expect_jose_alg()
                .returning(|| Some("EdDSA".to_string()));

            mock_signature_provider
                .expect_get_key_id()
                .returning(|| Some("key-id".to_string()));

            mock_signature_provider
                .expect_sign()
                .returning(|_| Ok(vec![0; 32]));

            Ok(Box::new(mock_signature_provider))
        });

    let service = SSIHolderService {
        credential_repository: Arc::new(credential_repository),
        proof_repository: Arc::new(proof_repository),
        formatter_provider: Arc::new(formatter_provider),
        verification_protocol_provider: Arc::new(verification_protocol_provider),
        identifier_repository: Arc::new(identifier_repository),
        blob_storage_provider: Arc::new(blob_storage_provider),
        key_provider: Arc::new(key_provider),
        ..mock_ssi_holder_service()
    };

    service
        .submit_proof(PresentationSubmitRequestDTO {
            interaction_id,
            submit_credentials: std::iter::once((
                "cred1".to_string(),
                vec![PresentationSubmitCredentialRequestDTO {
                    credential_id,
                    submit_claims: vec![],
                }],
            ))
            .collect(),
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn test_submit_proof_multiple_credentials_succeeds() {
    let identifier_id = Uuid::new_v4().into();
    let interaction_id = Uuid::new_v4();

    let proof_id = Uuid::new_v4().into();
    let protocol = "protocol";

    let key = dummy_key();
    let did = Did {
        keys: Some(vec![RelatedKey {
            role: KeyRole::Authentication,
            key: key.clone(),
            reference: "1".to_string(),
        }]),
        did_method: "KEY".to_string(),
        ..dummy_did()
    };

    let mut identifier_repository = MockIdentifierRepository::default();
    let did_copy = did.clone();
    identifier_repository.expect_get().return_once(move |_, _| {
        Ok(Some(Identifier {
            id: identifier_id,
            did: Some(did_copy),
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
                protocol: protocol.to_string(),
                state: ProofStateEnum::Requested,
                interaction: Some(Interaction {
                    id: interaction_id,
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    data: Some(serde_json::to_vec(&()).unwrap()),
                    organisation: None,
                    nonce_id: None,
                    interaction_type: InteractionType::Verification,
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

    let credential_id_1 = Uuid::new_v4().into();
    let credential_id_2 = Uuid::new_v4().into();
    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_get_credential()
        .times(2)
        .returning(move |credential_id, _| {
            Ok(Some(Credential {
                id: *credential_id,
                claims: Some(vec![]),
                holder_identifier: Some(Identifier {
                    key: Some(key.clone()),
                    did: Some(did.clone()),
                    ..dummy_identifier()
                }),
                key: Some(key.clone()),
                ..dummy_credential(None)
            }))
        });

    let mut formatter = MockCredentialFormatter::new();

    formatter
        .expect_format_credential_presentation()
        .times(2)
        .returning(|presentation, _, _| Ok(presentation.token));

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    let formatter = Arc::new(formatter);
    formatter_provider
        .expect_get_credential_formatter()
        .times(2)
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
                            multiple: Some(true),
                            fields: vec![],
                            applicable_credentials: vec![],
                            inapplicable_credentials: vec![],
                            validity_credential_nbf: None,
                        },
                        PresentationDefinitionRequestedCredentialResponseDTO {
                            id: "cred2".to_string(),
                            name: None,
                            purpose: None,
                            multiple: Some(true),
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
        .expect_get_capabilities()
        .times(1)
        .returning(|| VerificationProtocolCapabilities {
            supported_transports: vec![TransportType::Http],
            did_methods: vec![core_config::DidType::Key],
            verifier_identifier_types: vec![core_config::IdentifierType::Did],
            supported_presentation_definition: vec![PresentationDefinitionVersion::V1],
        });

    verification_protocol
        .expect_holder_submit_proof()
        .withf(move |proof, _| {
            assert_eq!(Uuid::from(proof.id), Uuid::from(proof_id));
            true
        })
        .once()
        .returning(|_, _| Ok(Default::default()));

    verification_protocol
        .expect_holder_get_holder_binding_context()
        .returning(|_, _| Ok(None));

    let mut verification_protocol_provider = MockVerificationProtocolProvider::new();
    verification_protocol_provider
        .expect_get_protocol()
        .with(eq(protocol))
        .once()
        .return_once(move |_| Some(Arc::new(verification_protocol)));

    let mut blob_storage = MockBlobStorage::new();
    blob_storage
        .expect_get()
        .times(2)
        .returning(|_| Ok(Some(dummy_blob())));
    let blob_storage = Arc::new(blob_storage);
    let mut blob_storage_provider = MockBlobStorageProvider::new();
    blob_storage_provider
        .expect_get_blob_storage()
        .times(2)
        .returning(move |_| Some(blob_storage.clone()));

    let mut key_provider = MockKeyProvider::new();
    key_provider
        .expect_get_signature_provider()
        .returning(move |_, _, _| {
            let mut mock_signature_provider = MockSignatureProvider::new();
            mock_signature_provider
                .expect_jose_alg()
                .returning(|| Some("EdDSA".to_string()));

            mock_signature_provider
                .expect_get_key_id()
                .returning(|| Some("key-id".to_string()));

            mock_signature_provider
                .expect_sign()
                .returning(|_| Ok(vec![0; 32]));

            Ok(Box::new(mock_signature_provider))
        });

    let service = SSIHolderService {
        credential_repository: Arc::new(credential_repository),
        proof_repository: Arc::new(proof_repository),
        formatter_provider: Arc::new(formatter_provider),
        verification_protocol_provider: Arc::new(verification_protocol_provider),
        identifier_repository: Arc::new(identifier_repository),
        blob_storage_provider: Arc::new(blob_storage_provider),
        key_provider: Arc::new(key_provider),
        ..mock_ssi_holder_service()
    };

    service
        .submit_proof(PresentationSubmitRequestDTO {
            interaction_id,
            submit_credentials: HashMap::from([
                (
                    "cred1".to_string(),
                    vec![PresentationSubmitCredentialRequestDTO {
                        credential_id: credential_id_1,
                        submit_claims: vec![],
                    }],
                ),
                (
                    "cred2".to_string(),
                    vec![PresentationSubmitCredentialRequestDTO {
                        credential_id: credential_id_2,
                        submit_claims: vec![],
                    }],
                ),
            ]),
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn test_submit_proof_repeating_claims() {
    let interaction_id = Uuid::new_v4();
    let proof_id = Uuid::new_v4().into();
    let credential_id = Uuid::new_v4().into();
    let claim_id = Uuid::new_v4();
    let protocol = "protocol";

    let key = dummy_key();
    let did = Did {
        keys: Some(vec![RelatedKey {
            role: KeyRole::Authentication,
            key: key.clone(),
            reference: "1".to_string(),
        }]),
        did_method: "KEY".to_string(),
        ..dummy_did()
    };
    let identifier = Identifier {
        did: Some(did.clone()),
        ..dummy_identifier()
    };

    let mut identifier_repository = MockIdentifierRepository::default();
    let identifier_copy = identifier.clone();
    identifier_repository
        .expect_get_from_did_id()
        .return_once(move |_, _| Ok(Some(identifier_copy)));

    let mut proof_repository = MockProofRepository::new();
    proof_repository
        .expect_get_proof_by_interaction_id()
        .once()
        .returning(move |_, _| {
            Ok(Some(Proof {
                id: proof_id,
                protocol: protocol.to_string(),
                state: ProofStateEnum::Requested,
                interaction: Some(Interaction {
                    id: interaction_id,
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    data: Some(serde_json::to_vec(&()).unwrap()),
                    organisation: None,
                    nonce_id: None,
                    interaction_type: InteractionType::Verification,
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
                claims: Some(vec![Claim {
                    id: claim_id,
                    credential_id,
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    value: Some("claim value".to_string()),
                    path: "claim1".to_string(),
                    selectively_disclosable: false,
                    schema: Some(ClaimSchema {
                        id: claim_id.into(),
                        key: "claim1".to_string(),
                        data_type: "STRING".to_string(),
                        created_date: OffsetDateTime::now_utc(),
                        last_modified: OffsetDateTime::now_utc(),
                        array: false,
                        metadata: false,
                    }),
                }]),
                holder_identifier: Some(identifier.clone()),
                key: Some(key.clone()),
                ..dummy_credential(None)
            }))
        });

    let mut formatter = MockCredentialFormatter::new();
    formatter
        .expect_format_credential_presentation()
        .returning(|presentation, _, _| Ok(presentation.token));

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    let formatter = Arc::new(formatter);
    formatter_provider
        .expect_get_credential_formatter()
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
                            multiple: None,
                            fields: vec![PresentationDefinitionFieldDTO {
                                id: "claim1".to_string(),
                                name: None,
                                purpose: None,
                                required: None,
                                key_map: HashMap::from([(credential_id, "claim1".to_string())]),
                            }],
                            applicable_credentials: vec![],
                            inapplicable_credentials: vec![],
                            validity_credential_nbf: None,
                        },
                        PresentationDefinitionRequestedCredentialResponseDTO {
                            id: "cred2".to_string(),
                            name: None,
                            multiple: None,
                            purpose: None,
                            fields: vec![PresentationDefinitionFieldDTO {
                                id: "claim1".to_string(),
                                name: None,
                                purpose: None,
                                required: None,
                                key_map: HashMap::from([(credential_id, "claim1".to_string())]),
                            }],
                            applicable_credentials: vec![credential_id],
                            inapplicable_credentials: vec![],
                            validity_credential_nbf: None,
                        },
                    ],
                }],
                credentials: vec![],
            })
        });
    verification_protocol
        .expect_get_capabilities()
        .times(1)
        .returning(|| VerificationProtocolCapabilities {
            supported_transports: vec![TransportType::Http],
            did_methods: vec![core_config::DidType::Key],
            verifier_identifier_types: vec![core_config::IdentifierType::Did],
            supported_presentation_definition: vec![PresentationDefinitionVersion::V1],
        });

    verification_protocol
        .expect_holder_submit_proof()
        .withf(move |proof, _| {
            assert_eq!(Uuid::from(proof.id), Uuid::from(proof_id));
            true
        })
        .once()
        .returning(|_, _| Ok(Default::default()));

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

    let mut blob_storage = MockBlobStorage::new();
    blob_storage
        .expect_get()
        .times(2)
        .returning(|_| Ok(Some(dummy_blob())));
    let blob_storage = Arc::new(blob_storage);
    let mut blob_storage_provider = MockBlobStorageProvider::new();
    blob_storage_provider
        .expect_get_blob_storage()
        .times(2)
        .returning(move |_| Some(blob_storage.clone()));

    let mut key_provider = MockKeyProvider::new();
    key_provider
        .expect_get_signature_provider()
        .returning(move |_, _, _| {
            let mut mock_signature_provider = MockSignatureProvider::new();
            mock_signature_provider
                .expect_jose_alg()
                .returning(|| Some("EdDSA".to_string()));

            mock_signature_provider
                .expect_get_key_id()
                .returning(|| Some("key-id".to_string()));

            mock_signature_provider
                .expect_sign()
                .returning(|_| Ok(vec![0; 32]));

            Ok(Box::new(mock_signature_provider))
        });

    let service = SSIHolderService {
        credential_repository: Arc::new(credential_repository),
        proof_repository: Arc::new(proof_repository),
        formatter_provider: Arc::new(formatter_provider),
        verification_protocol_provider: Arc::new(verification_protocol_provider),
        identifier_repository: Arc::new(identifier_repository),
        blob_storage_provider: Arc::new(blob_storage_provider),
        key_provider: Arc::new(key_provider),
        ..mock_ssi_holder_service()
    };

    service
        .submit_proof(PresentationSubmitRequestDTO {
            interaction_id,
            submit_credentials: HashMap::from([
                (
                    "cred1".to_string(),
                    vec![PresentationSubmitCredentialRequestDTO {
                        credential_id,
                        submit_claims: vec!["claim1".to_string()],
                    }],
                ),
                (
                    "cred2".to_string(),
                    vec![PresentationSubmitCredentialRequestDTO {
                        credential_id,
                        submit_claims: vec!["claim1".to_string()],
                    }],
                ),
            ]),
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
                    reference: "1".to_string(),
                }]),
                did_method: "KEY".to_string(),
                ..dummy_did()
            }),
            organisation: Some(dummy_organisation(None)),
            ..dummy_identifier()
        }))
    });

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .once()
        .returning(|_| Some(Arc::new(Ecdsa)));

    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_get_credentials_by_interaction_id()
        .once()
        .return_once(move |_, _| Ok(vec![dummy_credential(None)]));
    credential_repository
        .expect_update_credential()
        .once()
        .returning(|_, _| Ok(()));

    let mut exchange_protocol_mock = MockIssuanceProtocol::default();
    exchange_protocol_mock
        .expect_holder_accept_credential()
        .once()
        .returning(|_, _, _, _, _| {
            Ok(UpdateResponse {
                result: SubmitIssuerResponse {
                    credential: "credential".to_string(),
                    redirect_uri: None,
                    notification_id: None,
                },
                create_did: None,
                create_certificate: None,
                create_identifier: None,
                update_credential: None,
                update_credential_schema: None,
                create_key: None,
                create_credential: None,
                create_credential_schema: None,
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
                issuance_date: None,
                valid_from: Some(OffsetDateTime::now_utc()),
                valid_until: Some(OffsetDateTime::now_utc() + Duration::days(10)),
                update_at: None,
                invalid_before: Some(OffsetDateTime::now_utc()),
                issuer: IdentifierDetails::Did("did:test:123".parse().unwrap()),
                subject: None,
                claims: CredentialSubject {
                    claims: try_convert_inner(HashMap::from([(
                        "key1".to_string(),
                        json!("key1_value"),
                    )]))
                    .unwrap(),
                    id: None,
                },
                status: vec![],
                credential_schema: Some(
                    crate::provider::credential_formatter::model::CredentialSchema {
                        id: "SchemaId".to_string(),
                        r#type: "Mdoc".to_string(),
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
        .expect_get_credential_formatter()
        .times(2)
        .returning(move |_| Some(formatter.clone()));

    let mut blob_storage = MockBlobStorage::new();
    blob_storage
        .expect_update()
        .once()
        .return_once(|_, _| Ok(()));
    let blob_storage = Arc::new(blob_storage);
    let mut blob_storage_provider = MockBlobStorageProvider::new();
    blob_storage_provider
        .expect_get_blob_storage()
        .once()
        .returning(move |_| Some(blob_storage.clone()));

    let mut key_security_level_provider = MockKeySecurityLevelProvider::new();
    key_security_level_provider
        .expect_get_from_type()
        .returning(|_| {
            Some(Arc::new(Basic::new(Params {
                holder: HolderParams {
                    priority: 0,
                    key_storages: vec!["foo".to_string()],
                },
            })))
        });

    let service = SSIHolderService {
        credential_repository: Arc::new(credential_repository),
        issuance_protocol_provider: Arc::new(issuance_protocol_provider),
        identifier_repository: Arc::new(identifier_repository),
        key_algorithm_provider: Arc::new(key_algorithm_provider),
        formatter_provider: Arc::new(formatter_provider),
        blob_storage_provider: Arc::new(blob_storage_provider),
        key_security_level_provider: Arc::new(key_security_level_provider),
        ..mock_ssi_holder_service()
    };

    let interaction_id = Uuid::new_v4();
    service
        .accept_credential(interaction_id, None, Some(identifier_id), None, None, None)
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
                        reference: "1".to_string(),
                    }]),
                    did_method: "KEY".to_string(),
                    ..dummy_did()
                }),
                organisation: Some(dummy_organisation(None)),
                ..dummy_identifier()
            }))
        });

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .once()
        .returning(|_| Some(Arc::new(Ecdsa)));

    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_get_credentials_by_interaction_id()
        .once()
        .return_once(move |_, _| Ok(vec![dummy_credential(None)]));
    credential_repository
        .expect_update_credential()
        .once()
        .returning(|_, _| Ok(()));

    let mut exchange_protocol_mock = MockIssuanceProtocol::default();
    exchange_protocol_mock
        .expect_holder_accept_credential()
        .once()
        .returning(|_, _, _, _, _| {
            Ok(UpdateResponse {
                result: SubmitIssuerResponse {
                    credential: "credential".to_string(),
                    redirect_uri: None,
                    notification_id: None,
                },
                create_did: None,
                create_certificate: None,
                create_identifier: None,
                update_credential: None,
                update_credential_schema: None,
                create_key: None,
                create_credential: None,
                create_credential_schema: None,
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
                issuance_date: None,
                valid_from: Some(OffsetDateTime::now_utc()),
                valid_until: Some(OffsetDateTime::now_utc() + Duration::days(10)),
                update_at: None,
                invalid_before: Some(OffsetDateTime::now_utc()),
                issuer: IdentifierDetails::Did("did:test:123".parse().unwrap()),
                subject: None,
                claims: CredentialSubject {
                    claims: try_convert_inner(HashMap::from([(
                        "key1".to_string(),
                        json!("key1_value"),
                    )]))
                    .unwrap(),
                    id: None,
                },
                status: vec![],
                credential_schema: Some(
                    crate::provider::credential_formatter::model::CredentialSchema {
                        id: "SchemaId".to_string(),
                        r#type: "Mdoc".to_string(),
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
        .expect_get_credential_formatter()
        .times(2)
        .returning(move |_| Some(formatter.clone()));

    let mut blob_storage = MockBlobStorage::new();
    blob_storage
        .expect_update()
        .once()
        .return_once(|_, _| Ok(()));
    let blob_storage = Arc::new(blob_storage);
    let mut blob_storage_provider = MockBlobStorageProvider::new();
    blob_storage_provider
        .expect_get_blob_storage()
        .once()
        .returning(move |_| Some(blob_storage.clone()));

    let mut key_security_level_provider = MockKeySecurityLevelProvider::new();
    key_security_level_provider
        .expect_get_from_type()
        .returning(|_| {
            Some(Arc::new(Basic::new(Params {
                holder: HolderParams {
                    priority: 0,
                    key_storages: vec!["foo".to_string()],
                },
            })))
        });

    let service = SSIHolderService {
        credential_repository: Arc::new(credential_repository),
        issuance_protocol_provider: Arc::new(issuance_protocol_provider),
        identifier_repository: Arc::new(identifier_repository),
        key_algorithm_provider: Arc::new(key_algorithm_provider),
        formatter_provider: Arc::new(formatter_provider),
        blob_storage_provider: Arc::new(blob_storage_provider),
        key_security_level_provider: Arc::new(key_security_level_provider),
        ..mock_ssi_holder_service()
    };

    let interaction_id = Uuid::new_v4();
    service
        .accept_credential(interaction_id, Some(did_id), None, None, None, None)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_reject_credential() {
    let mut credential = dummy_credential(None);
    credential.state = CredentialStateEnum::Accepted;

    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_get_credentials_by_interaction_id()
        .once()
        .return_once(move |_, _| Ok(vec![credential]));
    credential_repository
        .expect_update_credential()
        .once()
        .returning(|_, _| Ok(()));

    let mut exchange_protocol_mock = MockIssuanceProtocol::default();
    exchange_protocol_mock
        .expect_get_capabilities()
        .returning(|| IssuanceProtocolCapabilities {
            features: vec![Features::SupportsRejection],
            did_methods: vec![],
        });
    exchange_protocol_mock
        .expect_holder_reject_credential()
        .once()
        .returning(|_, _| Ok(()));

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

#[tokio::test]
async fn test_initiate_issuance() {
    let mut organisation_repository = MockOrganisationRepository::new();
    organisation_repository
        .expect_get_organisation()
        .return_once(|_, _| Ok(Some(dummy_organisation(None))));

    let mut interaction_repository = MockInteractionRepository::new();
    interaction_repository
        .expect_create_interaction()
        .return_once(|i| Ok(i.id));

    let service = SSIHolderService {
        organisation_repository: Arc::new(organisation_repository),
        interaction_repository: Arc::new(interaction_repository),
        ..mock_ssi_holder_service()
    };

    let mock_server = MockServer::start().await;

    let authorization_endpoint = "https://authorize.com/authorize";
    let issuer = mock_server.uri();
    Mock::given(method(Method::GET))
        .and(path("/.well-known/oauth-authorization-server"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(OAuthAuthorizationServerMetadata {
                issuer: issuer.parse().unwrap(),
                authorization_endpoint: Some(Url::parse(authorization_endpoint).unwrap()),
                token_endpoint: None,
                pushed_authorization_request_endpoint: None,
                jwks_uri: None,
                code_challenge_methods_supported: vec![],
                response_types_supported: vec![],
                grant_types_supported: vec![],
                token_endpoint_auth_methods_supported: vec![],
                challenge_endpoint: None,
                client_attestation_signing_alg_values_supported: None,
                client_attestation_pop_signing_alg_values_supported: None,
            }),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = service
        .initiate_issuance(InitiateIssuanceRequestDTO {
            organisation_id: Uuid::new_v4().into(),
            protocol: "OPENID4VCI_DRAFT13".to_string(),
            issuer,
            client_id: "clientId".to_string(),
            redirect_uri: Some("http://redirect.uri".to_string()),
            scope: Some(vec!["scope1".to_string(), "scope2".to_string()]),
            authorization_details: Some(vec![InitiateIssuanceAuthorizationDetailDTO {
                r#type: "type".to_string(),
                credential_configuration_id: "configurationId".to_string(),
            }]),
            issuer_state: None,
            authorization_server: None,
        })
        .await
        .unwrap();

    assert!(result.url.contains("https://authorize.com/"));
    assert!(result.url.contains("response_type=code"));
    assert!(result.url.contains("client_id=clientId"));
    assert!(
        Regex::new(".*state=[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}.*")
            .unwrap()
            .is_match(&result.url)
    );
    assert!(
        result
            .url
            .contains("redirect_uri=http%3A%2F%2Fredirect.uri")
    );
    assert!(result.url.contains("scope=scope1+scope2"));
    assert!(result.url.contains("authorization_details=%5B%7B%22credential_configuration_id%22%3A%22configurationId%22%2C%22type%22%3A%22type%22%7D%5D"));
}

#[tokio::test]
async fn test_continue_issuance() {
    // given
    let organisation = dummy_organisation(None);
    let interaction_id = Uuid::new_v4();

    let interaction_data = OpenIDAuthorizationCodeFlowInteractionData {
        request: InitiateIssuanceRequestDTO {
            organisation_id: organisation.id,
            protocol: "protocol".to_string(),
            issuer: "issuer".to_string(),
            client_id: "client_id".to_string(),
            redirect_uri: None,
            scope: Some(vec!["scope1".to_string(), "scope2".to_string()]),
            authorization_details: None,
            issuer_state: None,
            authorization_server: None,
        },
        code_verifier: None,
    };

    let mut interaction_repository = MockInteractionRepository::new();
    interaction_repository
        .expect_get_interaction()
        .return_once(move |_, _, _| {
            Ok(Some(Interaction {
                id: Default::default(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                data: Some(serde_json::to_vec(&interaction_data).unwrap()),
                organisation: Some(organisation.clone()),
                nonce_id: None,
                interaction_type: InteractionType::Verification,
            }))
        });

    let mut issuance_protocol = MockIssuanceProtocol::new();
    issuance_protocol
        .expect_holder_continue_issuance()
        .once()
        .returning(move |_, _, _| {
            Ok(ContinueIssuanceResponseDTO {
                interaction_id,
                key_storage_security_levels: None,
                key_algorithms: None,
            })
        });

    let mut issuance_protocol_provider = MockIssuanceProtocolProvider::new();

    let issuance_protocol = Arc::new(issuance_protocol);
    issuance_protocol_provider
        .expect_get_protocol()
        .once()
        .returning(move |_| Some(issuance_protocol.clone()));

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_supported_verification_jose_alg_ids()
        .return_once(Vec::new);

    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_create_credential()
        .return_once(|_| Ok(Uuid::new_v4().into()));

    let service = SSIHolderService {
        interaction_repository: Arc::new(interaction_repository),
        issuance_protocol_provider: Arc::new(issuance_protocol_provider),
        key_algorithm_provider: Arc::new(key_algorithm_provider),
        credential_repository: Arc::new(credential_repository),
        ..mock_ssi_holder_service()
    };

    // when
    let response = service
        .continue_issuance(format!(
            "https://localhost:3000/some_path?state={interaction_id}&code=test_code"
        ))
        .await
        .unwrap();

    // then
    assert_eq!(response.interaction_id, interaction_id);
}

#[tokio::test]
async fn test_initiate_issuance_pkce() {
    let mut organisation_repository = MockOrganisationRepository::new();
    organisation_repository
        .expect_get_organisation()
        .return_once(|_, _| Ok(Some(dummy_organisation(None))));

    let mut interaction_repository = MockInteractionRepository::new();
    interaction_repository
        .expect_create_interaction()
        .once()
        .withf(|request| {
            let data: OpenIDAuthorizationCodeFlowInteractionData =
                serde_json::from_slice(request.data.as_ref().unwrap()).unwrap();

            data.code_verifier.is_some()
        })
        .return_once(|_| Ok(Uuid::new_v4()));

    let service = SSIHolderService {
        organisation_repository: Arc::new(organisation_repository),
        interaction_repository: Arc::new(interaction_repository),
        ..mock_ssi_holder_service()
    };

    let mock_server = MockServer::start().await;

    let issuer = mock_server.uri();
    Mock::given(method(Method::GET))
        .and(path("/.well-known/oauth-authorization-server"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(OAuthAuthorizationServerMetadata {
                issuer: issuer.parse().unwrap(),
                authorization_endpoint: Some(
                    Url::parse("https://authorize.com/authorize").unwrap(),
                ),
                token_endpoint: None,
                pushed_authorization_request_endpoint: None,
                jwks_uri: None,
                code_challenge_methods_supported: vec![OAuthCodeChallengeMethod::S256],
                response_types_supported: vec![],
                grant_types_supported: vec![],
                token_endpoint_auth_methods_supported: vec![],
                challenge_endpoint: None,
                client_attestation_signing_alg_values_supported: None,
                client_attestation_pop_signing_alg_values_supported: None,
            }),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = service
        .initiate_issuance(InitiateIssuanceRequestDTO {
            organisation_id: Uuid::new_v4().into(),
            protocol: "OPENID4VCI_DRAFT13".to_string(),
            issuer,
            client_id: "clientId".to_string(),
            redirect_uri: Some("http://redirect.uri".to_string()),
            scope: Some(vec!["scope".to_string()]),
            authorization_details: None,
            issuer_state: None,
            authorization_server: None,
        })
        .await
        .unwrap();

    assert!(result.url.contains("code_challenge="));
    assert!(result.url.contains("code_challenge_method=S256"));
}

fn mock_ssi_holder_service() -> SSIHolderService {
    let client = Arc::new(ReqwestClient::default());

    SSIHolderService {
        credential_repository: Arc::new(MockCredentialRepository::new()),
        proof_repository: Arc::new(MockProofRepository::new()),
        organisation_repository: Arc::new(MockOrganisationRepository::new()),
        interaction_repository: Arc::new(MockInteractionRepository::new()),
        credential_schema_repository: Arc::new(MockCredentialSchemaRepository::new()),
        validity_credential_repository: Arc::new(MockValidityCredentialRepository::new()),
        did_repository: Arc::new(MockDidRepository::new()),
        key_repository: Arc::new(MockKeyRepository::new()),
        identifier_repository: Arc::new(MockIdentifierRepository::new()),
        certificate_repository: Arc::new(MockCertificateRepository::new()),
        key_provider: Arc::new(MockKeyProvider::new()),
        key_algorithm_provider: Arc::new(MockKeyAlgorithmProvider::new()),
        key_security_level_provider: Arc::new(MockKeySecurityLevelProvider::new()),
        formatter_provider: Arc::new(MockCredentialFormatterProvider::new()),
        issuance_protocol_provider: Arc::new(MockIssuanceProtocolProvider::new()),
        verification_protocol_provider: Arc::new(MockVerificationProtocolProvider::new()),
        blob_storage_provider: Arc::new(MockBlobStorageProvider::new()),
        config: Arc::new(generic_config().core),
        client,
        session_provider: Arc::new(NoSessionProvider),
        credential_schema_importer: Arc::new(MockCredentialSchemaImporter::new()),
        identifier_creator: Arc::new(MockIdentifierCreator::new()),
    }
}

fn dummy_credential(organisation_id: Option<OrganisationId>) -> Credential {
    Credential {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        issuance_date: None,
        last_modified: OffsetDateTime::now_utc(),
        deleted_at: None,
        protocol: "OPENID4VCI_DRAFT13".to_string(),
        redirect_uri: None,
        role: CredentialRole::Issuer,
        state: CredentialStateEnum::Pending,
        suspend_end_date: None,
        claims: None,
        profile: None,
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
        issuer_certificate: None,
        holder_identifier: None,
        schema: Some(crate::model::credential_schema::CredentialSchema {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            imported_source_url: "CORE_URL".to_string(),
            name: "schema".to_string(),
            key_storage_security: Some(KeyStorageSecurity::Basic),
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
                    metadata: false,
                },
                required: true,
            }]),
            organisation: Some(dummy_organisation(organisation_id)),
            deleted_at: None,
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: "CredentialSchemaId".to_owned(),
            allow_suspension: true,
            requires_app_attestation: false,
        }),
        interaction: Some(Interaction {
            id: Uuid::new_v4(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            data: Some(b"interaction data".to_vec()),
            organisation: Some(dummy_organisation(organisation_id)),
            nonce_id: None,
            interaction_type: InteractionType::Verification,
        }),
        key: None,
        credential_blob_id: Some(Uuid::new_v4().into()),
        wallet_unit_attestation_blob_id: None,
        wallet_app_attestation_blob_id: None,
    }
}

#[tokio::test]
async fn test_handle_invitation_session_org_mismatch() {
    // given
    let service = SSIHolderService {
        session_provider: Arc::new(StaticSessionProvider::new_random()),
        ..mock_ssi_holder_service()
    };

    // when
    let result = service
        .handle_invitation(
            "https://localhost:3000/some_path".parse().unwrap(),
            Uuid::new_v4().into(),
            None,
            None,
        )
        .await;

    // then
    assert!(matches!(
        result,
        Err(ServiceError::Validation(ValidationError::Forbidden))
    ));
}

#[tokio::test]
async fn test_accept_credential_identifier_org_mismatch() {
    let identifier_id = Uuid::new_v4().into();
    let organisation_id = Uuid::new_v4().into();
    let session_organisation_id = Uuid::new_v4().into();

    let mut identifier_repository = MockIdentifierRepository::new();
    identifier_repository.expect_get().return_once(move |_, _| {
        Ok(Some(Identifier {
            id: identifier_id,
            did: Some(Did {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key: dummy_key(),
                    reference: "1".to_string(),
                }]),
                did_method: "KEY".to_string(),
                ..dummy_did()
            }),
            organisation: Some(dummy_organisation(Some(organisation_id))),
            ..dummy_identifier()
        }))
    });
    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_get_credentials_by_interaction_id()
        .once()
        .return_once(move |_, _| Ok(vec![dummy_credential(Some(session_organisation_id))]));
    let service = SSIHolderService {
        credential_repository: Arc::new(credential_repository),
        identifier_repository: Arc::new(identifier_repository),
        session_provider: Arc::new(StaticSessionProvider(Session {
            organisation_id: Some(session_organisation_id),
            user_id: "test-user".to_string(),
        })),
        ..mock_ssi_holder_service()
    };

    let result = service
        .accept_credential(Uuid::new_v4(), None, Some(identifier_id), None, None, None)
        .await;
    assert!(matches!(
        result,
        Err(ServiceError::Validation(ValidationError::Forbidden))
    ));
}

#[tokio::test]
async fn test_accept_credential_credential_org_mismatch() {
    let identifier_id = Uuid::new_v4().into();
    let organisation_id = Uuid::new_v4().into();
    let session_organisation_id = Uuid::new_v4().into();

    let mut identifier_repository = MockIdentifierRepository::new();
    identifier_repository.expect_get().return_once(move |_, _| {
        Ok(Some(Identifier {
            id: identifier_id,
            did: Some(Did {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key: dummy_key(),
                    reference: "1".to_string(),
                }]),
                did_method: "KEY".to_string(),
                ..dummy_did()
            }),
            organisation: Some(dummy_organisation(Some(session_organisation_id))),
            ..dummy_identifier()
        }))
    });
    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_get_credentials_by_interaction_id()
        .once()
        .return_once(move |_, _| Ok(vec![dummy_credential(Some(organisation_id))]));

    let mut key_provider = MockKeyProvider::new();
    key_provider.expect_get_key_storage().returning(|_| {
        let mut key_storage = MockKeyStorage::new();
        key_storage
            .expect_get_capabilities()
            .return_once(|| KeyStorageCapabilities {
                features: vec![],
                algorithms: vec![],
            });
        Some(Arc::new(key_storage))
    });
    let service = SSIHolderService {
        credential_repository: Arc::new(credential_repository),
        identifier_repository: Arc::new(identifier_repository),
        key_provider: Arc::new(key_provider),
        session_provider: Arc::new(StaticSessionProvider(Session {
            organisation_id: Some(session_organisation_id),
            user_id: "test-user".to_string(),
        })),
        ..mock_ssi_holder_service()
    };

    let result = service
        .accept_credential(Uuid::new_v4(), None, Some(identifier_id), None, None, None)
        .await;
    assert!(matches!(
        result,
        Err(ServiceError::Validation(ValidationError::Forbidden))
    ));
}

#[tokio::test]
async fn test_reject_credential_credential_org_mismatch() {
    let identifier_id = Uuid::new_v4().into();
    let organisation_id = Uuid::new_v4().into();
    let session_organisation_id = Uuid::new_v4().into();

    let mut identifier_repository = MockIdentifierRepository::new();
    identifier_repository.expect_get().return_once(move |_, _| {
        Ok(Some(Identifier {
            id: identifier_id,
            did: Some(Did {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key: dummy_key(),
                    reference: "1".to_string(),
                }]),
                did_method: "KEY".to_string(),
                ..dummy_did()
            }),
            organisation: Some(dummy_organisation(Some(session_organisation_id))),
            ..dummy_identifier()
        }))
    });
    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_get_credentials_by_interaction_id()
        .once()
        .return_once(move |_, _| Ok(vec![dummy_credential(Some(organisation_id))]));
    let service = SSIHolderService {
        credential_repository: Arc::new(credential_repository),
        identifier_repository: Arc::new(identifier_repository),
        session_provider: Arc::new(StaticSessionProvider(Session {
            organisation_id: Some(session_organisation_id),
            user_id: "test-user".to_string(),
        })),
        ..mock_ssi_holder_service()
    };

    let result = service.reject_credential(&Uuid::new_v4()).await;
    assert!(matches!(
        result,
        Err(ServiceError::Validation(ValidationError::Forbidden))
    ));
}

#[tokio::test]
async fn test_initiate_issuance_session_org_mismatch() {
    // given
    let service = SSIHolderService {
        session_provider: Arc::new(StaticSessionProvider::new_random()),
        ..mock_ssi_holder_service()
    };

    // when
    let result = service
        .initiate_issuance(InitiateIssuanceRequestDTO {
            organisation_id: Uuid::new_v4().into(),
            protocol: "".to_string(),
            issuer: "".to_string(),
            client_id: "".to_string(),
            redirect_uri: None,
            scope: None,
            authorization_details: None,
            issuer_state: None,
            authorization_server: None,
        })
        .await;

    // then
    assert!(matches!(
        result,
        Err(ServiceError::Validation(ValidationError::Forbidden))
    ));
}
