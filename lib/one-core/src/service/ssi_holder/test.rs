use std::borrow::Cow;
use std::str::FromStr;
use std::sync::Arc;
use std::vec;

use mockall::predicate::{always, eq};
use regex::Regex;
use shared_types::{CredentialFormat, EcosystemId, OrganisationId};
use similar_asserts::assert_eq;
use standardized_types::oauth2::authorization_server_metadata::{
    AuthorizationServerMetadata, CodeChallengeMethod,
};
use standardized_types::openid4vci::{AuthorizationDetail, CredentialIssuerMetadata};
use standardized_types::openid4vp::dcql::DcqlQuery;
use url::Url;
use uuid::Uuid;
use wiremock::http::Method;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::dto::HandleInvitationRequestDTO;
use crate::config::core_config::TransportType;
use crate::error::{ErrorCode, ErrorCodeMixin, ErrorCodeMixinExt};
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{
    Credential, CredentialCommon, CredentialRole, CredentialStateEnum, CredentialType,
};
use crate::model::credential_schema::{KeyStorageSecurity, WalletAttestation};
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::credential_schema_format_claim_schema::CredentialSchemaFormatClaimSchema;
use crate::model::did::{Did, DidType, KeyRole, RelatedKey};
use crate::model::ecosystem::EcosystemOutcomes;
use crate::model::history::{
    HistoryAction, HistoryEntityType, HistoryErrorMetadata, HistoryMetadata,
};
use crate::model::identifier::{Identifier, IdentifierData, IdentifierState};
use crate::model::interaction::{Interaction, InteractionEcosystems, InteractionType};
use crate::model::proof::{Proof, ProofStateEnum};
use crate::proto::ecosystem_resolver::EcosystemResolverProto;
use crate::proto::http_client::reqwest_client::ReqwestClient;
use crate::proto::identifier_creator::MockIdentifierCreator;
use crate::proto::session_provider::test::StaticSessionProvider;
use crate::proto::session_provider::{NoSessionProvider, Session};
use crate::proto::transaction_manager::NoTransactionManager;
use crate::provider::blob_storage::MockBlobStorage;
use crate::provider::blob_storage::provider::MockBlobStorageProvider;
use crate::provider::credential_formatter::MockCredentialFormatter;
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::ecosystem::MockEcosystem;
use crate::provider::ecosystem::directory::MockEcosystemDirectory;
use crate::provider::ecosystem::model::{IssuerMetadataRepresentation, ProtocolArtifact};
use crate::provider::issuance_protocol::MockIssuanceProtocol;
use crate::provider::issuance_protocol::dto::{Features, IssuanceProtocolCapabilities};
use crate::provider::issuance_protocol::error::{IssuanceProtocolError, TxCodeError};
use crate::provider::issuance_protocol::model::{
    ContinueIssuanceResponseDTO, CredentialWithBlob, IssuanceAcceptResponse, IssuanceAcceptResult,
};
use crate::provider::issuance_protocol::openid4vci_final1_0::model::{
    HolderCredentialConfiguration, HolderInteractionData,
};
use crate::provider::issuance_protocol::provider::MockIssuanceProtocolProvider;
use crate::provider::key_algorithm::ecdsa::Ecdsa;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_security_level::basic::Basic;
use crate::provider::key_security_level::dto::{HolderParams, Params};
use crate::provider::key_security_level::provider::MockKeySecurityLevelProvider;
use crate::provider::verification_protocol::MockVerificationProtocol;
use crate::provider::verification_protocol::dto::{
    InvitationResponseDTO, VerificationProtocolCapabilities,
};
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::provider::MockVerificationProtocolProvider;
use crate::repository::credential_repository::MockCredentialRepository;
use crate::repository::history_repository::MockHistoryRepository;
use crate::repository::identifier_repository::MockIdentifierRepository;
use crate::repository::interaction_repository::MockInteractionRepository;
use crate::repository::organisation_repository::MockOrganisationRepository;
use crate::repository::proof_repository::MockProofRepository;
use crate::service::ssi_holder::SSIHolderService;
use crate::service::ssi_holder::dto::{
    InitiateIssuanceRequestDTO, OpenIDAuthorizationCodeFlowInteractionData,
};
use crate::service::test_utilities::{
    CredentialBuilder, dummy_did, dummy_identifier, dummy_key, dummy_organisation, dummy_proof,
    generic_config, generic_formatter_capabilities, get_dummy_date,
};

#[tokio::test]
async fn test_reject_proof_request_succeeds_and_sets_state_to_rejected_when_latest_state_is_requested()
 {
    let interaction_id = Uuid::new_v4().into();
    let proof_id = Uuid::new_v4().into();
    let protocol = "OPENID4VP_FINAL1";

    let mut proof_repository = MockProofRepository::new();
    proof_repository
        .expect_get_proof_by_interaction_id()
        .once()
        .return_once(move |_| {
            Ok(Proof {
                id: proof_id,
                protocol: protocol.to_string(),
                state: ProofStateEnum::Requested,
                interaction: Some(
                    Interaction {
                        id: interaction_id,
                        created_date: crate::clock::now_utc(),
                        last_modified: crate::clock::now_utc(),
                        data: None,
                        organisation: dummy_organisation(None).into(),
                        interaction_type: InteractionType::Verification,
                        expires_at: None,
                        ecosystem: None,
                        ecosystem_data: Default::default(),
                    }
                    .into(),
                ),
                ..dummy_proof()
            })
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
        .return_once(move |_| Ok(Arc::new(verification_protocol_mock)));

    // rejecting ends the interaction, so the ecosystems get recorded
    let mut interaction_repository = MockInteractionRepository::new();
    interaction_repository
        .expect_get_interaction()
        .returning(move |_, _| {
            Ok(Interaction {
                id: interaction_id,
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                data: None,
                organisation: dummy_organisation(None).into(),
                interaction_type: InteractionType::Verification,
                expires_at: None,
                ecosystem: None,
                ecosystem_data: Default::default(),
            })
        });

    let service = SSIHolderService {
        proof_repository: Arc::new(proof_repository),
        verification_protocol_provider: Arc::new(verification_protocol_provider),
        interaction_repository: Arc::new(interaction_repository),
        ..mock_ssi_holder_service()
    };

    service.reject_proof_request(&interaction_id).await.unwrap();
}

#[tokio::test]
async fn test_handling_a_proof_invitation_records_the_resolved_ecosystems() {
    // trust is decided at the invitation, so the event is written there and not at the end
    let interaction_id = Uuid::new_v4().into();
    let proof_id = Uuid::new_v4().into();

    let mut outcomes = EcosystemOutcomes::default();
    outcomes.record(EcosystemId::from("EUDI"), Ok(()));
    outcomes.record(
        EcosystemId::from("OTHER"),
        Err(HistoryErrorMetadata {
            error_code: ErrorCode::BR_0477,
            message: "not on the trust list".to_string(),
        }),
    );
    let mut ecosystem_data = InteractionEcosystems::default();
    ecosystem_data.merge_outcomes(&outcomes);

    let mut interaction_repository = MockInteractionRepository::new();
    interaction_repository
        .expect_get_interaction()
        .returning(move |_, _| {
            Ok(Interaction {
                id: interaction_id,
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                data: None,
                organisation: dummy_organisation(None).into(),
                interaction_type: InteractionType::Verification,
                expires_at: None,
                ecosystem: None,
                ecosystem_data: ecosystem_data.to_owned(),
            })
        });
    // the organisation selects no ecosystem, so resolution commits nothing
    interaction_repository
        .expect_update_interaction()
        .returning(|_, _| Ok(()));

    let mut verification_protocol_mock = MockVerificationProtocol::default();
    verification_protocol_mock
        .expect_get_capabilities()
        .returning(|| VerificationProtocolCapabilities {
            features: vec![],
            supported_transports: vec![TransportType::Http],
            did_methods: vec![],
            verifier_identifier_types: vec![],
            supported_presentation_definition: vec![],
            supported_encryption_algorithms: vec![],
        });
    verification_protocol_mock
        .expect_holder_handle_invitation()
        .once()
        .return_once(move |_, _, _| {
            Ok(InvitationResponseDTO {
                interaction_id,
                proof: dummy_proof(),
                ecosystem_artifact: ProtocolArtifact::HolderProof {
                    verifier_details: Cow::Owned(None),
                    dcql_query: DcqlQuery {
                        credentials: vec![],
                        credential_sets: None,
                    },
                    verifier_info: vec![],
                    proof_id,
                },
            })
        });
    let mut verification_protocol_provider = MockVerificationProtocolProvider::new();
    verification_protocol_provider
        .expect_detect_protocol()
        .once()
        .return_once(move |_| {
            Some((
                "OPENID4VP_FINAL1".to_string(),
                Arc::new(verification_protocol_mock) as _,
            ))
        });

    let mut proof_repository = MockProofRepository::new();
    proof_repository
        .expect_create_proof()
        .once()
        .return_once(move |_| Ok(proof_id));

    let expected = outcomes.to_owned();
    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .once()
        .withf(move |history| {
            assert_eq!(HistoryAction::EcosystemsResolved, history.action);
            assert_eq!(HistoryEntityType::Proof, history.entity_type);
            // recorded on the proof the invitation just created
            assert_eq!(Some(proof_id.into()), history.entity_id);

            let Some(HistoryMetadata::EcosystemsResolved(recorded)) = &history.metadata else {
                panic!("the event carries the outcome of every consulted ecosystem");
            };
            assert_eq!(expected, *recorded);
            true
        })
        .return_once(|history| Ok(history.id));

    let interaction_repository = Arc::new(interaction_repository);
    let service = SSIHolderService {
        proof_repository: Arc::new(proof_repository),
        verification_protocol_provider: Arc::new(verification_protocol_provider),
        interaction_repository: interaction_repository.clone(),
        ecosystem_resolver: ecosystem_resolver(
            interaction_repository,
            MockEcosystemDirectory::new(),
            history_repository,
        ),
        ..mock_ssi_holder_service()
    };

    service
        .handle_verification_invitation(
            "https://localhost:3000/some_path".parse().unwrap(),
            dummy_organisation(None),
            None,
            None,
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn test_rejecting_a_proof_consults_no_ecosystem_and_records_nothing() {
    // verification resolves its trust once, at the invitation: no later step adds to it, so
    // rejecting neither consults an ecosystem nor writes a second event
    let interaction_id = Uuid::new_v4().into();
    let proof_id = Uuid::new_v4().into();
    let protocol = "OPENID4VP_FINAL1";

    let mut proof_repository = MockProofRepository::new();
    proof_repository
        .expect_get_proof_by_interaction_id()
        .once()
        .return_once(move |_| {
            Ok(Proof {
                id: proof_id,
                protocol: protocol.to_string(),
                state: ProofStateEnum::Requested,
                ..dummy_proof()
            })
        });
    proof_repository
        .expect_update_proof()
        .once()
        .return_once(move |_, _, _| Ok(()));

    let mut verification_protocol_mock = MockVerificationProtocol::default();
    verification_protocol_mock
        .expect_holder_reject_proof()
        .once()
        .return_once(move |_| Ok(()));
    let mut verification_protocol_provider = MockVerificationProtocolProvider::new();
    verification_protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Ok(Arc::new(verification_protocol_mock)));

    let mut history_repository = MockHistoryRepository::new();
    history_repository.expect_create_history().never();

    // the interaction still carries what the invitation resolved, and it is not read again
    let mut interaction_repository = MockInteractionRepository::new();
    interaction_repository.expect_get_interaction().never();

    let interaction_repository = Arc::new(interaction_repository);
    let service = SSIHolderService {
        proof_repository: Arc::new(proof_repository),
        verification_protocol_provider: Arc::new(verification_protocol_provider),
        interaction_repository: interaction_repository.clone(),
        // the directory has no expectations: consulting any ecosystem here would panic
        ecosystem_resolver: ecosystem_resolver(
            interaction_repository,
            MockEcosystemDirectory::new(),
            history_repository,
        ),
        ..mock_ssi_holder_service()
    };

    service.reject_proof_request(&interaction_id).await.unwrap();
}

#[tokio::test]
async fn test_reject_proof_request_fails_when_latest_state_is_not_requested() {
    let reject_proof_for_state = |state| async move {
        let interaction_id = Uuid::new_v4().into();
        let proof_id = Uuid::new_v4().into();
        let protocol = "OPENID4VP_FINAL1";
        let mut proof_repository = MockProofRepository::new();
        proof_repository
            .expect_get_proof_by_interaction_id()
            .once()
            .return_once(move |_| {
                Ok(Proof {
                    id: proof_id,
                    protocol: protocol.to_string(),
                    state,
                    interaction: Some(
                        Interaction {
                            id: interaction_id,
                            created_date: crate::clock::now_utc(),
                            last_modified: crate::clock::now_utc(),
                            data: None,
                            organisation: dummy_organisation(None).into(),
                            interaction_type: InteractionType::Verification,
                            expires_at: None,
                            ecosystem: None,
                            ecosystem_data: Default::default(),
                        }
                        .into(),
                    ),
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
        ProofStateEnum::Pending,
        ProofStateEnum::Accepted,
        ProofStateEnum::Rejected,
        ProofStateEnum::Error,
    ] {
        let result = reject_proof_for_state(state).await;
        assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0013);
    }
}

#[tokio::test]
async fn test_reject_proof_request_suceeds_when_holder_reject_proof_errors_state_is_set_to_errored()
{
    let interaction_id = Uuid::new_v4().into();
    let proof_id = Uuid::new_v4().into();
    let protocol = "OPENID4VP_FINAL1";

    let mut proof_repository = MockProofRepository::new();
    proof_repository
        .expect_get_proof_by_interaction_id()
        .once()
        .return_once(move |_| {
            Ok(Proof {
                id: proof_id,
                protocol: protocol.to_string(),
                state: ProofStateEnum::Requested,
                interaction: Some(
                    Interaction {
                        id: interaction_id,
                        created_date: crate::clock::now_utc(),
                        last_modified: crate::clock::now_utc(),
                        data: None,
                        organisation: dummy_organisation(None).into(),
                        interaction_type: InteractionType::Verification,
                        expires_at: None,
                        ecosystem: None,
                        ecosystem_data: Default::default(),
                    }
                    .into(),
                ),
                ..dummy_proof()
            })
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
        .return_once(move |_| Ok(Arc::new(verification_protocol_mock)));

    // rejecting ends the interaction, so the ecosystems get recorded
    let mut interaction_repository = MockInteractionRepository::new();
    interaction_repository
        .expect_get_interaction()
        .returning(move |_, _| {
            Ok(Interaction {
                id: interaction_id,
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                data: None,
                organisation: dummy_organisation(None).into(),
                interaction_type: InteractionType::Verification,
                expires_at: None,
                ecosystem: None,
                ecosystem_data: Default::default(),
            })
        });

    let service = SSIHolderService {
        proof_repository: Arc::new(proof_repository),
        verification_protocol_provider: Arc::new(verification_protocol_provider),
        interaction_repository: Arc::new(interaction_repository),
        ..mock_ssi_holder_service()
    };

    service.reject_proof_request(&interaction_id).await.unwrap();
}

#[tokio::test]
async fn test_accept_credential() {
    let identifier_id = Uuid::new_v4().into();

    let mut identifier_repository = MockIdentifierRepository::new();
    identifier_repository.expect_get().returning(move |_| {
        Ok(Identifier {
            id: identifier_id,
            data: IdentifierData::Did(
                (Did {
                    keys: vec![RelatedKey {
                        role: KeyRole::Authentication,
                        key: dummy_key(),
                        reference: "1".to_string(),
                    }]
                    .into(),
                    did_method: "KEY".into(),
                    ..dummy_did()
                })
                .into(),
            ),
            organisation: dummy_organisation(None).into(),
            ..dummy_identifier()
        })
    });

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_key()
        .once()
        .returning(|_| Ok(Arc::new(Ecdsa)));

    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_create_credentials()
        .once()
        .returning(|credentials| {
            Ok(credentials
                .into_iter()
                .map(|credential| credential.common().id)
                .collect())
        });

    let mut exchange_protocol_mock = MockIssuanceProtocol::default();
    exchange_protocol_mock
        .expect_holder_accept_credential()
        .once()
        .returning(|_, _, _, _| {
            Ok(IssuanceAcceptResult {
                issued: vec![IssuanceAcceptResponse {
                    credential_configuration_id: String::new(),
                    main_credential: CredentialWithBlob {
                        credential: dummy_credential(None),
                        serialized: Some("credential".into()),
                    },
                    batch_items: vec![],
                }],
                failed: vec![],
            })
        });

    let mut issuance_protocol_provider = MockIssuanceProtocolProvider::new();
    issuance_protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Ok(Arc::new(exchange_protocol_mock)));

    let mut formatter = MockCredentialFormatter::new();
    formatter
        .expect_get_capabilities()
        .once()
        .returning(generic_formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    let formatter = Arc::new(formatter);
    formatter_provider
        .expect_get_formatter_by_type()
        .times(1)
        .returning(move |_| {
            Some((
                CredentialFormat::from_str("SD_JWT_VC").unwrap(),
                formatter.clone(),
            ))
        });

    let mut blob_storage = MockBlobStorage::new();
    blob_storage.expect_create().once().return_once(|_| Ok(()));
    let blob_storage = Arc::new(blob_storage);
    let mut blob_storage_provider = MockBlobStorageProvider::new();
    blob_storage_provider
        .expect_get_blob_storage()
        .once()
        .returning(move |_| Ok(blob_storage.clone()));

    let mut key_security_level_provider = MockKeySecurityLevelProvider::new();
    key_security_level_provider
        .expect_get_from_type()
        .returning(|_| {
            Ok(Arc::new(Basic::new(Params {
                holder: HolderParams {
                    priority: 0,
                    key_storages: vec!["foo".to_string()],
                },
            })))
        });
    let interaction_id = Uuid::new_v4().into();

    let mut interaction_repository = MockInteractionRepository::new();
    interaction_repository
        .expect_get_interaction()
        .returning(|_, _| {
            Ok(Interaction {
                id: Uuid::new_v4().into(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                data: Some(serde_json::to_vec(&dummy_interaction()).unwrap()),
                organisation: dummy_organisation(None).into(),
                interaction_type: InteractionType::Issuance,
                expires_at: None,
                ecosystem: None,
                ecosystem_data: Default::default(),
            })
        });

    // no ecosystem selected, so nothing is consulted and the interaction is not touched
    interaction_repository.expect_update_interaction().never();

    let interaction_repository = Arc::new(interaction_repository);
    let service = SSIHolderService {
        credential_repository: Arc::new(credential_repository),
        issuance_protocol_provider: Arc::new(issuance_protocol_provider),
        identifier_repository: Arc::new(identifier_repository),
        key_algorithm_provider: Arc::new(key_algorithm_provider),
        formatter_provider: Arc::new(formatter_provider),
        blob_storage_provider: Arc::new(blob_storage_provider),
        key_security_level_provider: Arc::new(key_security_level_provider),
        interaction_repository: interaction_repository.clone(),
        ecosystem_resolver: ecosystem_resolver(
            interaction_repository,
            MockEcosystemDirectory::new(),
            MockHistoryRepository::new(),
        ),
        ..mock_ssi_holder_service()
    };

    service
        .accept_credential(interaction_id, None, Some(identifier_id), None, None)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_accept_credential_validates_every_configuration_against_the_ecosystem() {
    let ecosystem_id = EcosystemId::from("ecosystem");
    let identifier_id = Uuid::new_v4().into();

    let mut identifier_repository = MockIdentifierRepository::new();
    identifier_repository.expect_get().returning(move |_| {
        Ok(Identifier {
            id: identifier_id,
            data: IdentifierData::Did(
                (Did {
                    keys: vec![RelatedKey {
                        role: KeyRole::Authentication,
                        key: dummy_key(),
                        reference: "1".to_string(),
                    }]
                    .into(),
                    did_method: "KEY".into(),
                    ..dummy_did()
                })
                .into(),
            ),
            organisation: dummy_organisation(None).into(),
            ..dummy_identifier()
        })
    });

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_key()
        .returning(|_| Ok(Arc::new(Ecdsa)));

    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_create_credentials()
        .once()
        .withf(|credentials| credentials.len() == 2)
        .returning(|credentials| {
            Ok(credentials
                .into_iter()
                .map(|credential| credential.common().id)
                .collect())
        });

    let mut exchange_protocol_mock = MockIssuanceProtocol::default();
    exchange_protocol_mock
        .expect_holder_accept_credential()
        .once()
        .returning(|_, _, _, _| {
            let issued = |credential_configuration_id: &str| IssuanceAcceptResponse {
                credential_configuration_id: credential_configuration_id.to_string(),
                main_credential: CredentialWithBlob {
                    credential: dummy_credential(None),
                    serialized: Some("credential".into()),
                },
                batch_items: vec![],
            };
            Ok(IssuanceAcceptResult {
                issued: vec![issued("first"), issued("second")],
                failed: vec![],
            })
        });

    let mut issuance_protocol_provider = MockIssuanceProtocolProvider::new();
    issuance_protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Ok(Arc::new(exchange_protocol_mock)));

    let mut formatter = MockCredentialFormatter::new();
    formatter
        .expect_get_capabilities()
        .returning(generic_formatter_capabilities);
    let formatter = Arc::new(formatter);
    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_formatter_by_type()
        .returning(move |_| {
            Some((
                CredentialFormat::from_str("SD_JWT_VC").unwrap(),
                formatter.clone(),
            ))
        });

    let mut blob_storage = MockBlobStorage::new();
    blob_storage.expect_create().times(2).returning(|_| Ok(()));
    let blob_storage = Arc::new(blob_storage);
    let mut blob_storage_provider = MockBlobStorageProvider::new();
    blob_storage_provider
        .expect_get_blob_storage()
        .once()
        .returning(move |_| Ok(blob_storage.clone()));

    let mut key_security_level_provider = MockKeySecurityLevelProvider::new();
    key_security_level_provider
        .expect_get_from_type()
        .returning(|_| {
            Ok(Arc::new(Basic::new(Params {
                holder: HolderParams {
                    priority: 0,
                    key_storages: vec!["foo".to_string()],
                },
            })))
        });

    // two offered configurations, the interaction is committed to an ecosystem
    let mut interaction_data = dummy_interaction();
    let mut second = interaction_data.credential_configurations[0].clone();
    second.credential_configuration_id = "second".to_string();
    interaction_data.credential_configurations.push(second);
    let mut organisation = dummy_organisation(None);
    organisation.configuration.selected_ecosystems = vec![ecosystem_id.clone()];

    let interaction_id = Uuid::new_v4().into();
    let mut interaction_repository = MockInteractionRepository::new();
    let committed = ecosystem_id.clone();
    interaction_repository
        .expect_get_interaction()
        .returning(move |_, _| {
            Ok(Interaction {
                id: interaction_id,
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                data: Some(serde_json::to_vec(&interaction_data).unwrap()),
                organisation: organisation.clone().into(),
                interaction_type: InteractionType::Issuance,
                expires_at: None,
                ecosystem: Some(committed.clone()),
                ecosystem_data: Default::default(),
            })
        });

    // the committed ecosystem outcome is carried on the interaction
    interaction_repository
        .expect_update_interaction()
        .once()
        .withf(|_, request| {
            request
                .ecosystem_data
                .as_ref()
                .is_some_and(|data| !data.outcomes().is_empty())
        })
        .returning(|_, _| Ok(()));

    // every issued configuration is validated against the committed ecosystem
    let mut ecosystem = MockEcosystem::new();
    ecosystem
        .expect_validate_interaction()
        .times(2)
        .returning(|_, _| Ok(crate::model::ecosystem::EcosystemTrustResult::Trusted.into()));
    let ecosystem = Arc::new(ecosystem);
    let mut ecosystem_provider = MockEcosystemDirectory::new();
    ecosystem_provider
        .expect_get()
        .with(eq(ecosystem_id))
        .returning(move |_| Ok(ecosystem.clone()));

    // One history event for each issued credential.
    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .times(2)
        .withf(|history| {
            history.action == HistoryAction::EcosystemsResolved
                && history.entity_type == HistoryEntityType::Credential
        })
        .returning(|history| Ok(history.id));

    let interaction_repository = Arc::new(interaction_repository);
    let service = SSIHolderService {
        credential_repository: Arc::new(credential_repository),
        issuance_protocol_provider: Arc::new(issuance_protocol_provider),
        identifier_repository: Arc::new(identifier_repository),
        key_algorithm_provider: Arc::new(key_algorithm_provider),
        formatter_provider: Arc::new(formatter_provider),
        blob_storage_provider: Arc::new(blob_storage_provider),
        key_security_level_provider: Arc::new(key_security_level_provider),
        interaction_repository: interaction_repository.clone(),
        ecosystem_resolver: ecosystem_resolver(
            interaction_repository,
            ecosystem_provider,
            history_repository,
        ),
        ..mock_ssi_holder_service()
    };

    let response = service
        .accept_credential(interaction_id, None, Some(identifier_id), None, None)
        .await
        .unwrap();
    assert_eq!(response.credential_ids.len(), 2);
}

#[tokio::test]
async fn test_accept_credential_with_did() {
    let did_id = Uuid::new_v4().into();

    let mut identifier_repository = MockIdentifierRepository::new();
    identifier_repository
        .expect_get_from_did_id()
        .return_once(move |_| {
            Ok(Some(Identifier {
                data: IdentifierData::Did(
                    (Did {
                        id: did_id,
                        keys: vec![RelatedKey {
                            role: KeyRole::Authentication,
                            key: dummy_key(),
                            reference: "1".to_string(),
                        }]
                        .into(),
                        did_method: "KEY".into(),
                        ..dummy_did()
                    })
                    .into(),
                ),
                organisation: dummy_organisation(None).into(),
                ..dummy_identifier()
            }))
        });

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_key()
        .once()
        .returning(|_| Ok(Arc::new(Ecdsa)));

    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_create_credentials()
        .once()
        .returning(|credentials| {
            Ok(credentials
                .into_iter()
                .map(|credential| credential.common().id)
                .collect())
        });

    let mut exchange_protocol_mock = MockIssuanceProtocol::default();
    exchange_protocol_mock
        .expect_holder_accept_credential()
        .once()
        .returning(|_, _, _, _| {
            Ok(IssuanceAcceptResult {
                issued: vec![IssuanceAcceptResponse {
                    credential_configuration_id: String::new(),
                    main_credential: CredentialWithBlob {
                        credential: dummy_credential(None),
                        serialized: Some("credential".into()),
                    },
                    batch_items: vec![],
                }],
                failed: vec![],
            })
        });

    let mut issuance_protocol_provider = MockIssuanceProtocolProvider::new();
    issuance_protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Ok(Arc::new(exchange_protocol_mock)));

    let mut formatter = MockCredentialFormatter::new();
    formatter
        .expect_get_capabilities()
        .once()
        .returning(generic_formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    let formatter = Arc::new(formatter);
    formatter_provider
        .expect_get_formatter_by_type()
        .times(1)
        .returning(move |_| {
            Some((
                CredentialFormat::from_str("SD_JWT_VC").unwrap(),
                formatter.clone(),
            ))
        });

    let mut blob_storage = MockBlobStorage::new();
    blob_storage.expect_create().once().return_once(|_| Ok(()));
    let blob_storage = Arc::new(blob_storage);
    let mut blob_storage_provider = MockBlobStorageProvider::new();
    blob_storage_provider
        .expect_get_blob_storage()
        .once()
        .returning(move |_| Ok(blob_storage.clone()));

    let mut key_security_level_provider = MockKeySecurityLevelProvider::new();
    key_security_level_provider
        .expect_get_from_type()
        .returning(|_| {
            Ok(Arc::new(Basic::new(Params {
                holder: HolderParams {
                    priority: 0,
                    key_storages: vec!["foo".to_string()],
                },
            })))
        });

    let interaction_id = Uuid::new_v4().into();

    let mut interaction_repository = MockInteractionRepository::new();
    interaction_repository
        .expect_get_interaction()
        .returning(|_, _| {
            Ok(Interaction {
                id: Uuid::new_v4().into(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                data: Some(serde_json::to_vec(&dummy_interaction()).unwrap()),
                organisation: dummy_organisation(None).into(),
                interaction_type: InteractionType::Issuance,
                expires_at: None,
                ecosystem: None,
                ecosystem_data: Default::default(),
            })
        });

    // no ecosystem selected, so nothing is consulted and the interaction is not touched
    interaction_repository.expect_update_interaction().never();

    let interaction_repository = Arc::new(interaction_repository);
    let service = SSIHolderService {
        credential_repository: Arc::new(credential_repository),
        issuance_protocol_provider: Arc::new(issuance_protocol_provider),
        identifier_repository: Arc::new(identifier_repository),
        key_algorithm_provider: Arc::new(key_algorithm_provider),
        formatter_provider: Arc::new(formatter_provider),
        blob_storage_provider: Arc::new(blob_storage_provider),
        key_security_level_provider: Arc::new(key_security_level_provider),
        interaction_repository: interaction_repository.clone(),
        ecosystem_resolver: ecosystem_resolver(
            interaction_repository,
            MockEcosystemDirectory::new(),
            MockHistoryRepository::new(),
        ),
        ..mock_ssi_holder_service()
    };

    service
        .accept_credential(interaction_id, Some(did_id), None, None, None)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_accept_credential_batch() {
    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_create_credentials()
        .once()
        .withf(|credentials| credentials.len() == 3)
        .returning(|credentials| {
            Ok(credentials
                .into_iter()
                .map(|credential| credential.common().id)
                .collect())
        });

    let mut exchange_protocol_mock = MockIssuanceProtocol::default();
    let main_credential = dummy_credential(None);
    let cred_clone = main_credential.clone();
    exchange_protocol_mock
        .expect_holder_accept_credential()
        .once()
        .with(always(), eq(None), always(), always())
        .returning(move |_, _, _, _| {
            Ok(IssuanceAcceptResult {
                issued: vec![IssuanceAcceptResponse {
                    credential_configuration_id: String::new(),
                    main_credential: CredentialWithBlob {
                        credential: cred_clone.clone(),
                        serialized: None,
                    },
                    batch_items: vec![
                        CredentialWithBlob {
                            credential: dummy_credential(None),
                            serialized: Some("credential1".into()),
                        },
                        CredentialWithBlob {
                            credential: dummy_credential(None),
                            serialized: Some("credential2".into()),
                        },
                    ],
                }],
                failed: vec![],
            })
        });

    let mut issuance_protocol_provider = MockIssuanceProtocolProvider::new();
    issuance_protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Ok(Arc::new(exchange_protocol_mock)));

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    let formatter = Arc::new(MockCredentialFormatter::new());
    formatter_provider
        .expect_get_formatter_by_type()
        .times(1)
        .returning(move |_| {
            Some((
                CredentialFormat::from_str("SD_JWT_VC").unwrap(),
                formatter.clone(),
            ))
        });

    let mut blob_storage = MockBlobStorage::new();
    blob_storage.expect_create().times(2).returning(|_| Ok(()));
    let blob_storage = Arc::new(blob_storage);
    let mut blob_storage_provider = MockBlobStorageProvider::new();
    blob_storage_provider
        .expect_get_blob_storage()
        .once()
        .returning(move |_| Ok(blob_storage.clone()));

    let interaction_id = Uuid::new_v4().into();
    let mut interaction_repository = MockInteractionRepository::new();
    interaction_repository
        .expect_get_interaction()
        .returning(move |_, _| {
            Ok(Interaction {
                id: interaction_id,
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                data: Some(
                    serde_json::to_vec(&HolderInteractionData {
                        batch_size: Some(2),
                        ..dummy_interaction()
                    })
                    .unwrap(),
                ),
                organisation: dummy_organisation(None).into(),
                interaction_type: InteractionType::Issuance,
                expires_at: None,
                ecosystem: None,
                ecosystem_data: Default::default(),
            })
        });

    // no ecosystem selected, so nothing is consulted and the interaction is not touched
    interaction_repository.expect_update_interaction().never();

    let interaction_repository = Arc::new(interaction_repository);
    let service = SSIHolderService {
        credential_repository: Arc::new(credential_repository),
        issuance_protocol_provider: Arc::new(issuance_protocol_provider),
        formatter_provider: Arc::new(formatter_provider),
        blob_storage_provider: Arc::new(blob_storage_provider),
        interaction_repository: interaction_repository.clone(),
        ecosystem_resolver: ecosystem_resolver(
            interaction_repository,
            MockEcosystemDirectory::new(),
            MockHistoryRepository::new(),
        ),
        ..mock_ssi_holder_service()
    };

    let response = service
        .accept_credential(interaction_id, None, None, None, None)
        .await
        .unwrap();

    assert_eq!(response.credential_ids, vec![main_credential.common().id]);
}

#[tokio::test]
async fn test_accept_credential_wrong_tx_code() {
    let identifier_id = Uuid::new_v4().into();

    let mut identifier_repository = MockIdentifierRepository::new();
    identifier_repository
        .expect_get()
        .once()
        .return_once(move |_| {
            Ok(Identifier {
                id: identifier_id,
                data: IdentifierData::Did(
                    (Did {
                        keys: vec![RelatedKey {
                            role: KeyRole::Authentication,
                            key: dummy_key(),
                            reference: "1".to_string(),
                        }]
                        .into(),
                        did_method: "KEY".into(),
                        ..dummy_did()
                    })
                    .into(),
                ),
                organisation: dummy_organisation(None).into(),
                ..dummy_identifier()
            })
        });

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_key()
        .once()
        .returning(|_| Ok(Arc::new(Ecdsa)));

    let mut exchange_protocol_mock = MockIssuanceProtocol::default();
    exchange_protocol_mock
        .expect_holder_accept_credential()
        .once()
        .return_once(|_, _, _, _| Err(TxCodeError::IncorrectCode.error_while("").into()));

    let mut issuance_protocol_provider = MockIssuanceProtocolProvider::new();
    issuance_protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Ok(Arc::new(exchange_protocol_mock)));

    let mut formatter = MockCredentialFormatter::new();
    formatter
        .expect_get_capabilities()
        .once()
        .returning(generic_formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    let formatter = Arc::new(formatter);
    formatter_provider
        .expect_get_formatter_by_type()
        .times(1)
        .returning(move |_| {
            Some((
                CredentialFormat::from_str("SD_JWT_VC").unwrap(),
                formatter.clone(),
            ))
        });

    let organisation = dummy_organisation(None);
    let interaction_id = Uuid::new_v4().into();

    let mut interaction_repository = MockInteractionRepository::new();
    interaction_repository
        // consulted again when the issuance ends, to record the ecosystems
        .expect_get_interaction()
        .returning(move |_, _| {
            Ok(Interaction {
                id: Uuid::new_v4().into(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                data: Some(serde_json::to_vec(&dummy_interaction()).unwrap()),
                organisation: organisation.clone().into(),
                interaction_type: InteractionType::Issuance,
                expires_at: None,
                ecosystem: None,
                ecosystem_data: Default::default(),
            })
        });

    let service = SSIHolderService {
        issuance_protocol_provider: Arc::new(issuance_protocol_provider),
        identifier_repository: Arc::new(identifier_repository),
        key_algorithm_provider: Arc::new(key_algorithm_provider),
        formatter_provider: Arc::new(formatter_provider),
        interaction_repository: Arc::new(interaction_repository),
        ..mock_ssi_holder_service()
    };

    let result = service
        .accept_credential(interaction_id, None, Some(identifier_id), None, None)
        .await
        .unwrap_err();

    assert_eq!(result.error_code(), ErrorCode::BR_0169);
}

#[tokio::test]
async fn test_reject_credential() {
    let mut credential = dummy_credential(None);
    credential.common_mut().state = CredentialStateEnum::Accepted;

    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_get_credentials_by_interaction_id()
        .once()
        .return_once(move |_| Ok(vec![credential]));
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
            supported_encryption_algorithms: vec![],
        });
    exchange_protocol_mock
        .expect_holder_reject_credential()
        .once()
        .returning(|_| Ok(()));

    let mut issuance_protocol_provider = MockIssuanceProtocolProvider::new();
    issuance_protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Ok(Arc::new(exchange_protocol_mock)));

    let service = SSIHolderService {
        credential_repository: Arc::new(credential_repository),
        issuance_protocol_provider: Arc::new(issuance_protocol_provider),
        ..mock_ssi_holder_service()
    };

    let interaction_id = Uuid::new_v4().into();
    service
        .reject_credential(&interaction_id, None)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_reject_credential_failed_issuer_notification() {
    let mut credential = dummy_credential(None);
    credential.common_mut().state = CredentialStateEnum::Accepted;

    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_get_credentials_by_interaction_id()
        .once()
        .return_once(move |_| Ok(vec![credential]));
    credential_repository
        .expect_update_credential()
        .once()
        .withf(|_, request| {
            assert_eq!(request.state, Some(CredentialStateEnum::Rejected));
            true
        })
        .returning(|_, _| Ok(()));

    let mut exchange_protocol_mock = MockIssuanceProtocol::default();
    exchange_protocol_mock
        .expect_get_capabilities()
        .returning(|| IssuanceProtocolCapabilities {
            features: vec![Features::SupportsRejection],
            did_methods: vec![],
            supported_encryption_algorithms: vec![],
        });
    exchange_protocol_mock
        .expect_holder_reject_credential()
        .once()
        .returning(|_| Err(IssuanceProtocolError::Failed("notification".to_string())));

    let mut issuance_protocol_provider = MockIssuanceProtocolProvider::new();
    issuance_protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Ok(Arc::new(exchange_protocol_mock)));

    let service = SSIHolderService {
        credential_repository: Arc::new(credential_repository),
        issuance_protocol_provider: Arc::new(issuance_protocol_provider),
        ..mock_ssi_holder_service()
    };

    let interaction_id = Uuid::new_v4().into();
    service
        .reject_credential(&interaction_id, None)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_initiate_issuance() {
    let mut organisation_repository = MockOrganisationRepository::new();
    organisation_repository
        .expect_get_organisation()
        .return_once(|_| Ok(dummy_organisation(None)));

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
            ResponseTemplate::new(200).set_body_json(AuthorizationServerMetadata {
                issuer: issuer.parse().unwrap(),
                authorization_endpoint: Some(Url::parse(authorization_endpoint).unwrap()),
                token_endpoint: None,
                pushed_authorization_request_endpoint: None,
                jwks_uri: None,
                code_challenge_methods_supported: vec![],
                scopes_supported: vec![],
                response_types_supported: vec![],
                grant_types_supported: vec![],
                token_endpoint_auth_methods_supported: vec![],
                challenge_endpoint: None,
                client_attestation_signing_alg_values_supported: None,
                client_attestation_pop_signing_alg_values_supported: None,
                dpop_signing_alg_values_supported: None,
                signed_metadata: None,
            }),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = service
        .initiate_issuance(InitiateIssuanceRequestDTO {
            organisation_id: Uuid::new_v4().into(),
            protocol: "OPENID4VCI_FINAL1".to_string(),
            issuer,
            client_id: "clientId".to_string(),
            redirect_uri: Some("http://redirect.uri".to_string()),
            scope: Some(vec!["scope1".to_string(), "scope2".to_string()]),
            authorization_details: Some(vec![AuthorizationDetail {
                r#type: "type".to_string(),
                credential_configuration_id: "configurationId".to_string(),
            }]),
            issuer_state: None,
            authorization_server: None,
            ecosystem: None,
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
    let interaction_id = Uuid::new_v4().into();

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
            ecosystem: None,
        },
        code_verifier: None,
    };

    let mut interaction_repository = MockInteractionRepository::new();
    interaction_repository
        .expect_get_interaction()
        .returning(move |id, _| {
            Ok(Interaction {
                id: *id,
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                data: Some(serde_json::to_vec(&interaction_data).unwrap()),
                organisation: organisation.clone().into(),
                interaction_type: InteractionType::Verification,
                expires_at: None,
                ecosystem: None,
                ecosystem_data: Default::default(),
            })
        });
    // no ecosystem selected, so nothing is consulted and the interaction is not touched
    interaction_repository.expect_update_interaction().never();

    let mut issuance_protocol = MockIssuanceProtocol::new();
    issuance_protocol
        .expect_holder_continue_issuance()
        .once()
        .returning(move |_, _| {
            Ok(ContinueIssuanceResponseDTO {
                interaction_id,
                key_storage_security_levels: None,
                key_algorithms: None,
                requires_wallet_instance_attestation: false,
                protocol: "protocol".to_string(),
                ecosystem_artifact: ProtocolArtifact::HolderIssuanceInvitation {
                    issuer_metadata: IssuerMetadataRepresentation::Unsigned(Box::new(
                        CredentialIssuerMetadata {
                            credential_issuer: "credential_issuer".to_string(),
                            authorization_servers: None,
                            credential_endpoint: "credential_endpoint".to_string(),
                            nonce_endpoint: None,
                            notification_endpoint: None,
                            credential_configurations_supported: Default::default(),
                            display: None,
                            issuer_info: Default::default(),
                            batch_credential_issuance: None,
                            credential_request_encryption: None,
                            credential_response_encryption: None,
                            preferred_client_status_period: None,
                        },
                    )),
                    credential_configuration_ids: vec![],
                },
            })
        });

    let mut issuance_protocol_provider = MockIssuanceProtocolProvider::new();

    let issuance_protocol = Arc::new(issuance_protocol);
    issuance_protocol_provider
        .expect_get_protocol()
        .once()
        .returning(move |_| Ok(issuance_protocol.clone()));

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_supported_verification_jose_alg_ids()
        .return_once(Vec::new);

    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_create_credentials()
        .return_once(|credentials| {
            Ok(credentials
                .into_iter()
                .map(|credential| credential.common().id)
                .collect())
        });

    let interaction_repository = Arc::new(interaction_repository);
    let service = SSIHolderService {
        interaction_repository: interaction_repository.clone(),
        issuance_protocol_provider: Arc::new(issuance_protocol_provider),
        key_algorithm_provider: Arc::new(key_algorithm_provider),
        credential_repository: Arc::new(credential_repository),
        ecosystem_resolver: ecosystem_resolver(
            interaction_repository,
            MockEcosystemDirectory::new(),
            MockHistoryRepository::new(),
        ),
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
        .return_once(|_| Ok(dummy_organisation(None)));

    let mut interaction_repository = MockInteractionRepository::new();
    interaction_repository
        .expect_create_interaction()
        .once()
        .withf(|request| {
            let data: OpenIDAuthorizationCodeFlowInteractionData =
                serde_json::from_slice(request.data.as_ref().unwrap()).unwrap();

            data.code_verifier.is_some()
        })
        .return_once(|_| Ok(Uuid::new_v4().into()));

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
            ResponseTemplate::new(200).set_body_json(AuthorizationServerMetadata {
                issuer: issuer.parse().unwrap(),
                authorization_endpoint: Some(
                    Url::parse("https://authorize.com/authorize").unwrap(),
                ),
                token_endpoint: None,
                pushed_authorization_request_endpoint: None,
                jwks_uri: None,
                code_challenge_methods_supported: vec![CodeChallengeMethod::S256],
                scopes_supported: vec![],
                response_types_supported: vec![],
                grant_types_supported: vec![],
                token_endpoint_auth_methods_supported: vec![],
                challenge_endpoint: None,
                client_attestation_signing_alg_values_supported: None,
                client_attestation_pop_signing_alg_values_supported: None,
                dpop_signing_alg_values_supported: None,
                signed_metadata: None,
            }),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = service
        .initiate_issuance(InitiateIssuanceRequestDTO {
            organisation_id: Uuid::new_v4().into(),
            protocol: "OPENID4VCI_FINAL1".to_string(),
            issuer,
            client_id: "clientId".to_string(),
            redirect_uri: Some("http://redirect.uri".to_string()),
            scope: Some(vec!["scope".to_string()]),
            authorization_details: None,
            issuer_state: None,
            authorization_server: None,
            ecosystem: None,
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
        identifier_repository: Arc::new(MockIdentifierRepository::new()),
        key_algorithm_provider: Arc::new(MockKeyAlgorithmProvider::new()),
        key_security_level_provider: Arc::new(MockKeySecurityLevelProvider::new()),
        formatter_provider: Arc::new(MockCredentialFormatterProvider::new()),
        issuance_protocol_provider: Arc::new(MockIssuanceProtocolProvider::new()),
        verification_protocol_provider: Arc::new(MockVerificationProtocolProvider::new()),
        blob_storage_provider: Arc::new(MockBlobStorageProvider::new()),
        config: Arc::new(generic_config().core),
        client,
        session_provider: Arc::new(NoSessionProvider),
        identifier_creator: Arc::new(MockIdentifierCreator::new()),
        transaction_manager: Arc::new(NoTransactionManager),
        ecosystem_provider: Arc::new(MockEcosystemDirectory::new()),
        ecosystem_resolver: ecosystem_resolver(
            Arc::new(MockInteractionRepository::new()),
            MockEcosystemDirectory::new(),
            MockHistoryRepository::new(),
        ),
    }
}

/// A real resolver that uses the same interaction repository as the service.
fn ecosystem_resolver(
    interaction_repository: Arc<MockInteractionRepository>,
    ecosystem_provider: MockEcosystemDirectory,
    history_repository: MockHistoryRepository,
) -> Arc<EcosystemResolverProto> {
    Arc::new(EcosystemResolverProto::new(
        interaction_repository,
        Arc::new(ecosystem_provider),
        Arc::new(history_repository),
        Arc::new(NoSessionProvider),
    ))
}

fn dummy_credential(organisation_id: Option<OrganisationId>) -> Credential {
    let credential_schema_id = Uuid::new_v4().into();
    let claim_schema = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "key1".to_string(),
        data_type: "STRING".to_string(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        array: false,
        metadata: false,
        required: true,
        translations: Default::default(),
    };
    let credential_schema_format_id = Uuid::new_v4().into();
    let format = CredentialSchemaFormat {
        id: credential_schema_format_id,
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        credential_schema_id,
        format: "JWT".into(),
        ecosystem_schema_id: "CredentialSchemaId".to_owned(),
        claim_mappings: vec![CredentialSchemaFormatClaimSchema {
            id: Uuid::new_v4().into(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            credential_schema_format_id,
            claim_schema_id: claim_schema.id,
            technical_key: "key1".to_string(),
            namespace: None,
        }]
        .into(),
    };
    CredentialBuilder {
        common: CredentialCommon {
            expires_at: None,
            ecosystem: None,
            id: Uuid::new_v4().into(),
            created_date: crate::clock::now_utc(),
            issuance_date: None,
            last_modified: crate::clock::now_utc(),
            deleted_at: None,
            protocol: "OPENID4VCI_FINAL1".to_string(),
            redirect_uri: None,
            state: CredentialStateEnum::Pending,
            profile: None,
            schema: crate::model::credential_schema::CredentialSchema {
                expiration: None,
                ecosystem: None,
                batch_size: None,
                allow_revocation: false,
                id: credential_schema_id,
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                imported_source_url: "CORE_URL".to_string(),
                name: "schema".to_string(),
                wallet_attestation: WalletAttestation {
                    require_instance_attestation: false,
                    key_storage_security_level: Some(KeyStorageSecurity::Basic),
                    preferred_key_storage_attestation_lifetime: None,
                    preferred_instance_attestation_lifetime: None,
                },
                formats: vec![format.clone()].into(),
                claim_schemas: vec![claim_schema].into(),
                organisation: dummy_organisation(organisation_id).into(),
                deleted_at: None,
                layout_properties: None,
                allow_suspension: true,
                transaction_code: None,
                translations: Default::default(),
                embedded_disclosure_policy: None,
            }
            .into(),
            interaction: Some(
                Interaction {
                    id: Uuid::new_v4().into(),
                    created_date: crate::clock::now_utc(),
                    last_modified: crate::clock::now_utc(),
                    data: Some(b"interaction data".to_vec()),
                    organisation: dummy_organisation(organisation_id).into(),
                    interaction_type: InteractionType::Verification,
                    expires_at: None,
                    ecosystem: None,
                    ecosystem_data: Default::default(),
                }
                .into(),
            ),
        },
        consumed_at: None,
        role: CredentialRole::Holder,
        r#type: CredentialType::Single,
        claims: Default::default(),
        issuer_identifier: Some(
            Identifier {
                id: Uuid::new_v4().into(),
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                name: "identifier".to_string(),
                data: IdentifierData::Did(
                    (Did {
                        deleted_at: None,
                        id: Uuid::new_v4().into(),
                        created_date: crate::clock::now_utc(),
                        last_modified: crate::clock::now_utc(),
                        name: "issuer_did".to_string(),
                        did: "did:key:123".parse().unwrap(),
                        did_type: DidType::Remote,
                        did_method: "KEY".into(),
                        keys: Default::default(),
                        organisation: dummy_organisation(None).into(),
                        deactivated: false,
                        log: None,
                    })
                    .into(),
                ),
                is_remote: true,
                state: IdentifierState::Active,
                deleted_at: None,
                autogenerated: false,
                organisation: dummy_organisation(None).into(),
                trust_information: Default::default(),
                logo: None,
                translations: Default::default(),
            }
            .into(),
        ),
        issuer_certificate: None,
        holder_identifier: None,
        key: None,
        credential_blob_id: Some(Uuid::new_v4().into()),
        wallet_key_attestation_blob_id: None,
        wallet_instance_attestation_blob_id: None,
        webhook_url: None,
        parent: None,
        embedded_disclosure_policy: None,
        subscriber_information: None,
        format: Some(format.into()),
    }
    .build()
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
        .handle_invitation(HandleInvitationRequestDTO {
            url: "https://localhost:3000/some_path".parse().unwrap(),
            organisation_id: Uuid::new_v4().into(),
            transport: None,
            redirect_uri: None,
            ecosystem: None,
        })
        .await;

    // then
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);
}

#[tokio::test]
async fn test_accept_credential_identifier_org_mismatch() {
    let identifier_id = Uuid::new_v4().into();
    let organisation_id = Uuid::new_v4().into();
    let session_organisation_id = Uuid::new_v4().into();

    let mut identifier_repository = MockIdentifierRepository::new();
    identifier_repository.expect_get().return_once(move |_| {
        Ok(Identifier {
            id: identifier_id,
            data: IdentifierData::Did(
                (Did {
                    keys: vec![RelatedKey {
                        role: KeyRole::Authentication,
                        key: dummy_key(),
                        reference: "1".to_string(),
                    }]
                    .into(),
                    did_method: "KEY".into(),
                    ..dummy_did()
                })
                .into(),
            ),
            organisation: dummy_organisation(Some(organisation_id)).into(),
            ..dummy_identifier()
        })
    });
    let service = SSIHolderService {
        identifier_repository: Arc::new(identifier_repository),
        session_provider: Arc::new(StaticSessionProvider(Session {
            organisation_id: Some(session_organisation_id),
            permissions: vec![],
            user_id: "test-user".to_string(),
            actor: None,
        })),
        ..mock_ssi_holder_service()
    };

    let result = service
        .accept_credential(Uuid::new_v4().into(), None, Some(identifier_id), None, None)
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);
}

#[tokio::test]
async fn test_accept_interaction_credential_org_mismatch() {
    let identifier_id = Uuid::new_v4().into();
    let organisation_id = Uuid::new_v4().into();
    let session_organisation_id = Uuid::new_v4().into();

    let mut identifier_repository = MockIdentifierRepository::new();
    identifier_repository.expect_get().return_once(move |_| {
        Ok(Identifier {
            id: identifier_id,
            data: IdentifierData::Did(
                (Did {
                    keys: vec![RelatedKey {
                        role: KeyRole::Authentication,
                        key: dummy_key(),
                        reference: "1".to_string(),
                    }]
                    .into(),
                    did_method: "KEY".into(),
                    ..dummy_did()
                })
                .into(),
            ),
            organisation: dummy_organisation(Some(session_organisation_id)).into(),
            ..dummy_identifier()
        })
    });
    let organisation = dummy_organisation(Some(organisation_id));
    let interaction_id = Uuid::new_v4().into();

    let mut interaction_repository = MockInteractionRepository::new();
    interaction_repository
        // consulted again when the issuance ends, to record the ecosystems
        .expect_get_interaction()
        .returning(move |_, _| {
            Ok(Interaction {
                id: Uuid::new_v4().into(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                data: Some(serde_json::to_vec(&dummy_interaction()).unwrap()),
                organisation: organisation.clone().into(),
                interaction_type: InteractionType::Issuance,
                expires_at: None,
                ecosystem: None,
                ecosystem_data: Default::default(),
            })
        });

    let service = SSIHolderService {
        identifier_repository: Arc::new(identifier_repository),
        session_provider: Arc::new(StaticSessionProvider(Session {
            organisation_id: Some(session_organisation_id),
            permissions: vec![],
            user_id: "test-user".to_string(),
            actor: None,
        })),
        interaction_repository: Arc::new(interaction_repository),
        ..mock_ssi_holder_service()
    };

    let result = service
        .accept_credential(interaction_id, None, Some(identifier_id), None, None)
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);
}

#[tokio::test]
async fn test_reject_credential_credential_org_mismatch() {
    let identifier_id = Uuid::new_v4().into();
    let organisation_id = Uuid::new_v4().into();
    let session_organisation_id = Uuid::new_v4().into();

    let mut identifier_repository = MockIdentifierRepository::new();
    identifier_repository.expect_get().return_once(move |_| {
        Ok(Identifier {
            id: identifier_id,
            data: IdentifierData::Did(
                (Did {
                    keys: vec![RelatedKey {
                        role: KeyRole::Authentication,
                        key: dummy_key(),
                        reference: "1".to_string(),
                    }]
                    .into(),
                    did_method: "KEY".into(),
                    ..dummy_did()
                })
                .into(),
            ),
            organisation: dummy_organisation(Some(session_organisation_id)).into(),
            ..dummy_identifier()
        })
    });
    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_get_credentials_by_interaction_id()
        .once()
        .return_once(move |_| Ok(vec![dummy_credential(Some(organisation_id))]));
    let service = SSIHolderService {
        credential_repository: Arc::new(credential_repository),
        identifier_repository: Arc::new(identifier_repository),
        session_provider: Arc::new(StaticSessionProvider(Session {
            organisation_id: Some(session_organisation_id),
            permissions: vec![],
            user_id: "test-user".to_string(),
            actor: None,
        })),
        ..mock_ssi_holder_service()
    };

    let result = service
        .reject_credential(&Uuid::new_v4().into(), None)
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);
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
            ecosystem: None,
        })
        .await;

    // then
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);
}

fn dummy_interaction() -> HolderInteractionData {
    HolderInteractionData {
        issuer_url: "".to_string(),
        credential_endpoint: "".to_string(),
        token_endpoint: None,
        notification_endpoint: None,
        nonce_endpoint: None,
        challenge_endpoint: None,
        grants: None,
        batch_size: None,
        continue_issuance: None,
        access_token: None,
        access_token_expires_at: None,
        refresh_token: None,
        refresh_token_expires_at: None,
        token_endpoint_auth_methods_supported: vec![],
        client_attestation_pop_signing_alg_values_supported: None,
        issuer_display: None,
        credential_request_encryption: None,
        credential_response_encryption: None,
        protocol: "".to_string(),
        credential_configurations: vec![HolderCredentialConfiguration {
            credential_configuration_id: "".to_string(),
            format: "dc+sd-jwt".to_string(),
            cryptographic_binding_methods_supported: None,
            credential_signing_alg_values_supported: None,
            proof_types_supported: None,
            credential_metadata: None,
            disclosure_policy: None,
            notification_id: None,
            credential_id: None,
            credential_schema_format_id: None,
        }],
    }
}

#[tokio::test]
async fn accept_merges_same_schema_batches_changing_only_the_items_parent() {
    let service = mock_ssi_holder_service();
    let common = dummy_credential(None).common().clone();
    let schema = common.schema;

    // The protocol issued JWT and MDOC configurations of the same schema, each with its own parent.
    let mut issued = vec![];
    for (configuration_id, format_name) in [("jwt", "JWT"), ("mdoc", "MDOC")] {
        let mut credential = crate::service::test_utilities::holder_single_credential(
            crate::service::test_utilities::dummy_credential(),
        );
        let holder = credential.holder_mut().unwrap();
        holder.common.schema = schema.clone();
        holder.data.embedded_disclosure_policy = Some(format!("{configuration_id}-policy"));
        {
            let mut format = holder.data.format.as_mut().await.unwrap();
            format.credential_schema_id = schema.id();
            format.format = format_name.into();
        }
        let mut item = CredentialWithBlob {
            credential,
            serialized: Some(format!("{configuration_id}-credential").into()),
        };
        let parent = item.batch_parent(false).unwrap();
        item.credential = CredentialBuilder {
            r#type: CredentialType::BatchItem,
            parent: Some(parent.credential.clone().into()),
            ..item.credential.into()
        }
        .build();
        item.credential.common_mut().interaction = None;
        issued.push(IssuanceAcceptResponse {
            credential_configuration_id: configuration_id.to_string(),
            main_credential: parent,
            batch_items: vec![item],
        });
    }
    let jwt_parent = issued[0].main_credential.clone();
    let original_items: Vec<_> = issued
        .iter()
        .flat_map(|response| response.batch_items.clone())
        .collect();

    let (grouped, assignments) = service.group_issued_credentials(issued).await.unwrap();

    // The first parent survives, and only the MDOC configuration needs reassignment.
    assert_eq!(grouped.len(), 1);
    let batch = &grouped[0];
    assert_eq!(batch.main_credential.credential, jwt_parent.credential);
    assert_eq!(batch.main_credential.serialized, jwt_parent.serialized);
    assert_eq!(
        assignments,
        [("mdoc".to_string(), jwt_parent.credential.common().id)]
            .into_iter()
            .collect()
    );

    // Reparenting must preserve both concrete credentials, including formats, policies, claims and blobs.
    assert_eq!(batch.batch_items.len(), 2);
    for (item, mut expected) in batch.batch_items.iter().zip(original_items) {
        expected.credential = CredentialBuilder {
            parent: Some(jwt_parent.credential.clone().into()),
            ..expected.credential.into()
        }
        .build();
        assert_eq!(item.credential, expected.credential);
        assert_eq!(item.serialized, expected.serialized);
    }
}

#[rstest::rstest]
#[case::different_values(
    &[("name", Some("Alice"), false)],
    &[("name", Some("Bob"), false)],
    false
)]
#[case::same_values_in_different_order(
    &[("name", Some("Alice"), false), ("age", Some("30"), false)],
    &[("age", Some("30"), false), ("name", Some("Alice"), false)],
    true
)]
#[case::different_metadata(
    &[("name", Some("Alice"), false), ("id", Some("first"), true)],
    &[("id", Some("second"), true), ("name", Some("Alice"), false), ("expires_at", Some("tomorrow"), true)],
    true
)]
#[case::only_metadata(
    &[("id", Some("first"), true)],
    &[("id", Some("second"), true)],
    true
)]
#[case::missing_claim(
    &[("name", Some("Alice"), false), ("age", Some("30"), false)],
    &[("name", Some("Alice"), false)],
    false
)]
#[case::different_paths(
    &[("first_name", Some("Alice"), false)],
    &[("last_name", Some("Alice"), false)],
    false
)]
#[case::different_array_values(
    &[("names/0", Some("Alice"), false), ("names/1", Some("Bob"), false)],
    &[("names/0", Some("Bob"), false), ("names/1", Some("Alice"), false)],
    false
)]
#[case::absent_and_empty_values(
    &[("name", None, false)],
    &[("name", Some(""), false)],
    false
)]
#[tokio::test]
async fn accept_groups_batches_by_non_metadata_claims(
    #[case] first_claims: &[(&str, Option<&str>, bool)],
    #[case] second_claims: &[(&str, Option<&str>, bool)],
    #[case] merge: bool,
) {
    let service = mock_ssi_holder_service();
    let common = dummy_credential(None).common().clone();
    let schema = common.schema;
    let mut issued = vec![];
    // Repeated configurations must find their matching group even after another group appears.
    for (index, claims) in [first_claims, second_claims, first_claims, second_claims]
        .into_iter()
        .enumerate()
    {
        let mut credential = dummy_credential(None);
        credential.common_mut().schema = schema.clone();
        credential.holder_mut().unwrap().data.claims = claims
            .iter()
            .map(|(path, value, metadata)| Claim {
                id: Uuid::new_v4().into(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                value: value.map(str::to_owned),
                path: (*path).to_owned(),
                selectively_disclosable: false,
                schema: ClaimSchema {
                    key: (*path).to_owned(),
                    metadata: *metadata,
                    ..crate::service::test_utilities::dummy_claim_schema()
                }
                .into(),
            })
            .collect::<Vec<_>>()
            .into();
        let mut item = CredentialWithBlob {
            credential,
            serialized: Some(format!("credential-{index}").into()),
        };
        let parent = item.batch_parent(false).unwrap();
        item.credential = CredentialBuilder {
            r#type: CredentialType::BatchItem,
            parent: Some(parent.credential.clone().into()),
            ..item.credential.into()
        }
        .build();
        item.credential.common_mut().interaction = None;
        issued.push(IssuanceAcceptResponse {
            credential_configuration_id: format!("config-{index}"),
            main_credential: parent,
            batch_items: vec![item],
        });
    }
    let original = issued.clone();

    let (grouped, assignments) = service.group_issued_credentials(issued).await.unwrap();

    assert_eq!(grouped.len(), if merge { 1 } else { 2 });
    let mut expected_assignments = std::collections::HashMap::new();
    for (group_index, group) in grouped.iter().enumerate() {
        let parent = &original[group_index].main_credential;
        assert_eq!(group.main_credential.credential, parent.credential);
        assert_eq!(group.main_credential.serialized, parent.serialized);
        let members: Vec<_> = original
            .iter()
            .enumerate()
            .filter(|(index, _)| merge || index % 2 == group_index)
            .collect();
        assert_eq!(group.batch_items.len(), members.len());
        for (item, (index, response)) in group.batch_items.iter().zip(members) {
            let mut expected = response.batch_items[0].clone();
            expected.credential = CredentialBuilder {
                parent: Some(parent.credential.clone().into()),
                ..expected.credential.into()
            }
            .build();
            assert_eq!(item.credential, expected.credential);
            assert_eq!(item.serialized, expected.serialized);
            if index != group_index {
                expected_assignments.insert(
                    response.credential_configuration_id.clone(),
                    parent.credential.common().id,
                );
            }
        }
    }
    assert_eq!(assignments, expected_assignments);
}

#[tokio::test]
async fn accept_keeps_singles_separate_even_with_the_same_schema() {
    let service = mock_ssi_holder_service();
    let first = dummy_credential(None);
    let second = {
        let mut updated_credential = first.clone();
        updated_credential.common_mut().id = Uuid::new_v4().into();
        updated_credential
    };
    let expected = [first, second];
    let issued = expected
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, credential)| IssuanceAcceptResponse {
            credential_configuration_id: format!("config-{index}"),
            main_credential: CredentialWithBlob {
                credential,
                serialized: Some(format!("serialized-{index}").into()),
            },
            batch_items: vec![],
        })
        .collect();

    let (grouped, assignments) = service.group_issued_credentials(issued).await.unwrap();

    assert!(assignments.is_empty());
    assert_eq!(grouped.len(), 2);
    for (index, (response, original)) in grouped.iter().zip(expected).enumerate() {
        assert_eq!(response.main_credential.credential, original);
        assert_eq!(
            response.main_credential.serialized,
            Some(format!("serialized-{index}").into())
        );
        assert!(response.batch_items.is_empty());
    }
}

#[tokio::test]
async fn accept_keeps_batch_parents_with_different_schemas_and_ecosystems_separate() {
    let service = mock_ssi_holder_service();
    let first = dummy_credential(None);
    let second = dummy_credential(None);
    let third = {
        let mut updated_credential = first.clone();
        updated_credential.common_mut().id = Uuid::new_v4().into();
        updated_credential.common_mut().ecosystem = Some("another-ecosystem".into());
        updated_credential
    };
    let issued: Vec<_> = [first, second, third]
        .into_iter()
        .enumerate()
        .map(|(index, credential)| {
            let mut item = CredentialWithBlob {
                credential,
                serialized: Some("credential".into()),
            };
            let parent = item.batch_parent(true).unwrap();
            item.credential = CredentialBuilder {
                r#type: CredentialType::BatchItem,
                parent: Some(parent.credential.clone().into()),
                ..item.credential.into()
            }
            .build();
            item.credential.common_mut().interaction = None;
            IssuanceAcceptResponse {
                credential_configuration_id: format!("config-{index}"),
                main_credential: parent,
                batch_items: vec![item],
            }
        })
        .collect();
    let expected_ids: Vec<_> = issued
        .iter()
        .map(|response| response.main_credential.credential.common().id)
        .collect();

    let (grouped, assignments) = service.group_issued_credentials(issued).await.unwrap();

    assert!(assignments.is_empty());
    assert_eq!(grouped.len(), 3);
    for (response, id) in grouped.iter().zip(expected_ids) {
        assert_eq!(response.main_credential.credential.common().id, id);
        assert_eq!(response.batch_items.len(), 1);
        assert!(matches!(
            &response.batch_items[0].credential,
            Credential::HolderBatchItem { parent, .. } if parent.id() == id
        ));
    }
}

#[tokio::test]
async fn refresh_validates_each_configuration_even_when_they_share_a_batch_parent() {
    use std::sync::Mutex;

    use crate::model::blob::{Blob, BlobType};
    use crate::provider::issuance_protocol::model::IssuanceRefreshResponse;

    // Two configurations return items under the same parent. Sharing the parent must not
    // cause the service to validate only one of the configurations against the ecosystem.
    let mut first = dummy_credential(None);
    let parent = CredentialWithBlob {
        credential: first.clone(),
        serialized: None,
    }
    .batch_parent(true)
    .unwrap();
    first = CredentialBuilder {
        r#type: CredentialType::BatchItem,
        parent: Some(parent.credential.clone().into()),
        ..first.into()
    }
    .build();
    first.common_mut().interaction = None;
    let second = {
        let mut updated_credential = first.clone();
        updated_credential.common_mut().id = Uuid::new_v4().into();
        updated_credential
            .holder_mut()
            .unwrap()
            .data
            .credential_blob_id = Some(Uuid::new_v4().into());
        updated_credential
    };
    let expected_ids = vec![first.common().id, second.common().id];
    let expected_validations = vec![
        ("first".to_string(), first.common().id),
        ("second".to_string(), second.common().id),
    ];
    let configurations = [("first", first), ("second", second)];
    let refreshed = configurations
        .iter()
        .map(|(configuration_id, item)| IssuanceRefreshResponse {
            credential_configuration_id: configuration_id.to_string(),
            credentials: vec![item.clone()],
        })
        .collect();

    let mut data = dummy_interaction();
    data.refresh_token = Some(b"refresh-token".to_vec());
    data.credential_configurations = configurations
        .iter()
        .map(|(configuration_id, item)| HolderCredentialConfiguration {
            credential_configuration_id: configuration_id.to_string(),
            format: "jwt_vc_json".to_string(),
            credential_id: Some(parent.credential.common().id),
            credential_schema_format_id: Some(item.holder().unwrap().data.format.id()),
            ..data.credential_configurations[0].clone()
        })
        .collect();

    let mut protocol = MockIssuanceProtocol::new();
    protocol
        .expect_holder_refresh_credential()
        .once()
        .return_once(move |_, _| Ok(refreshed));
    let mut protocol_provider = MockIssuanceProtocolProvider::new();
    protocol_provider
        .expect_get_protocol()
        .return_once(move |_| Ok(Arc::new(protocol)));
    let mut credential_repository = MockCredentialRepository::new();
    for (_, item) in configurations {
        credential_repository
            .expect_get_credential()
            .with(eq(item.common().id))
            .once()
            .return_once(move |_| Ok(item));
    }
    let interaction_id = Uuid::new_v4().into();
    let mut organisation = dummy_organisation(None);
    organisation.configuration.selected_ecosystems = vec!["EUDI".into()];
    let mut interactions = MockInteractionRepository::new();
    interactions
        .expect_get_interaction()
        .return_once(move |_, _| {
            Ok(Interaction {
                id: interaction_id,
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                data: Some(serde_json::to_vec(&data).unwrap()),
                organisation: organisation.into(),
                interaction_type: InteractionType::Issuance,
                expires_at: None,
                ecosystem: Some("EUDI".into()),
                ecosystem_data: Default::default(),
            })
        });
    let mut blob_storage = MockBlobStorage::new();
    blob_storage.expect_get().returning(|id| {
        Ok(Some(Blob {
            id: *id,
            ..Blob::new(b"credential".to_vec(), BlobType::Credential)
        }))
    });
    let mut blobs = MockBlobStorageProvider::new();
    blobs
        .expect_get_blob_storage()
        .return_once(move |_| Ok(Arc::new(blob_storage)));

    let validated_configurations = Arc::new(Mutex::new(vec![]));
    let validations = validated_configurations.clone();
    let mut ecosystem = MockEcosystem::new();
    ecosystem
        .expect_validate_interaction()
        .returning(move |artifact, _| {
            if let ProtocolArtifact::HolderIssuanceCredential {
                credential,
                credential_configuration_id,
                ..
            } = artifact
            {
                validations
                    .lock()
                    .unwrap()
                    .push((credential_configuration_id.clone(), credential.common().id));
            }
            Ok(crate::model::ecosystem::EcosystemTrustResult::Trusted.into())
        });
    let ecosystem = Arc::new(ecosystem);
    let mut ecosystems = MockEcosystemDirectory::new();
    ecosystems
        .expect_get()
        .returning(move |_| Ok(ecosystem.clone()));
    let service = SSIHolderService {
        credential_repository: Arc::new(credential_repository),
        interaction_repository: Arc::new(interactions),
        issuance_protocol_provider: Arc::new(protocol_provider),
        blob_storage_provider: Arc::new(blobs),
        ecosystem_resolver: ecosystem_resolver(
            Arc::new(MockInteractionRepository::new()),
            ecosystems,
            MockHistoryRepository::new(),
        ),
        ..mock_ssi_holder_service()
    };

    let refreshed_ids = service.refresh_credentials(interaction_id).await.unwrap();

    // Both configuration IDs reach the ecosystem with their own concrete item, not their shared parent.
    assert_eq!(
        *validated_configurations.lock().unwrap(),
        expected_validations
    );
    assert_eq!(refreshed_ids, expected_ids);
}
