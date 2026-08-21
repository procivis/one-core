use std::str::FromStr;
use std::sync::Arc;
use std::vec;

use mockall::predicate::{always, eq};
use regex::Regex;
use shared_types::{CredentialFormat, OrganisationId};
use similar_asserts::assert_eq;
use standardized_types::oauth2::authorization_server_metadata::{
    AuthorizationServerMetadata, CodeChallengeMethod,
};
use standardized_types::openid4vci::{AuthorizationDetail, CredentialIssuerMetadata};
use url::Url;
use uuid::Uuid;
use wiremock::http::Method;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::dto::HandleInvitationRequestDTO;
use crate::error::{ErrorCode, ErrorCodeMixin, ErrorCodeMixinExt};
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{Credential, CredentialRole, CredentialStateEnum, CredentialType};
use crate::model::credential_schema::KeyStorageSecurity;
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::credential_schema_format_claim_schema::CredentialSchemaFormatClaimSchema;
use crate::model::did::{Did, DidType, KeyRole, RelatedKey};
use crate::model::identifier::{Identifier, IdentifierData, IdentifierState};
use crate::model::interaction::{Interaction, InteractionType};
use crate::model::proof::{Proof, ProofStateEnum};
use crate::proto::http_client::reqwest_client::ReqwestClient;
use crate::proto::identifier_creator::MockIdentifierCreator;
use crate::proto::session_provider::test::StaticSessionProvider;
use crate::proto::session_provider::{NoSessionProvider, Session};
use crate::proto::transaction_manager::NoTransactionManager;
use crate::provider::blob_storage::MockBlobStorage;
use crate::provider::blob_storage::provider::MockBlobStorageProvider;
use crate::provider::credential_formatter::MockCredentialFormatter;
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::ecosystem::directory::MockEcosystemDirectory;
use crate::provider::ecosystem::model::{IssuerMetadataRepresentation, ProtocolArtifact};
use crate::provider::issuance_protocol::MockIssuanceProtocol;
use crate::provider::issuance_protocol::dto::{Features, IssuanceProtocolCapabilities};
use crate::provider::issuance_protocol::error::{IssuanceProtocolError, TxCodeError};
use crate::provider::issuance_protocol::model::{
    ContinueIssuanceResponseDTO, CredentialWithBlob, IssuanceAcceptResponse,
};
use crate::provider::issuance_protocol::openid4vci_final1_0::model::HolderInteractionData;
use crate::provider::issuance_protocol::provider::MockIssuanceProtocolProvider;
use crate::provider::key_algorithm::ecdsa::Ecdsa;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_security_level::basic::Basic;
use crate::provider::key_security_level::dto::{HolderParams, Params};
use crate::provider::key_security_level::provider::MockKeySecurityLevelProvider;
use crate::provider::verification_protocol::MockVerificationProtocol;
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::provider::MockVerificationProtocolProvider;
use crate::repository::credential_repository::MockCredentialRepository;
use crate::repository::identifier_repository::MockIdentifierRepository;
use crate::repository::interaction_repository::MockInteractionRepository;
use crate::repository::organisation_repository::MockOrganisationRepository;
use crate::repository::proof_repository::MockProofRepository;
use crate::service::ssi_holder::SSIHolderService;
use crate::service::ssi_holder::dto::{
    InitiateIssuanceRequestDTO, OpenIDAuthorizationCodeFlowInteractionData,
};
use crate::service::test_utilities::{
    dummy_did, dummy_identifier, dummy_key, dummy_organisation, dummy_proof, generic_config,
    generic_formatter_capabilities, get_dummy_date,
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
                        nonce_id: None,
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
                            nonce_id: None,
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
                        nonce_id: None,
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

    let service = SSIHolderService {
        proof_repository: Arc::new(proof_repository),
        verification_protocol_provider: Arc::new(verification_protocol_provider),
        ..mock_ssi_holder_service()
    };

    service.reject_proof_request(&interaction_id).await.unwrap();
}

#[tokio::test]
async fn test_accept_credential() {
    let identifier_id = Uuid::new_v4().into();

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
        .expect_create_credential()
        .once()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let mut exchange_protocol_mock = MockIssuanceProtocol::default();
    exchange_protocol_mock
        .expect_holder_accept_credential()
        .once()
        .returning(|_, _, _| {
            Ok(IssuanceAcceptResponse {
                main_credential: CredentialWithBlob {
                    credential: dummy_credential(None),
                    serialized: Some("credential".into()),
                },
                batch_items: vec![],
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
    let organisation = dummy_organisation(None);
    let interaction_id = Uuid::new_v4().into();

    let mut interaction_repository = MockInteractionRepository::new();
    interaction_repository
        .expect_get_interaction()
        .return_once(move |_, _| {
            Ok(Interaction {
                id: Uuid::new_v4().into(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                data: Some(serde_json::to_vec(&dummy_interaction()).unwrap()),
                organisation: organisation.into(),
                nonce_id: None,
                interaction_type: InteractionType::Issuance,
                expires_at: None,
                ecosystem: None,
                ecosystem_data: Default::default(),
            })
        });

    let service = SSIHolderService {
        credential_repository: Arc::new(credential_repository),
        issuance_protocol_provider: Arc::new(issuance_protocol_provider),
        identifier_repository: Arc::new(identifier_repository),
        key_algorithm_provider: Arc::new(key_algorithm_provider),
        formatter_provider: Arc::new(formatter_provider),
        blob_storage_provider: Arc::new(blob_storage_provider),
        key_security_level_provider: Arc::new(key_security_level_provider),
        interaction_repository: Arc::new(interaction_repository),
        ..mock_ssi_holder_service()
    };

    service
        .accept_credential(interaction_id, None, Some(identifier_id), None, None)
        .await
        .unwrap();
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
        .expect_create_credential()
        .once()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let mut exchange_protocol_mock = MockIssuanceProtocol::default();
    exchange_protocol_mock
        .expect_holder_accept_credential()
        .once()
        .returning(|_, _, _| {
            Ok(IssuanceAcceptResponse {
                main_credential: CredentialWithBlob {
                    credential: dummy_credential(None),
                    serialized: Some("credential".into()),
                },
                batch_items: vec![],
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

    let organisation = dummy_organisation(None);
    let interaction_id = Uuid::new_v4().into();

    let mut interaction_repository = MockInteractionRepository::new();
    interaction_repository
        .expect_get_interaction()
        .return_once(move |_, _| {
            Ok(Interaction {
                id: Uuid::new_v4().into(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                data: Some(serde_json::to_vec(&dummy_interaction()).unwrap()),
                organisation: organisation.into(),
                nonce_id: None,
                interaction_type: InteractionType::Issuance,
                expires_at: None,
                ecosystem: None,
                ecosystem_data: Default::default(),
            })
        });

    let service = SSIHolderService {
        credential_repository: Arc::new(credential_repository),
        issuance_protocol_provider: Arc::new(issuance_protocol_provider),
        identifier_repository: Arc::new(identifier_repository),
        key_algorithm_provider: Arc::new(key_algorithm_provider),
        formatter_provider: Arc::new(formatter_provider),
        blob_storage_provider: Arc::new(blob_storage_provider),
        key_security_level_provider: Arc::new(key_security_level_provider),
        interaction_repository: Arc::new(interaction_repository),
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
        .expect_create_credential()
        .times(3)
        .returning(|_| Ok(Uuid::new_v4().into()));

    let mut exchange_protocol_mock = MockIssuanceProtocol::default();
    let main_credential = dummy_credential(None);
    let cred_clone = main_credential.clone();
    exchange_protocol_mock
        .expect_holder_accept_credential()
        .once()
        .with(always(), eq(None), always())
        .returning(move |_, _, _| {
            Ok(IssuanceAcceptResponse {
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
        .once()
        .return_once(move |_, _| {
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
                nonce_id: None,
                interaction_type: InteractionType::Issuance,
                expires_at: None,
                ecosystem: None,
                ecosystem_data: Default::default(),
            })
        });

    let service = SSIHolderService {
        credential_repository: Arc::new(credential_repository),
        issuance_protocol_provider: Arc::new(issuance_protocol_provider),
        formatter_provider: Arc::new(formatter_provider),
        blob_storage_provider: Arc::new(blob_storage_provider),
        interaction_repository: Arc::new(interaction_repository),
        ..mock_ssi_holder_service()
    };

    let credential_id = service
        .accept_credential(interaction_id, None, None, None, None)
        .await
        .unwrap();

    assert_eq!(credential_id, main_credential.id);
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
        .return_once(|_, _, _| Err(TxCodeError::IncorrectCode.error_while("").into()));

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
        .expect_get_interaction()
        .return_once(move |_, _| {
            Ok(Interaction {
                id: Uuid::new_v4().into(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                data: Some(serde_json::to_vec(&dummy_interaction()).unwrap()),
                organisation: organisation.into(),
                nonce_id: None,
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
    credential.state = CredentialStateEnum::Accepted;

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
    service.reject_credential(&interaction_id).await.unwrap();
}

#[tokio::test]
async fn test_reject_credential_failed_issuer_notification() {
    let mut credential = dummy_credential(None);
    credential.state = CredentialStateEnum::Accepted;

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
    service.reject_credential(&interaction_id).await.unwrap();
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
                nonce_id: None,
                interaction_type: InteractionType::Verification,
                expires_at: None,
                ecosystem: None,
                ecosystem_data: Default::default(),
            })
        });

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
    }
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
    Credential {
        expires_at: None,
        ecosystem: None,
        id: Uuid::new_v4().into(),
        created_date: crate::clock::now_utc(),
        issuance_date: None,
        last_modified: crate::clock::now_utc(),
        deleted_at: None,
        consumed_at: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        redirect_uri: None,
        role: CredentialRole::Issuer,
        r#type: CredentialType::Single,
        state: CredentialStateEnum::Pending,
        suspend_end_date: None,
        claims: Default::default(),
        profile: None,
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
                organisation: dummy_organisation(None).into(),
                trust_information: Default::default(),
            }
            .into(),
        ),
        issuer_certificate: None,
        holder_identifier: None,
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
            key_storage_security: Some(KeyStorageSecurity::Basic),
            formats: vec![CredentialSchemaFormat {
                id: credential_schema_format_id,
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                credential_schema_id,
                format: "JWT".into(),
                schema_id: "CredentialSchemaId".to_owned(),
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
            }]
            .into(),
            claim_schemas: vec![claim_schema].into(),
            organisation: dummy_organisation(organisation_id).into(),
            deleted_at: None,
            layout_properties: None,
            allow_suspension: true,
            requires_wallet_instance_attestation: false,
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
                nonce_id: None,
                interaction_type: InteractionType::Verification,
                expires_at: None,
                ecosystem: None,
                ecosystem_data: Default::default(),
            }
            .into(),
        ),
        key: None,
        credential_blob_id: Some(Uuid::new_v4().into()),
        wallet_unit_attestation_blob_id: None,
        wallet_instance_attestation_blob_id: None,
        webhook_url: None,
        parent: None,
        embedded_disclosure_policy: None,

        subscriber_information: None,
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
        .expect_get_interaction()
        .return_once(move |_, _| {
            Ok(Interaction {
                id: Uuid::new_v4().into(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                data: Some(serde_json::to_vec(&dummy_interaction()).unwrap()),
                organisation: organisation.into(),
                nonce_id: None,
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

    let result = service.reject_credential(&Uuid::new_v4().into()).await;
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
        cryptographic_binding_methods_supported: None,
        credential_signing_alg_values_supported: None,
        proof_types_supported: None,
        token_endpoint_auth_methods_supported: None,
        client_attestation_pop_signing_alg_values_supported: None,
        credential_metadata: None,
        credential_request_encryption: None,
        credential_response_encryption: None,
        credential_configuration_id: "".to_string(),
        notification_id: None,
        protocol: "".to_string(),
        format: "dc+sd-jwt".to_string(),
        disclosure_policy: None,
    }
}
