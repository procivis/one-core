use std::str::FromStr;
use std::sync::Arc;

use maplit::hashmap;
use mockall::predicate::eq;
use one_crypto::jwe::MockPrivateKeyAgreementHandle;
use shared_types::{EcosystemId, InteractionId, ProofId};
use similar_asserts::assert_eq;
use standardized_types::iana::EncryptionAlgorithm;
use standardized_types::jwk::{JwkUse, Jwks, PublicJwk, PublicJwkEc};
use standardized_types::openid4vp::{
    ClientIdPrefix, ClientMetadata, DirectPostResponse, MdocAlgs, SdJwtVcAlgs, VPFormatsSupported,
    VpTokenResponse, W3CJwtAlgs, W3CLdpAlgs,
};
use uuid::Uuid;

use super::OID4VPFinal1_0Service;
use super::error::OID4VPFinal1_0ServiceError;
use crate::config::core_config::{CoreConfig, TransportType, VerificationProtocolType};
use crate::error::{ErrorCode, ErrorCodeMixin};
use crate::model::claim_schema::ClaimSchema;
use crate::model::common::LockType;
use crate::model::did::{Did, DidType, KeyRole, RelatedKey};
use crate::model::history::{HistoryAction, HistoryEntityType, HistoryMetadata};
use crate::model::identifier::{Identifier, IdentifierData};
use crate::model::interaction::{Interaction, InteractionType};
use crate::model::key::Key;
use crate::model::organisation::{Organisation, OrganisationConfiguration};
use crate::model::proof::{Proof, ProofRole, ProofStateEnum};
use crate::model::proof_schema::{ProofInputClaimSchema, ProofInputSchema, ProofSchema};
use crate::proto::ecosystem_resolver::EcosystemResolverProto;
use crate::proto::identifier_creator::MockIdentifierCreator;
use crate::proto::openid4vp_proof_validator::{MockOpenId4VpProofValidator, ValidatedProofResult};
use crate::proto::session_provider::NoSessionProvider;
use crate::proto::transaction_manager::NoTransactionManager;
use crate::provider::blob_storage::MockBlobStorage;
use crate::provider::blob_storage::provider::MockBlobStorageProvider;
use crate::provider::credential_formatter::model::{CertificateDetails, IdentifierDetails};
use crate::provider::ecosystem::MockEcosystem;
use crate::provider::ecosystem::directory::MockEcosystemDirectory;
use crate::provider::ecosystem::error::EcosystemError;
use crate::provider::ecosystem::model::ProtocolArtifact;
use crate::provider::key_algorithm::MockKeyAlgorithm;
use crate::provider::key_algorithm::key::{
    KeyAgreementHandle, KeyHandle, MockPublicKeyAgreementHandle, MockSignaturePublicKeyHandle,
    SignatureKeyHandle,
};
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_storage::MockKeyStorage;
use crate::provider::key_storage::model::KeyStorageCapabilities;
use crate::provider::key_storage::provider::MockKeyProvider;
use crate::provider::verification_protocol::MockVerificationProtocol;
use crate::provider::verification_protocol::dto::VerificationProtocolCapabilities;
use crate::provider::verification_protocol::openid4vp::error::OpenID4VCError;
use crate::provider::verification_protocol::openid4vp::model::*;
use crate::provider::verification_protocol::provider::MockVerificationProtocolProvider;
use crate::repository::credential_repository::MockCredentialRepository;
use crate::repository::history_repository::MockHistoryRepository;
use crate::repository::interaction_repository::MockInteractionRepository;
use crate::repository::key_repository::MockKeyRepository;
use crate::repository::proof_repository::MockProofRepository;
use crate::service::test_utilities::*;

#[derive(Default)]
struct Mocks {
    pub credential_repository: MockCredentialRepository,
    pub proof_repository: MockProofRepository,
    pub interaction_repository: MockInteractionRepository,
    pub key_repository: MockKeyRepository,
    pub key_provider: MockKeyProvider,
    pub config: CoreConfig,
    pub key_algorithm_provider: MockKeyAlgorithmProvider,
    pub blob_storage_provider: MockBlobStorageProvider,
    pub identifier_creator: MockIdentifierCreator,
    pub proof_validator: MockOpenId4VpProofValidator,
    pub ecosystem_provider: MockEcosystemDirectory,
    pub history_repository: MockHistoryRepository,
    pub protocol_provider: MockVerificationProtocolProvider,
}

fn setup_service(mocks: Mocks) -> OID4VPFinal1_0Service {
    OID4VPFinal1_0Service::new(
        Arc::new(mocks.credential_repository),
        Arc::new(mocks.proof_repository),
        Arc::new(mocks.key_repository),
        Arc::new(mocks.key_provider),
        Arc::new(mocks.config),
        Arc::new(mocks.key_algorithm_provider),
        Arc::new(mocks.blob_storage_provider),
        Arc::new(mocks.identifier_creator),
        Arc::new(NoTransactionManager),
        Arc::new(mocks.proof_validator),
        Arc::new(EcosystemResolverProto::new(
            Arc::new(mocks.interaction_repository),
            Arc::new(mocks.ecosystem_provider),
            Arc::new(mocks.history_repository),
            Arc::new(NoSessionProvider),
        )),
        Arc::new(mocks.protocol_provider),
    )
}

#[rstest::rstest]
#[case::pending(ProofStateEnum::Pending, true)]
#[case::requested(ProofStateEnum::Requested, true)]
#[case::accepted(ProofStateEnum::Accepted, false)]
#[case::rejected(ProofStateEnum::Rejected, false)]
#[case::retracted(ProofStateEnum::Retracted, false)]
#[case::expired(ProofStateEnum::InteractionExpired, false)]
#[case::error(ProofStateEnum::Error, false)]
#[tokio::test]
async fn test_submit_proof_validator_failure_only_updates_active_proofs(
    #[case] persisted_state: ProofStateEnum,
    #[case] mark_failed: bool,
) {
    let proof_id: ProofId = Uuid::new_v4().into();
    let verifier_did = "did:verifier:123".parse().unwrap();
    let mut proof_repository = MockProofRepository::new();
    let interaction_id: InteractionId = Uuid::parse_str("a83dabc3-1601-4642-84ec-7a5ad8a70d36")
        .unwrap()
        .into();
    let nonce = "7QqBfOcEcydceH6ZrXtu9fhDCvXjtLBv".to_string();

    let claim_id = Uuid::new_v4();
    let credential_schema = dummy_credential_schema();
    let interaction_data = OpenID4VPVerifierInteractionContent {
        nonce: nonce.to_owned(),
        encryption_key: None,
        dcql_query: dummy_dcql_query(true),
        client_id: "client_id".to_string(),
        client_id_scheme: Some(ClientIdPrefix::RedirectUri),
        response_uri: None,
        common: Default::default(),
    };
    let interaction_data_serialized = serde_json::to_vec(&interaction_data).unwrap();
    let now = crate::clock::now_utc();
    let interaction = Interaction {
        id: interaction_id,
        created_date: now,
        last_modified: now,
        data: Some(interaction_data_serialized),
        organisation: dummy_organisation(None).into(),
        interaction_type: InteractionType::Verification,
        expires_at: None,
        ecosystem: None,
        ecosystem_data: Default::default(),
    };

    let interaction_id_copy = interaction_id.to_owned();
    proof_repository
        .expect_get_proof_by_interaction_id()
        .withf(move |_interaction_id| {
            assert_eq!(*_interaction_id, interaction_id_copy);
            true
        })
        .once()
        .return_once(move |_| {
            Ok(Proof {
                id: proof_id,
                verifier_identifier: Some(
                    Identifier {
                        data: IdentifierData::Did(
                            (Did {
                                did: verifier_did,
                                ..dummy_did()
                            })
                            .into(),
                        ),
                        ..dummy_identifier()
                    }
                    .into(),
                ),
                state: ProofStateEnum::Pending,
                schema: Some(
                    ProofSchema {
                        input_schemas: vec![ProofInputSchema {
                            formats: vec!["JWT".into()],
                            claim_schemas: vec![
                                ProofInputClaimSchema {
                                    schema: ClaimSchema {
                                        id: shared_types::ClaimSchemaId::from(Into::<Uuid>::into(
                                            claim_id,
                                        )),
                                        key: "required_key".to_string(),
                                        ..dummy_claim_schema()
                                    },
                                    required: true,
                                    order: 0,
                                },
                                ProofInputClaimSchema {
                                    schema: ClaimSchema {
                                        key: "optional_key".to_string(),
                                        ..dummy_claim_schema()
                                    },
                                    required: false,
                                    order: 1,
                                },
                            ]
                            .into(),
                            credential_schema: credential_schema.into(),
                        }]
                        .into(),
                        organisation: dummy_organisation(None).into(),
                        ..dummy_proof_schema()
                    }
                    .into(),
                ),
                interaction: Some(interaction.into()),
                ..dummy_proof_with_protocol("OPENID4VP_FINAL1")
            })
        });

    proof_repository
        .expect_get_proof()
        .with(eq(proof_id), eq(Some(LockType::Update)))
        .once()
        .return_once(move |_, _| {
            Ok(Proof {
                id: proof_id,
                state: persisted_state,
                ..dummy_proof_with_protocol("OPENID4VP_FINAL1")
            })
        });
    proof_repository
        .expect_update_proof()
        .withf(move |id, update, error| {
            id == &proof_id
                && update.state == Some(ProofStateEnum::Error)
                && update.proof_blob_id.flatten().is_some()
                && error.is_some()
        })
        .times(if mark_failed { 1 } else { 0 })
        .returning(|_, _, _| Ok(()));

    let mut blob_storage = MockBlobStorage::new();
    blob_storage.expect_create().returning(|_| Ok(()));

    let blob_storage = Arc::new(blob_storage);
    let mut blob_storage_provider = MockBlobStorageProvider::new();
    blob_storage_provider
        .expect_get_blob_storage()
        .returning(move |_| Ok(blob_storage.clone()));

    let mut proof_validator = MockOpenId4VpProofValidator::new();
    proof_validator
        .expect_validate_submission()
        .returning(|_, _, _, _| Err(OpenID4VCError::ValidationError("failed".to_string())));

    let service = setup_service(Mocks {
        proof_repository,
        blob_storage_provider,
        proof_validator,
        config: generic_config().core,
        ..Default::default()
    });

    let err = service
        .direct_post(OpenID4VPDirectPostRequestDTO {
            submission_data: VpSubmissionData::Dcql(VpTokenResponse {
                vp_token: hashmap! { "credential_id".to_string() => vec!["vp_token".to_string()] },
            }),
            state: Some("a83dabc3-1601-4642-84ec-7a5ad8a70d36".parse().unwrap()),
        })
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        OID4VPFinal1_0ServiceError::OpenID4VCError(OpenID4VCError::ValidationError(_))
    ));
}

#[tokio::test]
async fn test_submit_proof_failed_on_trust_failure() {
    let proof_id: ProofId = Uuid::new_v4().into();
    let verifier_did = "did:verifier:123".parse().unwrap();
    let mut proof_repository = MockProofRepository::new();
    let interaction_id: InteractionId = Uuid::parse_str("a83dabc3-1601-4642-84ec-7a5ad8a70d36")
        .unwrap()
        .into();
    let nonce = "7QqBfOcEcydceH6ZrXtu9fhDCvXjtLBv".to_string();

    let claim_id = Uuid::new_v4();
    let credential_schema = dummy_credential_schema();
    let interaction_data = OpenID4VPVerifierInteractionContent {
        nonce: nonce.to_owned(),
        encryption_key: None,
        dcql_query: dummy_dcql_query(true),
        client_id: "client_id".to_string(),
        client_id_scheme: Some(ClientIdPrefix::RedirectUri),
        response_uri: None,
        common: Default::default(),
    };
    let interaction_data_serialized = serde_json::to_vec(&interaction_data).unwrap();
    let now = crate::clock::now_utc();
    let ecosystem_id: EcosystemId = "EUDI".into();
    let organisation = Organisation {
        configuration: OrganisationConfiguration {
            selected_ecosystems: vec![ecosystem_id.clone()],
            ..Default::default()
        },
        ..dummy_organisation(None)
    };
    let interaction = Interaction {
        id: interaction_id,
        created_date: now,
        last_modified: now,
        data: Some(interaction_data_serialized),
        organisation: organisation.into(),
        interaction_type: InteractionType::Verification,
        expires_at: None,
        ecosystem: Some(ecosystem_id.clone()),
        ecosystem_data: Default::default(),
    };

    let mut interaction_repository = MockInteractionRepository::new();
    let interaction_copy = interaction.clone();
    interaction_repository
        .expect_get_interaction()
        .returning(move |_, _| Ok(interaction_copy.clone()));

    let interaction_id_copy = interaction_id.to_owned();
    proof_repository
        .expect_get_proof_by_interaction_id()
        .withf(move |interaction_id| {
            assert_eq!(*interaction_id, interaction_id_copy);
            true
        })
        .once()
        .return_once(move |_| {
            Ok(Proof {
                id: proof_id,
                verifier_identifier: Some(
                    Identifier {
                        data: IdentifierData::Did(
                            (Did {
                                did: verifier_did,
                                ..dummy_did()
                            })
                            .into(),
                        ),
                        ..dummy_identifier()
                    }
                    .into(),
                ),
                state: ProofStateEnum::Pending,
                ecosystem: Some("EUDI".into()),
                schema: Some(
                    ProofSchema {
                        input_schemas: vec![ProofInputSchema {
                            formats: vec!["JWT".into()],
                            claim_schemas: vec![
                                ProofInputClaimSchema {
                                    schema: ClaimSchema {
                                        id: shared_types::ClaimSchemaId::from(Into::<Uuid>::into(
                                            claim_id,
                                        )),
                                        key: "required_key".to_string(),
                                        ..dummy_claim_schema()
                                    },
                                    required: true,
                                    order: 0,
                                },
                                ProofInputClaimSchema {
                                    schema: ClaimSchema {
                                        key: "optional_key".to_string(),
                                        ..dummy_claim_schema()
                                    },
                                    required: false,
                                    order: 1,
                                },
                            ]
                            .into(),
                            credential_schema: credential_schema.into(),
                        }]
                        .into(),
                        organisation: dummy_organisation(None).into(),
                        ..dummy_proof_schema()
                    }
                    .into(),
                ),
                interaction: Some(interaction.into()),
                ..dummy_proof_with_protocol("OPENID4VP_FINAL1")
            })
        });

    proof_repository
        .expect_get_proof()
        .with(eq(proof_id), eq(Some(LockType::Update)))
        .once()
        .return_once(move |_, _| {
            Ok(Proof {
                id: proof_id,
                state: ProofStateEnum::Pending,
                ..dummy_proof_with_protocol("OPENID4VP_FINAL1")
            })
        });
    proof_repository
        .expect_update_proof()
        .withf(move |id, _, _| {
            assert_eq!(id, &proof_id);
            true
        })
        .once()
        .returning(|_, _, _| Ok(()));

    let mut blob_storage = MockBlobStorage::new();
    blob_storage.expect_create().returning(|_| Ok(()));

    let blob_storage = Arc::new(blob_storage);
    let mut blob_storage_provider = MockBlobStorageProvider::new();
    blob_storage_provider
        .expect_get_blob_storage()
        .returning(move |_| Ok(blob_storage.clone()));

    let mut proof_validator = MockOpenId4VpProofValidator::new();
    proof_validator
        .expect_validate_submission()
        .returning(|_, _, _, _| {
            let mut credential = dummy_credential();
            credential.common.schema = dummy_credential_schema_with_format("JWT").into();
            Ok((
                ValidatedProofResult {
                    proved_credentials: vec![ProvedCredential {
                        credential,
                        issuer_details: IdentifierDetails::Certificate(CertificateDetails {
                            chain: "chain".to_string(),
                            fingerprint: "fingerprint".to_string(),
                            expiry: get_dummy_date(),
                            subject_common_name: None,
                            x5_references: Default::default(),
                        }),
                        holder_details: IdentifierDetails::Did("did:holder:123".parse().unwrap()),
                    }],
                    proved_claims: vec![],
                },
                DirectPostResponse { redirect_uri: None },
            ))
        });

    let mut ecosystem_provider = MockEcosystemDirectory::new();
    ecosystem_provider
        .expect_get()
        .once()
        .with(eq(ecosystem_id))
        .returning(|_| {
            let mut ecosystem = MockEcosystem::new();
            ecosystem
                .expect_validate_interaction()
                .once()
                .withf(|artifact, _| {
                    matches!(artifact, ProtocolArtifact::VerifierSubmission { .. })
                })
                .returning(|_, _| Err(EcosystemError::MissingIdentifier));
            Ok(Arc::new(ecosystem))
        });

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .once()
        .withf(move |history| {
            history.action == HistoryAction::EcosystemsResolved
                && history.entity_type == HistoryEntityType::Proof
                && history.entity_id == Some(proof_id.into())
                && matches!(
                    &history.metadata,
                    Some(HistoryMetadata::EcosystemsResolved(outcomes))
                        if outcomes.get(&"EUDI".into()).is_some_and(|outcome| !outcome.is_trusted())
                )
        })
        .returning(|history| Ok(history.id));

    let service = setup_service(Mocks {
        proof_repository,
        interaction_repository,
        blob_storage_provider,
        proof_validator,
        ecosystem_provider,
        history_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let err = service
        .direct_post(OpenID4VPDirectPostRequestDTO {
            submission_data: VpSubmissionData::Dcql(VpTokenResponse {
                vp_token: hashmap! { "credential_id".to_string() => vec!["vp_token".to_string()] },
            }),
            state: Some("a83dabc3-1601-4642-84ec-7a5ad8a70d36".parse().unwrap()),
        })
        .await
        .unwrap_err();

    assert_eq!(err.error_code(), ErrorCode::BR_0477);
}

#[tokio::test]
async fn test_get_client_metadata_success() {
    let mut proof_repository = MockProofRepository::default();
    let mut key_algorithm = MockKeyAlgorithm::default();
    let mut key_algorithm_provider = MockKeyAlgorithmProvider::default();
    let mut key_provider = MockKeyProvider::default();

    let now = crate::clock::now_utc();
    let proof_id: ProofId = Uuid::new_v4().into();
    let verifier_key = Key {
        autogenerated: false,
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
            .unwrap()
            .into(),
        created_date: now,
        last_modified: now,
        public_key: vec![],
        name: "verifier_key1".to_string(),
        key_reference: None,
        storage_type: "INTERNAL".to_string(),
        key_type: "EDDSA".to_string(),
        organisation: dummy_organisation(None).into(),
    };
    let proof = Proof {
        ecosystem: None,
        id: proof_id,
        created_date: now,
        last_modified: now,
        protocol: VerificationProtocolType::OpenId4VpFinal1_0.to_string(),
        transport: "HTTP".to_string(),
        redirect_uri: None,
        state: ProofStateEnum::Pending,
        role: ProofRole::Verifier,
        requested_date: Some(now),
        completed_date: None,
        schema: None,
        claims: Default::default(),
        verifier_identifier: Some(
            Identifier {
                data: IdentifierData::Did(
                    (Did {
                        deleted_at: None,
                        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb966")
                            .unwrap()
                            .into(),
                        created_date: now,
                        last_modified: now,
                        name: "did1".to_string(),
                        organisation: dummy_organisation(Some(
                            Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
                                .unwrap()
                                .into(),
                        ))
                        .into(),
                        did: "did:example:1".parse().unwrap(),
                        did_type: DidType::Local,
                        did_method: "KEY".into(),
                        keys: vec![RelatedKey {
                            role: KeyRole::KeyAgreement,
                            key: verifier_key.clone(),
                            reference: "1".to_string(),
                        }]
                        .into(),
                        deactivated: false,
                        log: None,
                    })
                    .into(),
                ),
                ..dummy_identifier()
            }
            .into(),
        ),
        verifier_key: Some(verifier_key.into()),
        verifier_certificate: None,
        interaction: None,
        profile: None,
        proof_blob_id: None,
        engagement: None,
        webhook_url: None,
        subscriber_information: None,
    };
    {
        proof_repository
            .expect_get_proof()
            .times(1)
            .return_once(move |_, _| Ok(proof));

        key_algorithm
            .expect_reconstruct_key()
            .return_once(|_, _, _| {
                let signature_key_handle = MockSignaturePublicKeyHandle::default();
                let mut key_agreement_handle = MockPublicKeyAgreementHandle::default();
                key_agreement_handle.expect_as_jwk().return_once(|| {
                    Ok(PublicJwk::Okp(PublicJwkEc {
                        alg: Some("ECDH-ES".to_string()),
                        r#use: Some(JwkUse::Encryption),
                        kid: None,
                        crv: "123".to_string(),
                        x: "456".to_string(),
                        y: None,
                    }))
                });

                Ok(KeyHandle::SignatureAndKeyAgreement {
                    signature: SignatureKeyHandle::PublicKeyOnly(Arc::new(signature_key_handle)),
                    key_agreement: KeyAgreementHandle::PublicKeyOnly(Arc::new(
                        key_agreement_handle,
                    )),
                })
            });

        key_algorithm_provider
            .expect_key_algorithm_from_key()
            .return_once(|_| Ok(Arc::new(key_algorithm)));
    }
    key_provider.expect_get_key_storage().returning(|_| {
        let mut key_storage = MockKeyStorage::default();
        key_storage
            .expect_get_capabilities()
            .return_once(|| KeyStorageCapabilities {
                features: vec![],
                algorithms: vec![],
            });
        // the key has to expose a private key agreement handle, otherwise it is not offered
        key_storage.expect_key_handle().returning(|_| {
            Ok(KeyHandle::SignatureAndKeyAgreement {
                signature: SignatureKeyHandle::PublicKeyOnly(Arc::new(
                    MockSignaturePublicKeyHandle::default(),
                )),
                key_agreement: KeyAgreementHandle::WithPrivateKey {
                    private: Arc::new(MockPrivateKeyAgreementHandle::default()),
                    public: Arc::new(MockPublicKeyAgreementHandle::default()),
                },
            })
        });

        Ok(Arc::new(key_storage))
    });
    // the advertised algorithms come from the protocol capabilities, not a hardcoded list
    let mut protocol_provider = MockVerificationProtocolProvider::default();
    protocol_provider.expect_get_protocol().return_once(|_| {
        let mut protocol = MockVerificationProtocol::default();
        protocol
            .expect_get_capabilities()
            .return_once(|| VerificationProtocolCapabilities {
                features: vec![],
                supported_transports: vec![TransportType::Http],
                did_methods: vec![],
                verifier_identifier_types: vec![],
                supported_presentation_definition: vec![],
                supported_encryption_algorithms: vec![
                    EncryptionAlgorithm::A128GCM,
                    EncryptionAlgorithm::A256GCM,
                ],
            });
        Ok(Arc::new(protocol))
    });

    let service = setup_service(Mocks {
        key_algorithm_provider,
        key_provider,
        proof_repository,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });
    let result = service.get_client_metadata(proof_id).await.unwrap();
    assert_eq!(
        ClientMetadata {
            jwks: Some(Jwks {
                keys: vec![PublicJwk::Okp(PublicJwkEc {
                    alg: Some("ECDH-ES".to_string()),
                    r#use: Some(JwkUse::Encryption),
                    kid: Some("c322aa7f-9803-410d-b891-939b279fb965".to_string()),
                    crv: "123".to_string(),
                    x: "456".to_string(),
                    y: None,
                }),]
            }),
            vp_formats_supported: VPFormatsSupported {
                ldp_vc: Some(W3CLdpAlgs {
                    proof_type_values: vec!["DataIntegrityProof".to_string()],
                    cryptosuite_values: vec![
                        "bbs-2023".to_string(),
                        "ecdsa-rdfc-2019".to_string(),
                        "eddsa-rdfc-2022".to_string(),
                    ],
                }),
                mso_mdoc: Some(MdocAlgs {
                    issuerauth_alg_values: vec![-7, -8, -9, -19],
                    deviceauth_alg_values: vec![-7, -8, -9, -19],
                }),
                dc_sd_jwt: Some(SdJwtVcAlgs {
                    sd_jwt_alg_values: vec!["EdDSA".to_string(), "ES256".to_string()],
                    kb_jwt_alg_values: vec!["EdDSA".to_string(), "ES256".to_string()],
                }),
                jwt_vc_json: Some(W3CJwtAlgs {
                    alg_values: vec!["EdDSA".to_string(), "ES256".to_string()]
                })
            },
            encrypted_response_enc_values_supported: Some(vec![
                EncryptionAlgorithm::A128GCM,
                EncryptionAlgorithm::A256GCM
            ]),
            ..Default::default()
        },
        result
    );
}
