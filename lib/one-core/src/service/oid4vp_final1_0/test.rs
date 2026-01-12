use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use shared_types::{InteractionId, ProofId};
use similar_asserts::assert_eq;
use standardized_types::jwa::EncryptionAlgorithm;
use standardized_types::jwk::{JwkUse, PublicJwk, PublicJwkEc};
use standardized_types::openid4vp::{
    ClientMetadata, ClientMetadataJwks, GenericAlgs, MdocAlgs, PresentationFormat, SdJwtVcAlgs,
    W3CJwtAlgs, W3CLdpAlgs,
};
use time::OffsetDateTime;
use uuid::Uuid;

use super::OID4VPFinal1_0Service;
use crate::config::core_config::{CoreConfig, VerificationProtocolType};
use crate::model::claim_schema::ClaimSchema;
use crate::model::did::{Did, DidType, KeyRole, RelatedKey};
use crate::model::identifier::Identifier;
use crate::model::interaction::{Interaction, InteractionType};
use crate::model::key::Key;
use crate::model::proof::{Proof, ProofRole, ProofStateEnum};
use crate::model::proof_schema::{ProofInputClaimSchema, ProofInputSchema, ProofSchema};
use crate::proto::identifier_creator::MockIdentifierCreator;
use crate::proto::openid4vp_proof_validator::MockOpenId4VpProofValidator;
use crate::proto::transaction_manager::NoTransactionManager;
use crate::provider::blob_storage_provider::{MockBlobStorage, MockBlobStorageProvider};
use crate::provider::key_algorithm::MockKeyAlgorithm;
use crate::provider::key_algorithm::key::{
    KeyAgreementHandle, KeyHandle, MockPublicKeyAgreementHandle, MockSignaturePublicKeyHandle,
    SignatureKeyHandle,
};
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_storage::MockKeyStorage;
use crate::provider::key_storage::model::KeyStorageCapabilities;
use crate::provider::key_storage::provider::MockKeyProvider;
use crate::provider::verification_protocol::openid4vp::error::OpenID4VCError;
use crate::provider::verification_protocol::openid4vp::model::*;
use crate::repository::credential_repository::MockCredentialRepository;
use crate::repository::key_repository::MockKeyRepository;
use crate::repository::proof_repository::MockProofRepository;
use crate::repository::validity_credential_repository::MockValidityCredentialRepository;
use crate::service::error::ServiceError;
use crate::service::test_utilities::*;

#[derive(Default)]
struct Mocks {
    pub credential_repository: MockCredentialRepository,
    pub proof_repository: MockProofRepository,
    pub key_repository: MockKeyRepository,
    pub key_provider: MockKeyProvider,
    pub config: CoreConfig,
    pub key_algorithm_provider: MockKeyAlgorithmProvider,
    pub validity_credential_repository: MockValidityCredentialRepository,
    pub blob_storage_provider: MockBlobStorageProvider,
    pub identifier_creator: MockIdentifierCreator,
    pub proof_validator: MockOpenId4VpProofValidator,
}

fn setup_service(mocks: Mocks) -> OID4VPFinal1_0Service {
    OID4VPFinal1_0Service::new(
        Arc::new(mocks.credential_repository),
        Arc::new(mocks.proof_repository),
        Arc::new(mocks.key_repository),
        Arc::new(mocks.key_provider),
        Arc::new(mocks.config),
        Arc::new(mocks.key_algorithm_provider),
        Arc::new(mocks.validity_credential_repository),
        Arc::new(mocks.blob_storage_provider),
        Arc::new(mocks.identifier_creator),
        Arc::new(NoTransactionManager),
        Arc::new(mocks.proof_validator),
    )
}

fn jwt_format_map() -> HashMap<String, PresentationFormat> {
    HashMap::from([(
        "jwt_vc_json".to_string(),
        PresentationFormat::GenericAlgList(GenericAlgs {
            alg: vec!["EdDSA".to_string(), "ES256".to_string()],
        }),
    )])
}

#[tokio::test]
async fn test_submit_proof_failed_credential_suspended() {
    let proof_id: ProofId = Uuid::new_v4().into();
    let verifier_did = "did:verifier:123".parse().unwrap();
    let mut proof_repository = MockProofRepository::new();
    let interaction_id: InteractionId = Uuid::parse_str("a83dabc3-1601-4642-84ec-7a5ad8a70d36")
        .unwrap()
        .into();
    let nonce = "7QqBfOcEcydceH6ZrXtu9fhDCvXjtLBv".to_string();
    let claim_id = Uuid::new_v4().into();
    let credential_schema = dummy_credential_schema();
    let interaction_data = OpenID4VPVerifierInteractionContent {
        nonce: nonce.to_owned(),
        encryption_key: None,
        dcql_query: None,
        presentation_definition: Some(OpenID4VPPresentationDefinition {
            id: interaction_id.to_string(),
            input_descriptors: vec![OpenID4VPPresentationDefinitionInputDescriptor {
                id: "input_0".to_string(),
                name: None,
                purpose: None,
                format: jwt_format_map(),
                constraints: OpenID4VPPresentationDefinitionConstraint {
                    fields: vec![
                        OpenID4VPPresentationDefinitionConstraintField {
                            id: None,
                            name: None,
                            purpose: None,
                            path: vec!["$.credentialSchema.id".to_string()],
                            optional: None,
                            filter: Some(OpenID4VPPresentationDefinitionConstraintFieldFilter {
                                r#type: "string".to_string(),
                                r#const: credential_schema.schema_id.to_owned(),
                            }),
                            intent_to_retain: None,
                        },
                        OpenID4VPPresentationDefinitionConstraintField {
                            id: Some(claim_id),
                            name: None,
                            purpose: None,
                            path: vec!["$.vc.credentialSubject.string".to_string()],
                            optional: Some(false),
                            filter: None,
                            intent_to_retain: None,
                        },
                    ],
                    validity_credential_nbf: None,
                    limit_disclosure: None,
                },
            }],
        }),
        client_id: "client_id".to_string(),
        client_id_scheme: Some(ClientIdScheme::RedirectUri),
        response_uri: None,
    };
    let interaction_data_serialized = serde_json::to_vec(&interaction_data).unwrap();
    let now = OffsetDateTime::now_utc();
    let interaction = Interaction {
        id: interaction_id,
        created_date: now,
        last_modified: now,
        data: Some(interaction_data_serialized),
        organisation: None,
        nonce_id: None,
        interaction_type: InteractionType::Verification,
        expires_at: None,
    };

    let interaction_id_copy = interaction_id.to_owned();
    proof_repository
        .expect_get_proof_by_interaction_id()
        .withf(move |_interaction_id, _| {
            assert_eq!(*_interaction_id, interaction_id_copy);
            true
        })
        .once()
        .return_once(move |_, _| {
            Ok(Some(Proof {
                id: proof_id,
                verifier_identifier: Some(Identifier {
                    did: Some(Did {
                        did: verifier_did,
                        ..dummy_did()
                    }),
                    ..dummy_identifier()
                }),
                state: ProofStateEnum::Pending,
                schema: Some(ProofSchema {
                    input_schemas: Some(vec![ProofInputSchema {
                        validity_constraint: None,
                        claim_schemas: Some(vec![
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
                        ]),
                        credential_schema: Some(credential_schema),
                    }]),
                    organisation: Some(dummy_organisation(None)),
                    ..dummy_proof_schema()
                }),
                interaction: Some(interaction),
                ..dummy_proof_with_protocol("OPENID4VP_FINAL1")
            }))
        });

    proof_repository
        .expect_update_proof()
        .withf(move |_proof_id, _, _| {
            assert_eq!(_proof_id, &proof_id);
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
        .returning(move |_| Some(blob_storage.clone()));

    let mut proof_validator = MockOpenId4VpProofValidator::new();
    proof_validator
        .expect_validate_submission()
        .returning(|_, _, _, _| Err(OpenID4VCError::CredentialIsRevokedOrSuspended));
    let service = setup_service(Mocks {
        proof_repository,
        blob_storage_provider,
        proof_validator,
        config: generic_config().core,
        ..Default::default()
    });

    let err = service
        .direct_post(OpenID4VPDirectPostRequestDTO {
            submission_data: VpSubmissionData::Pex(PexSubmission {
                vp_token: vec!["vp_token".to_string()],
                presentation_submission: PresentationSubmissionMappingDTO {
                    id: "25f5a42c-6850-49a0-b842-c7b2411021a5".to_string(),
                    definition_id: interaction_id.to_string(),
                    descriptor_map: vec![PresentationSubmissionDescriptorDTO {
                        id: "input_0".to_string(),
                        format: "jwt_vp_json".to_string(),
                        path: "$".to_string(),
                        path_nested: Some(NestedPresentationSubmissionDescriptorDTO {
                            format: "jwt_vc_json".to_string(),
                            path: "$.vp.verifiableCredential[0]".to_string(),
                        }),
                    }],
                },
            }),
            state: Some("a83dabc3-1601-4642-84ec-7a5ad8a70d36".parse().unwrap()),
        })
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        ServiceError::OpenID4VCError(OpenID4VCError::CredentialIsRevokedOrSuspended)
    ));
}

#[tokio::test]
async fn test_submit_proof_failed_on_validator_failure() {
    let proof_id: ProofId = Uuid::new_v4().into();
    let verifier_did = "did:verifier:123".parse().unwrap();
    let mut proof_repository = MockProofRepository::new();
    let interaction_id: InteractionId = Uuid::parse_str("a83dabc3-1601-4642-84ec-7a5ad8a70d36")
        .unwrap()
        .into();
    let nonce = "7QqBfOcEcydceH6ZrXtu9fhDCvXjtLBv".to_string();

    let claim_id = Uuid::new_v4().into();
    let credential_schema = dummy_credential_schema();
    let interaction_data = OpenID4VPVerifierInteractionContent {
        nonce: nonce.to_owned(),
        encryption_key: None,
        dcql_query: None,
        presentation_definition: Some(OpenID4VPPresentationDefinition {
            id: interaction_id.to_string(),
            input_descriptors: vec![OpenID4VPPresentationDefinitionInputDescriptor {
                id: "input_0".to_string(),
                name: None,
                purpose: None,
                format: jwt_format_map(),
                constraints: OpenID4VPPresentationDefinitionConstraint {
                    fields: vec![
                        OpenID4VPPresentationDefinitionConstraintField {
                            id: None,
                            name: None,
                            purpose: None,
                            path: vec!["$.credentialSchema.id".to_string()],
                            optional: None,
                            filter: Some(OpenID4VPPresentationDefinitionConstraintFieldFilter {
                                r#type: "string".to_string(),
                                r#const: credential_schema.schema_id.to_owned(),
                            }),
                            intent_to_retain: None,
                        },
                        OpenID4VPPresentationDefinitionConstraintField {
                            id: Some(claim_id),
                            name: None,
                            purpose: None,
                            path: vec!["$.vc.credentialSubject.string".to_string()],
                            optional: Some(false),
                            filter: None,
                            intent_to_retain: None,
                        },
                    ],
                    validity_credential_nbf: None,
                    limit_disclosure: None,
                },
            }],
        }),
        client_id: "client_id".to_string(),
        client_id_scheme: Some(ClientIdScheme::RedirectUri),
        response_uri: None,
    };
    let interaction_data_serialized = serde_json::to_vec(&interaction_data).unwrap();
    let now = OffsetDateTime::now_utc();
    let interaction = Interaction {
        id: interaction_id,
        created_date: now,
        last_modified: now,
        data: Some(interaction_data_serialized),
        organisation: None,
        nonce_id: None,
        interaction_type: InteractionType::Verification,
        expires_at: None,
    };

    let interaction_id_copy = interaction_id.to_owned();
    proof_repository
        .expect_get_proof_by_interaction_id()
        .withf(move |_interaction_id, _| {
            assert_eq!(*_interaction_id, interaction_id_copy);
            true
        })
        .once()
        .return_once(move |_, _| {
            Ok(Some(Proof {
                id: proof_id,
                verifier_identifier: Some(Identifier {
                    did: Some(Did {
                        did: verifier_did,
                        ..dummy_did()
                    }),
                    ..dummy_identifier()
                }),
                state: ProofStateEnum::Pending,
                schema: Some(ProofSchema {
                    input_schemas: Some(vec![ProofInputSchema {
                        validity_constraint: None,
                        claim_schemas: Some(vec![
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
                        ]),
                        credential_schema: Some(credential_schema),
                    }]),
                    organisation: Some(dummy_organisation(None)),
                    ..dummy_proof_schema()
                }),
                interaction: Some(interaction),
                ..dummy_proof_with_protocol("OPENID4VP_FINAL1")
            }))
        });

    proof_repository
        .expect_update_proof()
        .withf(move |_proof_id, _, _| {
            assert_eq!(_proof_id, &proof_id);
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
        .returning(move |_| Some(blob_storage.clone()));

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
            submission_data: VpSubmissionData::Pex(PexSubmission {
                vp_token: vec!["vp_token".to_string()],
                presentation_submission: PresentationSubmissionMappingDTO {
                    id: "25f5a42c-6850-49a0-b842-c7b2411021a5".to_string(),
                    definition_id: interaction_id.to_string(),
                    descriptor_map: vec![PresentationSubmissionDescriptorDTO {
                        id: "input_0".to_string(),
                        format: "jwt_vp_json".to_string(),
                        path: "$".to_string(),
                        path_nested: Some(NestedPresentationSubmissionDescriptorDTO {
                            format: "jwt_vc_json".to_string(),
                            path: "$.vp.verifiableCredential[0]".to_string(),
                        }),
                    }],
                },
            }),
            state: Some("a83dabc3-1601-4642-84ec-7a5ad8a70d36".parse().unwrap()),
        })
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        ServiceError::OpenID4VCError(OpenID4VCError::ValidationError(_))
    ));
}

#[tokio::test]
async fn test_get_client_metadata_success() {
    let mut proof_repository = MockProofRepository::default();
    let mut key_algorithm = MockKeyAlgorithm::default();
    let mut key_algorithm_provider = MockKeyAlgorithmProvider::default();
    let mut key_provider = MockKeyProvider::default();

    let now = OffsetDateTime::now_utc();
    let proof_id: ProofId = Uuid::new_v4().into();
    let verifier_key = Key {
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
        organisation: None,
    };
    let proof = Proof {
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
        claims: None,
        verifier_identifier: Some(Identifier {
            did: Some(Did {
                id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb966")
                    .unwrap()
                    .into(),
                created_date: now,
                last_modified: now,
                name: "did1".to_string(),
                organisation: Some(dummy_organisation(Some(
                    Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
                        .unwrap()
                        .into(),
                ))),
                did: "did:example:1".parse().unwrap(),
                did_type: DidType::Local,
                did_method: "KEY".to_string(),
                keys: Some(vec![RelatedKey {
                    role: KeyRole::KeyAgreement,
                    key: verifier_key.clone(),
                    reference: "1".to_string(),
                }]),
                deactivated: false,
                log: None,
            }),
            ..dummy_identifier()
        }),
        verifier_key: Some(verifier_key),
        verifier_certificate: None,
        interaction: None,
        profile: None,
        proof_blob_id: None,
        engagement: None,
    };
    {
        proof_repository
            .expect_get_proof()
            .times(1)
            .return_once(move |_, _, _| Ok(Some(proof)));

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
            .expect_key_algorithm_from_type()
            .return_once(|_| Some(Arc::new(key_algorithm)));
    }
    key_provider.expect_get_key_storage().return_once(|_| {
        let mut key_storage = MockKeyStorage::default();
        key_storage
            .expect_get_capabilities()
            .return_once(|| KeyStorageCapabilities {
                features: vec![],
                algorithms: vec![],
            });

        Some(Arc::new(key_storage))
    });
    let service = setup_service(Mocks {
        key_algorithm_provider,
        key_provider,
        proof_repository,
        config: generic_config().core,
        ..Default::default()
    });
    let result = service.get_client_metadata(proof_id).await.unwrap();
    assert_eq!(
        ClientMetadata {
            jwks: Some(ClientMetadataJwks {
                keys: vec![PublicJwk::Okp(PublicJwkEc {
                    alg: Some("ECDH-ES".to_string()),
                    r#use: Some(JwkUse::Encryption),
                    kid: Some("c322aa7f-9803-410d-b891-939b279fb965".to_string()),
                    crv: "123".to_string(),
                    x: "456".to_string(),
                    y: None,
                }),]
            }),
            vp_formats_supported: HashMap::from([
                (
                    "ldp_vc".to_string(),
                    PresentationFormat::W3CLdpAlgs(W3CLdpAlgs {
                        proof_type_values: vec!["DataIntegrityProof".to_string()],
                        cryptosuite_values: vec![
                            "bbs-2023".to_string(),
                            "ecdsa-rdfc-2019".to_string(),
                            "eddsa-rdfc-2022".to_string(),
                        ],
                    })
                ),
                (
                    "mso_mdoc".to_string(),
                    PresentationFormat::MdocAlgs(MdocAlgs {
                        issuerauth_alg_values: vec![-7, -8, -9, -19],
                        deviceauth_alg_values: vec![-7, -8, -9, -19],
                    })
                ),
                (
                    "dc+sd-jwt".to_string(),
                    PresentationFormat::SdJwtVcAlgs(SdJwtVcAlgs {
                        sd_jwt_alg_values: vec!["EdDSA".to_string(), "ES256".to_string()],
                        kb_jwt_alg_values: vec!["EdDSA".to_string(), "ES256".to_string()],
                    })
                ),
                (
                    "jwt_vc_json".to_string(),
                    PresentationFormat::W3CJwtAlgs(W3CJwtAlgs {
                        alg_values: vec!["EdDSA".to_string(), "ES256".to_string()]
                    })
                ),
            ]),
            encrypted_response_enc_values_supported: Some(vec![
                EncryptionAlgorithm::A256GCM,
                EncryptionAlgorithm::A128CBCHS256
            ]),
            ..Default::default()
        },
        result
    );
}
