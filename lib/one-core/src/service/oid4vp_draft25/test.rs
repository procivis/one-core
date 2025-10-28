use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use one_dto_mapper::try_convert_inner;
use serde_json::json;
use shared_types::{DidValue, ProofId};
use similar_asserts::assert_eq;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::OID4VPDraft25Service;
use crate::config::core_config::{CoreConfig, VerificationProtocolType};
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential_schema::{CredentialSchema, LayoutType};
use crate::model::did::{Did, DidType, KeyRole, RelatedKey};
use crate::model::identifier::Identifier;
use crate::model::interaction::{Interaction, InteractionType};
use crate::model::key::{JwkUse, Key, PublicKeyJwk, PublicKeyJwkEllipticData};
use crate::model::proof::{Proof, ProofRole, ProofStateEnum};
use crate::model::proof_schema::{ProofInputClaimSchema, ProofInputSchema, ProofSchema};
use crate::proto::certificate_validator::MockCertificateValidator;
use crate::provider::blob_storage_provider::{MockBlobStorage, MockBlobStorageProvider};
use crate::provider::credential_formatter::MockCredentialFormatter;
use crate::provider::credential_formatter::model::{
    CredentialStatus, CredentialSubject, DetailCredential, FormatterCapabilities, IdentifierDetails,
};
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::did_method::model::{DidDocument, DidVerificationMethod};
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::key_algorithm::MockKeyAlgorithm;
use crate::provider::key_algorithm::key::{
    KeyHandle, MockSignaturePublicKeyHandle, SignatureKeyHandle,
};
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_storage::MockKeyStorage;
use crate::provider::key_storage::model::{KeySecurity, KeyStorageCapabilities};
use crate::provider::key_storage::provider::MockKeyProvider;
use crate::provider::presentation_formatter::MockPresentationFormatter;
use crate::provider::presentation_formatter::model::ExtractedPresentation;
use crate::provider::presentation_formatter::provider::MockPresentationFormatterProvider;
use crate::provider::revocation::MockRevocationMethod;
use crate::provider::revocation::model::CredentialRevocationState;
use crate::provider::revocation::provider::MockRevocationMethodProvider;
use crate::provider::verification_protocol::openid4vp::error::OpenID4VCError;
use crate::provider::verification_protocol::openid4vp::model::*;
use crate::repository::certificate_repository::MockCertificateRepository;
use crate::repository::credential_repository::MockCredentialRepository;
use crate::repository::did_repository::MockDidRepository;
use crate::repository::identifier_repository::MockIdentifierRepository;
use crate::repository::key_repository::MockKeyRepository;
use crate::repository::proof_repository::MockProofRepository;
use crate::repository::validity_credential_repository::MockValidityCredentialRepository;
use crate::service::error::ServiceError;
use crate::service::key::dto::{PublicKeyJwkDTO, PublicKeyJwkEllipticDataDTO};
use crate::service::test_utilities::*;

#[derive(Default)]
struct Mocks {
    pub credential_repository: MockCredentialRepository,
    pub proof_repository: MockProofRepository,
    pub key_repository: MockKeyRepository,
    pub key_provider: MockKeyProvider,
    pub config: CoreConfig,
    pub did_repository: MockDidRepository,
    pub identifier_repository: MockIdentifierRepository,
    pub credential_formatter_provider: MockCredentialFormatterProvider,
    pub presentation_formatter_provider: MockPresentationFormatterProvider,
    pub did_method_provider: MockDidMethodProvider,
    pub key_algorithm_provider: MockKeyAlgorithmProvider,
    pub revocation_method_provider: MockRevocationMethodProvider,
    pub validity_credential_repository: MockValidityCredentialRepository,
    pub certificate_validator: MockCertificateValidator,
    pub certificate_repository: MockCertificateRepository,
    pub blob_storage_provider: MockBlobStorageProvider,
}

#[allow(clippy::too_many_arguments)]
fn setup_service(mocks: Mocks) -> OID4VPDraft25Service {
    OID4VPDraft25Service::new(
        Arc::new(mocks.credential_repository),
        Arc::new(mocks.proof_repository),
        Arc::new(mocks.key_repository),
        Arc::new(mocks.key_provider),
        Arc::new(mocks.config),
        Arc::new(mocks.did_repository),
        Arc::new(mocks.identifier_repository),
        Arc::new(mocks.credential_formatter_provider),
        Arc::new(mocks.presentation_formatter_provider),
        Arc::new(mocks.did_method_provider),
        Arc::new(mocks.key_algorithm_provider),
        Arc::new(mocks.revocation_method_provider),
        Arc::new(mocks.validity_credential_repository),
        Arc::new(mocks.certificate_validator),
        Arc::new(mocks.certificate_repository),
        Arc::new(mocks.blob_storage_provider),
    )
}

fn jwt_format_map() -> HashMap<String, OpenID4VpPresentationFormat> {
    HashMap::from([(
        "jwt_vc_json".to_string(),
        OpenID4VpPresentationFormat::GenericAlgList(OpenID4VPAlgs {
            alg: vec!["EdDSA".to_string(), "ES256".to_string()],
        }),
    )])
}

#[tokio::test]
async fn test_presentation_definition_success() {
    let mut proof_repository = MockProofRepository::default();

    let proof_id: ProofId = Uuid::new_v4().into();

    let interaction_data = serde_json::to_vec(&OpenID4VPVerifierInteractionContent {
        nonce: "nonce".to_string(),
        encryption_key: None,
        dcql_query: None,
        presentation_definition: Some(OpenID4VPPresentationDefinition {
            id: Uuid::new_v4().to_string(),
            input_descriptors: vec![OpenID4VPPresentationDefinitionInputDescriptor {
                id: "123".to_string(),
                name: None,
                purpose: None,
                format: jwt_format_map(),
                constraints: OpenID4VPPresentationDefinitionConstraint {
                    validity_credential_nbf: None,
                    fields: vec![OpenID4VPPresentationDefinitionConstraintField {
                        id: Some(Uuid::new_v4().into()),
                        name: None,
                        purpose: None,
                        path: vec!["123".to_string()],
                        optional: Some(false),
                        filter: None,
                        intent_to_retain: None,
                    }],
                    limit_disclosure: None,
                },
            }],
        }),
        client_id: "client_id".to_string(),
        client_id_scheme: None,
        response_uri: None,
    })
    .unwrap();

    {
        let now = OffsetDateTime::now_utc();
        proof_repository
            .expect_get_proof()
            .once()
            .return_once(move |_, _| {
                Ok(Some(Proof {
                    id: proof_id.to_owned(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    protocol: "OPENID4VP_DRAFT25".to_string(),
                    transport: "HTTP".to_string(),
                    redirect_uri: None,
                    state: ProofStateEnum::Pending,
                    role: ProofRole::Verifier,
                    requested_date: Some(get_dummy_date()),
                    completed_date: None,
                    profile: None,
                    proof_blob_id: None,
                    engagement: None,
                    schema: Some(ProofSchema {
                        id: Uuid::default().into(),
                        created_date: now,
                        imported_source_url: Some("CORE_URL".to_string()),
                        last_modified: now,
                        deleted_at: None,
                        name: "test".to_string(),
                        expire_duration: 0,
                        organisation: None,
                        input_schemas: Some(vec![ProofInputSchema {
                            validity_constraint: Some(100),
                            claim_schemas: Some(vec![ProofInputClaimSchema {
                                schema: ClaimSchema {
                                    id: Uuid::from_str("2fa85f64-5717-4562-b3fc-2c963f66afa6")
                                        .unwrap()
                                        .into(),
                                    key: "Key".to_owned(),
                                    data_type: "STRING".to_owned(),
                                    created_date: get_dummy_date(),
                                    last_modified: get_dummy_date(),
                                    array: false,
                                    metadata: false,
                                },
                                required: true,
                                order: 0,
                            }]),
                            credential_schema: Some(CredentialSchema {
                                id: Uuid::from_str("3fa85f64-5717-4562-b3fc-2c963f66afa6")
                                    .unwrap()
                                    .into(),
                                imported_source_url: "CORE_URL".to_string(),
                                deleted_at: None,
                                created_date: get_dummy_date(),
                                last_modified: get_dummy_date(),
                                name: "Credential1".to_owned(),
                                format: "JWT".to_owned(),
                                revocation_method: "NONE".to_owned(),
                                wallet_storage_type: None,
                                claim_schemas: None,
                                organisation: None,
                                layout_type: LayoutType::Card,
                                layout_properties: None,
                                schema_id: "CredentialSchemaId".to_owned(),
                                allow_suspension: true,
                            }),
                        }]),
                    }),
                    claims: None,
                    verifier_identifier: None,
                    holder_identifier: None,
                    verifier_key: None,
                    verifier_certificate: None,
                    interaction: Some(Interaction {
                        id: Uuid::new_v4(),
                        created_date: get_dummy_date(),
                        last_modified: get_dummy_date(),
                        data: Some(interaction_data),
                        organisation: None,
                        nonce_id: None,
                        interaction_type: InteractionType::Verification,
                    }),
                }))
            });
    }

    let service = setup_service(Mocks {
        proof_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.presentation_definition(proof_id).await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_submit_proof_failed_credential_suspended() {
    let proof_id: ProofId = Uuid::new_v4().into();
    let verifier_did = "did:verifier:123".parse().unwrap();
    let holder_did: DidValue = "did:holder:123".parse().unwrap();
    let issuer_did: DidValue = "did:issuer:123".parse().unwrap();

    let mut proof_repository = MockProofRepository::new();

    let interaction_id = Uuid::parse_str("a83dabc3-1601-4642-84ec-7a5ad8a70d36").unwrap();

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
        id: interaction_id.to_owned(),
        created_date: now,
        last_modified: now,
        data: Some(interaction_data_serialized),
        organisation: None,
        nonce_id: None,
        interaction_type: InteractionType::Verification,
    };

    let interaction_id_copy = interaction_id.to_owned();
    let holder_did_clone = holder_did.clone();
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
                holder_identifier: Some(Identifier {
                    did: Some(Did {
                        did: holder_did_clone,
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
                ..dummy_proof_with_protocol("OPENID4VP_DRAFT25")
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

    let mut credential_formatter = MockCredentialFormatter::new();
    let mut presentation_formatter = MockPresentationFormatter::new();

    let holder_did_clone = holder_did.clone();
    let issuer_did_clone = issuer_did.clone();
    credential_formatter
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
                issuer: IdentifierDetails::Did(issuer_did_clone.to_owned()),
                subject: Some(IdentifierDetails::Did(holder_did_clone.to_owned())),
                claims: CredentialSubject {
                    claims: try_convert_inner(HashMap::from([
                        ("unknown_key".to_string(), json!("unknown_key_value")),
                        ("required_key".to_string(), json!("required_key_value")),
                    ]))
                    .unwrap(),
                    id: None,
                },
                status: vec![],
                credential_schema: None,
            })
        });

    let holder_did_clone = holder_did.clone();
    let nonce_clone = nonce.clone();
    presentation_formatter
        .expect_extract_presentation_unverified()
        .once()
        .returning(move |_, _| {
            Ok(ExtractedPresentation {
                id: Some("presentation id".to_string()),
                issued_at: Some(OffsetDateTime::now_utc()),
                expires_at: Some(OffsetDateTime::now_utc() + Duration::days(10)),
                issuer: Some(IdentifierDetails::Did(holder_did_clone.to_owned())),
                nonce: Some(nonce_clone.to_owned()),
                credentials: vec!["credential".to_string()],
            })
        });

    let holder_did_clone = holder_did.clone();
    let nonce_clone = nonce.clone();
    presentation_formatter
        .expect_extract_presentation()
        .once()
        .returning(move |_, _, _| {
            Ok(ExtractedPresentation {
                id: Some("presentation id".to_string()),
                issued_at: Some(OffsetDateTime::now_utc()),
                expires_at: Some(OffsetDateTime::now_utc() + Duration::days(10)),
                issuer: Some(IdentifierDetails::Did(holder_did_clone.to_owned())),
                nonce: Some(nonce_clone.to_owned()),
                credentials: vec!["credential".to_string()],
            })
        });
    credential_formatter.expect_get_leeway().returning(|| 10);
    presentation_formatter.expect_get_leeway().returning(|| 10);
    let issuer_did_clone = issuer_did.clone();
    credential_formatter
        .expect_extract_credentials()
        .once()
        .returning(move |_, _, _, _| {
            Ok(DetailCredential {
                id: None,
                issuance_date: None,
                valid_from: Some(OffsetDateTime::now_utc()),
                valid_until: Some(OffsetDateTime::now_utc() + Duration::days(10)),
                update_at: None,
                invalid_before: Some(OffsetDateTime::now_utc()),
                issuer: IdentifierDetails::Did(issuer_did_clone.to_owned()),
                subject: Some(IdentifierDetails::Did(holder_did.to_owned())),
                claims: CredentialSubject {
                    claims: try_convert_inner(HashMap::from([
                        ("unknown_key".to_string(), json!("unknown_key_value")),
                        ("required_key".to_string(), json!("required_key_value")),
                    ]))
                    .unwrap(),
                    id: None,
                },
                status: vec![CredentialStatus {
                    id: Some("did:status:test".parse().unwrap()),
                    r#type: "".to_string(),
                    status_purpose: None,
                    additional_fields: Default::default(),
                }],
                credential_schema: None,
            })
        });

    let formatter = Arc::new(credential_formatter);
    let presentation_formatter = Arc::new(presentation_formatter);

    let mut credential_formatter_provider = MockCredentialFormatterProvider::new();
    let mut presentation_formatter_provider = MockPresentationFormatterProvider::new();

    presentation_formatter_provider
        .expect_get_presentation_formatter()
        .times(2)
        .returning(move |_| Some(presentation_formatter.clone()));

    credential_formatter_provider
        .expect_get_credential_formatter()
        .times(2)
        .returning(move |_| Some(formatter.clone()));

    let mut revocation_method = MockRevocationMethod::new();
    revocation_method
        .expect_check_credential_revocation_status()
        .once()
        .return_once(|_, _, _, _| {
            Ok(CredentialRevocationState::Suspended {
                suspend_end_date: None,
            })
        });

    let mut revocation_method_provider = MockRevocationMethodProvider::new();
    revocation_method_provider
        .expect_get_revocation_method_by_status_type()
        .once()
        .return_once(|_| Some((Arc::new(revocation_method), "".to_string())));

    let mut blob_storage = MockBlobStorage::new();
    blob_storage.expect_create().returning(|_| Ok(()));

    let blob_storage = Arc::new(blob_storage);
    let mut blob_storage_provider = MockBlobStorageProvider::new();
    blob_storage_provider
        .expect_get_blob_storage()
        .returning(move |_| Some(blob_storage.clone()));

    let service = setup_service(Mocks {
        proof_repository,
        credential_formatter_provider,
        presentation_formatter_provider,
        revocation_method_provider,
        blob_storage_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let vp_token = "vp_token";

    let err = service
        .direct_post(OpenID4VPDirectPostRequestDTO {
            submission_data: VpSubmissionData::Pex(PexSubmission {
                vp_token: vp_token.to_string(),
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
async fn test_submit_proof_failed_incapable_holder_did_method() {
    let proof_id: ProofId = Uuid::new_v4().into();
    let verifier_did = "did:verifier:123".parse().unwrap();
    let holder_did: DidValue = "did:holder:123".parse().unwrap();
    let subject_did: DidValue = "did:subject:123".parse().unwrap();
    let issuer_did: DidValue = "did:issuer:123".parse().unwrap();

    let mut proof_repository = MockProofRepository::new();

    let interaction_id = Uuid::parse_str("a83dabc3-1601-4642-84ec-7a5ad8a70d36").unwrap();

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
        id: interaction_id.to_owned(),
        created_date: now,
        last_modified: now,
        data: Some(interaction_data_serialized),
        organisation: None,
        nonce_id: None,
        interaction_type: InteractionType::Verification,
    };

    let interaction_id_copy = interaction_id.to_owned();
    let holder_did_clone = holder_did.clone();
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
                holder_identifier: Some(Identifier {
                    did: Some(Did {
                        did: holder_did_clone,
                        did_method: "MDL".to_string(),
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
                ..dummy_proof_with_protocol("OPENID4VP_DRAFT25")
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

    let mut credential_formatter = MockCredentialFormatter::new();
    let mut presentation_formatter = MockPresentationFormatter::new();

    let issuer_did_clone = issuer_did.clone();
    let subject_did_clone = subject_did.clone();
    credential_formatter
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
                issuer: IdentifierDetails::Did(issuer_did_clone.to_owned()),
                subject: Some(IdentifierDetails::Did(subject_did_clone.to_owned())),
                claims: CredentialSubject {
                    claims: try_convert_inner(HashMap::from([
                        ("unknown_key".to_string(), json!("unknown_key_value")),
                        ("required_key".to_string(), json!("required_key_value")),
                    ]))
                    .unwrap(),
                    id: None,
                },
                status: vec![],
                credential_schema: None,
            })
        });

    let holder_did_clone = holder_did.clone();
    let nonce_clone = nonce.clone();
    presentation_formatter
        .expect_extract_presentation_unverified()
        .once()
        .returning(move |_, _| {
            Ok(ExtractedPresentation {
                id: Some("presentation id".to_string()),
                issued_at: Some(OffsetDateTime::now_utc()),
                expires_at: Some(OffsetDateTime::now_utc() + Duration::days(10)),
                issuer: Some(IdentifierDetails::Did(holder_did_clone.to_owned())),
                nonce: Some(nonce_clone.to_owned()),
                credentials: vec!["credential".to_string()],
            })
        });

    let holder_did_clone = holder_did.clone();
    let nonce_clone = nonce.clone();
    presentation_formatter
        .expect_extract_presentation()
        .once()
        .returning(move |_, _, _| {
            Ok(ExtractedPresentation {
                id: Some("presentation id".to_string()),
                issued_at: Some(OffsetDateTime::now_utc()),
                expires_at: Some(OffsetDateTime::now_utc() + Duration::days(10)),
                issuer: Some(IdentifierDetails::Did(holder_did_clone.to_owned())),
                nonce: Some(nonce_clone.to_owned()),
                credentials: vec!["credential".to_string()],
            })
        });
    credential_formatter.expect_get_leeway().returning(|| 10);
    presentation_formatter.expect_get_leeway().returning(|| 10);
    let issuer_did_clone = issuer_did.clone();
    credential_formatter
        .expect_extract_credentials()
        .once()
        .returning(move |_, _, _, _| {
            Ok(DetailCredential {
                id: None,
                issuance_date: None,
                valid_from: Some(OffsetDateTime::now_utc()),
                valid_until: Some(OffsetDateTime::now_utc() + Duration::days(10)),
                update_at: None,
                invalid_before: Some(OffsetDateTime::now_utc()),
                issuer: IdentifierDetails::Did(issuer_did_clone.to_owned()),
                subject: Some(IdentifierDetails::Did(subject_did.to_owned())),
                claims: CredentialSubject {
                    claims: try_convert_inner(HashMap::from([
                        ("unknown_key".to_string(), json!("unknown_key_value")),
                        ("required_key".to_string(), json!("required_key_value")),
                    ]))
                    .unwrap(),
                    id: None,
                },
                status: vec![CredentialStatus {
                    id: Some("did:status:test".parse().unwrap()),
                    r#type: "".to_string(),
                    status_purpose: None,
                    additional_fields: Default::default(),
                }],
                credential_schema: None,
            })
        });
    credential_formatter
        .expect_get_capabilities()
        .returning(|| FormatterCapabilities {
            features: vec![],
            selective_disclosure: vec![],
            issuance_did_methods: vec![],
            issuance_exchange_protocols: vec![],
            proof_exchange_protocols: vec![],
            revocation_methods: vec![],
            signing_key_algorithms: vec![],
            verification_key_algorithms: vec![],
            verification_key_storages: vec![],
            datatypes: vec![],
            allowed_schema_ids: vec![],
            forbidden_claim_names: vec![],
            issuance_identifier_types: vec![],
            verification_identifier_types: vec![],
            holder_identifier_types: vec![],
            holder_key_algorithms: vec![],
            holder_did_methods: vec![],
        });

    let formatter = Arc::new(credential_formatter);
    let presentation_formatter = Arc::new(presentation_formatter);

    let mut credential_formatter_provider = MockCredentialFormatterProvider::new();
    let mut presentation_formatter_provider = MockPresentationFormatterProvider::new();

    presentation_formatter_provider
        .expect_get_presentation_formatter()
        .times(2)
        .returning(move |_| Some(presentation_formatter.clone()));

    credential_formatter_provider
        .expect_get_credential_formatter()
        .times(2)
        .returning(move |_| Some(formatter.clone()));

    let mut revocation_method = MockRevocationMethod::new();
    revocation_method
        .expect_check_credential_revocation_status()
        .once()
        .return_once(|_, _, _, _| Ok(CredentialRevocationState::Valid));

    let mut revocation_method_provider = MockRevocationMethodProvider::new();
    revocation_method_provider
        .expect_get_revocation_method_by_status_type()
        .once()
        .return_once(|_| Some((Arc::new(revocation_method), "".to_string())));

    let mut did_method_provider = MockDidMethodProvider::new();
    did_method_provider.expect_resolve().returning(|did| {
        Ok(DidDocument {
            context: json!({}),
            id: did.to_owned(),
            verification_method: vec![DidVerificationMethod {
                id: "did-vm-id".to_string(),
                r#type: "did-vm-type".to_string(),
                controller: "did-vm-controller".to_string(),
                public_key_jwk: PublicKeyJwk::Ec(PublicKeyJwkEllipticData {
                    alg: None,
                    r#use: None,
                    kid: None,
                    crv: "P-256".to_string(),
                    x: Base64UrlSafeNoPadding::encode_to_string("xabc").unwrap(),
                    y: Some(Base64UrlSafeNoPadding::encode_to_string("yabc").unwrap()),
                }),
            }],
            authentication: None,
            assertion_method: None,
            key_agreement: None,
            capability_invocation: None,
            capability_delegation: None,
            also_known_as: None,
            service: None,
        })
    });

    let mut blob_storage = MockBlobStorage::new();
    blob_storage.expect_create().returning(|_| Ok(()));

    let blob_storage = Arc::new(blob_storage);
    let mut blob_storage_provider = MockBlobStorageProvider::new();
    blob_storage_provider
        .expect_get_blob_storage()
        .returning(move |_| Some(blob_storage.clone()));

    let service = setup_service(Mocks {
        proof_repository,
        credential_formatter_provider,
        presentation_formatter_provider,
        revocation_method_provider,
        did_method_provider,
        blob_storage_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let vp_token = "vp_token";

    let err = service
        .direct_post(OpenID4VPDirectPostRequestDTO {
            submission_data: VpSubmissionData::Pex(PexSubmission {
                vp_token: vp_token.to_string(),
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
        ServiceError::OpenID4VCError(OpenID4VCError::ValidationError(e)) if e == "Unsupported holder DID method: subject"));
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
        protocol: VerificationProtocolType::OpenId4VpDraft25.to_string(),
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
        holder_identifier: None,
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
            .return_once(move |_, _| Ok(Some(proof)));

        key_algorithm
            .expect_reconstruct_key()
            .return_once(|_, _, _| {
                let mut key_handle = MockSignaturePublicKeyHandle::default();
                key_handle.expect_as_jwk().return_once(|| {
                    Ok(PublicKeyJwk::Okp(PublicKeyJwkEllipticData {
                        alg: None,
                        r#use: Some(JwkUse::Encryption),
                        kid: None,
                        crv: "123".to_string(),
                        x: "456".to_string(),
                        y: None,
                    }))
                });
                Ok(KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(
                    Arc::new(key_handle),
                )))
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
                security: vec![KeySecurity::Software],
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
        OpenID4VPDraftClientMetadata {
            jwks: Some(OpenID4VPClientMetadataJwks {
                keys: vec![OpenID4VPClientMetadataJwkDTO {
                    key_id: "c322aa7f-9803-410d-b891-939b279fb965"
                        .parse::<Uuid>()
                        .unwrap()
                        .into(),
                    jwk: PublicKeyJwkDTO::Okp(PublicKeyJwkEllipticDataDTO {
                        alg: None,
                        r#use: Some("enc".to_string()),
                        kid: None,
                        crv: "123".to_string(),
                        x: "456".to_string(),
                        y: None,
                    }),
                }]
            }),
            vp_formats: HashMap::from([
                (
                    "jwt_vp_json".to_string(),
                    OpenID4VpPresentationFormat::GenericAlgList(OpenID4VPAlgs {
                        alg: vec!["EdDSA".to_string(), "ES256".to_string()]
                    })
                ),
                (
                    "ldp_vp".to_string(),
                    OpenID4VpPresentationFormat::LdpVcAlgs(LdpVcAlgs {
                        proof_type: vec!["DataIntegrityProof".to_string()],
                    })
                ),
                (
                    "vc+sd-jwt".to_string(),
                    OpenID4VpPresentationFormat::SdJwtVcAlgs(OpenID4VPVcSdJwtAlgs {
                        sd_jwt_alg_values: vec!["EdDSA".to_string(), "ES256".to_string()],
                        kb_jwt_alg_values: vec!["EdDSA".to_string(), "ES256".to_string()],
                    })
                ),
                (
                    "dc+sd-jwt".to_string(),
                    OpenID4VpPresentationFormat::SdJwtVcAlgs(OpenID4VPVcSdJwtAlgs {
                        sd_jwt_alg_values: vec!["EdDSA".to_string(), "ES256".to_string()],
                        kb_jwt_alg_values: vec!["EdDSA".to_string(), "ES256".to_string()],
                    })
                ),
                (
                    "jwt_vc_json".to_string(),
                    OpenID4VpPresentationFormat::GenericAlgList(OpenID4VPAlgs {
                        alg: vec!["EdDSA".to_string(), "ES256".to_string()]
                    })
                ),
                (
                    "mso_mdoc".to_string(),
                    OpenID4VpPresentationFormat::GenericAlgList(OpenID4VPAlgs {
                        alg: vec!["EdDSA".to_string(), "ES256".to_string()]
                    })
                ),
            ]),
            authorization_encrypted_response_alg: Some(
                AuthorizationEncryptedResponseAlgorithm::EcdhEs
            ),
            authorization_encrypted_response_enc: Some(
                AuthorizationEncryptedResponseContentEncryptionAlgorithm::A256GCM
            ),
            ..Default::default()
        },
        result
    );
}
