use std::collections::HashMap;
use std::sync::Arc;

use dcql::{CredentialFormat, CredentialMeta, CredentialQuery, DcqlQuery};
use maplit::hashmap;
use one_dto_mapper::try_convert_inner;
use serde_json::json;
use shared_types::{DidValue, ProofId};
use similar_asserts::assert_eq;
use standardized_types::openid4vp::{GenericAlgs, PresentationFormat};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::config::core_config::VerificationProtocolType;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential_schema::CredentialSchemaClaim;
use crate::model::did::Did;
use crate::model::identifier::Identifier;
use crate::model::interaction::{Interaction, InteractionType};
use crate::model::proof::{Proof, ProofStateEnum};
use crate::model::proof_schema::{ProofInputClaimSchema, ProofInputSchema, ProofSchema};
use crate::proto::certificate_validator::MockCertificateValidator;
use crate::proto::openid4vp_proof_validator::OpenId4VpProofValidator;
use crate::proto::openid4vp_proof_validator::validator::OpenId4VpProofValidatorProto;
use crate::provider::credential_formatter::MockCredentialFormatter;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{
    CredentialStatus, CredentialSubject, DetailCredential, IdentifierDetails,
};
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::presentation_formatter::MockPresentationFormatter;
use crate::provider::presentation_formatter::model::ExtractedPresentation;
use crate::provider::presentation_formatter::provider::MockPresentationFormatterProvider;
use crate::provider::revocation::MockRevocationMethod;
use crate::provider::revocation::error::RevocationError;
use crate::provider::revocation::model::RevocationState;
use crate::provider::revocation::provider::MockRevocationMethodProvider;
use crate::provider::verification_protocol::openid4vp::error::OpenID4VCError;
use crate::provider::verification_protocol::openid4vp::model::{
    DcqlSubmission, NestedPresentationSubmissionDescriptorDTO, OpenID4VPPresentationDefinition,
    OpenID4VPPresentationDefinitionConstraint, OpenID4VPPresentationDefinitionConstraintField,
    OpenID4VPPresentationDefinitionConstraintFieldFilter,
    OpenID4VPPresentationDefinitionInputDescriptor, OpenID4VPVerifierInteractionContent,
    PexSubmission, PresentationSubmissionDescriptorDTO, PresentationSubmissionMappingDTO,
    SubmissionRequestData, VpSubmissionData,
};
use crate::service::test_utilities::{
    dummy_claim_schema, dummy_credential_schema, dummy_did, dummy_identifier, dummy_organisation,
    dummy_proof_schema, dummy_proof_with_protocol, generic_config, generic_formatter_capabilities,
};

#[derive(Default)]
struct Mocks {
    did_method_provider: MockDidMethodProvider,
    credential_formatter_provider: MockCredentialFormatterProvider,
    presentation_formatter_provider: MockPresentationFormatterProvider,
    key_algorithm_provider: MockKeyAlgorithmProvider,
    revocation_method_provider: MockRevocationMethodProvider,
    certificate_validator: MockCertificateValidator,
}

struct TestData {
    issuer_did: DidValue,
    interaction_data: OpenID4VPVerifierInteractionContent,
    proof: Proof,
    mock_data: MockData,
}

#[derive(Default)]
struct MockData {
    presentation_extraction_unverified: Option<Result<ExtractedPresentation, FormatterError>>,
    presentation_extraction: Option<Result<ExtractedPresentation, FormatterError>>,
    credential_extraction_unverified: Option<Result<DetailCredential, FormatterError>>,
    credential_extraction: Option<Result<DetailCredential, FormatterError>>,
    revocation_check: Option<Result<RevocationState, RevocationError>>,
}

fn setup_proto(mocks: Mocks) -> OpenId4VpProofValidatorProto {
    OpenId4VpProofValidatorProto::new(
        Arc::new(generic_config().core),
        Arc::new(mocks.did_method_provider),
        Arc::new(mocks.credential_formatter_provider),
        Arc::new(mocks.presentation_formatter_provider),
        Arc::new(mocks.key_algorithm_provider),
        Arc::new(mocks.revocation_method_provider),
        Arc::new(mocks.certificate_validator),
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
async fn test_validate_submission_success_pex() {
    let test_data = test_data(Some(dummy_presentation_definition()), None);
    let mocks = mocks_with_test_data(test_data.mock_data);
    let proto = setup_proto(mocks);

    let submission_data = SubmissionRequestData {
        submission_data: VpSubmissionData::Pex(PexSubmission {
            vp_token: vec!["vp_token".to_string()],
            presentation_submission: PresentationSubmissionMappingDTO {
                id: "25f5a42c-6850-49a0-b842-c7b2411021a5".to_string(),
                definition_id: Uuid::parse_str("a83dabc3-1601-4642-84ec-7a5ad8a70d36")
                    .unwrap()
                    .to_string(),
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
        state: "a83dabc3-1601-4642-84ec-7a5ad8a70d36".parse().unwrap(),
        mdoc_generated_nonce: None,
        encryption_key: None,
    };
    let result = proto
        .validate_submission(
            submission_data,
            test_data.proof,
            test_data.interaction_data,
            VerificationProtocolType::OpenId4VpDraft20,
        )
        .await
        .unwrap();
    assert_eq!(result.0.proved_claims.len(), 1);
    assert_eq!(result.0.proved_credentials.len(), 1);
    assert_eq!(
        result.0.proved_credentials.first().unwrap().issuer_details,
        IdentifierDetails::Did(test_data.issuer_did.to_owned())
    );
}

#[tokio::test]
async fn test_validate_submission_success_dcql() {
    let test_data = test_data(None, Some(dummy_dcql_query()));
    let mocks = mocks_with_test_data(test_data.mock_data);
    let proto = setup_proto(mocks);

    let submission_data = SubmissionRequestData {
        submission_data: VpSubmissionData::Dcql(DcqlSubmission {
            vp_token: hashmap! {"a83dabc3-1601-4642-84ec-7a5ad8a70d36".to_string() => vec!["vp_token".to_string()]},
        }),
        state: "a83dabc3-1601-4642-84ec-7a5ad8a70d36".parse().unwrap(),
        mdoc_generated_nonce: None,
        encryption_key: None,
    };
    let result = proto
        .validate_submission(
            submission_data,
            test_data.proof,
            test_data.interaction_data,
            VerificationProtocolType::OpenId4VpFinal1_0,
        )
        .await
        .unwrap();
    assert_eq!(result.0.proved_claims.len(), 1);
    assert_eq!(result.0.proved_credentials.len(), 1);
    assert_eq!(
        result.0.proved_credentials.first().unwrap().issuer_details,
        IdentifierDetails::Did(test_data.issuer_did.to_owned())
    );
}

#[tokio::test]
async fn test_validate_submission_suspended() {
    let mut test_data = test_data(Some(dummy_presentation_definition()), None);
    test_data.mock_data.revocation_check = Some(Ok(RevocationState::Suspended {
        suspend_end_date: None,
    }));
    let mocks = mocks_with_test_data(test_data.mock_data);
    let proto = setup_proto(mocks);

    let submission_data = SubmissionRequestData {
        submission_data: VpSubmissionData::Pex(PexSubmission {
            vp_token: vec!["vp_token".to_string()],
            presentation_submission: PresentationSubmissionMappingDTO {
                id: "25f5a42c-6850-49a0-b842-c7b2411021a5".to_string(),
                definition_id: Uuid::parse_str("a83dabc3-1601-4642-84ec-7a5ad8a70d36")
                    .unwrap()
                    .to_string(),
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
        state: "a83dabc3-1601-4642-84ec-7a5ad8a70d36".parse().unwrap(),
        mdoc_generated_nonce: None,
        encryption_key: None,
    };
    let result = proto
        .validate_submission(
            submission_data,
            test_data.proof,
            test_data.interaction_data,
            VerificationProtocolType::OpenId4VpDraft20,
        )
        .await;
    assert!(result.is_err())
}

#[tokio::test]
async fn test_validate_submission_suspended_dcql() {
    let mut test_data = test_data(None, Some(dummy_dcql_query()));
    test_data.mock_data.revocation_check = Some(Ok(RevocationState::Suspended {
        suspend_end_date: None,
    }));
    let mocks = mocks_with_test_data(test_data.mock_data);
    let proto = setup_proto(mocks);

    let submission_data = SubmissionRequestData {
        submission_data: VpSubmissionData::Dcql(DcqlSubmission {
            vp_token: hashmap! {"a83dabc3-1601-4642-84ec-7a5ad8a70d36".to_string() => vec!["vp_token".to_string()]},
        }),
        state: "a83dabc3-1601-4642-84ec-7a5ad8a70d36".parse().unwrap(),
        mdoc_generated_nonce: None,
        encryption_key: None,
    };
    let result = proto
        .validate_submission(
            submission_data,
            test_data.proof,
            test_data.interaction_data,
            VerificationProtocolType::OpenId4VpFinal1_0,
        )
        .await;
    assert!(result.is_err())
}

#[tokio::test]
async fn test_validate_submission_incompatible_did_method() {
    let mut test_data = test_data(None, Some(dummy_dcql_query()));
    test_data
        .mock_data
        .presentation_extraction_unverified
        .as_mut()
        .unwrap()
        .as_mut()
        .unwrap()
        .issuer = Some(IdentifierDetails::Did(
        "did:unsupported:123".parse().unwrap(),
    ));
    test_data
        .mock_data
        .presentation_extraction
        .as_mut()
        .unwrap()
        .as_mut()
        .unwrap()
        .issuer = Some(IdentifierDetails::Did(
        "did:unsupported:123".parse().unwrap(),
    ));
    let mocks = mocks_with_test_data(test_data.mock_data);
    let proto = setup_proto(mocks);

    let submission_data = SubmissionRequestData {
        submission_data: VpSubmissionData::Dcql(DcqlSubmission {
            vp_token: hashmap! {"a83dabc3-1601-4642-84ec-7a5ad8a70d36".to_string() => vec!["vp_token".to_string()]},
        }),
        state: "a83dabc3-1601-4642-84ec-7a5ad8a70d36".parse().unwrap(),
        mdoc_generated_nonce: None,
        encryption_key: None,
    };
    let err = proto
        .validate_submission(
            submission_data,
            test_data.proof,
            test_data.interaction_data,
            VerificationProtocolType::OpenId4VpFinal1_0,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err,OpenID4VCError::ValidationError(e) if e == "Unsupported holder DID method: holder")
    );
}

fn mocks_with_test_data(mock_data: MockData) -> Mocks {
    let mut mocks = Mocks::default();

    let mut presentation_formatter = MockPresentationFormatter::new();
    presentation_formatter.expect_get_leeway().returning(|| 10);
    if let Some(presentation_extraction) = mock_data.presentation_extraction_unverified {
        presentation_formatter
            .expect_extract_presentation_unverified()
            .return_once(move |_, _| presentation_extraction);
    }
    if let Some(presentation_extraction) = mock_data.presentation_extraction {
        presentation_formatter
            .expect_extract_presentation()
            .return_once(move |_, _, _| presentation_extraction);
    }

    let mut credential_formatter = MockCredentialFormatter::new();
    credential_formatter
        .expect_get_capabilities()
        .returning(generic_formatter_capabilities);
    credential_formatter.expect_get_leeway().returning(|| 10);
    if let Some(credential_extraction) = mock_data.credential_extraction_unverified {
        credential_formatter
            .expect_extract_credentials_unverified()
            .return_once(move |_, _| credential_extraction);
    }
    if let Some(credential_extraction) = mock_data.credential_extraction {
        credential_formatter
            .expect_extract_credentials()
            .return_once(move |_, _, _, _| credential_extraction);
    }
    let presentation_formatter = Arc::new(presentation_formatter);
    let presentation_formatter_clone = presentation_formatter.clone();
    mocks
        .presentation_formatter_provider
        .expect_get_presentation_formatter()
        .returning(move |_| Some(presentation_formatter_clone.clone()));
    mocks
        .presentation_formatter_provider
        .expect_get_presentation_formatter_by_type()
        .returning(move |_| Some(("JWT".to_string(), presentation_formatter.clone())));
    let credential_formatter = Arc::new(credential_formatter);
    let credential_formatter_clone = credential_formatter.clone();
    mocks
        .credential_formatter_provider
        .expect_get_credential_formatter()
        .returning(move |_| Some(credential_formatter_clone.clone()));
    mocks
        .credential_formatter_provider
        .expect_get_formatter_by_type()
        .returning(move |_| Some(("JWT".into(), credential_formatter.clone())));

    let mut revocation_method = MockRevocationMethod::new();
    if let Some(revocation_check) = mock_data.revocation_check {
        revocation_method
            .expect_check_credential_revocation_status()
            .once()
            .return_once(|_, _, _, _| revocation_check);
    }
    mocks
        .revocation_method_provider
        .expect_get_revocation_method_by_status_type()
        .once()
        .return_once(|_| Some((Arc::new(revocation_method), "".into())));
    mocks
}

fn dummy_presentation_definition() -> OpenID4VPPresentationDefinition {
    OpenID4VPPresentationDefinition {
        id: "a83dabc3-1601-4642-84ec-7a5ad8a70d36".to_string(),
        input_descriptors: vec![OpenID4VPPresentationDefinitionInputDescriptor {
            id: "input_0".to_string(),
            name: None,
            purpose: None,
            format: jwt_format_map(),
            constraints: OpenID4VPPresentationDefinitionConstraint {
                fields: vec![
                    OpenID4VPPresentationDefinitionConstraintField {
                        id: Some(Uuid::new_v4().into()),
                        name: None,
                        purpose: None,
                        path: vec!["$.credentialSchema.id".to_string()],
                        optional: None,
                        filter: Some(OpenID4VPPresentationDefinitionConstraintFieldFilter {
                            r#type: "string".to_string(),
                            r#const: "CredentialSchemaId".to_owned(),
                        }),
                        intent_to_retain: None,
                    },
                    OpenID4VPPresentationDefinitionConstraintField {
                        id: Some(Uuid::new_v4().into()),
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
    }
}

fn dummy_dcql_query() -> DcqlQuery {
    DcqlQuery {
        credentials: vec![CredentialQuery {
            id: "a83dabc3-1601-4642-84ec-7a5ad8a70d36".into(),
            format: CredentialFormat::JwtVc,
            meta: CredentialMeta::W3cVc {
                type_values: vec![vec!["CredentialSchemaId".to_string()]],
            },
            claims: None,
            claim_sets: None,
            trusted_authorities: None,
            multiple: false,
            require_cryptographic_holder_binding: false,
        }],
        credential_sets: None,
    }
}

fn test_data(
    presentation_definition: Option<OpenID4VPPresentationDefinition>,
    dcql_query: Option<DcqlQuery>,
) -> TestData {
    let issuer_did: DidValue = "did:issuer:123".parse().unwrap();
    let holder_did: DidValue = "did:holder:123".parse().unwrap();
    let verifier_did: DidValue = "did:verifier:123".parse().unwrap();
    let proof_id: ProofId = Uuid::new_v4().into();
    let mut credential_schema = dummy_credential_schema();
    credential_schema.id = "a83dabc3-1601-4642-84ec-7a5ad8a70d36".parse().unwrap();
    let nonce = "7QqBfOcEcydceH6ZrXtu9fhDCvXjtLBv".to_string();
    let interaction_data = OpenID4VPVerifierInteractionContent {
        nonce: nonce.to_owned(),
        encryption_key: None,
        dcql_query,
        presentation_definition,
        client_id: "client_id".to_string(),
        client_id_scheme: None,
        response_uri: None,
    };
    let interaction_data_serialized = serde_json::to_vec(&interaction_data).unwrap();
    let interaction = Interaction {
        id: Uuid::parse_str("a83dabc3-1601-4642-84ec-7a5ad8a70d36")
            .unwrap()
            .into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        data: Some(interaction_data_serialized),
        organisation: None,
        nonce_id: None,
        interaction_type: InteractionType::Verification,
        expires_at: None,
    };
    let claim_schema_required = ClaimSchema {
        key: "required_key".to_string(),
        ..dummy_claim_schema()
    };
    let claim_schema_optional = ClaimSchema {
        key: "optional_key".to_string(),
        ..dummy_claim_schema()
    };
    credential_schema.claim_schemas = Some(vec![
        CredentialSchemaClaim {
            schema: claim_schema_required.clone(),
            required: true,
        },
        CredentialSchemaClaim {
            schema: claim_schema_optional.clone(),
            required: false,
        },
    ]);
    let proof = Proof {
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
                        schema: claim_schema_required,
                        required: true,
                        order: 0,
                    },
                    ProofInputClaimSchema {
                        schema: claim_schema_optional,
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
        ..dummy_proof_with_protocol("OPENID4VP_DRAFT20")
    };

    let extracted_credential = DetailCredential {
        id: None,
        issuance_date: None,
        valid_from: Some(OffsetDateTime::now_utc()),
        valid_until: Some(OffsetDateTime::now_utc() + Duration::days(10)),
        update_at: None,
        invalid_before: Some(OffsetDateTime::now_utc()),
        issuer: IdentifierDetails::Did(issuer_did.to_owned()),
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
    };

    let extracted_presentation = ExtractedPresentation {
        id: Some("presentation id".to_string()),
        issued_at: Some(OffsetDateTime::now_utc()),
        expires_at: Some(OffsetDateTime::now_utc() + Duration::days(10)),
        issuer: Some(IdentifierDetails::Did(holder_did)),
        nonce: Some(nonce),
        credentials: vec!["credential".to_string()],
    };

    let mock_data = MockData {
        presentation_extraction_unverified: Some(Ok(extracted_presentation.clone())),
        presentation_extraction: Some(Ok(extracted_presentation)),
        credential_extraction_unverified: Some(Ok(extracted_credential.clone())),
        credential_extraction: Some(Ok(extracted_credential)),
        revocation_check: Some(Ok(RevocationState::Valid)),
    };
    TestData {
        issuer_did,
        interaction_data,
        proof,
        mock_data,
    }
}
