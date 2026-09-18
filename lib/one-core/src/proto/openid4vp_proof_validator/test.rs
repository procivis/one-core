use std::collections::HashMap;
use std::sync::Arc;

use indexmap::IndexMap;
use maplit::hashmap;
use one_dto_mapper::try_convert_inner;
use serde_json::json;
use shared_types::{DidValue, ProofId};
use similar_asserts::assert_eq;
use standardized_types::openid4vp::VpTokenResponse;
use standardized_types::openid4vp::dcql::{
    CredentialFormat, CredentialQuery, DcqlQuery, MsoMdocMeta,
};
use time::Duration;
use uuid::Uuid;

use crate::config::core_config::VerificationProtocolType;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::credential_schema_format_claim_schema::CredentialSchemaFormatClaimSchema;
use crate::model::did::Did;
use crate::model::identifier::{Identifier, IdentifierData};
use crate::model::interaction::{Interaction, InteractionType};
use crate::model::proof::{Proof, ProofStateEnum};
use crate::model::proof_schema::{ProofInputClaimSchema, ProofInputSchema, ProofSchema};
use crate::proto::certificate_validator::MockCertificateValidator;
use crate::proto::openid4vp_proof_validator::OpenId4VpProofValidator;
use crate::proto::openid4vp_proof_validator::validator::OpenId4VpProofValidatorProto;
use crate::provider::credential_formatter::MockCredentialFormatter;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{
    CredentialStatus, DetailCredential, IdentifierDetails,
};
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::presentation_formatter::MockPresentationFormatter;
use crate::provider::presentation_formatter::model::{
    ExtractedPresentation, PresentedTransactionData,
};
use crate::provider::presentation_formatter::provider::MockPresentationFormatterProvider;
use crate::provider::revocation::MockRevocationMethod;
use crate::provider::revocation::error::RevocationError;
use crate::provider::revocation::model::RevocationState;
use crate::provider::revocation::provider::MockRevocationMethodProvider;
use crate::provider::transaction_data::provider::MockTransactionDataProvider;
use crate::provider::transaction_data::{MockTransactionData, TransactionDataAuthorization};
use crate::provider::verification_protocol::openid4vp::error::OpenID4VCError;
use crate::provider::verification_protocol::openid4vp::model::{
    OpenID4VPVerifierInteractionContent, SubmissionRequestData, TransactionDataRequest,
    VpSubmissionData,
};
use crate::service::test_utilities::{
    dummy_claim_schema, dummy_credential_schema, dummy_dcql_query, dummy_did, dummy_identifier,
    dummy_organisation, dummy_proof_schema, dummy_proof_with_protocol,
    generic_formatter_capabilities,
};

#[derive(Default)]
struct Mocks {
    did_method_provider: MockDidMethodProvider,
    credential_formatter_provider: MockCredentialFormatterProvider,
    presentation_formatter_provider: MockPresentationFormatterProvider,
    key_algorithm_provider: MockKeyAlgorithmProvider,
    revocation_method_provider: MockRevocationMethodProvider,
    certificate_validator: MockCertificateValidator,
    transaction_data_provider: MockTransactionDataProvider,
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
        Arc::new(mocks.did_method_provider),
        Arc::new(mocks.credential_formatter_provider),
        Arc::new(mocks.presentation_formatter_provider),
        Arc::new(mocks.key_algorithm_provider),
        Arc::new(mocks.revocation_method_provider),
        Arc::new(mocks.certificate_validator),
        Arc::new(mocks.transaction_data_provider),
    )
}

#[tokio::test]
async fn test_validate_submission_success_dcql() {
    let test_data = test_data(dummy_dcql_query(true));
    let mocks = mocks_with_test_data(test_data.mock_data);
    let proto = setup_proto(mocks);

    let submission_data = SubmissionRequestData {
        submission_data: VpSubmissionData::Dcql(VpTokenResponse {
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
        result.0.proved_credentials[0]
            .credential
            .credential_format()
            .await
            .unwrap(),
        Some("format".into())
    );
    assert_eq!(
        result.0.proved_credentials.first().unwrap().issuer_details,
        IdentifierDetails::Did(test_data.issuer_did.to_owned())
    );
}

#[tokio::test]
async fn test_validate_submission_suspended_dcql() {
    let mut test_data = test_data(dummy_dcql_query(true));
    test_data.mock_data.revocation_check = Some(Ok(RevocationState::Suspended {
        suspend_end_date: None,
    }));
    let mocks = mocks_with_test_data(test_data.mock_data);
    let proto = setup_proto(mocks);

    let submission_data = SubmissionRequestData {
        submission_data: VpSubmissionData::Dcql(VpTokenResponse {
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
    let mut test_data = test_data(dummy_dcql_query(true));
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
        submission_data: VpSubmissionData::Dcql(VpTokenResponse {
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

fn base_credential_formatter() -> MockCredentialFormatter {
    let mut formatter = MockCredentialFormatter::new();
    formatter
        .expect_get_capabilities()
        .returning(generic_formatter_capabilities);
    formatter
        .expect_get_leeway()
        .return_const(Duration::seconds(10));
    formatter
}

fn setup_mocks(
    presentation_formatter: MockPresentationFormatter,
    credential_formatter: MockCredentialFormatter,
    revocation_method: Option<MockRevocationMethod>,
) -> Mocks {
    let mut mocks = Mocks::default();

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
        .returning(move |_| Ok(credential_formatter_clone.clone()));
    mocks
        .credential_formatter_provider
        .expect_get_formatter_by_type()
        .returning(move |_| Some(("JWT".into(), credential_formatter.clone())));

    if let Some(revocation_method) = revocation_method {
        mocks
            .revocation_method_provider
            .expect_get_revocation_method_by_status_type()
            .once()
            .return_once(|_| Some((Arc::new(revocation_method), "mock".into())));
    }

    mocks
}

fn mocks_with_test_data(mock_data: MockData) -> Mocks {
    let mut presentation_formatter = MockPresentationFormatter::new();
    presentation_formatter
        .expect_get_leeway()
        .return_const(Duration::seconds(10));
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

    let mut credential_formatter = base_credential_formatter();
    if let Some(credential_extraction) = mock_data.credential_extraction_unverified {
        credential_formatter
            .expect_extract_credentials_unverified()
            .return_once(move |_, _| credential_extraction);
    }
    if let Some(credential_extraction) = mock_data.credential_extraction {
        credential_formatter
            .expect_extract_credentials()
            .return_once(move |_, _, _| credential_extraction);
    }

    let revocation_method = mock_data.revocation_check.map(|check| {
        let mut rm = MockRevocationMethod::new();
        rm.expect_check_credential_revocation_status()
            .once()
            .return_once(|_, _, _, _| check);
        rm
    });

    setup_mocks(
        presentation_formatter,
        credential_formatter,
        revocation_method,
    )
}

fn test_data(dcql_query: DcqlQuery) -> TestData {
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
        presentation_definition: None,
        dcql_query: Some(dcql_query),
        client_id: "client_id".to_string(),
        client_id_scheme: None,
        response_uri: None,
        common: Default::default(),
    };
    let interaction_data_serialized = serde_json::to_vec(&interaction_data).unwrap();
    let interaction = Interaction {
        id: Uuid::parse_str("a83dabc3-1601-4642-84ec-7a5ad8a70d36")
            .unwrap()
            .into(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        data: Some(interaction_data_serialized),
        organisation: dummy_organisation(None).into(),
        interaction_type: InteractionType::Verification,
        expires_at: None,
        ecosystem: None,
        ecosystem_data: Default::default(),
    };
    let claim_schema_required = ClaimSchema {
        key: "required_key".to_string(),
        required: true,
        ..dummy_claim_schema()
    };
    let claim_schema_optional = ClaimSchema {
        key: "optional_key".to_string(),
        required: false,
        ..dummy_claim_schema()
    };
    let claim_schemas = vec![claim_schema_required.clone(), claim_schema_optional.clone()];

    let format_id = Uuid::new_v4().into();
    credential_schema.formats = vec![CredentialSchemaFormat {
        id: format_id,
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        credential_schema_id: credential_schema.id,
        format: "format".into(),
        ecosystem_schema_id: "CredentialSchemaId".to_owned(),
        claim_mappings: claim_schemas
            .iter()
            .map(|cs| CredentialSchemaFormatClaimSchema {
                id: Uuid::new_v4().into(),
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                credential_schema_format_id: format_id,
                claim_schema_id: cs.id,
                technical_key: cs.key.to_owned(),
                namespace: None,
            })
            .collect::<Vec<_>>()
            .into(),
    }]
    .into();
    credential_schema.claim_schemas = claim_schemas.into();

    let proof = Proof {
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
                    claim_schemas: vec![
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
                    ]
                    .into(),
                    credential_schema: credential_schema.into(),
                }]
                .into(),
                ..dummy_proof_schema()
            }
            .into(),
        ),
        interaction: Some(interaction.into()),
        ..dummy_proof_with_protocol("OPENID4VP_DRAFT20")
    };

    let extracted_credential = DetailCredential {
        issuance_date: None,
        valid_from: Some(crate::clock::now_utc()),
        valid_until: Some(crate::clock::now_utc() + Duration::days(10)),
        update_at: None,
        invalid_before: Some(crate::clock::now_utc()),
        issuer: IdentifierDetails::Did(issuer_did.to_owned()),
        subject: Some(IdentifierDetails::Did(holder_did.to_owned())),
        claims: try_convert_inner(HashMap::from([
            ("unknown_key".to_string(), json!("unknown_key_value")),
            ("required_key".to_string(), json!("required_key_value")),
        ]))
        .unwrap(),
        status: vec![CredentialStatus {
            id: Some("did:status:test".parse().unwrap()),
            r#type: "".to_string(),
            status_purpose: None,
            additional_fields: Default::default(),
        }],
    };

    let extracted_presentation = ExtractedPresentation {
        id: Some("presentation id".to_string()),
        issued_at: Some(crate::clock::now_utc()),
        expires_at: Some(crate::clock::now_utc() + Duration::days(10)),
        issuer: Some(IdentifierDetails::Did(holder_did)),
        nonce: Some(nonce),
        credentials: vec!["credential".into()],
        transaction_data: None,
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

#[tokio::test]
async fn test_validate_submission_dcql_no_holder_binding() {
    let mut test_data = test_data(dummy_dcql_query(false));
    // No VP extraction for bare credentials
    test_data.mock_data.presentation_extraction = None;
    test_data.mock_data.presentation_extraction_unverified = None;
    let mocks = mocks_with_test_data(test_data.mock_data);
    let proto = setup_proto(mocks);

    let submission_data = SubmissionRequestData {
        submission_data: VpSubmissionData::Dcql(VpTokenResponse {
            vp_token: hashmap! {"a83dabc3-1601-4642-84ec-7a5ad8a70d36".to_string() => vec!["bare_credential_token".to_string()]},
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

fn mdoc_dcql_query() -> DcqlQuery {
    DcqlQuery {
        credentials: vec![CredentialQuery {
            id: "a83dabc3-1601-4642-84ec-7a5ad8a70d36".into(),
            format: CredentialFormat::MsoMdoc(MsoMdocMeta {
                doctype_value: "org.iso.18013.5.1.mDL".to_string(),
            }),
            claims: None,
            claim_sets: None,
            trusted_authorities: None,
            multiple: false,
            require_cryptographic_holder_binding: true,
        }],
        credential_sets: None,
    }
}

fn qes_approval_evidence() -> IndexMap<String, IndexMap<String, ciborium::Value>> {
    IndexMap::from([(
        "org.cloudsignatureconsortium.dm.1".to_string(),
        IndexMap::from([(
            "qesApproval".to_string(),
            ciborium::Value::Bytes(vec![1, 2, 3]),
        )]),
    )])
}

fn transaction_data_request() -> TransactionDataRequest {
    TransactionDataRequest {
        r#type: "QES_APPROVAL".into(),
        credential_ids: vec!["a83dabc3-1601-4642-84ec-7a5ad8a70d36".into()],
        data: None,
        encoded: "encoded-transaction-data".to_string(),
    }
}

fn transaction_data_mocks(mocks: &mut Mocks) {
    let mut transaction_data = MockTransactionData::new();
    transaction_data
        .expect_prepare_transaction_data()
        .returning(|_, _| Ok("ZW5jb2RlZC1lbnRyeQ".to_string()));
    transaction_data
        .expect_verify_transaction_data()
        .returning(|_, _, _| Ok(TransactionDataAuthorization::Authorized));
    let transaction_data = Arc::new(transaction_data);
    mocks
        .transaction_data_provider
        .expect_get_transaction_data_by_name()
        .returning(move |_| Ok(transaction_data.clone()));
}

#[tokio::test]
async fn test_validate_submission_transaction_data_authorized() {
    let mut test_data = test_data(mdoc_dcql_query());
    test_data.interaction_data.common.transaction_data = vec![transaction_data_request()];
    test_data
        .mock_data
        .presentation_extraction
        .as_mut()
        .unwrap()
        .as_mut()
        .unwrap()
        .transaction_data = Some(PresentedTransactionData::DeviceSignedElements(
        qes_approval_evidence(),
    ));

    let mut mocks = mocks_with_test_data(test_data.mock_data);
    transaction_data_mocks(&mut mocks);
    let proto = setup_proto(mocks);

    let submission_data = SubmissionRequestData {
        submission_data: VpSubmissionData::Dcql(VpTokenResponse {
            vp_token: hashmap! {"a83dabc3-1601-4642-84ec-7a5ad8a70d36".to_string() => vec!["vp_token".to_string()]},
        }),
        state: "a83dabc3-1601-4642-84ec-7a5ad8a70d36".parse().unwrap(),
        mdoc_generated_nonce: None,
        encryption_key: None,
    };
    proto
        .validate_submission(
            submission_data,
            test_data.proof,
            test_data.interaction_data,
            VerificationProtocolType::OpenId4VpFinal1_0,
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn test_validate_submission_transaction_data_missing_evidence() {
    let mut test_data = test_data(mdoc_dcql_query());
    test_data.interaction_data.common.transaction_data = vec![transaction_data_request()];

    let mut mocks = mocks_with_test_data(test_data.mock_data);
    transaction_data_mocks(&mut mocks);
    let proto = setup_proto(mocks);

    let submission_data = SubmissionRequestData {
        submission_data: VpSubmissionData::Dcql(VpTokenResponse {
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
    assert!(matches!(err, OpenID4VCError::ValidationError(_)));
}

#[tokio::test]
async fn test_validate_submission_transaction_data_duplicate_entries() {
    let mut test_data = test_data(mdoc_dcql_query());
    test_data.interaction_data.common.transaction_data =
        vec![transaction_data_request(), transaction_data_request()];
    test_data
        .mock_data
        .presentation_extraction
        .as_mut()
        .unwrap()
        .as_mut()
        .unwrap()
        .transaction_data = Some(PresentedTransactionData::DeviceSignedElements(
        qes_approval_evidence(),
    ));

    let mut mocks = mocks_with_test_data(test_data.mock_data);
    transaction_data_mocks(&mut mocks);
    let proto = setup_proto(mocks);

    let submission_data = SubmissionRequestData {
        submission_data: VpSubmissionData::Dcql(VpTokenResponse {
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
        matches!(err, OpenID4VCError::ValidationError(e) if e.contains("Duplicate transaction data"))
    );
}

#[tokio::test]
async fn test_validate_submission_transaction_data_unsolicited_evidence() {
    let mut test_data = test_data(mdoc_dcql_query());
    // No transaction data requested, but the presentation carries evidence.
    test_data.interaction_data.common.transaction_data = vec![];
    test_data
        .mock_data
        .presentation_extraction
        .as_mut()
        .unwrap()
        .as_mut()
        .unwrap()
        .transaction_data = Some(PresentedTransactionData::DeviceSignedElements(
        qes_approval_evidence(),
    ));

    let mocks = mocks_with_test_data(test_data.mock_data);
    let proto = setup_proto(mocks);

    let submission_data = SubmissionRequestData {
        submission_data: VpSubmissionData::Dcql(VpTokenResponse {
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
        matches!(err, OpenID4VCError::ValidationError(e) if e.contains("not matching any requested entry"))
    );
}

#[tokio::test]
async fn test_validate_submission_empty_transaction_data_evidence_is_ignored() {
    let mut test_data = test_data(mdoc_dcql_query());
    // No transaction data requested; the formatter reports empty device-signed
    // elements for a plain mdoc presentation. This must not count as evidence.
    test_data.interaction_data.common.transaction_data = vec![];
    test_data
        .mock_data
        .presentation_extraction
        .as_mut()
        .unwrap()
        .as_mut()
        .unwrap()
        .transaction_data = Some(PresentedTransactionData::DeviceSignedElements(
        IndexMap::new(),
    ));

    let mocks = mocks_with_test_data(test_data.mock_data);
    let proto = setup_proto(mocks);

    let submission_data = SubmissionRequestData {
        submission_data: VpSubmissionData::Dcql(VpTokenResponse {
            vp_token: hashmap! {"a83dabc3-1601-4642-84ec-7a5ad8a70d36".to_string() => vec!["vp_token".to_string()]},
        }),
        state: "a83dabc3-1601-4642-84ec-7a5ad8a70d36".parse().unwrap(),
        mdoc_generated_nonce: None,
        encryption_key: None,
    };
    proto
        .validate_submission(
            submission_data,
            test_data.proof,
            test_data.interaction_data,
            VerificationProtocolType::OpenId4VpFinal1_0,
        )
        .await
        .unwrap();
}
