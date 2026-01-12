use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use dcql::DcqlQuery;
use mockall::predicate::{always, eq};
use shared_types::CredentialFormat;
use similar_asserts::assert_eq;
use standardized_types::jwa::EncryptionAlgorithm;
use standardized_types::jwk::{JwkUse, PublicJwk, PublicJwkEc};
use standardized_types::openid4vp::{ClientMetadata, MdocAlgs, PresentationFormat};
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;

use super::OpenID4VPFinal1_0;
use super::model::{Params, PresentationVerifierParams};
use crate::config::core_config::FormatType;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential_schema::CredentialSchema;
use crate::model::did::{Did, DidType, KeyRole, RelatedKey};
use crate::model::identifier::Identifier;
use crate::model::interaction::{Interaction, InteractionType};
use crate::model::key::Key;
use crate::model::proof::{Proof, ProofRole, ProofStateEnum};
use crate::model::proof_schema::{ProofInputClaimSchema, ProofInputSchema, ProofSchema};
use crate::proto::certificate_validator::MockCertificateValidator;
use crate::proto::http_client::{
    Method, MockHttpClient, Request, RequestBuilder, Response, StatusCode,
};
use crate::provider::credential_formatter::MockCredentialFormatter;
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::key_algorithm::MockKeyAlgorithm;
use crate::provider::key_algorithm::key::{
    KeyAgreementHandle, KeyHandle, MockPublicKeyAgreementHandle, MockSignaturePublicKeyHandle,
    SignatureKeyHandle,
};
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_storage::MockKeyStorage;
use crate::provider::key_storage::model::KeyStorageCapabilities;
use crate::provider::key_storage::provider::MockKeyProvider;
use crate::provider::presentation_formatter::provider::MockPresentationFormatterProvider;
use crate::provider::verification_protocol::dto::ShareResponse;
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::openid4vp::model::{
    ClientIdScheme, OpenID4VCPresentationHolderParams, OpenID4VCRedirectUriParams,
    OpenID4VPClientMetadata, OpenID4VPHolderInteractionData,
};
use crate::provider::verification_protocol::{
    FormatMapper, TypeToDescriptorMapper, VerificationProtocol, serialize_interaction_data,
};
use crate::service::proof::dto::ShareProofRequestParamsDTO;
use crate::service::test_utilities::{
    dummy_claim_schema, dummy_credential_schema, dummy_identifier, generic_config,
};

#[derive(Default)]
struct TestInputs {
    pub credential_formatter_provider: MockCredentialFormatterProvider,
    pub presentation_formatter_provider: MockPresentationFormatterProvider,
    pub key_algorithm_provider: MockKeyAlgorithmProvider,
    pub key_provider: MockKeyProvider,
    pub did_method_provider: MockDidMethodProvider,
    pub certificate_validator: MockCertificateValidator,
    pub http_client: MockHttpClient,
    pub params: Option<Params>,
}

fn setup_protocol(inputs: TestInputs) -> OpenID4VPFinal1_0 {
    OpenID4VPFinal1_0::new(
        Some("http://base_url".to_string()),
        Arc::new(inputs.credential_formatter_provider),
        Arc::new(inputs.presentation_formatter_provider),
        Arc::new(inputs.did_method_provider),
        Arc::new(inputs.key_algorithm_provider),
        Arc::new(inputs.key_provider),
        Arc::new(inputs.certificate_validator),
        Arc::new(inputs.http_client),
        inputs.params.unwrap_or(generic_params()),
        Arc::new(generic_config().core),
    )
}

fn generic_params() -> Params {
    Params {
        allow_insecure_http_transport: true,
        use_request_uri: false,
        url_scheme: "openid4vp".to_string(),
        holder: OpenID4VCPresentationHolderParams {
            supported_client_id_schemes: vec![
                ClientIdScheme::RedirectUri,
                ClientIdScheme::VerifierAttestation,
            ],
            dcql_vp_token_single_presentation: false,
        },
        verifier: PresentationVerifierParams {
            interaction_expires_in: Some(Duration::seconds(1000)),
            supported_client_id_schemes: vec![
                ClientIdScheme::RedirectUri,
                ClientIdScheme::VerifierAttestation,
            ],
        },
        redirect_uri: OpenID4VCRedirectUriParams {
            enabled: true,
            allowed_schemes: vec!["https".to_string()],
        },
    }
}

fn test_credential_schema(format: CredentialFormat) -> CredentialSchema {
    CredentialSchema {
        format,
        name: "test-credential-schema".to_string(),
        schema_id: "test_schema_id".to_string(),
        imported_source_url: "test_imported_src_url".to_string(),
        ..dummy_credential_schema()
    }
}

fn test_key(key_type: &str) -> Key {
    Key {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        public_key: vec![],
        name: "test_key".to_string(),
        key_reference: None,
        storage_type: "INTERNAL".to_string(),
        key_type: key_type.to_string(),
        organisation: None,
    }
}

fn test_verifier_proof(format: CredentialFormat, verifier_key: Option<RelatedKey>) -> Proof {
    let key = verifier_key
        .clone()
        .map(|k| k.key)
        .unwrap_or_else(|| test_key("ECDSA"));

    Proof {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        protocol: "OPENID4VP_FINAL1".to_string(),
        transport: "HTTP".to_string(),
        redirect_uri: None,
        state: ProofStateEnum::Created,
        role: ProofRole::Verifier,
        requested_date: None,
        completed_date: None,
        schema: Some(ProofSchema {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            deleted_at: None,
            name: "test-share-proof".into(),
            expire_duration: 123,
            imported_source_url: None,
            organisation: None,
            input_schemas: Some(vec![ProofInputSchema {
                validity_constraint: None,
                claim_schemas: Some(vec![ProofInputClaimSchema {
                    schema: ClaimSchema {
                        id: Uuid::new_v4().into(),
                        key: "required_key".to_string(),
                        ..dummy_claim_schema()
                    },
                    required: true,
                    order: 0,
                }]),
                credential_schema: Some(test_credential_schema(format)),
            }]),
        }),
        claims: None,
        verifier_identifier: Some(Identifier {
            did: Some(Did {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                name: "did".to_string(),
                did: "did:example:123".parse().unwrap(),
                did_type: DidType::Local,
                did_method: "KEY".to_string(),
                deactivated: false,
                keys: verifier_key.map(|k| vec![k]).or_else(|| {
                    Some(vec![RelatedKey {
                        role: KeyRole::AssertionMethod,
                        key: key.clone(),
                        reference: "1".to_string(),
                    }])
                }),
                organisation: None,
                log: None,
            }),
            ..dummy_identifier()
        }),
        verifier_key: Some(key),
        verifier_certificate: None,
        interaction: None,
        profile: None,
        proof_blob_id: None,
        engagement: None,
    }
}

fn test_holder_interaction_data(response_mode: Option<&str>) -> OpenID4VPHolderInteractionData {
    OpenID4VPHolderInteractionData {
        response_type: Some("vp_token".to_string()),
        state: Some(Uuid::new_v4().to_string()),
        nonce: Some("test-nonce-12345".to_string()),
        client_id_scheme: ClientIdScheme::RedirectUri,
        client_id: "https://verifier.example.com".to_string(),
        client_metadata: Some(OpenID4VPClientMetadata::Final1_0(ClientMetadata {
            vp_formats_supported: HashMap::from([(
                "mso_mdoc".to_string(),
                PresentationFormat::MdocAlgs(MdocAlgs {
                    issuerauth_alg_values: vec![],
                    deviceauth_alg_values: vec![],
                }),
            )]),
            ..Default::default()
        })),
        client_metadata_uri: None,
        response_mode: response_mode.map(String::from),
        response_uri: Some("https://verifier.example.com/response".parse().unwrap()),
        presentation_definition: None,
        presentation_definition_uri: None,
        dcql_query: None,
        redirect_uri: None,
        verifier_details: None,
    }
}

fn test_holder_proof(
    interaction_data: OpenID4VPHolderInteractionData,
    format: CredentialFormat,
) -> Proof {
    let interaction = Interaction {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        data: Some(serialize_interaction_data(&interaction_data).unwrap()),
        organisation: None,
        nonce_id: None,
        interaction_type: InteractionType::Verification,
        expires_at: None,
    };

    Proof {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        protocol: "OPENID4VP_FINAL1".to_string(),
        transport: "HTTP".to_string(),
        redirect_uri: None,
        state: ProofStateEnum::Requested,
        role: ProofRole::Holder,
        requested_date: None,
        completed_date: None,
        schema: Some(ProofSchema {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            deleted_at: None,
            name: "test-holder-proof".into(),
            expire_duration: 300,
            imported_source_url: None,
            organisation: None,
            input_schemas: Some(vec![ProofInputSchema {
                validity_constraint: None,
                claim_schemas: None,
                credential_schema: Some(test_credential_schema(format)),
            }]),
        }),
        claims: None,
        verifier_identifier: None,
        verifier_key: Some(test_key("ECDSA")),
        verifier_certificate: None,
        interaction: Some(interaction),
        profile: None,
        proof_blob_id: None,
        engagement: None,
    }
}

fn mock_http_post(url: &str) -> MockHttpClient {
    let url = url.to_string();
    let mut mock_client = MockHttpClient::new();

    let url_for_eq = url.clone();
    mock_client
        .expect_post()
        .with(eq(url_for_eq))
        .returning(move |req_url| {
            let mut inner_client = MockHttpClient::new();
            let url_for_response = url.clone();
            inner_client
                .expect_send()
                .with(eq(url.clone()), always(), always(), eq(Method::Post))
                .return_once(move |_, _, _, _| {
                    Ok(Response {
                        body: b"{}".to_vec(),
                        headers: Default::default(),
                        status: StatusCode(200),
                        request: Request {
                            body: None,
                            headers: Default::default(),
                            method: Method::Post,
                            url: url_for_response,
                        },
                    })
                });
            RequestBuilder::new(Arc::new(inner_client), Method::Post, req_url)
        });

    mock_client
}

fn setup_key_agreement_mocks(
    crv: &'static str,
    _key_type: &'static str,
    jwk_constructor: impl FnOnce(PublicJwkEc) -> PublicJwk + Send + 'static,
) -> (MockKeyAlgorithmProvider, MockKeyProvider, Uuid) {
    let key_id = Uuid::new_v4();

    let mut key_storage = MockKeyStorage::new();
    key_storage
        .expect_get_capabilities()
        .returning(KeyStorageCapabilities::default);

    let mut key_provider = MockKeyProvider::new();
    let arc = Arc::new(key_storage);
    key_provider
        .expect_get_key_storage()
        .returning(move |_| Some(arc.clone()));

    let mut key_algorithm = MockKeyAlgorithm::new();
    key_algorithm
        .expect_reconstruct_key()
        .return_once(move |_, _, _| {
            let mut key_agreement_handle = MockPublicKeyAgreementHandle::default();
            key_agreement_handle.expect_as_jwk().return_once(move || {
                Ok(jwk_constructor(PublicJwkEc {
                    alg: None,
                    r#use: Some(JwkUse::Encryption),
                    kid: None,
                    crv: crv.to_string(),
                    x: "".to_string(),
                    y: Some("".to_string()),
                }))
            });
            Ok(KeyHandle::SignatureAndKeyAgreement {
                signature: SignatureKeyHandle::PublicKeyOnly(Arc::new(
                    MockSignaturePublicKeyHandle::default(),
                )),
                key_agreement: KeyAgreementHandle::PublicKeyOnly(Arc::new(key_agreement_handle)),
            })
        });

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    let arc = Arc::new(key_algorithm);
    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .returning(move |_| Some(arc.clone()));

    (key_algorithm_provider, key_provider, key_id)
}

#[tokio::test]
async fn test_share_proof_direct_post() {
    let mut credential_formatter = MockCredentialFormatter::new();
    credential_formatter
        .expect_user_claims_path()
        .returning(Vec::new);

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .return_once(|_| Some(Arc::new(credential_formatter)));

    let protocol = setup_protocol(TestInputs {
        credential_formatter_provider: formatter_provider,
        ..Default::default()
    });

    let proof = test_verifier_proof("JWT".into(), None);
    let format_type_mapper: FormatMapper = Arc::new(move |_| Ok(FormatType::Jwt));
    let type_to_descriptor_mapper: TypeToDescriptorMapper = Arc::new(move |_| Ok(HashMap::new()));

    let ShareResponse {
        url,
        interaction_id,
        ..
    } = protocol
        .verifier_share_proof(
            &proof,
            format_type_mapper,
            type_to_descriptor_mapper,
            None,
            Some(ShareProofRequestParamsDTO {
                client_id_scheme: Some(ClientIdScheme::RedirectUri),
            }),
        )
        .await
        .unwrap();

    let url: Url = url.parse().unwrap();
    let query_pairs: HashMap<Cow<'_, str>, Cow<'_, str>> = url.query_pairs().collect();

    let expected_keys = vec![
        "client_id",
        "client_metadata",
        "dcql_query",
        "nonce",
        "response_mode",
        "response_type",
        "response_uri",
        "state",
    ];

    let mut actual_keys: Vec<&str> = query_pairs.keys().map(|k| k.as_ref()).collect();
    actual_keys.sort();
    assert_eq!(expected_keys, actual_keys);

    assert_eq!("vp_token", query_pairs.get("response_type").unwrap());
    assert_eq!("direct_post", query_pairs.get("response_mode").unwrap());
    assert_eq!(
        &interaction_id.to_string(),
        query_pairs.get("state").unwrap()
    );
    assert_eq!(
        "http://base_url/ssi/openid4vp/final-1.0/response",
        query_pairs.get("response_uri").unwrap()
    );
    assert_eq!(
        "redirect_uri:http://base_url/ssi/openid4vp/final-1.0/response",
        query_pairs.get("client_id").unwrap()
    );

    let returned_dcql_query =
        serde_json::from_str::<DcqlQuery>(query_pairs.get("dcql_query").unwrap()).unwrap();
    let returned_client_metadata =
        serde_json::from_str::<ClientMetadata>(query_pairs.get("client_metadata").unwrap())
            .unwrap();

    assert_eq!(returned_client_metadata.jwks, None);
    assert_eq!(
        returned_client_metadata.encrypted_response_enc_values_supported,
        None
    );
    assert_eq!(returned_dcql_query.credentials.len(), 1);
}

#[tokio::test]
async fn test_share_proof_direct_post_jwt_ecdsa() {
    let (key_algorithm_provider, key_provider, key_id) =
        setup_key_agreement_mocks("P-256", "ECDSA", PublicJwk::Ec);

    let mut credential_formatter = MockCredentialFormatter::new();
    credential_formatter
        .expect_user_claims_path()
        .returning(Vec::new);

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .return_once(|_| Some(Arc::new(credential_formatter)));

    let protocol = setup_protocol(TestInputs {
        key_provider,
        key_algorithm_provider,
        credential_formatter_provider: formatter_provider,
        ..Default::default()
    });

    let key_agreement_key = RelatedKey {
        role: KeyRole::KeyAgreement,
        key: Key {
            id: key_id.into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            public_key: vec![],
            name: "key".to_string(),
            key_reference: None,
            storage_type: "INTERNAL".to_string(),
            key_type: "ECDSA".to_string(),
            organisation: None,
        },
        reference: "1".to_string(),
    };

    let proof = test_verifier_proof("JWT".into(), Some(key_agreement_key));
    let format_type_mapper: FormatMapper = Arc::new(move |_| Ok(FormatType::Jwt));
    let type_to_descriptor_mapper: TypeToDescriptorMapper = Arc::new(move |_| Ok(HashMap::new()));

    let ShareResponse { url, .. } = protocol
        .verifier_share_proof(
            &proof,
            format_type_mapper,
            type_to_descriptor_mapper,
            None,
            Some(ShareProofRequestParamsDTO {
                client_id_scheme: Some(ClientIdScheme::RedirectUri),
            }),
        )
        .await
        .unwrap();

    let url: Url = url.parse().unwrap();
    let query_pairs: HashMap<Cow<'_, str>, Cow<'_, str>> = url.query_pairs().collect();

    assert_eq!("direct_post.jwt", query_pairs.get("response_mode").unwrap());

    let returned_client_metadata =
        serde_json::from_str::<ClientMetadata>(query_pairs.get("client_metadata").unwrap())
            .unwrap();

    let jwks = returned_client_metadata.jwks.unwrap().keys;
    assert_eq!(jwks.len(), 1);
    assert_eq!(jwks[0].r#use(), Some(&JwkUse::Encryption));
    assert_eq!(jwks[0].kid().unwrap(), key_id.to_string().as_str());

    assert_eq!(
        returned_client_metadata.encrypted_response_enc_values_supported,
        Some(vec![
            EncryptionAlgorithm::A128GCM,
            EncryptionAlgorithm::A256GCM,
            EncryptionAlgorithm::A128CBCHS256,
        ])
    );
}

#[tokio::test]
async fn test_share_proof_direct_post_jwt_eddsa() {
    let (key_algorithm_provider, key_provider, key_id) =
        setup_key_agreement_mocks("Ed25519", "EDDSA", |data| {
            PublicJwk::Okp(PublicJwkEc { y: None, ..data })
        });

    let mut credential_formatter = MockCredentialFormatter::new();
    credential_formatter
        .expect_user_claims_path()
        .returning(Vec::new);

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .return_once(|_| Some(Arc::new(credential_formatter)));

    let protocol = setup_protocol(TestInputs {
        key_provider,
        key_algorithm_provider,
        credential_formatter_provider: formatter_provider,
        ..Default::default()
    });

    let key_agreement_key = RelatedKey {
        role: KeyRole::KeyAgreement,
        key: Key {
            id: key_id.into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            public_key: vec![],
            name: "key".to_string(),
            key_reference: None,
            storage_type: "INTERNAL".to_string(),
            key_type: "EDDSA".to_string(),
            organisation: None,
        },
        reference: "1".to_string(),
    };

    let proof = test_verifier_proof("JWT".into(), Some(key_agreement_key));
    let format_type_mapper: FormatMapper = Arc::new(move |_| Ok(FormatType::Jwt));
    let type_to_descriptor_mapper: TypeToDescriptorMapper = Arc::new(move |_| Ok(HashMap::new()));

    let ShareResponse { url, .. } = protocol
        .verifier_share_proof(
            &proof,
            format_type_mapper,
            type_to_descriptor_mapper,
            None,
            Some(ShareProofRequestParamsDTO {
                client_id_scheme: Some(ClientIdScheme::RedirectUri),
            }),
        )
        .await
        .unwrap();

    let url: Url = url.parse().unwrap();
    let query_pairs: HashMap<Cow<'_, str>, Cow<'_, str>> = url.query_pairs().collect();

    assert_eq!("direct_post.jwt", query_pairs.get("response_mode").unwrap());

    let returned_client_metadata =
        serde_json::from_str::<ClientMetadata>(query_pairs.get("client_metadata").unwrap())
            .unwrap();

    let jwks = returned_client_metadata.jwks.unwrap().keys;
    assert_eq!(jwks.len(), 1);
    assert_eq!(jwks[0].r#use(), Some(&JwkUse::Encryption));
    assert_eq!(jwks[0].kid().unwrap(), key_id.to_string());
}

#[tokio::test]
async fn test_holder_submit_missing_response_mode_fails() {
    let protocol = setup_protocol(TestInputs::default());
    let proof = test_holder_proof(test_holder_interaction_data(None), "MDOC".into());

    let result = protocol.holder_submit_proof(&proof, vec![]).await;

    assert!(
        matches!(&result, Err(VerificationProtocolError::InvalidRequest(_))),
        "Expected InvalidRequest error for missing response_mode, got: {:?}",
        result
    );
}

#[tokio::test]
async fn test_holder_submit_invalid_response_mode_fails() {
    let protocol = setup_protocol(TestInputs::default());
    let proof = test_holder_proof(
        test_holder_interaction_data(Some("invalid_response_mode")),
        "MDOC".into(),
    );

    let result = protocol.holder_submit_proof(&proof, vec![]).await;

    assert!(
        matches!(&result, Err(VerificationProtocolError::InvalidRequest(_))),
        "Expected InvalidRequest error for invalid response_mode, got: {:?}",
        result
    );
}

#[tokio::test]
async fn test_holder_submit_direct_post_jwt_no_encryption_keys_fails() {
    let protocol = setup_protocol(TestInputs::default());
    let proof = test_holder_proof(
        test_holder_interaction_data(Some("direct_post.jwt")),
        "MDOC".into(),
    );

    let result = protocol.holder_submit_proof(&proof, vec![]).await;

    assert!(
        matches!(&result, Err(VerificationProtocolError::InvalidRequest(_))),
        "Expected InvalidRequest error when direct_post.jwt has no encryption keys, got: {:?}",
        result
    );
}

#[tokio::test]
async fn test_holder_submit_mdoc_direct_post() {
    let protocol = setup_protocol(TestInputs {
        http_client: mock_http_post("https://verifier.example.com/response"),
        ..Default::default()
    });

    let proof = test_holder_proof(
        test_holder_interaction_data(Some("direct_post")),
        "MDOC".into(),
    );

    // Verifies: response_mode validation passes, no MDOC-requires-encryption error, HTTP POST succeeds
    let result = protocol.holder_submit_proof(&proof, vec![]).await;
    assert!(result.is_ok(), "Expected Ok but got: {:?}", result);
}
