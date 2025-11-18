use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use dcql::DcqlQuery;
use similar_asserts::assert_eq;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use super::OpenID4VPFinal1_0;
use super::model::{Params, PresentationVerifierParams};
use crate::config::core_config::FormatType;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential_schema::{CredentialSchema, LayoutType};
use crate::model::did::{Did, DidType, KeyRole, RelatedKey};
use crate::model::identifier::Identifier;
use crate::model::key::{JwkUse, Key, PublicKeyJwk, PublicKeyJwkEllipticData};
use crate::model::proof::{Proof, ProofRole, ProofStateEnum};
use crate::model::proof_schema::{ProofInputClaimSchema, ProofInputSchema, ProofSchema};
use crate::proto::certificate_validator::MockCertificateValidator;
use crate::proto::http_client::reqwest_client::ReqwestClient;
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
use crate::provider::verification_protocol::openid4vp::final1_0::model::OpenID4VPFinal1_0ClientMetadata;
use crate::provider::verification_protocol::openid4vp::model::{
    AuthorizationEncryptedResponseContentEncryptionAlgorithm, ClientIdScheme,
    OpenID4VCPresentationHolderParams, OpenID4VCRedirectUriParams,
};
use crate::provider::verification_protocol::{
    FormatMapper, TypeToDescriptorMapper, VerificationProtocol,
};
use crate::service::proof::dto::ShareProofRequestParamsDTO;
use crate::service::test_utilities::{dummy_claim_schema, dummy_identifier, generic_config};

#[derive(Default)]
struct TestInputs {
    pub credential_formatter_provider: MockCredentialFormatterProvider,
    pub presentation_formatter_provider: MockPresentationFormatterProvider,
    pub key_algorithm_provider: MockKeyAlgorithmProvider,
    pub key_provider: MockKeyProvider,
    pub did_method_provider: MockDidMethodProvider,
    pub certificate_validator: MockCertificateValidator,
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
        Arc::new(ReqwestClient::default()),
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

fn test_proof(proof_id: Uuid, credential_format: &str, verifier_key: Option<RelatedKey>) -> Proof {
    let key_id = Uuid::new_v4().into();
    Proof {
        id: proof_id.into(),
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
                        id: shared_types::ClaimSchemaId::from(Into::<Uuid>::into(Uuid::new_v4())),
                        key: "required_key".to_string(),
                        ..dummy_claim_schema()
                    },
                    required: true,
                    order: 0,
                }]),

                credential_schema: Some(CredentialSchema {
                    id: Uuid::new_v4().into(),
                    deleted_at: None,
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    name: "test-credential-schema".to_string(),
                    format: credential_format.to_string(),
                    revocation_method: "NONE".to_string(),
                    key_storage_security: None,
                    layout_type: LayoutType::Card,
                    layout_properties: None,
                    schema_id: "test_schema_id".to_string(),
                    imported_source_url: "test_imported_src_url".to_string(),
                    allow_suspension: false,
                    requires_app_attestation: false,
                    claim_schemas: None,
                    organisation: None,
                }),
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
                keys: verifier_key
                    .clone()
                    .map(|k| vec![k])
                    .or(Some(vec![RelatedKey {
                        role: KeyRole::AssertionMethod,
                        key: Key {
                            id: key_id,
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
                    }])),
                organisation: None,
                log: None,
            }),
            ..dummy_identifier()
        }),
        verifier_key: verifier_key.map(|k| k.key).or(Some(Key {
            id: key_id,
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            public_key: vec![],
            name: "verifier_key".to_string(),
            key_reference: None,
            storage_type: "INTERNAL".to_string(),
            key_type: "ECDSA".to_string(),
            organisation: None,
        })),
        verifier_certificate: None,
        interaction: None,
        profile: None,
        proof_blob_id: None,
        engagement: None,
    }
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

    let proof_id = Uuid::new_v4();
    let proof = test_proof(proof_id, "JWT", None);

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

    let returned_client_metadata = serde_json::from_str::<OpenID4VPFinal1_0ClientMetadata>(
        query_pairs.get("client_metadata").unwrap(),
    )
    .unwrap();

    assert_eq!(returned_client_metadata.jwks, None);
    assert_eq!(
        returned_client_metadata.encrypted_response_enc_values_supported,
        None
    );
    assert_eq!(returned_dcql_query.credentials.len(), 1);
}

#[tokio::test]
async fn test_share_proof_direct_post_jwt_eccdsa() {
    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    let mut key_provider = MockKeyProvider::new();
    let mut key_storage = MockKeyStorage::new();
    key_storage
        .expect_get_capabilities()
        .returning(KeyStorageCapabilities::default);

    let arc = Arc::new(key_storage);
    key_provider
        .expect_get_key_storage()
        .returning(move |_| Some(arc.clone()));

    let mut key_algorithm = MockKeyAlgorithm::new();

    key_algorithm
        .expect_reconstruct_key()
        .return_once(|_, _, _| {
            let mut key_agreement_handle = MockPublicKeyAgreementHandle::default();
            key_agreement_handle.expect_as_jwk().return_once(|| {
                Ok(PublicKeyJwk::Ec(PublicKeyJwkEllipticData {
                    alg: None,
                    r#use: Some(JwkUse::Encryption),
                    kid: None,
                    crv: "P-256".to_string(),
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

    let arc = Arc::new(key_algorithm);

    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .returning(move |_| Some(arc.clone()));

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

    let proof_id = Uuid::new_v4();

    let key_id = Uuid::new_v4();
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

    let proof = test_proof(proof_id, "JWT", Some(key_agreement_key));
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
    assert_eq!("direct_post.jwt", query_pairs.get("response_mode").unwrap());
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

    let returned_client_metadata = serde_json::from_str::<OpenID4VPFinal1_0ClientMetadata>(
        query_pairs.get("client_metadata").unwrap(),
    )
    .unwrap();

    let jwks = returned_client_metadata.jwks.unwrap().keys;
    let jwk = jwks.first().unwrap().clone();

    assert_eq!(jwks.len(), 1);
    assert_eq!(jwk.jwk.get_use(), &Some("enc".to_string()));
    assert_eq!(jwk.key_id, key_id.to_string());

    assert_eq!(
        returned_client_metadata.encrypted_response_enc_values_supported,
        Some(vec![
            AuthorizationEncryptedResponseContentEncryptionAlgorithm::A256GCM,
            AuthorizationEncryptedResponseContentEncryptionAlgorithm::A128CBCHS256,
        ])
    );
    assert_eq!(returned_dcql_query.credentials.len(), 1);
}

#[tokio::test]
async fn test_share_proof_direct_post_jwt_eddsa() {
    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    let mut key_provider = MockKeyProvider::new();
    let mut key_storage = MockKeyStorage::new();
    key_storage
        .expect_get_capabilities()
        .returning(KeyStorageCapabilities::default);

    let arc = Arc::new(key_storage);
    key_provider
        .expect_get_key_storage()
        .returning(move |_| Some(arc.clone()));

    let mut key_algorithm = MockKeyAlgorithm::new();
    key_algorithm
        .expect_reconstruct_key()
        .return_once(|_, _, _| {
            let mut key_agreement_handle = MockPublicKeyAgreementHandle::default();
            key_agreement_handle.expect_as_jwk().return_once(|| {
                Ok(PublicKeyJwk::Okp(PublicKeyJwkEllipticData {
                    alg: None,
                    r#use: Some(JwkUse::Encryption),
                    kid: None,
                    crv: "Ed25519".to_string(),
                    x: "".to_string(),
                    y: None,
                }))
            });
            Ok(KeyHandle::SignatureAndKeyAgreement {
                signature: SignatureKeyHandle::PublicKeyOnly(Arc::new(
                    MockSignaturePublicKeyHandle::default(),
                )),
                key_agreement: KeyAgreementHandle::PublicKeyOnly(Arc::new(key_agreement_handle)),
            })
        });

    let arc = Arc::new(key_algorithm);

    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .returning(move |_| Some(arc.clone()));

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

    let proof_id = Uuid::new_v4();

    let key_id = Uuid::new_v4();
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

    let proof = test_proof(proof_id, "JWT", Some(key_agreement_key));
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
    assert_eq!("direct_post.jwt", query_pairs.get("response_mode").unwrap());
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

    let returned_client_metadata = serde_json::from_str::<OpenID4VPFinal1_0ClientMetadata>(
        query_pairs.get("client_metadata").unwrap(),
    )
    .unwrap();

    let jwks = returned_client_metadata.jwks.unwrap().keys;
    let jwk = jwks.first().unwrap().clone();

    assert_eq!(jwks.len(), 1);
    assert_eq!(jwk.jwk.get_use(), &Some("enc".to_string()));
    assert_eq!(jwk.key_id, key_id.to_string());

    assert_eq!(
        returned_client_metadata.encrypted_response_enc_values_supported,
        Some(vec![
            AuthorizationEncryptedResponseContentEncryptionAlgorithm::A256GCM,
            AuthorizationEncryptedResponseContentEncryptionAlgorithm::A128CBCHS256,
        ])
    );
    assert_eq!(returned_dcql_query.credentials.len(), 1);
}
