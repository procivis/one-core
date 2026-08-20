use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use indexmap::IndexMap;
use mockall::predicate::{always, eq};
use serde_json::json;
use shared_types::{CredentialFormat, TransactionDataId};
use similar_asserts::assert_eq;
use standardized_types::iana::EncryptionAlgorithm;
use standardized_types::jwk::{JwkUse, PublicJwk, PublicJwkEc};
use standardized_types::openid4vp::dcql::{CredentialQuery, CredentialQueryId, DcqlQuery};
use standardized_types::openid4vp::{
    AuthorizationRequestQueryParams, ClientIdPrefix, ClientMetadata, MdocAlgs, PresentationFormat,
    ResponseMode,
};
use url::Url;
use uuid::Uuid;

use super::OpenID4VPFinal1_0;
use crate::config::core_config::FormatType;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential_schema::CredentialSchema;
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::did::{Did, DidType, KeyRole, RelatedKey};
use crate::model::identifier::{Identifier, IdentifierData};
use crate::model::interaction::{Interaction, InteractionType};
use crate::model::key::Key;
use crate::model::proof::{Proof, ProofRole, ProofStateEnum};
use crate::model::proof_schema::{ProofInputClaimSchema, ProofInputSchema, ProofSchema};
use crate::proto::certificate_validator::MockCertificateValidator;
use crate::proto::http_client::{
    Method, MockHttpClient, Request, RequestBuilder, Response, StatusCode,
};
use crate::proto::wrp_validator::MockWRPValidator;
use crate::provider::credential_formatter::MockCredentialFormatter;
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::ecosystem::directory::MockEcosystemDirectory;
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
use crate::provider::transaction_data::provider::MockTransactionDataProvider;
use crate::provider::transaction_data::{
    Features, MockTransactionData, TransactionDataCapabilities,
};
use crate::provider::verification_protocol::dto::{FormattedCredentialPresentation, ShareResponse};
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::openid4vp::model::{
    HolderTxData, OpenID4VPHolderInteractionData, ValidatedHolderTxData,
};
use crate::provider::verification_protocol::{
    FormatMapper, VerificationProtocol, serialize_interaction_data,
};
use crate::repository::credential_repository::MockCredentialRepository;
use crate::repository::credential_schema_repository::MockCredentialSchemaRepository;
use crate::repository::interaction_repository::MockInteractionRepository;
use crate::service::proof::dto::ShareProofRequestParamsDTO;
use crate::service::test_utilities::{
    dummy_claim_schema, dummy_credential_schema, dummy_dcql_query, dummy_identifier,
    dummy_organisation, generic_config,
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
    pub interaction_repository: MockInteractionRepository,
    pub wrp_validator: MockWRPValidator,
    pub ecosystem_provider: MockEcosystemDirectory,
    pub transaction_data_provider: MockTransactionDataProvider,
    pub params: Option<serde_json::Value>,
}

fn setup_protocol(inputs: TestInputs) -> OpenID4VPFinal1_0 {
    OpenID4VPFinal1_0::new(
        "final1".to_string(),
        Some("http://base_url".to_string()),
        Arc::new(inputs.credential_formatter_provider),
        Arc::new(inputs.presentation_formatter_provider),
        Arc::new(inputs.did_method_provider),
        Arc::new(inputs.key_algorithm_provider),
        Arc::new(inputs.key_provider),
        Arc::new(inputs.certificate_validator),
        Arc::new(MockCredentialRepository::default()),
        Arc::new(MockCredentialSchemaRepository::default()),
        Arc::new(inputs.interaction_repository),
        Arc::new(inputs.wrp_validator),
        Arc::new(inputs.ecosystem_provider),
        Arc::new(inputs.transaction_data_provider),
        Arc::new(inputs.http_client),
        inputs.params.unwrap_or(generic_params()),
        Arc::new(generic_config().core),
    )
    .unwrap()
}

fn generic_params() -> serde_json::Value {
    json!({
        "allowInsecureHttpTransport": true,
        "useRequestUri": false,
        "urlScheme": "openid4vp",
        "holder":  {
            "supportedClientIdSchemes": [
                ClientIdPrefix::RedirectUri,
                ClientIdPrefix::VerifierAttestation
            ]
        },
        "verifier": {
            "interactionExpiresInSeconds": 1000,
            "supportedClientIdSchemes": [
                ClientIdPrefix::RedirectUri,
                ClientIdPrefix::VerifierAttestation
            ],
        },
        "redirectUri": {
            "enabled": true,
            "allowedSchemes": ["https"],
        }
    })
}

fn test_credential_schema(format: CredentialFormat) -> CredentialSchema {
    CredentialSchema {
        formats: vec![CredentialSchemaFormat {
            id: Uuid::new_v4().into(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            credential_schema_id: Uuid::new_v4().into(),
            format,
            schema_id: "test_schema_id".to_owned(),
            claim_mappings: Default::default(),
        }]
        .into(),
        batch_size: None,
        name: "test-credential-schema".to_string(),
        imported_source_url: "test_imported_src_url".to_string(),
        ..dummy_credential_schema()
    }
}

fn test_key(key_type: &str) -> Key {
    Key {
        id: Uuid::new_v4().into(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        public_key: vec![],
        name: "test_key".to_string(),
        key_reference: None,
        storage_type: "INTERNAL".to_string(),
        key_type: key_type.to_string(),
        organisation: dummy_organisation(None).into(),
    }
}

fn test_verifier_proof(format: CredentialFormat, verifier_key: Option<RelatedKey>) -> Proof {
    let key = verifier_key
        .clone()
        .map(|k| k.key)
        .unwrap_or_else(|| test_key("ECDSA"));

    Proof {
        ecosystem: None,
        id: Uuid::new_v4().into(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        protocol: "OPENID4VP_FINAL1".to_string(),
        transport: "HTTP".to_string(),
        redirect_uri: None,
        state: ProofStateEnum::Created,
        role: ProofRole::Verifier,
        requested_date: None,
        completed_date: None,
        schema: Some(
            ProofSchema {
                ecosystem: None,
                id: Uuid::new_v4().into(),
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                deleted_at: None,
                name: "test-share-proof".into(),
                expire_duration: 123,
                imported_source_url: None,
                organisation: dummy_organisation(None).into(),
                input_schemas: vec![ProofInputSchema {
                    claim_schemas: vec![ProofInputClaimSchema {
                        schema: ClaimSchema {
                            id: Uuid::new_v4().into(),
                            key: "required_key".to_string(),
                            ..dummy_claim_schema()
                        },
                        required: true,
                        order: 0,
                    }]
                    .into(),
                    credential_schema: test_credential_schema(format).into(),
                }]
                .into(),
            }
            .into(),
        ),
        claims: Default::default(),
        verifier_identifier: Some(
            Identifier {
                data: IdentifierData::Did(
                    (Did {
                        deleted_at: None,
                        id: Uuid::new_v4().into(),
                        created_date: crate::clock::now_utc(),
                        last_modified: crate::clock::now_utc(),
                        name: "did".to_string(),
                        did: "did:example:123".parse().unwrap(),
                        did_type: DidType::Local,
                        did_method: "KEY".into(),
                        deactivated: false,
                        keys: verifier_key
                            .map(|k| vec![k])
                            .unwrap_or(vec![RelatedKey {
                                role: KeyRole::AssertionMethod,
                                key: key.clone(),
                                reference: "1".to_string(),
                            }])
                            .into(),
                        organisation: dummy_organisation(None).into(),
                        log: None,
                    })
                    .into(),
                ),
                ..dummy_identifier()
            }
            .into(),
        ),
        verifier_key: Some(key.into()),
        verifier_certificate: None,
        interaction: None,
        profile: None,
        proof_blob_id: None,
        engagement: None,
        webhook_url: None,
        subscriber_information: None,
    }
}

fn test_holder_interaction_data(
    response_mode: Option<ResponseMode>,
) -> OpenID4VPHolderInteractionData {
    OpenID4VPHolderInteractionData {
        response_type: Some("vp_token".to_string()),
        state: Some(Uuid::new_v4().to_string()),
        nonce: Some("test-nonce-12345".to_string()),
        client_id_scheme: ClientIdPrefix::RedirectUri,
        client_id: "https://verifier.example.com".to_string(),
        client_metadata: Some(ClientMetadata {
            vp_formats_supported: HashMap::from([(
                "mso_mdoc".to_string(),
                PresentationFormat::MdocAlgs(MdocAlgs {
                    issuerauth_alg_values: vec![],
                    deviceauth_alg_values: vec![],
                }),
            )]),
            ..Default::default()
        }),
        client_metadata_uri: None,
        response_mode,
        response_uri: Some("https://verifier.example.com/response".parse().unwrap()),
        dcql_query: dummy_dcql_query(true),
        transaction_data: Default::default(),
        redirect_uri: None,
        verifier_details: None,
        verifier_info: vec![],
    }
}

fn test_holder_proof(
    interaction_data: OpenID4VPHolderInteractionData,
    format: CredentialFormat,
) -> Proof {
    let interaction = Interaction {
        id: Uuid::new_v4().into(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        data: Some(serialize_interaction_data(&interaction_data).unwrap()),
        organisation: dummy_organisation(None).into(),
        nonce_id: None,
        interaction_type: InteractionType::Verification,
        expires_at: None,
        ecosystem: None,
        ecosystem_data: Default::default(),
    };

    Proof {
        ecosystem: None,
        id: Uuid::new_v4().into(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        protocol: "OPENID4VP_FINAL1".to_string(),
        transport: "HTTP".to_string(),
        redirect_uri: None,
        state: ProofStateEnum::Requested,
        role: ProofRole::Holder,
        requested_date: None,
        completed_date: None,
        schema: Some(
            ProofSchema {
                ecosystem: None,
                id: Uuid::new_v4().into(),
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                deleted_at: None,
                name: "test-holder-proof".into(),
                expire_duration: 300,
                imported_source_url: None,
                organisation: dummy_organisation(None).into(),
                input_schemas: vec![ProofInputSchema {
                    claim_schemas: Default::default(),
                    credential_schema: test_credential_schema(format).into(),
                }]
                .into(),
            }
            .into(),
        ),
        claims: Default::default(),
        verifier_identifier: None,
        verifier_key: Some(test_key("ECDSA").into()),
        verifier_certificate: None,
        interaction: Some(interaction.into()),
        profile: None,
        proof_blob_id: None,
        engagement: None,
        webhook_url: None,
        subscriber_information: None,
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
                .with(
                    eq(url.clone()),
                    always(),
                    always(),
                    eq(Method::Post),
                    always(),
                )
                .return_once(move |_, _, _, _, _| {
                    Ok(Response {
                        body: b"{}".to_vec(),
                        headers: Default::default(),
                        status: StatusCode(200),
                        request: Request {
                            body: None,
                            headers: Default::default(),
                            method: Method::Post,
                            url: url_for_response,
                            timeout: None,
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
        .returning(move |_| Ok(arc.clone()));

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
        .expect_key_algorithm_from_key()
        .returning(move |_| Ok(arc.clone()));

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
        .return_once(|_| Ok(Arc::new(credential_formatter)));

    let protocol = setup_protocol(TestInputs {
        credential_formatter_provider: formatter_provider,
        ..Default::default()
    });

    let proof = test_verifier_proof("JWT".into(), None);
    let format_type_mapper: FormatMapper = Arc::new(move |_| Ok(FormatType::Jwt));

    let ShareResponse {
        url,
        interaction_id,
        ..
    } = protocol
        .verifier_share_proof(
            &proof,
            format_type_mapper,
            None,
            Some(ShareProofRequestParamsDTO {
                client_id_scheme: Some(ClientIdPrefix::RedirectUri),
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
        .return_once(|_| Ok(Arc::new(credential_formatter)));

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
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            public_key: vec![],
            name: "key".to_string(),
            key_reference: None,
            storage_type: "INTERNAL".to_string(),
            key_type: "ECDSA".to_string(),
            organisation: dummy_organisation(None).into(),
        },
        reference: "1".to_string(),
    };

    let proof = test_verifier_proof("JWT".into(), Some(key_agreement_key));
    let format_type_mapper: FormatMapper = Arc::new(move |_| Ok(FormatType::Jwt));

    let ShareResponse { url, .. } = protocol
        .verifier_share_proof(
            &proof,
            format_type_mapper,
            None,
            Some(ShareProofRequestParamsDTO {
                client_id_scheme: Some(ClientIdPrefix::RedirectUri),
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
        .return_once(|_| Ok(Arc::new(credential_formatter)));

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
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            public_key: vec![],
            name: "key".to_string(),
            key_reference: None,
            storage_type: "INTERNAL".to_string(),
            key_type: "EDDSA".to_string(),
            organisation: dummy_organisation(None).into(),
        },
        reference: "1".to_string(),
    };

    let proof = test_verifier_proof("JWT".into(), Some(key_agreement_key));
    let format_type_mapper: FormatMapper = Arc::new(move |_| Ok(FormatType::Jwt));

    let ShareResponse { url, .. } = protocol
        .verifier_share_proof(
            &proof,
            format_type_mapper,
            None,
            Some(ShareProofRequestParamsDTO {
                client_id_scheme: Some(ClientIdPrefix::RedirectUri),
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
async fn test_holder_submit_direct_post_jwt_no_encryption_keys_fails() {
    let protocol = setup_protocol(TestInputs::default());
    let proof = test_holder_proof(
        test_holder_interaction_data(Some(ResponseMode::DirectPostJwt)),
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
        test_holder_interaction_data(Some(ResponseMode::DirectPost)),
        "MDOC".into(),
    );

    // Verifies: response_mode validation passes, no MDOC-requires-encryption error, HTTP POST succeeds
    let result = protocol.holder_submit_proof(&proof, vec![]).await;
    assert!(result.is_ok(), "Expected Ok but got: {:?}", result);
}

/// Transaction data type whose entries clash when assigned to the same presentation
const CONFLICTING_TX_TYPE: &str = "QES_APPROVAL";
/// Second clashing type, to assert conflicts are detected per type
const OTHER_CONFLICTING_TX_TYPE: &str = "OTHER_APPROVAL";
/// Transaction data type declaring `SUPPORTS_MULTIPLE_TX_DATA_PER_PRESENTATION`
const CONFLICT_FREE_TX_TYPE: &str = "MULTI_APPROVAL";

fn interaction_with_tx_data(
    entries: Vec<(TransactionDataId, &str, Vec<&str>)>,
) -> OpenID4VPHolderInteractionData {
    interaction_with_typed_tx_data(
        entries
            .into_iter()
            .map(|(id, raw, credential_query_ids)| {
                (id, raw, credential_query_ids, CONFLICTING_TX_TYPE)
            })
            .collect(),
    )
}

fn interaction_with_typed_tx_data(
    entries: Vec<(TransactionDataId, &str, Vec<&str>, &str)>,
) -> OpenID4VPHolderInteractionData {
    let mut data = test_holder_interaction_data(Some(ResponseMode::DirectPost));
    let mut map = IndexMap::new();
    for (id, raw, credential_query_ids, transaction_data_type) in entries {
        map.insert(
            id,
            ValidatedHolderTxData {
                raw: raw.to_string(),
                credential_query_ids: credential_query_ids
                    .into_iter()
                    .map(CredentialQueryId::from)
                    .collect(),
                transaction_data_type: transaction_data_type.into(),
            },
        );
    }
    data.transaction_data = HolderTxData::Validated(map);
    data
}

/// One credential query per `(id, multiple)` entry
fn dcql_query_with(queries: &[(&str, bool)]) -> DcqlQuery {
    let mut query = dummy_dcql_query(true);
    let template = query.credentials.remove(0);
    query.credentials = queries
        .iter()
        .map(|(id, multiple)| CredentialQuery {
            id: CredentialQueryId::from(*id),
            multiple: *multiple,
            ..template.clone()
        })
        .collect();
    query
}

/// Resolves [`CONFLICT_FREE_TX_TYPE`] to a provider supporting multiple entries per
/// presentation, any other type to one that does not.
fn tx_data_provider() -> MockTransactionDataProvider {
    let mut provider = MockTransactionDataProvider::new();
    provider
        .expect_get_transaction_data_by_name()
        .returning(|name| {
            let features = if name.to_string() == CONFLICT_FREE_TX_TYPE {
                vec![Features::SupportsMultipleTxDataPerPresentation]
            } else {
                vec![]
            };

            let mut transaction_data = MockTransactionData::new();
            transaction_data
                .expect_get_capabilities()
                .returning(move || TransactionDataCapabilities {
                    transaction_data_types: vec![],
                    formats: vec![FormatType::Mdoc],
                    features: features.clone(),
                });
            Ok(Arc::new(transaction_data))
        });
    provider
}

/// Assigns the transaction data and reduces the result to `(credential query id, raw entries)`
/// per (possibly duplicated) presentation.
fn assign(
    interaction_data: &OpenID4VPHolderInteractionData,
    credential_presentations: Vec<FormattedCredentialPresentation>,
) -> Result<Vec<(String, Vec<String>)>, VerificationProtocolError> {
    let assignments = super::assign_transaction_data(
        credential_presentations,
        interaction_data,
        &tx_data_provider(),
    )?;

    Ok(assignments
        .into_iter()
        .map(|assignment| {
            (
                assignment
                    .credential_presentation
                    .credential_query_id
                    .to_string(),
                assignment
                    .transaction_data
                    .into_iter()
                    .map(|tx_data| tx_data.data)
                    .collect(),
            )
        })
        .collect())
}

fn tx_id() -> TransactionDataId {
    TransactionDataId::from(Uuid::new_v4())
}

fn test_credential_presentation(
    credential_query_id: &str,
    transaction_data_ids: Vec<TransactionDataId>,
) -> FormattedCredentialPresentation {
    FormattedCredentialPresentation {
        presentation: "presentation-token".to_string(),
        credential_schema: test_credential_schema("MDOC".into()),
        credential_query_id: CredentialQueryId::from(credential_query_id),
        holder_did: None,
        key: test_key("ECDSA"),
        jwk_key_id: None,
        transaction_data_ids,
    }
}

#[tokio::test]
async fn test_holder_submit_transaction_data_unknown_selection_fails() {
    let protocol = setup_protocol(TestInputs::default());

    let tx_id = TransactionDataId::from(Uuid::new_v4());
    let interaction = interaction_with_tx_data(vec![(tx_id, "raw-tx", vec!["cred1"])]);
    let proof = test_holder_proof(interaction, "MDOC".into());

    // Select a transaction data id that does not exist in the interaction data.
    let presentation =
        test_credential_presentation("cred1", vec![TransactionDataId::from(Uuid::new_v4())]);

    let result = protocol
        .holder_submit_proof(&proof, vec![presentation])
        .await;

    assert!(matches!(
        &result,
        Err(VerificationProtocolError::InvalidTransactionDataAssignment(
            _
        ))
    ));
}

#[tokio::test]
async fn test_holder_submit_transaction_data_non_applicable_selection_fails() {
    let protocol = setup_protocol(TestInputs::default());

    // Transaction data applies only to `cred2`.
    let tx_id = TransactionDataId::from(Uuid::new_v4());
    let interaction = interaction_with_tx_data(vec![(tx_id, "raw-tx", vec!["cred2"])]);
    let proof = test_holder_proof(interaction, "MDOC".into());

    // `cred1` selects it even though it is not applicable to `cred1`.
    let presentation = test_credential_presentation("cred1", vec![tx_id]);

    let result = protocol
        .holder_submit_proof(&proof, vec![presentation])
        .await;

    assert!(matches!(
        &result,
        Err(VerificationProtocolError::InvalidTransactionDataAssignment(
            _
        ))
    ));
}

#[tokio::test]
async fn test_holder_submit_transaction_data_duplicate_selection_fails() {
    let protocol = setup_protocol(TestInputs {
        transaction_data_provider: tx_data_provider(),
        ..Default::default()
    });

    let tx_id = TransactionDataId::from(Uuid::new_v4());
    let interaction = interaction_with_tx_data(vec![(tx_id, "raw-tx", vec!["cred1"])]);
    let proof = test_holder_proof(interaction, "MDOC".into());

    // The same transaction data id is selected twice.
    let presentation = test_credential_presentation("cred1", vec![tx_id, tx_id]);

    let result = protocol
        .holder_submit_proof(&proof, vec![presentation])
        .await;

    assert!(matches!(
        &result,
        Err(VerificationProtocolError::InvalidTransactionDataAssignment(
            _
        ))
    ));
}

#[test]
fn test_assign_transaction_data_auto_assigns_entry_to_applicable_presentation() {
    let (tx1, tx2) = (tx_id(), tx_id());
    let mut interaction = interaction_with_tx_data(vec![
        (tx1, "tx1", vec!["cred1"]),
        (tx2, "tx2", vec!["cred2"]),
    ]);
    interaction.dcql_query = dcql_query_with(&[("cred1", false), ("cred2", false)]);

    let result = assign(
        &interaction,
        vec![
            test_credential_presentation("cred1", vec![]),
            test_credential_presentation("cred2", vec![]),
        ],
    )
    .unwrap();

    assert_eq!(
        vec![
            ("cred1".to_string(), vec!["tx1".to_string()]),
            ("cred2".to_string(), vec!["tx2".to_string()]),
        ],
        result
    );
}

#[test]
fn test_assign_transaction_data_auto_assigns_conflict_free_entries_to_same_presentation() {
    let (tx1, tx2) = (tx_id(), tx_id());
    let mut interaction = interaction_with_typed_tx_data(vec![
        (tx1, "tx1", vec!["cred1"], CONFLICT_FREE_TX_TYPE),
        (tx2, "tx2", vec!["cred1"], CONFLICT_FREE_TX_TYPE),
    ]);
    interaction.dcql_query = dcql_query_with(&[("cred1", false)]);

    let result = assign(
        &interaction,
        vec![test_credential_presentation("cred1", vec![])],
    )
    .unwrap();

    assert_eq!(
        vec![(
            "cred1".to_string(),
            vec!["tx1".to_string(), "tx2".to_string()]
        )],
        result
    );
}

#[test]
fn test_assign_transaction_data_auto_assigns_entries_of_different_types_to_same_presentation() {
    let (tx1, tx2) = (tx_id(), tx_id());
    let mut interaction = interaction_with_typed_tx_data(vec![
        (tx1, "tx1", vec!["cred1"], CONFLICTING_TX_TYPE),
        (tx2, "tx2", vec!["cred1"], OTHER_CONFLICTING_TX_TYPE),
    ]);
    interaction.dcql_query = dcql_query_with(&[("cred1", false)]);

    let result = assign(
        &interaction,
        vec![test_credential_presentation("cred1", vec![])],
    )
    .unwrap();

    assert_eq!(
        vec![(
            "cred1".to_string(),
            vec!["tx1".to_string(), "tx2".to_string()]
        )],
        result
    );
}

#[test]
fn test_assign_transaction_data_auto_assign_conflicting_entries_fails_without_multiple() {
    let (tx1, tx2) = (tx_id(), tx_id());
    let mut interaction = interaction_with_tx_data(vec![
        (tx1, "tx1", vec!["cred1"]),
        (tx2, "tx2", vec!["cred1"]),
    ]);
    interaction.dcql_query = dcql_query_with(&[("cred1", false)]);

    let result = assign(
        &interaction,
        vec![test_credential_presentation("cred1", vec![])],
    );

    assert!(matches!(
        result,
        Err(VerificationProtocolError::InvalidTransactionDataAssignment(
            _
        ))
    ));
}

#[test]
fn test_assign_transaction_data_auto_assign_duplicates_presentation_for_conflicting_entries() {
    let (tx1, tx2, tx3) = (tx_id(), tx_id(), tx_id());
    let mut interaction = interaction_with_tx_data(vec![
        (tx1, "tx1", vec!["cred1"]),
        (tx2, "tx2", vec!["cred1"]),
        (tx3, "tx3", vec!["cred1"]),
    ]);
    interaction.dcql_query = dcql_query_with(&[("cred1", true)]);

    let result = assign(
        &interaction,
        vec![test_credential_presentation("cred1", vec![])],
    )
    .unwrap();

    // one presentation per conflicting entry
    assert_eq!(
        vec![
            ("cred1".to_string(), vec!["tx1".to_string()]),
            ("cred1".to_string(), vec!["tx2".to_string()]),
            ("cred1".to_string(), vec!["tx3".to_string()]),
        ],
        result
    );
}

#[test]
fn test_assign_transaction_data_auto_assign_prefers_presentation_without_conflict() {
    let (tx1, tx2) = (tx_id(), tx_id());
    let mut interaction = interaction_with_tx_data(vec![
        (tx1, "tx1", vec!["cred1"]),
        (tx2, "tx2", vec!["cred1"]),
    ]);
    interaction.dcql_query = dcql_query_with(&[("cred1", true)]);

    // two credentials answering the same query, so no presentation needs to be duplicated
    let result = assign(
        &interaction,
        vec![
            test_credential_presentation("cred1", vec![]),
            test_credential_presentation("cred1", vec![]),
        ],
    )
    .unwrap();

    assert_eq!(
        vec![
            ("cred1".to_string(), vec!["tx1".to_string()]),
            ("cred1".to_string(), vec!["tx2".to_string()]),
        ],
        result
    );
}

#[test]
fn test_assign_transaction_data_auto_assigns_to_duplicated_presentation() {
    let (tx1, tx2, tx3, tx4) = (tx_id(), tx_id(), tx_id(), tx_id());
    let mut interaction = interaction_with_typed_tx_data(vec![
        (tx1, "tx1", vec!["cred1"], CONFLICTING_TX_TYPE),
        (tx2, "tx2", vec!["cred1"], CONFLICTING_TX_TYPE),
        (tx3, "tx3", vec!["cred1"], OTHER_CONFLICTING_TX_TYPE),
        (tx4, "tx4", vec!["cred1"], OTHER_CONFLICTING_TX_TYPE),
    ]);
    interaction.dcql_query = dcql_query_with(&[("cred1", true)]);

    let result = assign(
        &interaction,
        vec![test_credential_presentation("cred1", vec![])],
    )
    .unwrap();

    // `tx2` duplicates the presentation, `tx4` is assigned to that duplicate instead of
    // duplicating the presentation a second time
    assert_eq!(
        vec![
            (
                "cred1".to_string(),
                vec!["tx1".to_string(), "tx3".to_string()]
            ),
            (
                "cred1".to_string(),
                vec!["tx2".to_string(), "tx4".to_string()]
            ),
        ],
        result
    );
}

#[test]
fn test_assign_transaction_data_reshuffles_existing_assignment() {
    let (tx1, tx2) = (tx_id(), tx_id());
    let mut interaction = interaction_with_tx_data(vec![
        (tx1, "tx1", vec!["cred1", "cred2"]),
        (tx2, "tx2", vec!["cred1"]),
    ]);
    interaction.dcql_query = dcql_query_with(&[("cred1", false), ("cred2", false)]);

    let result = assign(
        &interaction,
        vec![
            test_credential_presentation("cred1", vec![]),
            test_credential_presentation("cred2", vec![]),
        ],
    )
    .unwrap();

    // `tx1` is initially assigned to `cred1` but moves to `cred2`, making room for `tx2`
    assert_eq!(
        vec![
            ("cred1".to_string(), vec!["tx2".to_string()]),
            ("cred2".to_string(), vec!["tx1".to_string()]),
        ],
        result
    );
}

#[test]
fn test_assign_transaction_data_does_not_reshuffle_onto_missing_presentation() {
    let (tx1, tx2) = (tx_id(), tx_id());
    let mut interaction = interaction_with_tx_data(vec![
        (tx1, "tx1", vec!["cred1", "cred3"]),
        (tx2, "tx2", vec!["cred1"]),
    ]);
    interaction.dcql_query =
        dcql_query_with(&[("cred1", false), ("cred2", false), ("cred3", false)]);

    // `cred3` is not submitted, so `tx1` cannot be moved out of the way for `tx2`
    let result = assign(
        &interaction,
        vec![
            test_credential_presentation("cred1", vec![]),
            test_credential_presentation("cred2", vec![]),
        ],
    );

    let Err(VerificationProtocolError::InvalidTransactionDataAssignment(message)) = result else {
        panic!("Expected InvalidTransactionDataAssignment, got: {result:?}");
    };
    assert!(
        message.contains(&tx2.to_string()),
        "Expected the unassignable entry id in: {message}"
    );
}

#[test]
fn test_assign_transaction_data_does_not_reshuffle_onto_pinned_entry() {
    let (tx1, tx2, tx3) = (tx_id(), tx_id(), tx_id());
    let mut interaction = interaction_with_tx_data(vec![
        (tx1, "tx1", vec!["cred1"]),
        (tx2, "tx2", vec!["cred1", "cred2"]),
        (tx3, "tx3", vec!["cred2"]),
    ]);
    interaction.dcql_query = dcql_query_with(&[("cred1", false), ("cred2", true)]);

    // `tx1` is explicitly selected for `cred1`, so `tx2` must not be moved there for `tx3`
    let result = assign(
        &interaction,
        vec![
            test_credential_presentation("cred1", vec![tx1]),
            test_credential_presentation("cred2", vec![]),
        ],
    )
    .unwrap();

    assert_eq!(
        vec![
            ("cred1".to_string(), vec!["tx1".to_string()]),
            ("cred2".to_string(), vec!["tx2".to_string()]),
            ("cred2".to_string(), vec!["tx3".to_string()]),
        ],
        result
    );
}

#[test]
fn test_assign_transaction_data_pinned_entry_blocks_reshuffling_without_multiple() {
    let (tx1, tx2, tx3) = (tx_id(), tx_id(), tx_id());
    let mut interaction = interaction_with_tx_data(vec![
        (tx1, "tx1", vec!["cred1"]),
        (tx2, "tx2", vec!["cred1", "cred2"]),
        (tx3, "tx3", vec!["cred2"]),
    ]);
    interaction.dcql_query = dcql_query_with(&[("cred1", false), ("cred2", false)]);

    // as above, but `cred2` cannot be duplicated either
    let result = assign(
        &interaction,
        vec![
            test_credential_presentation("cred1", vec![tx1]),
            test_credential_presentation("cred2", vec![]),
        ],
    );

    let Err(VerificationProtocolError::InvalidTransactionDataAssignment(message)) = result else {
        panic!("Expected InvalidTransactionDataAssignment, got: {result:?}");
    };
    assert!(
        message.contains(&tx3.to_string()),
        "Expected the unassignable entry id in: {message}"
    );
}

#[test]
fn test_assign_transaction_data_without_applicable_presentation_fails() {
    let tx1 = tx_id();
    let mut interaction = interaction_with_tx_data(vec![(tx1, "tx1", vec!["cred2"])]);
    interaction.dcql_query = dcql_query_with(&[("cred1", false), ("cred2", false)]);

    // no presentation for `cred2`, which the transaction data is bound to
    let result = assign(
        &interaction,
        vec![test_credential_presentation("cred1", vec![])],
    );

    let Err(VerificationProtocolError::InvalidTransactionDataAssignment(message)) = result else {
        panic!("Expected InvalidTransactionDataAssignment, got: {result:?}");
    };
    assert!(
        message.contains(&tx1.to_string()),
        "Expected the unassigned entry id in: {message}"
    );
}

#[test]
fn test_assign_transaction_data_explicit_conflicting_selection_fails_without_multiple() {
    let (tx1, tx2) = (tx_id(), tx_id());
    let mut interaction = interaction_with_tx_data(vec![
        (tx1, "tx1", vec!["cred1"]),
        (tx2, "tx2", vec!["cred1"]),
    ]);
    interaction.dcql_query = dcql_query_with(&[("cred1", false)]);

    let result = assign(
        &interaction,
        vec![test_credential_presentation("cred1", vec![tx1, tx2])],
    );

    assert!(matches!(
        result,
        Err(VerificationProtocolError::InvalidTransactionDataAssignment(
            _
        ))
    ));
}

#[test]
fn test_assign_transaction_data_explicit_conflicting_selection_duplicates_presentation() {
    let (tx1, tx2) = (tx_id(), tx_id());
    let mut interaction = interaction_with_tx_data(vec![
        (tx1, "tx1", vec!["cred1"]),
        (tx2, "tx2", vec!["cred1"]),
    ]);
    interaction.dcql_query = dcql_query_with(&[("cred1", true)]);

    let result = assign(
        &interaction,
        vec![test_credential_presentation("cred1", vec![tx1, tx2])],
    )
    .unwrap();

    assert_eq!(
        vec![
            ("cred1".to_string(), vec!["tx1".to_string()]),
            ("cred1".to_string(), vec!["tx2".to_string()]),
        ],
        result
    );
}

#[test]
fn test_assign_transaction_data_auto_assigns_to_explicitly_created_duplicate() {
    let (tx1, tx2, tx3, tx4) = (tx_id(), tx_id(), tx_id(), tx_id());
    let mut interaction = interaction_with_typed_tx_data(vec![
        (tx1, "tx1", vec!["cred1"], CONFLICTING_TX_TYPE),
        (tx2, "tx2", vec!["cred1"], CONFLICTING_TX_TYPE),
        (tx3, "tx3", vec!["cred1"], OTHER_CONFLICTING_TX_TYPE),
        (tx4, "tx4", vec!["cred1"], OTHER_CONFLICTING_TX_TYPE),
    ]);
    interaction.dcql_query = dcql_query_with(&[("cred1", true)]);

    // `tx1` and `tx2` are selected explicitly, `tx3` and `tx4` are auto-assigned to the
    // presentation and the duplicate created by the explicit selection
    let result = assign(
        &interaction,
        vec![test_credential_presentation("cred1", vec![tx1, tx2])],
    )
    .unwrap();

    assert_eq!(
        vec![
            (
                "cred1".to_string(),
                vec!["tx1".to_string(), "tx3".to_string()]
            ),
            (
                "cred1".to_string(),
                vec!["tx2".to_string(), "tx4".to_string()]
            ),
        ],
        result
    );
}

fn unsigned_request_query(client_id: &str) -> String {
    let client_metadata = ClientMetadata {
        vp_formats_supported: HashMap::from([(
            "mso_mdoc".to_string(),
            PresentationFormat::MdocAlgs(MdocAlgs {
                issuerauth_alg_values: vec![],
                deviceauth_alg_values: vec![],
            }),
        )]),
        ..Default::default()
    };

    let query_params = AuthorizationRequestQueryParams {
        client_id: client_id.to_string(),
        state: Some("test-state".to_string()),
        nonce: Some("test-nonce-12345".to_string()),
        response_type: Some("vp_token".to_string()),
        response_mode: Some(ResponseMode::DirectPost),
        response_uri: Some("https://verifier.example.com/response".to_string()),
        client_metadata: Some(serde_json::to_string(&client_metadata).unwrap()),
        dcql_query: Some(serde_json::to_string(&dummy_dcql_query(true)).unwrap()),
        ..Default::default()
    };

    serde_qs::to_string(&query_params).unwrap()
}

#[tokio::test]
async fn test_request_from_openid4vp_query_unsigned_request() {
    let protocol = setup_protocol(TestInputs {
        ..Default::default()
    });

    let (request, verifier_details) = protocol
        .request_from_openid4vp_query(&unsigned_request_query(
            "redirect_uri:https://verifier.example.com/response",
        ))
        .await
        .unwrap();

    assert!(verifier_details.is_none());
    assert_eq!(
        "redirect_uri:https://verifier.example.com/response",
        request.client_id
    );
    assert_eq!(Some("test-state".to_string()), request.state);
    assert_eq!(Some("test-nonce-12345".to_string()), request.nonce);
    assert_eq!(Some("vp_token".to_string()), request.response_type);
    assert_eq!(Some(ResponseMode::DirectPost), request.response_mode);
    assert_eq!(
        Some("https://verifier.example.com/response".parse().unwrap()),
        request.response_uri
    );
    assert_eq!(dummy_dcql_query(true), request.dcql_query);
    assert!(request.client_metadata.is_some());
}

#[tokio::test]
async fn test_request_from_openid4vp_query_unsigned_request_fails_for_signed_only_scheme() {
    let protocol = setup_protocol(TestInputs {
        ..Default::default()
    });

    let result = protocol
        .request_from_openid4vp_query(&unsigned_request_query(
            "verifier_attestation:https://verifier.example.com",
        ))
        .await;

    assert!(matches!(
        result,
        Err(VerificationProtocolError::InvalidRequest(reason))
            if reason.contains("requires a signed request object")
    ));
}

#[tokio::test]
async fn test_request_from_openid4vp_query_unsigned_request_fails_for_unsupported_scheme() {
    let protocol = setup_protocol(TestInputs::default());

    // `x509_san_dns` is not in `holder.supportedClientIdSchemes` of the test params
    let result = protocol
        .request_from_openid4vp_query(&unsigned_request_query("x509_san_dns:verifier.example.com"))
        .await;

    assert!(matches!(
        result,
        Err(VerificationProtocolError::InvalidRequest(reason))
            if reason.contains("Unsupported client_id_scheme")
    ));
}
