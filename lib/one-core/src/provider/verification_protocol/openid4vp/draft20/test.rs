use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;

use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use serde_json::{Value, json};
use shared_types::DidValue;
use similar_asserts::assert_eq;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;
use wiremock::http::Method;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::OpenID4VP20HTTP;
use super::model::OpenID4Vp20Params;
use crate::common_mapper::PublicKeyWithJwk;
use crate::config::core_config::{CoreConfig, FormatType, KeyAlgorithmType};
use crate::model::credential_schema::{CredentialSchema, CredentialSchemaType, LayoutType};
use crate::model::did::{Did, DidType, KeyRole, RelatedKey};
use crate::model::identifier::{Identifier, IdentifierState, IdentifierType};
use crate::model::key::{Key, PublicKeyJwk, PublicKeyJwkEllipticData};
use crate::model::proof::{Proof, ProofRole, ProofStateEnum};
use crate::model::proof_schema::{ProofInputSchema, ProofSchema};
use crate::provider::credential_formatter::MockCredentialFormatter;
use crate::provider::credential_formatter::model::{FormatterCapabilities, IdentifierDetails};
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::did_method::DidMethod;
use crate::provider::did_method::jwk::JWKDidMethod;
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::http_client::reqwest_client::ReqwestClient;
use crate::provider::key_algorithm::MockKeyAlgorithm;
use crate::provider::key_algorithm::key::{
    KeyHandle, MockSignaturePublicKeyHandle, SignatureKeyHandle,
};
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_storage::provider::MockKeyProvider;
use crate::provider::presentation_formatter::provider::MockPresentationFormatterProvider;
use crate::provider::verification_protocol::dto::ShareResponse;
use crate::provider::verification_protocol::openid4vp::VerificationProtocolError;
use crate::provider::verification_protocol::openid4vp::draft20::model::OpenID4VC20PresentationVerifierParams;
use crate::provider::verification_protocol::openid4vp::model::{
    ClientIdScheme, OpenID4VCPresentationHolderParams, OpenID4VCRedirectUriParams, OpenID4VPAlgs,
    OpenID4VPDraftClientMetadata, OpenID4VPHolderInteractionData, OpenID4VPPresentationDefinition,
    OpenID4VpPresentationFormat,
};
use crate::provider::verification_protocol::{
    FormatMapper, TypeToDescriptorMapper, VerificationProtocol, deserialize_interaction_data,
};
use crate::service::certificate::validator::MockCertificateValidator;
use crate::service::proof::dto::ShareProofRequestParamsDTO;
use crate::service::storage_proxy::MockStorageProxy;
use crate::service::test_utilities::{dummy_identifier, dummy_organisation};

#[derive(Default)]
struct TestInputs {
    pub credential_formatter_provider: MockCredentialFormatterProvider,
    pub presentation_formatter_provider: MockPresentationFormatterProvider,
    pub key_algorithm_provider: MockKeyAlgorithmProvider,
    pub key_provider: MockKeyProvider,
    pub did_method_provider: MockDidMethodProvider,
    pub certificate_validator: MockCertificateValidator,
    pub params: Option<OpenID4Vp20Params>,
}

fn setup_protocol(inputs: TestInputs) -> OpenID4VP20HTTP {
    OpenID4VP20HTTP::new(
        Some("http://base_url".to_string()),
        Arc::new(inputs.credential_formatter_provider),
        Arc::new(inputs.presentation_formatter_provider),
        Arc::new(inputs.did_method_provider),
        Arc::new(inputs.key_algorithm_provider),
        Arc::new(inputs.key_provider),
        Arc::new(inputs.certificate_validator),
        Arc::new(ReqwestClient::default()),
        inputs.params.unwrap_or(generic_params()),
        Arc::new(CoreConfig::default()),
    )
}

fn generic_params() -> OpenID4Vp20Params {
    OpenID4Vp20Params {
        client_metadata_by_value: false,
        presentation_definition_by_value: false,
        allow_insecure_http_transport: true,
        use_request_uri: false,
        url_scheme: "openid4vp".to_string(),
        holder: OpenID4VCPresentationHolderParams {
            supported_client_id_schemes: vec![
                ClientIdScheme::RedirectUri,
                ClientIdScheme::VerifierAttestation,
                ClientIdScheme::Did,
            ],
        },
        verifier: OpenID4VC20PresentationVerifierParams {
            supported_client_id_schemes: vec![
                ClientIdScheme::RedirectUri,
                ClientIdScheme::VerifierAttestation,
                ClientIdScheme::Did,
            ],
        },
        redirect_uri: OpenID4VCRedirectUriParams {
            enabled: true,
            allowed_schemes: vec!["https".to_string()],
        },
        predefined_client_metadata: None,
    }
}

fn test_client_request_response(
    client_id: &str,
    client_id_scheme: &str,
    header: Option<Value>,
) -> String {
    [
        header.unwrap_or(json!({"alg": "none"})),
        json!({
          "response_type": "vp_token",
          "state": "0193a9e2-edb7-48b7-bf82-3cbe6a74d711",
          "nonce": "nonce123",
          "response_mode": "direct_post",
          "client_id_scheme": client_id_scheme,
          "client_id": client_id,
          "client_metadata": {
            "jwks": {
              "keys": [{
                "kid": "not-a-uuid",
                "kty": "EC",
                "use": "enc",
                "crv": "P-256",
                "x": "cd_LTtCQnat2XnDElumvgQAM5ZcnUMVTkPig458C1yc",
                "y": "iaQmPUgir80I2XCFqn2_KPqdWH0PxMzCCP8W3uPxlUA"
              }]
            },
            "vp_formats": {
              "jwt_vp_json": {
                "alg": [
                  "EdDSA",
                  "ES256"
                ]
              }
            },
            "authorization_encrypted_response_alg": "ECDH-ES",
            "authorization_encrypted_response_enc": "A256GCM"
          },
          "presentation_definition": {
            "id": "75fcc8e1-a14c-4509-9831-993c5fb37e26",
            "input_descriptors": [
              {
                "id": "input_0",
                "format": {
                  "jwt_vc_json": {
                    "alg": [
                      "EdDSA",
                      "ES256"
                    ]
                  }
                },
                "constraints": {
                  "fields": [
                    {
                      "id": "80ce6ddc-d994-4b27-8d80-41ce7a53a66e",
                      "path": [
                        "$.vc.credentialSubject.cat1"
                      ],
                      "optional": false,
                    },
                    {
                      "id": "58ca9c64-626b-49c1-856c-81f08932d112",
                      "path": [
                        "$.vc.credentialSubject.cat2"
                      ],
                      "optional": false,
                    }
                  ],
                  "validity_credential_nbf": null
                }
              }
            ]
          },
          "response_uri": client_id,
        }),
    ]
    .map(|json| json.to_string())
    .map(|s| Base64UrlSafeNoPadding::encode_to_string(s).unwrap())
    .join(".")
}

#[tokio::test]
async fn test_share_proof() {
    let mut credential_formatter_provider = MockCredentialFormatterProvider::new();
    let mut credential_formatter = MockCredentialFormatter::new();
    credential_formatter
        .expect_get_capabilities()
        .returning(FormatterCapabilities::default);
    let arc = Arc::new(credential_formatter);
    credential_formatter_provider
        .expect_get_credential_formatter()
        .returning(move |_| Some(arc.clone()));
    let protocol = setup_protocol(TestInputs {
        credential_formatter_provider,
        ..Default::default()
    });

    let proof_id = Uuid::new_v4();
    let proof = test_proof(proof_id, "JWT");

    let format_type_mapper: FormatMapper = Arc::new(move |_| Ok(FormatType::Jwt));

    let type_to_descriptor_mapper: TypeToDescriptorMapper = Arc::new(move |_| Ok(HashMap::new()));

    let encryption_key_jwk = PublicKeyWithJwk {
        key_id: Uuid::new_v4().into(),
        jwk: PublicKeyJwk::Ec(PublicKeyJwkEllipticData {
            alg: None,
            r#use: None,
            kid: None,
            crv: "P-256".to_string(),
            x: "x".to_string(),
            y: None,
        }),
    };

    let ShareResponse {
        url,
        interaction_id,
        ..
    } = protocol
        .verifier_share_proof(
            &proof,
            format_type_mapper,
            Some(encryption_key_jwk),
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

    assert_eq!(
        HashSet::<&str>::from_iter([
            "response_mode",
            "client_metadata_uri",
            "nonce",
            "response_type",
            "state",
            "client_id_scheme",
            "response_uri",
            "client_id",
            "presentation_definition_uri",
        ]),
        HashSet::from_iter(query_pairs.keys().map(|k| k.as_ref()))
    );

    assert_eq!("vp_token", query_pairs.get("response_type").unwrap());

    assert_eq!("direct_post", query_pairs.get("response_mode").unwrap());

    assert_eq!(
        &interaction_id.to_string(),
        query_pairs.get("state").unwrap()
    );
    assert_eq!("redirect_uri", query_pairs.get("client_id_scheme").unwrap());

    assert_eq!(
        "http://base_url/ssi/openid4vp/draft-20/response",
        query_pairs.get("response_uri").unwrap()
    );

    assert_eq!(
        "http://base_url/ssi/openid4vp/draft-20/response",
        query_pairs.get("client_id").unwrap()
    );

    assert_eq!(
        &format!(
            "http://base_url/ssi/openid4vp/draft-20/{}/presentation-definition",
            proof.id
        ),
        query_pairs.get("presentation_definition_uri").unwrap()
    );

    assert_eq!(
        &format!(
            "http://base_url/ssi/openid4vp/draft-20/{}/client-metadata",
            proof.id
        ),
        query_pairs.get("client_metadata_uri").unwrap()
    );
}

#[tokio::test]
async fn test_response_mode_direct_post_jwt_for_mdoc() {
    let mut credential_formatter_provider = MockCredentialFormatterProvider::new();
    let mut credential_formatter = MockCredentialFormatter::new();
    credential_formatter
        .expect_get_capabilities()
        .returning(FormatterCapabilities::default);
    let arc = Arc::new(credential_formatter);
    credential_formatter_provider
        .expect_get_credential_formatter()
        .returning(move |_| Some(arc.clone()));
    let protocol = setup_protocol(TestInputs {
        credential_formatter_provider,
        ..Default::default()
    });

    let proof = test_proof(Uuid::new_v4(), "MDOC");

    let format_type_mapper: FormatMapper = Arc::new(move |_| Ok(FormatType::Mdoc));

    let type_to_descriptor_mapper: TypeToDescriptorMapper = Arc::new(move |_| Ok(HashMap::new()));

    let encryption_key_jwk = PublicKeyWithJwk {
        key_id: Uuid::new_v4().into(),
        jwk: PublicKeyJwk::Ec(PublicKeyJwkEllipticData {
            alg: None,
            r#use: None,
            kid: None,
            crv: "P-256".to_string(),
            x: "x".to_string(),
            y: None,
        }),
    };

    let ShareResponse { url, .. } = protocol
        .verifier_share_proof(
            &proof,
            format_type_mapper,
            Some(encryption_key_jwk),
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
}

fn test_proof(proof_id: Uuid, credential_format: &str) -> Proof {
    Proof {
        id: proof_id.into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        issuance_date: OffsetDateTime::now_utc(),
        protocol: "OPENID4VP_DRAFT20".to_string(),
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
                claim_schemas: None,
                credential_schema: Some(CredentialSchema {
                    id: Uuid::new_v4().into(),
                    external_schema: false,
                    deleted_at: None,
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    name: "test-credential-schema".to_string(),
                    format: credential_format.to_string(),
                    revocation_method: "NONE".to_string(),
                    wallet_storage_type: None,
                    layout_type: LayoutType::Card,
                    layout_properties: None,
                    schema_id: "test_schema_id".to_string(),
                    schema_type: CredentialSchemaType::ProcivisOneSchema2024,
                    imported_source_url: "test_imported_src_url".to_string(),
                    allow_suspension: false,
                    claim_schemas: None,
                    organisation: None,
                }),
            }]),
        }),
        claims: None,
        verifier_identifier: Some(Identifier {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            name: "identifier".to_string(),
            r#type: IdentifierType::Did,
            is_remote: false,
            state: IdentifierState::Active,
            deleted_at: None,
            organisation: None,
            did: None,
            key: None,
            certificates: None,
        }),
        holder_identifier: None,
        verifier_key: None,
        verifier_certificate: None,
        interaction: None,
        profile: None,
    }
}

#[tokio::test]
async fn test_share_proof_with_use_request_uri() {
    let protocol = setup_protocol(TestInputs {
        params: Some(OpenID4Vp20Params {
            use_request_uri: true,
            ..generic_params()
        }),
        ..Default::default()
    });

    let now = OffsetDateTime::now_utc();
    let did = Did {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        name: "did".to_string(),
        did: "did:example:123".parse().unwrap(),
        did_type: DidType::Local,
        did_method: "KEY".to_string(),
        deactivated: false,
        keys: Some(vec![RelatedKey {
            role: KeyRole::Authentication,
            key: Key {
                id: Uuid::new_v4().into(),
                created_date: now,
                last_modified: now,
                public_key: vec![],
                name: "".to_string(),
                key_reference: None,
                storage_type: "".to_string(),
                key_type: "".to_string(),
                organisation: None,
            },
        }]),
        organisation: None,
        log: None,
    };
    let proof_id = Uuid::new_v4();
    let proof = Proof {
        id: proof_id.into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        issuance_date: OffsetDateTime::now_utc(),
        protocol: "OPENID4VP_DRAFT20".to_string(),
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
                claim_schemas: None,
                credential_schema: None,
            }]),
        }),
        claims: None,
        verifier_identifier: Some(Identifier {
            did: Some(did.clone()),
            ..dummy_identifier()
        }),
        holder_identifier: None,
        verifier_key: None,
        verifier_certificate: None,
        interaction: None,
        profile: None,
    };

    let format_type_mapper: FormatMapper = Arc::new(move |_| Ok(FormatType::Jwt));

    let type_to_descriptor_mapper: TypeToDescriptorMapper = Arc::new(move |_| Ok(HashMap::new()));

    let encryption_key_jwk = PublicKeyWithJwk {
        key_id: Uuid::new_v4().into(),
        jwk: PublicKeyJwk::Ec(PublicKeyJwkEllipticData {
            alg: None,
            r#use: None,
            kid: None,
            crv: "P-256".to_string(),
            x: "x".to_string(),
            y: None,
        }),
    };

    let ShareResponse { url, .. } = protocol
        .verifier_share_proof(
            &proof,
            format_type_mapper,
            Some(encryption_key_jwk),
            type_to_descriptor_mapper,
            None,
            Some(ShareProofRequestParamsDTO {
                client_id_scheme: Some(ClientIdScheme::Did),
            }),
        )
        .await
        .unwrap();
    let url: Url = url.parse().unwrap();
    let query_pairs: HashSet<(Cow<'_, str>, Cow<'_, str>)> = HashSet::from_iter(url.query_pairs());

    assert_eq!(
        HashSet::from_iter([
            ("client_id".into(), (&did.did.to_string()).into()),
            ("client_id_scheme".into(), "did".into()),
            (
                "request_uri".into(),
                format!("http://base_url/ssi/openid4vp/draft-20/{proof_id}/client-request").into()
            ),
        ]),
        query_pairs
    );
}

#[tokio::test]
async fn test_share_proof_with_use_request_uri_did_client_id_scheme() {
    let mut credential_formatter_provider = MockCredentialFormatterProvider::new();
    let mut credential_formatter = MockCredentialFormatter::new();
    credential_formatter
        .expect_get_capabilities()
        .returning(FormatterCapabilities::default);
    let arc = Arc::new(credential_formatter);
    credential_formatter_provider
        .expect_get_credential_formatter()
        .returning(move |_| Some(arc.clone()));

    let protocol = setup_protocol(TestInputs {
        credential_formatter_provider,
        params: Some(OpenID4Vp20Params {
            use_request_uri: true,
            ..generic_params()
        }),
        ..Default::default()
    });

    let proof_id = Uuid::new_v4();
    let proof = test_proof(proof_id, "JWT");

    let format_type_mapper: FormatMapper = Arc::new(move |_| Ok(FormatType::Jwt));

    let type_to_descriptor_mapper: TypeToDescriptorMapper = Arc::new(move |_| Ok(HashMap::new()));

    let encryption_key_jwk = PublicKeyWithJwk {
        key_id: Uuid::new_v4().into(),
        jwk: PublicKeyJwk::Ec(PublicKeyJwkEllipticData {
            alg: None,
            r#use: None,
            kid: None,
            crv: "P-256".to_string(),
            x: "x".to_string(),
            y: None,
        }),
    };

    let ShareResponse { url, .. } = protocol
        .verifier_share_proof(
            &proof,
            format_type_mapper,
            Some(encryption_key_jwk),
            type_to_descriptor_mapper,
            None,
            Some(ShareProofRequestParamsDTO {
                client_id_scheme: Some(ClientIdScheme::RedirectUri),
            }),
        )
        .await
        .unwrap();
    let url: Url = url.parse().unwrap();
    let query_pairs: HashSet<(Cow<'_, str>, Cow<'_, str>)> = HashSet::from_iter(url.query_pairs());

    assert_eq!(
        HashSet::from_iter([
            (
                "client_id".into(),
                "http://base_url/ssi/openid4vp/draft-20/response".into()
            ),
            ("client_id_scheme".into(), "redirect_uri".into()),
            (
                "request_uri".into(),
                format!("http://base_url/ssi/openid4vp/draft-20/{proof_id}/client-request").into()
            ),
        ]),
        query_pairs
    );
}

#[tokio::test]
async fn test_handle_invitation_proof_success() {
    let protocol = setup_protocol(Default::default());

    let client_metadata = serde_json::to_string(&OpenID4VPDraftClientMetadata {
        jwks: Default::default(),
        vp_formats: HashMap::from([(
            "jwt_vp_json".to_string(),
            OpenID4VpPresentationFormat::GenericAlgList(OpenID4VPAlgs {
                alg: vec!["EdDSA".to_string()],
            }),
        )]),
        ..Default::default()
    })
    .unwrap();
    let presentation_definition = serde_json::to_string(&OpenID4VPPresentationDefinition {
        id: Default::default(),
        input_descriptors: vec![],
    })
    .unwrap();

    let nonce = Uuid::new_v4().to_string();
    let callback_url = "http://127.0.0.1/callback";

    let url = Url::parse(&format!("openid4vp://?response_type=vp_token&nonce={nonce}&client_id_scheme=redirect_uri&client_id={callback_url}&client_metadata={client_metadata}&response_mode=direct_post&response_uri={callback_url}&presentation_definition={presentation_definition}")).unwrap();

    let mut storage_proxy = MockStorageProxy::default();
    storage_proxy
        .expect_create_interaction()
        .times(2)
        .returning(move |request| Ok(request.id));

    protocol
        .holder_handle_invitation(
            url,
            dummy_organisation(None),
            &storage_proxy,
            "HTTP".to_string(),
        )
        .await
        .unwrap();

    let mock_server = MockServer::start().await;

    let client_metadata_uri = format!("{}/client_metadata_uri", mock_server.uri());
    let presentation_definition_uri = format!("{}/presentation_definition_uri", mock_server.uri());

    Mock::given(method(Method::GET))
        .and(path("/client_metadata_uri"))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(client_metadata.to_owned(), "application/json"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;
    Mock::given(method(Method::GET))
        .and(path("/presentation_definition_uri"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(presentation_definition.to_owned(), "application/json"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let url_using_uri_instead_of_values = Url::parse(&format!("openid4vp://?response_type=vp_token&nonce={nonce}&client_id_scheme=redirect_uri&client_id={callback_url}&client_metadata_uri={client_metadata_uri}&response_mode=direct_post&response_uri={callback_url}&presentation_definition_uri={presentation_definition_uri}")).unwrap();

    protocol
        .holder_handle_invitation(
            url_using_uri_instead_of_values,
            dummy_organisation(None),
            &storage_proxy,
            "HTTP".to_string(),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn test_handle_invitation_proof_with_client_request_ok() {
    let protocol = setup_protocol(TestInputs {
        params: Some(generic_params()),
        ..Default::default()
    });

    let mock_server = MockServer::start().await;

    let client_id = format!("{}/client-id", mock_server.uri());
    let client_request_uri = format!("{}/client-request", mock_server.uri());
    let client_request_resp = test_client_request_response(&client_id, "redirect_uri", None);

    Mock::given(method(Method::GET))
        .and(path("/client-request"))
        .respond_with(ResponseTemplate::new(200).set_body_string(client_request_resp))
        .expect(1)
        .mount(&mock_server)
        .await;

    let url: Url = format!("openid4vp://?client_id={client_id}&client_id_scheme=redirect_uri&request_uri={client_request_uri}",)
        .parse()
        .unwrap();

    let mut storage_proxy = MockStorageProxy::default();
    storage_proxy
        .expect_create_interaction()
        .times(1)
        .returning(move |request| Ok(request.id));

    protocol
        .holder_handle_invitation(
            url,
            dummy_organisation(None),
            &storage_proxy,
            "HTTP".to_string(),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn test_handle_invitation_proof_with_client_id_scheme_in_client_request_token_ok() {
    let client_id = "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9";
    let did_method = JWKDidMethod::new(Arc::new(MockKeyAlgorithmProvider::new()));
    let mut did_method_provider = MockDidMethodProvider::new();
    let did_document = did_method
        .resolve(&client_id.parse().unwrap())
        .await
        .unwrap();
    did_method_provider
        .expect_resolve()
        .returning(move |_| Ok(did_document.clone()));
    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    let mut key_alg = MockKeyAlgorithm::new();

    let mut sig_handle = MockSignaturePublicKeyHandle::new();
    sig_handle.expect_verify().returning(|_, _| Ok(()));
    key_alg.expect_parse_jwk().return_once(|_| {
        Ok(KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(
            Arc::new(sig_handle),
        )))
    });
    key_algorithm_provider
        .expect_key_algorithm_from_jose_alg()
        .return_once(|_| Some((KeyAlgorithmType::Ecdsa, Arc::new(key_alg))));

    let protocol = setup_protocol(TestInputs {
        params: Some(generic_params()),
        did_method_provider,
        key_algorithm_provider,
        ..Default::default()
    });

    let mock_server = MockServer::start().await;

    let client_request_uri = format!("{}/client-request", mock_server.uri());
    let header = json!({
        "alg": "ES256",
        "kid": format!("{}#0", client_id),
        "crv": "P-256",
        "kty": "EC",
        "x": "acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0",
        "y": "_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE"
    });
    let client_request_resp = test_client_request_response(client_id, "did", Some(header));

    Mock::given(method(Method::GET))
        .and(path("/client-request"))
        .respond_with(ResponseTemplate::new(200).set_body_string(client_request_resp))
        .expect(1)
        .mount(&mock_server)
        .await;

    let url: Url = format!(
        "openid4vp://?client_id={client_id}&client_id_scheme=did&request_uri={client_request_uri}",
    )
    .parse()
    .unwrap();

    let mut storage_proxy = MockStorageProxy::default();
    storage_proxy
        .expect_create_interaction()
        .times(1)
        .withf(move |interaction| {
            let data: OpenID4VPHolderInteractionData =
                deserialize_interaction_data(interaction.data.as_ref()).unwrap();
            data.client_id_scheme == ClientIdScheme::Did
                && data.verifier_details
                    == Some(IdentifierDetails::Did(
                        DidValue::from_str(client_id).unwrap(),
                    ))
        })
        .returning(move |request| Ok(request.id));

    protocol
        .holder_handle_invitation(
            url,
            dummy_organisation(None),
            &storage_proxy,
            "HTTP".to_string(),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn test_handle_invitation_proof_failed() {
    let protocol = setup_protocol(Default::default());

    let client_metadata_uri = "https://127.0.0.1/client_metadata_uri";
    let client_metadata = serde_json::to_string(&OpenID4VPDraftClientMetadata {
        jwks: Default::default(),
        vp_formats: HashMap::from([(
            "jwt_vp_json".to_string(),
            OpenID4VpPresentationFormat::GenericAlgList(OpenID4VPAlgs {
                alg: vec!["EdDSA".to_string()],
            }),
        )]),
        ..Default::default()
    })
    .unwrap();
    let presentation_definition_uri = "https://127.0.0.1/presentation_definition_uri";
    let presentation_definition = serde_json::to_string(&OpenID4VPPresentationDefinition {
        id: Default::default(),
        input_descriptors: vec![],
    })
    .unwrap();

    let nonce = Uuid::new_v4().to_string();
    let callback_url = "http://127.0.0.1/callback";

    let storage_proxy = MockStorageProxy::default();

    let incorrect_response_type = Url::parse(&format!("openid4vp://?response_type=some_token&nonce={nonce}&client_id_scheme=redirect_uri&client_id={callback_url}&client_metadata={client_metadata}&response_mode=direct_post&response_uri={callback_url}&presentation_definition={presentation_definition}")).unwrap();
    let result = protocol
        .holder_handle_invitation(
            incorrect_response_type,
            dummy_organisation(None),
            &storage_proxy,
            "HTTP".to_string(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        result,
        VerificationProtocolError::InvalidRequest(_)
    ));

    let missing_nonce = Url::parse(&format!("openid4vp://?response_type=vp_token&client_id_scheme=redirect_uri&client_id={callback_url}&client_metadata={client_metadata}&response_mode=direct_post&response_uri={callback_url}&presentation_definition={presentation_definition}")).unwrap();
    let result = protocol
        .holder_handle_invitation(
            missing_nonce,
            dummy_organisation(None),
            &storage_proxy,
            "HTTP".to_string(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        result,
        VerificationProtocolError::InvalidRequest(_)
    ));

    let incorrect_client_id_scheme = Url::parse(&format!("openid4vp://?response_type=vp_token&nonce={nonce}&client_id_scheme=some_scheme&client_id={callback_url}&client_metadata={client_metadata}&response_mode=direct_post&response_uri={callback_url}&presentation_definition={presentation_definition}")).unwrap();
    let result = protocol
        .holder_handle_invitation(
            incorrect_client_id_scheme,
            dummy_organisation(None),
            &storage_proxy,
            "HTTP".to_string(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        result,
        VerificationProtocolError::InvalidRequest(_)
    ));

    let incorrect_response_mode = Url::parse(&format!("openid4vp://?response_type=vp_token&nonce={nonce}&client_id_scheme=redirect_uri&client_id={callback_url}&client_metadata={client_metadata}&response_mode=some_mode&response_uri={callback_url}&presentation_definition={presentation_definition}")).unwrap();
    let result = protocol
        .holder_handle_invitation(
            incorrect_response_mode,
            dummy_organisation(None),
            &storage_proxy,
            "HTTP".to_string(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        result,
        VerificationProtocolError::InvalidRequest(_)
    ));

    let incorrect_client_id_scheme = Url::parse(&format!("openid4vp://?response_type=vp_token&nonce={nonce}&client_id_scheme=some_scheme&client_id={callback_url}&client_metadata={client_metadata}&response_mode=direct_post&response_uri={callback_url}&presentation_definition={presentation_definition}")).unwrap();
    let result = protocol
        .holder_handle_invitation(
            incorrect_client_id_scheme,
            dummy_organisation(None),
            &storage_proxy,
            "HTTP".to_string(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        result,
        VerificationProtocolError::InvalidRequest(_)
    ));

    let metadata_missing_jwt_vp_json =
        serde_json::to_string(&OpenID4VPDraftClientMetadata::default()).unwrap();
    let missing_metadata_field = Url::parse(&format!("openid4vp://?response_type=some_token&nonce={nonce}&client_id_scheme=redirect_uri&client_id={callback_url}&client_metadata={metadata_missing_jwt_vp_json}&response_mode=direct_post&response_uri={callback_url}&presentation_definition={presentation_definition}")).unwrap();
    let result = protocol
        .holder_handle_invitation(
            missing_metadata_field,
            dummy_organisation(None),
            &storage_proxy,
            "HTTP".to_string(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        result,
        VerificationProtocolError::InvalidRequest(_)
    ));

    let both_client_metadata_and_uri_specified = Url::parse(&format!("openid4vp://?response_type=vp_token&nonce={nonce}&client_id_scheme=redirect_uri&client_id={callback_url}&client_metadata={client_metadata}&client_metadata_uri={client_metadata_uri}&response_mode=direct_post&response_uri={callback_url}&presentation_definition={presentation_definition}")).unwrap();
    let result = protocol
        .holder_handle_invitation(
            both_client_metadata_and_uri_specified,
            dummy_organisation(None),
            &storage_proxy,
            "HTTP".to_string(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        result,
        VerificationProtocolError::InvalidRequest(_)
    ));

    let both_presentation_definition_and_uri_specified = Url::parse(&format!("openid4vp://?response_type=vp_token&nonce={nonce}&client_id_scheme=redirect_uri&client_id={callback_url}&client_metadata={client_metadata}&response_mode=direct_post&response_uri={callback_url}&presentation_definition={presentation_definition}&presentation_definition_uri={presentation_definition_uri}")).unwrap();
    let result = protocol
        .holder_handle_invitation(
            both_presentation_definition_and_uri_specified,
            dummy_organisation(None),
            &storage_proxy,
            "HTTP".to_string(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        result,
        VerificationProtocolError::InvalidRequest(_)
    ));

    let protocol_https_only = setup_protocol(TestInputs {
        params: Some(OpenID4Vp20Params {
            allow_insecure_http_transport: false,
            ..generic_params()
        }),
        ..Default::default()
    });

    let invalid_client_metadata_uri = "http://127.0.0.1/client_metadata_uri";
    let client_metadata_uri_is_not_https = Url::parse(&format!("openid4vp://?response_type=vp_token&nonce={nonce}&client_id_scheme=redirect_uri&client_id={callback_url}&client_metadata_uri={invalid_client_metadata_uri}&response_mode=direct_post&response_uri={callback_url}&presentation_definition={presentation_definition}")).unwrap();
    let result = protocol_https_only
        .holder_handle_invitation(
            client_metadata_uri_is_not_https,
            dummy_organisation(None),
            &storage_proxy,
            "HTTP".to_string(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        result,
        VerificationProtocolError::InvalidRequest(_)
    ));

    let invalid_presentation_definition_uri = "http://127.0.0.1/presentation_definition_uri";
    let presentation_definition_uri_is_not_https = Url::parse(&format!("openid4vp://?response_type=vp_token&nonce={nonce}&client_id_scheme=redirect_uri&client_id={callback_url}&client_metadata={client_metadata}&response_mode=direct_post&response_uri={callback_url}&presentation_definition_uri={invalid_presentation_definition_uri}")).unwrap();
    let result = protocol_https_only
        .holder_handle_invitation(
            presentation_definition_uri_is_not_https,
            dummy_organisation(None),
            &storage_proxy,
            "HTTP".to_string(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        result,
        VerificationProtocolError::InvalidRequest(_)
    ));
}

#[test]
fn test_serialize_and_deserialize_interaction_data() {
    let client_metadata = serde_json::to_string(&OpenID4VPDraftClientMetadata {
        jwks: Default::default(),
        vp_formats: HashMap::from([(
            "jwt_vp_json".to_string(),
            OpenID4VpPresentationFormat::GenericAlgList(OpenID4VPAlgs {
                alg: vec!["EdDSA".to_string()],
            }),
        )]),
        ..Default::default()
    })
    .unwrap();
    let presentation_definition = serde_json::to_string(&OpenID4VPPresentationDefinition {
        id: Default::default(),
        input_descriptors: vec![],
    })
    .unwrap();

    let nonce = Uuid::new_v4().to_string();
    let callback_url = "http://127.0.0.1/callback";

    let query = Url::parse(&format!("openid4vp://?response_type=vp_token&nonce={nonce}&client_id_scheme=redirect_uri&client_id={callback_url}&client_metadata={client_metadata}&response_mode=direct_post&response_uri={callback_url}&presentation_definition={presentation_definition}")).unwrap().query().unwrap().to_string();
    let data: OpenID4VPHolderInteractionData = serde_qs::from_str(&query).unwrap();
    let json = serde_json::to_string(&data).unwrap();
    let _data_from_json: OpenID4VPHolderInteractionData = serde_json::from_str(&json).unwrap();

    let presentation_definition_uri = "https://127.0.0.1/presentation-definition";
    let query_with_presentation_definition_uri = Url::parse(&format!("openid4vp://?response_type=vp_token&nonce={nonce}&client_id_scheme=redirect_uri&client_id={callback_url}&client_metadata={client_metadata}&response_mode=direct_post&response_uri={callback_url}&presentation_definition_uri={presentation_definition_uri}")).unwrap().query().unwrap().to_string();
    let data: OpenID4VPHolderInteractionData =
        serde_qs::from_str(&query_with_presentation_definition_uri).unwrap();
    let json = serde_json::to_string(&data).unwrap();
    let _data_from_json: OpenID4VPHolderInteractionData = serde_json::from_str(&json).unwrap();
}

#[tokio::test]
async fn test_can_handle_presentation_success_with_custom_url_scheme() {
    let url_scheme = "my-custom-scheme";

    let protocol = setup_protocol(TestInputs {
        params: Some(test_params(url_scheme)),
        ..Default::default()
    });

    let test_url = format!(
        "{url_scheme}://?response_type=vp_token&nonce=123&client_id_scheme=redirect_uri&client_id=abc&client_metadata=foo&response_mode=direct_post&response_uri=uri&presentation_definition=def"
    );
    assert!(protocol.holder_can_handle(&test_url.parse().unwrap()))
}

#[test]
fn test_can_handle_presentation_fail_with_custom_url_scheme() {
    let url_scheme = "my-custom-scheme";
    let other_url_scheme = "my-different-scheme";

    let protocol = setup_protocol(TestInputs {
        params: Some(test_params(url_scheme)),
        ..Default::default()
    });

    let test_url = format!(
        "{other_url_scheme}://?credential_offer_uri=http%3A%2F%2Fbase_url%2Fssi%2Foidc-issuer%2Fv1%2Fc322aa7f-9803-410d-b891-939b279fb965%2Foffer%2Fc322aa7f-9803-410d-b891-939b279fb965"
    );
    assert!(!protocol.holder_can_handle(&test_url.parse().unwrap()))
}

#[tokio::test]
async fn test_share_proof_custom_scheme() {
    let url_scheme = "my-custom-scheme";
    let mut credential_formatter_provider = MockCredentialFormatterProvider::new();
    let mut credential_formatter = MockCredentialFormatter::new();
    credential_formatter
        .expect_get_capabilities()
        .returning(FormatterCapabilities::default);
    let arc = Arc::new(credential_formatter);
    credential_formatter_provider
        .expect_get_credential_formatter()
        .returning(move |_| Some(arc.clone()));
    let protocol = setup_protocol(TestInputs {
        credential_formatter_provider,
        params: Some(test_params(url_scheme)),
        ..Default::default()
    });

    let proof_id = Uuid::new_v4();
    let proof = test_proof(proof_id, "JWT");

    let format_type_mapper: FormatMapper = Arc::new(move |_| Ok(FormatType::Jwt));

    let type_to_descriptor_mapper: TypeToDescriptorMapper = Arc::new(move |_| Ok(HashMap::new()));

    let encryption_key_jwk = PublicKeyWithJwk {
        key_id: Uuid::new_v4().into(),
        jwk: PublicKeyJwk::Ec(PublicKeyJwkEllipticData {
            alg: None,
            r#use: None,
            kid: None,
            crv: "P-256".to_string(),
            x: "x".to_string(),
            y: None,
        }),
    };

    let ShareResponse { url, .. } = protocol
        .verifier_share_proof(
            &proof,
            format_type_mapper,
            Some(encryption_key_jwk),
            type_to_descriptor_mapper,
            None,
            Some(ShareProofRequestParamsDTO {
                client_id_scheme: Some(ClientIdScheme::RedirectUri),
            }),
        )
        .await
        .unwrap();
    assert!(url.starts_with(url_scheme));
}

fn test_params(presentation_url_scheme: &str) -> OpenID4Vp20Params {
    OpenID4Vp20Params {
        client_metadata_by_value: false,
        presentation_definition_by_value: false,
        allow_insecure_http_transport: true,
        use_request_uri: false,
        url_scheme: presentation_url_scheme.to_string(),
        holder: OpenID4VCPresentationHolderParams {
            supported_client_id_schemes: vec![
                ClientIdScheme::RedirectUri,
                ClientIdScheme::VerifierAttestation,
            ],
        },
        verifier: OpenID4VC20PresentationVerifierParams {
            supported_client_id_schemes: vec![
                ClientIdScheme::RedirectUri,
                ClientIdScheme::VerifierAttestation,
            ],
        },
        redirect_uri: OpenID4VCRedirectUriParams {
            enabled: true,
            allowed_schemes: vec!["https".to_string()],
        },
        predefined_client_metadata: None,
    }
}
