use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;

use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use indexmap::{indexmap, IndexMap};
use serde_json::{json, Value};
use shared_types::DidValue;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;
use wiremock::http::Method;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::{build_claims_keys_for_mdoc, OpenID4VCHTTP};
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{Credential, CredentialRole, CredentialStateEnum};
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaClaim, CredentialSchemaType, LayoutType,
    WalletStorageTypeEnum,
};
use crate::model::did::{Did, DidType};
use crate::model::interaction::Interaction;
use crate::model::organisation::Organisation;
use crate::model::proof::{Proof, ProofStateEnum};
use crate::model::proof_schema::{ProofInputSchema, ProofSchema};
use crate::provider::credential_formatter::model::FormatterCapabilities;
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::credential_formatter::MockCredentialFormatter;
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::exchange_protocol::openid4vc::mapper::{
    get_parent_claim_paths, map_offered_claims_to_credential_schema,
};
use crate::provider::exchange_protocol::openid4vc::model::{
    ClientIdSchemaType, InvitationResponseDTO, OpenID4VCICredentialOfferClaim,
    OpenID4VCICredentialOfferClaimValue, OpenID4VCICredentialValueDetails, OpenID4VCIssuanceParams,
    OpenID4VCParams, OpenID4VCPresentationHolderParams, OpenID4VCPresentationParams,
    OpenID4VCPresentationVerifierParams, OpenID4VCRedirectUriParams, OpenID4VPClientMetadata,
    OpenID4VPFormat, OpenID4VPHolderInteractionData, OpenID4VPPresentationDefinition,
    ShareResponse,
};
use crate::provider::exchange_protocol::openid4vc::service::create_credential_offer;
use crate::provider::exchange_protocol::openid4vc::ExchangeProtocolError;
use crate::provider::exchange_protocol::{
    BasicSchemaData, BuildCredentialSchemaResponse, FormatMapper, MockHandleInvitationOperations,
    MockStorageProxy, TypeToDescriptorMapper,
};
use crate::provider::http_client::reqwest_client::ReqwestClient;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_storage::provider::MockKeyProvider;
use crate::provider::revocation::provider::MockRevocationMethodProvider;
use crate::service::key::dto::{PublicKeyJwkDTO, PublicKeyJwkEllipticDataDTO};
use crate::service::oidc::service::credentials_format;
use crate::service::test_utilities::get_dummy_date;

#[derive(Default)]
struct TestInputs {
    pub formatter_provider: MockCredentialFormatterProvider,
    pub revocation_provider: MockRevocationMethodProvider,
    pub key_algorithm_provider: MockKeyAlgorithmProvider,
    pub key_provider: MockKeyProvider,
    pub did_method_provider: MockDidMethodProvider,
    pub params: Option<OpenID4VCParams>,
}

fn setup_protocol(inputs: TestInputs) -> OpenID4VCHTTP {
    OpenID4VCHTTP::new(
        Some("http://base_url".to_string()),
        Arc::new(inputs.formatter_provider),
        Arc::new(inputs.revocation_provider),
        Arc::new(inputs.did_method_provider),
        Arc::new(inputs.key_algorithm_provider),
        Arc::new(inputs.key_provider),
        Arc::new(ReqwestClient::default()),
        inputs.params.unwrap_or(OpenID4VCParams {
            pre_authorized_code_expires_in: 10,
            token_expires_in: 10,
            credential_offer_by_value: false,
            client_metadata_by_value: false,
            presentation_definition_by_value: false,
            allow_insecure_http_transport: true,
            refresh_expires_in: 1000,
            use_request_uri: false,
            issuance: OpenID4VCIssuanceParams {
                disabled: false,
                url_scheme: "openid-credential-offer".to_string(),
                redirect_uri: OpenID4VCRedirectUriParams {
                    disabled: false,
                    allowed_schemes: vec!["https".to_string()],
                },
            },
            presentation: generic_presentation_params(),
        }),
    )
}

fn generic_presentation_params() -> OpenID4VCPresentationParams {
    OpenID4VCPresentationParams {
        disabled: false,
        url_scheme: "openid4vp".to_string(),
        x509_ca_certificate: None,
        holder: OpenID4VCPresentationHolderParams {
            supported_client_id_schemes: vec![
                ClientIdSchemaType::RedirectUri,
                ClientIdSchemaType::VerifierAttestation,
            ],
        },
        verifier: OpenID4VCPresentationVerifierParams {
            default_client_id_schema: ClientIdSchemaType::RedirectUri,
            supported_client_id_schemes: vec![
                ClientIdSchemaType::RedirectUri,
                ClientIdSchemaType::VerifierAttestation,
            ],
        },
        redirect_uri: OpenID4VCRedirectUriParams {
            disabled: false,
            allowed_schemes: vec!["https".to_string()],
        },
    }
}

fn generic_organisation() -> Organisation {
    let now = OffsetDateTime::now_utc();
    Organisation {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
    }
}

fn generic_credential() -> Credential {
    let now = OffsetDateTime::now_utc();

    let claim_schema = ClaimSchema {
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
            .unwrap()
            .into(),
        key: "NUMBER".to_string(),
        data_type: "NUMBER".to_string(),
        created_date: now,
        last_modified: now,
        array: false,
    };

    let credential_id = Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
        .unwrap()
        .into();
    Credential {
        id: credential_id,
        created_date: now,
        issuance_date: now,
        last_modified: now,
        deleted_at: None,
        credential: vec![],
        exchange: "OPENID4VC".to_string(),
        redirect_uri: None,
        role: CredentialRole::Issuer,
        state: CredentialStateEnum::Created,
        suspend_end_date: None,
        claims: Some(vec![Claim {
            id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965").unwrap(),
            credential_id,
            created_date: now,
            last_modified: now,
            value: "123".to_string(),
            path: claim_schema.key.to_owned(),
            schema: Some(claim_schema.clone()),
        }]),
        issuer_did: Some(Did {
            id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
                .unwrap()
                .into(),
            created_date: now,
            last_modified: now,
            name: "did1".to_string(),
            did: "did:example:123".parse().unwrap(),
            did_type: DidType::Remote,
            did_method: "KEY".to_string(),
            keys: None,
            deactivated: false,
            organisation: Some(generic_organisation()),
        }),
        holder_did: None,
        schema: Some(CredentialSchema {
            id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
                .unwrap()
                .into(),
            deleted_at: None,
            imported_source_url: "CORE_URL".to_string(),
            created_date: now,
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            last_modified: now,
            name: "schema".to_string(),
            format: "JWT".to_string(),
            revocation_method: "NONE".to_string(),
            claim_schemas: Some(vec![CredentialSchemaClaim {
                schema: claim_schema,
                required: true,
            }]),
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_type: CredentialSchemaType::ProcivisOneSchema2024,
            schema_id: "CredentialSchemaId".to_owned(),
            organisation: Some(generic_organisation()),
            allow_suspension: true,
        }),
        interaction: Some(Interaction {
            id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965").unwrap(),
            created_date: now,
            host: Some("http://host.co".parse().unwrap()),
            data: Some(vec![1, 2, 3]),
            last_modified: now,
            organisation: None,
        }),
        key: None,
        revocation_list: None,
    }
}

#[tokio::test]
async fn test_generate_offer() {
    let base_url = "BASE_URL".to_string();
    let interaction_id = Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965").unwrap();
    let credential = generic_credential();

    let keys = credential.claims.unwrap_or_default();

    let credential_subject =
        credentials_format(Some(WalletStorageTypeEnum::Software), &keys).unwrap();

    let offer = create_credential_offer(
        &base_url,
        &interaction_id.to_string(),
        credential.issuer_did.unwrap().did,
        &credential.schema.as_ref().unwrap().id,
        &credential.schema.as_ref().unwrap().schema_id,
        credential_subject,
    )
    .unwrap();

    assert_eq!(
        json!(&offer),
        json!({
            "credential_issuer": "BASE_URL/ssi/oidc-issuer/v1/c322aa7f-9803-410d-b891-939b279fb965",
            "issuer_did": "did:example:123",
            "credential_configuration_ids" : [
                credential.schema.as_ref().unwrap().schema_id,
            ],
            "grants": {
                "urn:ietf:params:oauth:grant-type:pre-authorized_code": { "pre-authorized_code": "c322aa7f-9803-410d-b891-939b279fb965" }
            },
            "credential_subject": {
                "keys": {
                    "NUMBER": {
                        "value": "123",
                        "value_type": "NUMBER"
                    }
                },
                "wallet_storage_type": "SOFTWARE"
            }
        })
    )
}

#[tokio::test]
async fn test_generate_share_credentials() {
    let credential = generic_credential();
    let protocol = setup_protocol(Default::default());

    let result = protocol
        .issuer_share_credential(&credential, "")
        .await
        .unwrap();
    assert_eq!(result.url, "openid-credential-offer://?credential_offer_uri=http%3A%2F%2Fbase_url%2Fssi%2Foidc-issuer%2Fv1%2Fc322aa7f-9803-410d-b891-939b279fb965%2Foffer%2Fc322aa7f-9803-410d-b891-939b279fb965");
}

#[tokio::test]
async fn test_generate_share_credentials_offer_by_value() {
    let credential = generic_credential();

    let protocol = setup_protocol(TestInputs {
        params: Some(OpenID4VCParams {
            pre_authorized_code_expires_in: 10,
            token_expires_in: 10,
            credential_offer_by_value: true,
            client_metadata_by_value: false,
            presentation_definition_by_value: false,
            allow_insecure_http_transport: true,
            refresh_expires_in: 1000,
            use_request_uri: false,
            issuance: OpenID4VCIssuanceParams {
                disabled: false,
                url_scheme: "openid-credential-offer".to_string(),
                redirect_uri: OpenID4VCRedirectUriParams {
                    disabled: false,
                    allowed_schemes: vec!["https".to_string()],
                },
            },
            presentation: generic_presentation_params(),
        }),
        ..Default::default()
    });

    let result = protocol
        .issuer_share_credential(&credential, "jwt_vc_json")
        .await
        .unwrap();
    // Everything except for interaction id is here.
    // Generating token with predictable interaction id is tested somewhere else.
    assert!(
        result.url.starts_with(r#"openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22http%3A%2F%2Fbase_url%2Fssi%2Foidc-issuer%2Fv1%2Fc322aa7f-9803-410d-b891-939b279fb965%22%2C%22credential_configuration_ids%22%3A%5B%22CredentialSchemaId%22%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%"#)
    );
    assert!(result
        .url
        .contains("%22issuer_did%22%3A%22did%3Aexample%3A123%22"))
}

#[tokio::test]
async fn test_share_proof() {
    let mut formatter_provider = MockCredentialFormatterProvider::new();
    let mut credential_formatter = MockCredentialFormatter::new();
    credential_formatter
        .expect_get_capabilities()
        .returning(FormatterCapabilities::default);
    let arc = Arc::new(credential_formatter);
    formatter_provider
        .expect_get_formatter()
        .returning(move |_| Some(arc.clone()));
    let protocol = setup_protocol(TestInputs {
        formatter_provider,
        ..Default::default()
    });

    let proof_id = Uuid::new_v4();
    let proof = test_proof(proof_id, "JWT");

    let format_type_mapper: FormatMapper = Arc::new(move |input| Ok(input.to_owned()));

    let type_to_descriptor_mapper: TypeToDescriptorMapper = Arc::new(move |_| Ok(HashMap::new()));

    let key_id = Uuid::new_v4().into();
    let encryption_key_jwk = PublicKeyJwkDTO::Ec(PublicKeyJwkEllipticDataDTO {
        r#use: None,
        kid: None,
        crv: "P-256".to_string(),
        x: "x".to_string(),
        y: None,
    });
    let vp_formats = HashMap::new();

    let ShareResponse {
        url,
        interaction_id,
        ..
    } = protocol
        .verifier_share_proof(
            &proof,
            format_type_mapper,
            key_id,
            encryption_key_jwk,
            vp_formats,
            type_to_descriptor_mapper,
            ClientIdSchemaType::RedirectUri,
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
        "http://base_url/ssi/oidc-verifier/v1/response",
        query_pairs.get("response_uri").unwrap()
    );

    assert_eq!(
        "http://base_url/ssi/oidc-verifier/v1/response",
        query_pairs.get("client_id").unwrap()
    );

    assert_eq!(
        &format!(
            "http://base_url/ssi/oidc-verifier/v1/{}/presentation-definition",
            proof.id
        ),
        query_pairs.get("presentation_definition_uri").unwrap()
    );

    assert_eq!(
        &format!(
            "http://base_url/ssi/oidc-verifier/v1/{}/client-metadata",
            proof.id
        ),
        query_pairs.get("client_metadata_uri").unwrap()
    );
}

#[tokio::test]
async fn test_response_mode_direct_post_jwt_for_mdoc() {
    let mut formatter_provider = MockCredentialFormatterProvider::new();
    let mut credential_formatter = MockCredentialFormatter::new();
    credential_formatter
        .expect_get_capabilities()
        .returning(FormatterCapabilities::default);
    let arc = Arc::new(credential_formatter);
    formatter_provider
        .expect_get_formatter()
        .returning(move |_| Some(arc.clone()));
    let protocol = setup_protocol(TestInputs {
        formatter_provider,
        ..Default::default()
    });

    let proof = test_proof(Uuid::new_v4(), "MDOC");

    let format_type_mapper: FormatMapper = Arc::new(move |input| Ok(input.to_owned()));

    let type_to_descriptor_mapper: TypeToDescriptorMapper = Arc::new(move |_| Ok(HashMap::new()));

    let key_id = Uuid::new_v4().into();
    let encryption_key_jwk = PublicKeyJwkDTO::Ec(PublicKeyJwkEllipticDataDTO {
        r#use: None,
        kid: None,
        crv: "P-256".to_string(),
        x: "x".to_string(),
        y: None,
    });
    let vp_formats = HashMap::new();

    let ShareResponse { url, .. } = protocol
        .verifier_share_proof(
            &proof,
            format_type_mapper,
            key_id,
            encryption_key_jwk,
            vp_formats,
            type_to_descriptor_mapper,
            ClientIdSchemaType::RedirectUri,
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
        exchange: "OPENID4VC".to_string(),
        transport: "HTTP".to_string(),
        redirect_uri: None,
        state: ProofStateEnum::Created,
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
        verifier_did: None,
        holder_did: None,
        verifier_key: None,
        interaction: None,
    }
}

#[tokio::test]
async fn test_share_proof_with_use_request_uri() {
    let protocol = setup_protocol(TestInputs {
        params: Some(OpenID4VCParams {
            pre_authorized_code_expires_in: 10,
            token_expires_in: 10,
            credential_offer_by_value: false,
            client_metadata_by_value: false,
            presentation_definition_by_value: false,
            allow_insecure_http_transport: true,
            refresh_expires_in: 1000,
            use_request_uri: true,
            issuance: OpenID4VCIssuanceParams {
                disabled: false,
                url_scheme: "openid-credential-offer".to_string(),
                redirect_uri: OpenID4VCRedirectUriParams {
                    disabled: false,
                    allowed_schemes: vec!["https".to_string()],
                },
            },
            presentation: generic_presentation_params(),
        }),
        ..Default::default()
    });

    let proof_id = Uuid::new_v4();
    let proof = Proof {
        id: proof_id.into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        issuance_date: OffsetDateTime::now_utc(),
        exchange: "OPENID4VC".to_string(),
        transport: "HTTP".to_string(),
        redirect_uri: None,
        state: ProofStateEnum::Created,
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
        verifier_did: None,
        holder_did: None,
        verifier_key: None,
        interaction: None,
    };

    let format_type_mapper: FormatMapper = Arc::new(move |input| Ok(input.to_owned()));

    let type_to_descriptor_mapper: TypeToDescriptorMapper = Arc::new(move |_| Ok(HashMap::new()));

    let key_id = Uuid::new_v4().into();
    let encryption_key_jwk = PublicKeyJwkDTO::Ec(PublicKeyJwkEllipticDataDTO {
        r#use: None,
        kid: None,
        crv: "P-256".to_string(),
        x: "x".to_string(),
        y: None,
    });
    let vp_formats = HashMap::new();

    let ShareResponse { url, .. } = protocol
        .verifier_share_proof(
            &proof,
            format_type_mapper,
            key_id,
            encryption_key_jwk,
            vp_formats,
            type_to_descriptor_mapper,
            ClientIdSchemaType::RedirectUri,
        )
        .await
        .unwrap();
    let url: Url = url.parse().unwrap();
    let query_pairs: HashSet<(Cow<'_, str>, Cow<'_, str>)> = HashSet::from_iter(url.query_pairs());

    assert_eq!(
        HashSet::from_iter([
            (
                "client_id".into(),
                "http://base_url/ssi/oidc-verifier/v1/response".into()
            ),
            ("client_id_scheme".into(), "redirect_uri".into()),
            (
                "request_uri".into(),
                format!("http://base_url/ssi/oidc-verifier/v1/{proof_id}/client-request").into()
            ),
        ]),
        query_pairs
    );
}

#[tokio::test]
async fn test_handle_invitation_credential_by_ref_with_did_success() {
    let credential = generic_credential();

    let mut storage_proxy = MockStorageProxy::default();
    let credential_clone = credential.clone();
    storage_proxy
        .expect_get_or_create_did()
        .times(1)
        .returning(move |_, _, _| Ok(credential_clone.issuer_did.as_ref().unwrap().clone()));

    inner_test_handle_invitation_credential_by_ref_success(
        storage_proxy,
        credential,
        Some("did:example:123".to_string()),
    )
    .await;
}

#[tokio::test]
async fn test_handle_invitation_credential_by_ref_without_did_success() {
    inner_test_handle_invitation_credential_by_ref_success(
        MockStorageProxy::default(),
        generic_credential(),
        None,
    )
    .await;
}

async fn inner_test_handle_invitation_credential_by_ref_success(
    mut storage_proxy: MockStorageProxy,
    credential: Credential,
    issuer_did: Option<String>,
) {
    let mock_server = MockServer::start().await;
    let issuer_url = Url::from_str(&mock_server.uri()).unwrap();
    let credential_schema_id = credential.schema.clone().unwrap().id;
    let credential_issuer = format!("{issuer_url}ssi/oidc-issuer/v1/{credential_schema_id}");

    let mut credential_offer = json!({
        "credential_issuer": credential_issuer,
        "credential_configuration_ids" : [credential_schema_id],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": { "pre-authorized_code": "c322aa7f-9803-410d-b891-939b279fb965" }
        },
        "credential_subject": {
            "keys": {
                "NUMBER": {
                    "value": "123",
                    "value_type": "NUMBER"
                }
            },
            "wallet_storage_type": "SOFTWARE"
        }
    });
    if let Some(ref issuer_did) = issuer_did {
        credential_offer
            .as_object_mut()
            .unwrap()
            .insert("issuer_did".into(), Value::String(issuer_did.to_owned()));
    };

    Mock::given(method(Method::GET))
        .and(path(format!(
            "/ssi/oidc-issuer/v1/{}/offer/{}",
            credential_schema_id, credential.id
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(credential_offer))
        .expect(1)
        .mount(&mock_server)
        .await;
    let token_endpoint = format!("{credential_issuer}/token");
    Mock::given(method(Method::GET))
        .and(path(format!(
            "/ssi/oidc-issuer/v1/{credential_schema_id}/.well-known/openid-configuration"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "authorization_endpoint": format!("{credential_issuer}/authorize"),
                "grant_types_supported": [
                    "urn:ietf:params:oauth:grant-type:pre-authorized_code"
                ],
                "id_token_signing_alg_values_supported": [],
                "issuer": credential_issuer,
                "jwks_uri": format!("{credential_issuer}/jwks"),
                "response_types_supported": [
                    "token"
                ],
                "subject_types_supported": [
                    "public"
                ],
                "token_endpoint": token_endpoint
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;
    Mock::given(method(Method::GET))
        .and(path(format!(
            "/ssi/oidc-issuer/v1/{credential_schema_id}/.well-known/openid-credential-issuer"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "credential_endpoint": format!("{credential_issuer}/credential"),
                "credential_issuer": credential_issuer,
                "credential_configurations_supported": {
                    credential_schema_id.to_string(): {
                        "credential_definition": {
                            "type": [
                                "VerifiableCredential"
                            ],
                            "credentialSubject" : {
                                "address": {
                                    "value_type": "STRING",
                                }
                            }
                        },
                        "format": "vc+sd-jwt",
                    }
              }
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    storage_proxy
        .expect_create_interaction()
        .times(1)
        .returning(|_| Ok(Uuid::new_v4()));
    storage_proxy
        .expect_get_schema()
        .times(1)
        .returning(|_, _, _| Ok(None));

    let mut operations = MockHandleInvitationOperations::default();
    let credential_clone = credential.clone();
    operations
        .expect_find_schema_data()
        .once()
        .returning(move |_, _, _| {
            Ok(BasicSchemaData {
                id: credential_schema_id.to_string(),
                r#type: "SD_JWT_VC".to_string(),
                offer_id: credential_clone.id.to_string(),
            })
        });
    operations
        .expect_create_new_schema()
        .once()
        .returning(move |_, _, _, _, _, _| {
            Ok(BuildCredentialSchemaResponse {
                claims: credential.claims.clone().unwrap(),
                schema: credential.schema.clone().unwrap(),
            })
        });

    let url = Url::parse(&format!("openid-credential-offer://?credential_offer_uri=http%3A%2F%2F{}%2Fssi%2Foidc-issuer%2Fv1%2F{}%2Foffer%2F{}", issuer_url.authority(), credential_schema_id, credential.id)).unwrap();

    let protocol = setup_protocol(Default::default());
    let result = protocol
        .holder_handle_invitation(url, generic_organisation(), &storage_proxy, &operations)
        .await
        .unwrap();

    match result {
        InvitationResponseDTO::Credential { credentials, .. } => {
            assert_eq!(credentials.len(), 1);

            if let Some(issuer_did) = issuer_did {
                assert_eq!(
                    credentials[0].issuer_did.as_ref().unwrap().did,
                    DidValue::from_str(issuer_did.as_str()).unwrap()
                );
            } else {
                assert!(credentials[0].issuer_did.is_none());
            }
        }
        InvitationResponseDTO::ProofRequest { .. } => panic!("expected credential"),
    }
}

#[tokio::test]
async fn test_handle_invitation_proof_success() {
    let protocol = setup_protocol(Default::default());

    let client_metadata = serde_json::to_string(&OpenID4VPClientMetadata {
        jwks: vec![],
        vp_formats: HashMap::from([(
            "jwt_vp_json".to_string(),
            OpenID4VPFormat {
                alg: vec!["EdDSA".to_string()],
            },
        )]),
        client_id_scheme: ClientIdSchemaType::RedirectUri,
        authorization_encrypted_response_alg: None,
        authorization_encrypted_response_enc: None,
    })
    .unwrap();
    let presentation_definition = serde_json::to_string(&OpenID4VPPresentationDefinition {
        id: Default::default(),
        input_descriptors: vec![],
    })
    .unwrap();

    let nonce = Uuid::new_v4().to_string();
    let callback_url = "http://127.0.0.1/callback";

    let url = Url::parse(&format!("openid4vp://?response_type=vp_token&nonce={}&client_id_scheme=redirect_uri&client_id={}&client_metadata={}&response_mode=direct_post&response_uri={}&presentation_definition={}"
        , nonce, callback_url, client_metadata, callback_url, presentation_definition)).unwrap();

    let mut storage_proxy = MockStorageProxy::default();
    storage_proxy
        .expect_create_interaction()
        .times(2)
        .returning(move |request| Ok(request.id));

    let operations = MockHandleInvitationOperations::default();

    let result = protocol
        .holder_handle_invitation(url, generic_organisation(), &storage_proxy, &operations)
        .await
        .unwrap();
    assert!(matches!(result, InvitationResponseDTO::ProofRequest { .. }));

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

    let url_using_uri_instead_of_values = Url::parse(&format!("openid4vp://?response_type=vp_token&nonce={}&client_id_scheme=redirect_uri&client_id={}&client_metadata_uri={}&response_mode=direct_post&response_uri={}&presentation_definition_uri={}"
                                                              , nonce, callback_url, client_metadata_uri, callback_url, presentation_definition_uri)).unwrap();

    let result = protocol
        .holder_handle_invitation(
            url_using_uri_instead_of_values,
            generic_organisation(),
            &storage_proxy,
            &operations,
        )
        .await
        .unwrap();
    assert!(matches!(result, InvitationResponseDTO::ProofRequest { .. }));
}

#[tokio::test]
async fn test_handle_invitation_proof_with_client_request_ok() {
    let protocol = setup_protocol(TestInputs {
        params: Some(OpenID4VCParams {
            pre_authorized_code_expires_in: 60,
            token_expires_in: 60,
            refresh_expires_in: 60,
            credential_offer_by_value: false,
            client_metadata_by_value: false,
            presentation_definition_by_value: false,
            allow_insecure_http_transport: true,
            use_request_uri: true,
            issuance: OpenID4VCIssuanceParams {
                disabled: false,
                url_scheme: "openid-credential-offer".to_string(),
                redirect_uri: OpenID4VCRedirectUriParams {
                    disabled: false,
                    allowed_schemes: vec!["https".to_string()],
                },
            },
            presentation: generic_presentation_params(),
        }),
        ..Default::default()
    });

    let mock_server = MockServer::start().await;

    let client_id = format!("{}/client-id", mock_server.uri());
    let client_request_uri = format!("{}/client-request", mock_server.uri());
    let client_request_resp = [
        json!({"alg": "none"}),
        json!({
          "response_type": "vp_token",
          "state": "0193a9e2-edb7-48b7-bf82-3cbe6a74d711",
          "nonce": "nonce123",
          "response_mode": "direct_post",
          "client_id_scheme": "redirect_uri",
          "client_id": client_id,
          "client_metadata": {
            "jwks": [
              {
                "kid": "e8745b9f-337a-4584-b8a3-3697e56512b5",
                "kty": "EC",
                "use": "enc",
                "crv": "P-256",
                "x": "cd_LTtCQnat2XnDElumvgQAM5ZcnUMVTkPig458C1yc",
                "y": "iaQmPUgir80I2XCFqn2_KPqdWH0PxMzCCP8W3uPxlUA"
              }
            ],
            "vp_formats": {
              "jwt_vp_json": {
                "alg": [
                  "EdDSA",
                  "ES256"
                ]
              }
            },
            "client_id_scheme": "redirect_uri",
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
    .join(".");

    Mock::given(method(Method::GET))
        .and(path("/client-request"))
        .respond_with(ResponseTemplate::new(200).set_body_string(client_request_resp))
        .expect(1)
        .mount(&mock_server)
        .await;

    let url: Url = format!("openid4vp://?client_id={client_id}&request_uri={client_request_uri}",)
        .parse()
        .unwrap();

    let mut storage_proxy = MockStorageProxy::default();
    storage_proxy
        .expect_create_interaction()
        .times(1)
        .returning(move |request| Ok(request.id));

    let operations = MockHandleInvitationOperations::default();

    let result = protocol
        .holder_handle_invitation(url, generic_organisation(), &storage_proxy, &operations)
        .await
        .unwrap();
    assert!(matches!(result, InvitationResponseDTO::ProofRequest { .. }));
}

#[tokio::test]
async fn test_handle_invitation_proof_failed() {
    let protocol = setup_protocol(Default::default());

    let client_metadata_uri = "https://127.0.0.1/client_metadata_uri";
    let client_metadata = serde_json::to_string(&OpenID4VPClientMetadata {
        jwks: vec![],
        vp_formats: HashMap::from([(
            "jwt_vp_json".to_string(),
            OpenID4VPFormat {
                alg: vec!["EdDSA".to_string()],
            },
        )]),
        client_id_scheme: ClientIdSchemaType::RedirectUri,
        authorization_encrypted_response_alg: None,
        authorization_encrypted_response_enc: None,
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
    let operations = MockHandleInvitationOperations::default();

    let incorrect_response_type = Url::parse(&format!("openid4vp://?response_type=some_token&nonce={}&client_id_scheme=redirect_uri&client_id={}&client_metadata={}&response_mode=direct_post&response_uri={}&presentation_definition={}"
                                                      , nonce, callback_url, client_metadata, callback_url, presentation_definition)).unwrap();
    let result = protocol
        .holder_handle_invitation(
            incorrect_response_type,
            generic_organisation(),
            &storage_proxy,
            &operations,
        )
        .await
        .unwrap_err();
    assert!(matches!(result, ExchangeProtocolError::InvalidRequest(_)));

    let missing_nonce = Url::parse(&format!("openid4vp://?response_type=vp_token&client_id_scheme=redirect_uri&client_id={}&client_metadata={}&response_mode=direct_post&response_uri={}&presentation_definition={}"
                                            , callback_url, client_metadata, callback_url, presentation_definition)).unwrap();
    let result = protocol
        .holder_handle_invitation(
            missing_nonce,
            generic_organisation(),
            &storage_proxy,
            &operations,
        )
        .await
        .unwrap_err();
    assert!(matches!(result, ExchangeProtocolError::InvalidRequest(_)));

    let incorrect_client_id_scheme = Url::parse(&format!("openid4vp://?response_type=vp_token&nonce={}&client_id_scheme=some_scheme&client_id={}&client_metadata={}&response_mode=direct_post&response_uri={}&presentation_definition={}"
                                                         , nonce, callback_url, client_metadata, callback_url, presentation_definition)).unwrap();
    let result = protocol
        .holder_handle_invitation(
            incorrect_client_id_scheme,
            generic_organisation(),
            &storage_proxy,
            &operations,
        )
        .await
        .unwrap_err();
    assert!(matches!(result, ExchangeProtocolError::InvalidRequest(_)));

    let incorrect_response_mode = Url::parse(&format!("openid4vp://?response_type=vp_token&nonce={}&client_id_scheme=redirect_uri&client_id={}&client_metadata={}&response_mode=some_mode&response_uri={}&presentation_definition={}"
                                                      , nonce, callback_url, client_metadata, callback_url, presentation_definition)).unwrap();
    let result = protocol
        .holder_handle_invitation(
            incorrect_response_mode,
            generic_organisation(),
            &storage_proxy,
            &operations,
        )
        .await
        .unwrap_err();
    assert!(matches!(result, ExchangeProtocolError::InvalidRequest(_)));

    let incorrect_client_id_scheme = Url::parse(&format!("openid4vp://?response_type=vp_token&nonce={}&client_id_scheme=some_scheme&client_id={}&client_metadata={}&response_mode=direct_post&response_uri={}&presentation_definition={}"
                                                         , nonce, callback_url, client_metadata, callback_url, presentation_definition)).unwrap();
    let result = protocol
        .holder_handle_invitation(
            incorrect_client_id_scheme,
            generic_organisation(),
            &storage_proxy,
            &operations,
        )
        .await
        .unwrap_err();
    assert!(matches!(result, ExchangeProtocolError::InvalidRequest(_)));

    let metadata_missing_jwt_vp_json = serde_json::to_string(&OpenID4VPClientMetadata {
        jwks: vec![],
        vp_formats: Default::default(),
        client_id_scheme: ClientIdSchemaType::RedirectUri,
        authorization_encrypted_response_alg: None,
        authorization_encrypted_response_enc: None,
    })
    .unwrap();
    let missing_metadata_field = Url::parse(&format!("openid4vp://?response_type=some_token&nonce={}&client_id_scheme=redirect_uri&client_id={}&client_metadata={}&response_mode=direct_post&response_uri={}&presentation_definition={}", nonce, callback_url, metadata_missing_jwt_vp_json, callback_url, presentation_definition)).unwrap();
    let result = protocol
        .holder_handle_invitation(
            missing_metadata_field,
            generic_organisation(),
            &storage_proxy,
            &operations,
        )
        .await
        .unwrap_err();
    assert!(matches!(result, ExchangeProtocolError::InvalidRequest(_)));

    let both_client_metadata_and_uri_specified = Url::parse(&format!("openid4vp://?response_type=vp_token&nonce={}&client_id_scheme=redirect_uri&client_id={}&client_metadata={}&client_metadata_uri={}&response_mode=direct_post&response_uri={}&presentation_definition={}"
                                                                     , nonce, callback_url, client_metadata, client_metadata_uri, callback_url, presentation_definition)).unwrap();
    let result = protocol
        .holder_handle_invitation(
            both_client_metadata_and_uri_specified,
            generic_organisation(),
            &storage_proxy,
            &operations,
        )
        .await
        .unwrap_err();
    assert!(matches!(result, ExchangeProtocolError::InvalidRequest(_)));

    let both_presentation_definition_and_uri_specified = Url::parse(&format!("openid4vp://?response_type=vp_token&nonce={}&client_id_scheme=redirect_uri&client_id={}&client_metadata={}&response_mode=direct_post&response_uri={}&presentation_definition={}&presentation_definition_uri={}"
                                                                             , nonce, callback_url, client_metadata, callback_url, presentation_definition, presentation_definition_uri)).unwrap();
    let result = protocol
        .holder_handle_invitation(
            both_presentation_definition_and_uri_specified,
            generic_organisation(),
            &storage_proxy,
            &operations,
        )
        .await
        .unwrap_err();
    assert!(matches!(result, ExchangeProtocolError::InvalidRequest(_)));

    let protocol_https_only = setup_protocol(TestInputs {
        params: Some(OpenID4VCParams {
            pre_authorized_code_expires_in: 10,
            token_expires_in: 10,
            credential_offer_by_value: false,
            client_metadata_by_value: false,
            presentation_definition_by_value: false,
            allow_insecure_http_transport: false,
            refresh_expires_in: 1000,
            use_request_uri: false,
            issuance: OpenID4VCIssuanceParams {
                disabled: false,
                url_scheme: "openid-credential-offer".to_string(),
                redirect_uri: OpenID4VCRedirectUriParams {
                    disabled: false,
                    allowed_schemes: vec!["https".to_string()],
                },
            },
            presentation: generic_presentation_params(),
        }),
        ..Default::default()
    });

    let invalid_client_metadata_uri = "http://127.0.0.1/client_metadata_uri";
    let client_metadata_uri_is_not_https = Url::parse(&format!("openid4vp://?response_type=vp_token&nonce={}&client_id_scheme=redirect_uri&client_id={}&client_metadata_uri={}&response_mode=direct_post&response_uri={}&presentation_definition={}"
                                                               , nonce, callback_url, invalid_client_metadata_uri, callback_url, presentation_definition)).unwrap();
    let result = protocol_https_only
        .holder_handle_invitation(
            client_metadata_uri_is_not_https,
            generic_organisation(),
            &storage_proxy,
            &operations,
        )
        .await
        .unwrap_err();
    assert!(matches!(result, ExchangeProtocolError::InvalidRequest(_)));

    let invalid_presentation_definition_uri = "http://127.0.0.1/presentation_definition_uri";
    let presentation_definition_uri_is_not_https = Url::parse(&format!("openid4vp://?response_type=vp_token&nonce={}&client_id_scheme=redirect_uri&client_id={}&client_metadata={}&response_mode=direct_post&response_uri={}&presentation_definition_uri={}"
                                                                       , nonce, callback_url, client_metadata, callback_url, invalid_presentation_definition_uri)).unwrap();
    let result = protocol_https_only
        .holder_handle_invitation(
            presentation_definition_uri_is_not_https,
            generic_organisation(),
            &storage_proxy,
            &operations,
        )
        .await
        .unwrap_err();
    assert!(matches!(result, ExchangeProtocolError::InvalidRequest(_)));
}

#[test]
fn test_serialize_and_deserialize_interaction_data() {
    let client_metadata = serde_json::to_string(&OpenID4VPClientMetadata {
        jwks: vec![],
        vp_formats: HashMap::from([(
            "jwt_vp_json".to_string(),
            OpenID4VPFormat {
                alg: vec!["EdDSA".to_string()],
            },
        )]),
        client_id_scheme: ClientIdSchemaType::RedirectUri,
        authorization_encrypted_response_alg: None,
        authorization_encrypted_response_enc: None,
    })
    .unwrap();
    let presentation_definition = serde_json::to_string(&OpenID4VPPresentationDefinition {
        id: Default::default(),
        input_descriptors: vec![],
    })
    .unwrap();

    let nonce = Uuid::new_v4().to_string();
    let callback_url = "http://127.0.0.1/callback";

    let query = Url::parse(&format!("openid4vp://?response_type=vp_token&nonce={}&client_id_scheme=redirect_uri&client_id={}&client_metadata={}&response_mode=direct_post&response_uri={}&presentation_definition={}"
                                    , nonce, callback_url, client_metadata, callback_url, presentation_definition)).unwrap().query().unwrap().to_string();
    let data: OpenID4VPHolderInteractionData = serde_qs::from_str(&query).unwrap();
    let json = serde_json::to_string(&data).unwrap();
    let _data_from_json: OpenID4VPHolderInteractionData = serde_json::from_str(&json).unwrap();

    let presentation_definition_uri = "https://127.0.0.1/presentation-definition";
    let query_with_presentation_definition_uri = Url::parse(&format!("openid4vp://?response_type=vp_token&nonce={}&client_id_scheme=redirect_uri&client_id={}&client_metadata={}&response_mode=direct_post&response_uri={}&presentation_definition_uri={}"
                                                                     , nonce, callback_url, client_metadata, callback_url, presentation_definition_uri)).unwrap().query().unwrap().to_string();
    let data: OpenID4VPHolderInteractionData =
        serde_qs::from_str(&query_with_presentation_definition_uri).unwrap();
    let json = serde_json::to_string(&data).unwrap();
    let _data_from_json: OpenID4VPHolderInteractionData = serde_json::from_str(&json).unwrap();
}

#[test]
fn test_get_parent_claim_paths() {
    assert!(get_parent_claim_paths("").is_empty());
    assert!(get_parent_claim_paths("this_is_not_yellow").is_empty());
    assert_eq!(
        vec!["this", "this/is", "this/is/yellow"],
        get_parent_claim_paths("this/is/yellow/man")
    );
}

#[test]
fn test_build_claims_keys_for_mdoc_converts_to_credential_subjects_compatible_claim_keys() {
    let claims = [
        (indexmap! {}, indexmap! {}),
        (
            indexmap! {
                "age".into() => OpenID4VCICredentialOfferClaim {
                    value_type: "INTEGER".into(),
                    value: OpenID4VCICredentialOfferClaimValue::String("55".into()),
                },
                "address".into() => OpenID4VCICredentialOfferClaim {
                    value_type: "OBJECT".into(),
                    value: OpenID4VCICredentialOfferClaimValue::Nested(indexmap! {
                        "streetName".into() => OpenID4VCICredentialOfferClaim {
                            value: OpenID4VCICredentialOfferClaimValue::String("Via Roma".into()),
                            value_type: "STRING".into(),
                        },
                    }),
                },
                "company".into() => OpenID4VCICredentialOfferClaim {
                    value_type: "OBJECT".into(),
                    value: OpenID4VCICredentialOfferClaimValue::Nested(indexmap! {
                        "name".into() => OpenID4VCICredentialOfferClaim {
                            value_type: "STRING".into(),
                            value: OpenID4VCICredentialOfferClaimValue::String("Procivis".into()),
                        },
                        "address".into() => OpenID4VCICredentialOfferClaim {
                            value_type: "OBJECT".into(),
                            value: OpenID4VCICredentialOfferClaimValue::Nested(indexmap! {
                                "streetName".into() => OpenID4VCICredentialOfferClaim {
                                    value: OpenID4VCICredentialOfferClaimValue::String("Deitzingerstrasse 22".into()),
                                    value_type: "STRING".into(),
                                },
                            }),
                        },
                    }),
                }
            },
            // expected
            indexmap! {
                "age".into() => OpenID4VCICredentialValueDetails { value: "55".into(), value_type: "INTEGER".into() },
                "address/streetName".into() => OpenID4VCICredentialValueDetails { value: "Via Roma".into(), value_type: "STRING".into() },
                "company/name".into() => OpenID4VCICredentialValueDetails { value: "Procivis".into(), value_type: "STRING".into() },
                "company/address/streetName".into() => OpenID4VCICredentialValueDetails { value: "Deitzingerstrasse 22".into(), value_type: "STRING".into() }
            },
        ),
    ];

    for (input, expected) in claims {
        let res = build_claims_keys_for_mdoc(&input);
        assert_eq!(expected, res);
    }
}

fn generic_schema() -> CredentialSchema {
    CredentialSchema {
        id: Uuid::new_v4().into(),
        deleted_at: None,
        imported_source_url: "CORE_URL".to_string(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: "LPTestNestedSelectiveZug".to_string(),
        format: "JSON_LD_BBSPLUS".to_string(),
        revocation_method: "NONE".to_string(),
        wallet_storage_type: None,
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_id: "http://127.0.0.1/ssi/schema/v1/id".to_string(),
        schema_type: CredentialSchemaType::ProcivisOneSchema2024,
        claim_schemas: Some(vec![
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "First Name".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                },
                required: true,
            },
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "Last Name".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                },
                required: true,
            },
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "Address".to_string(),
                    data_type: "OBJECT".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                },
                required: false,
            },
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "Address/Street".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                },
                required: true,
            },
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "Address/Number".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                },
                required: true,
            },
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "Address/Apartment".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                },
                required: false,
            },
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "Address/Zip".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                },
                required: true,
            },
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "Address/City".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                },
                required: true,
            },
        ]),
        organisation: Some(Organisation {
            id: Uuid::new_v4().into(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        }),
        allow_suspension: true,
    }
}

fn generic_schema_array_object() -> CredentialSchema {
    CredentialSchema {
        id: Uuid::new_v4().into(),
        deleted_at: None,
        created_date: get_dummy_date(),
        imported_source_url: "CORE_URL".to_string(),
        last_modified: get_dummy_date(),
        name: "LPTestNestedSelectiveZug".to_string(),
        format: "JSON_LD_CLASSIC".to_string(),
        revocation_method: "NONE".to_string(),
        wallet_storage_type: None,
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_id: "http://127.0.0.1/ssi/schema/v1/id".to_string(),
        schema_type: CredentialSchemaType::ProcivisOneSchema2024,
        claim_schemas: Some(vec![
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "array_string".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: true,
                },
                required: true,
            },
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "optional_array_string".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: true,
                },
                required: false,
            },
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "array_object".to_string(),
                    data_type: "OBJECT".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: true,
                },
                required: true,
            },
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "array_object/Field 1".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                },
                required: true,
            },
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "array_object/Field 2".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                },
                required: false,
            },
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "array_object/Field array".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: true,
                },
                required: false,
            },
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "Address".to_string(),
                    data_type: "OBJECT".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                },
                required: true,
            },
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "Address/Street".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                },
                required: true,
            },
        ]),
        organisation: Some(Organisation {
            id: Uuid::new_v4().into(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        }),
        allow_suspension: true,
    }
}

fn generic_schema_object_hell() -> CredentialSchema {
    CredentialSchema {
        id: Uuid::new_v4().into(),
        deleted_at: None,
        created_date: get_dummy_date(),
        imported_source_url: "CORE_URL".to_string(),
        last_modified: get_dummy_date(),
        name: "LPTestNestedSelectiveZug".to_string(),
        format: "JSON_LD_CLASSIC".to_string(),
        revocation_method: "NONE".to_string(),
        wallet_storage_type: None,
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_id: "http://127.0.0.1/ssi/schema/v1/id".to_string(),
        schema_type: CredentialSchemaType::ProcivisOneSchema2024,
        claim_schemas: Some(vec![
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "opt_obj".to_string(),
                    data_type: "OBJECT".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                },
                required: false,
            },
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "opt_obj/obj_str".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                },
                required: true,
            },
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "opt_obj/opt_obj".to_string(),
                    data_type: "OBJECT".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                },
                required: false,
            },
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "opt_obj/opt_obj/field_man".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                },
                required: true,
            },
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "opt_obj/opt_obj/field_opt".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                },
                required: false,
            },
        ]),
        organisation: Some(Organisation {
            id: Uuid::new_v4().into(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        }),
        allow_suspension: true,
    }
}

#[test]
fn test_map_offered_claims_to_credential_schema_success_missing_optional_object() {
    let schema = generic_schema();

    let claim_keys = IndexMap::from([
        (
            "Last Name".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "Last Name Value".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "First Name".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "First Name Value".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
    ]);

    let result =
        map_offered_claims_to_credential_schema(&schema, Uuid::new_v4().into(), &claim_keys)
            .unwrap();
    assert_eq!(2, result.len());

    let result = result
        .into_iter()
        .map(|v| (v.path, v.value))
        .collect::<HashMap<_, _>>();

    assert_eq!(claim_keys["First Name"].value, result["First Name"]);
    assert_eq!(claim_keys["Last Name"].value, result["Last Name"]);
}

#[test]
fn test_map_offered_claims_to_credential_schema_failed_partially_missing_optional_object() {
    let schema = generic_schema();

    let claim_keys = IndexMap::from([
        (
            "Last Name".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "Last Name Value".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "First Name".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "First Name Value".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "Address/Street".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "Street Value".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
    ]);

    let result =
        map_offered_claims_to_credential_schema(&schema, Uuid::new_v4().into(), &claim_keys);
    assert!(matches!(result, Err(ExchangeProtocolError::Failed(_))));
}

#[test]
fn test_map_offered_claims_to_credential_schema_success_object_array() {
    let schema = generic_schema_array_object();

    let claim_keys = IndexMap::from([
        (
            "array_string/0".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "111".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "array_string/1".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "222".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "array_string/2".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "333".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "optional_array_string/0".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "opt111".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "array_object/0/Field 1".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "01".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "array_object/0/Field 2".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "02".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "array_object/0/Field array/0".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "0array0".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "array_object/0/Field array/1".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "0array1".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "array_object/1/Field 1".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "11".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "Address/Street".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "Street Value".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
        // Field 2 and array is missing for array object 2
    ]);

    let result =
        map_offered_claims_to_credential_schema(&schema, Uuid::new_v4().into(), &claim_keys)
            .unwrap();
    assert_eq!(10, result.len());

    for claim in result {
        assert_eq!(claim_keys[claim.path.as_str()].value, claim.value)
    }
}

#[test]
fn test_map_offered_claims_to_credential_schema_success_optional_array_missing() {
    let schema = generic_schema_array_object();

    let claim_keys = IndexMap::from([
        (
            "array_string/0".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "1".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "array_object/0/Field 1".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "01".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "array_object/0/Field 2".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "02".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "Address/Street".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "Street Value".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
    ]);

    let result =
        map_offered_claims_to_credential_schema(&schema, Uuid::new_v4().into(), &claim_keys)
            .unwrap();
    assert_eq!(4, result.len());

    for claim in result {
        assert_eq!(claim_keys[claim.path.as_str()].value, claim.value)
    }
}

#[test]
fn test_map_offered_claims_to_credential_schema_mandatory_array_missing_error() {
    let schema = generic_schema_array_object();

    let claim_keys = IndexMap::from([
        (
            "array_object/0/Field 1".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "01".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "array_object/0/Field 2".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "02".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "Address/Street".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "Street Value".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
    ]);

    assert!(
        map_offered_claims_to_credential_schema(&schema, Uuid::new_v4().into(), &claim_keys)
            .is_err()
    )
}

#[test]
fn test_map_offered_claims_to_credential_schema_mandatory_array_object_field_missing_error() {
    let schema = generic_schema_array_object();

    let claim_keys = IndexMap::from([
        (
            "array_string/0".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "1".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "array_object/0/Field 2".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "02".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "Address/Street".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "Street Value".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
    ]);

    assert!(
        map_offered_claims_to_credential_schema(&schema, Uuid::new_v4().into(), &claim_keys)
            .is_err()
    )
}

#[test]
fn test_map_offered_claims_to_credential_schema_mandatory_object_error() {
    let schema = generic_schema_array_object();

    let claim_keys = IndexMap::from([
        (
            "array_string/0".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "1".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "array_object/0/Field 1".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "02".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "array_object/0/Field 2".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "02".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
    ]);

    assert!(
        map_offered_claims_to_credential_schema(&schema, Uuid::new_v4().into(), &claim_keys)
            .is_err()
    )
}

#[test]
fn test_map_offered_claims_to_credential_schema_opt_object_opt_obj_present() {
    let schema = generic_schema_object_hell();

    let claim_keys = IndexMap::from([
        (
            "opt_obj/obj_str".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "os".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "opt_obj/opt_obj/field_man".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "oofm".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
    ]);

    let result =
        map_offered_claims_to_credential_schema(&schema, Uuid::new_v4().into(), &claim_keys)
            .unwrap();
    assert_eq!(2, result.len());

    for claim in result {
        assert_eq!(claim_keys[claim.path.as_str()].value, claim.value)
    }
}

#[test]
fn test_map_offered_claims_to_credential_schema_opt_object_opt_obj_missing() {
    let schema = generic_schema_object_hell();

    let claim_keys = IndexMap::from([(
        "opt_obj/obj_str".to_string(),
        OpenID4VCICredentialValueDetails {
            value: "os".to_string(),
            value_type: "STRING".to_string(),
        },
    )]);

    let result =
        map_offered_claims_to_credential_schema(&schema, Uuid::new_v4().into(), &claim_keys)
            .unwrap();
    assert_eq!(1, result.len());

    for claim in result {
        assert_eq!(claim_keys[claim.path.as_str()].value, claim.value)
    }
}

#[test]
fn test_map_offered_claims_to_credential_schema_opt_object_opt_obj_present_man_field_missing_error()
{
    let schema = generic_schema_object_hell();

    let claim_keys = IndexMap::from([
        (
            "opt_obj/obj_str".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "os".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "opt_obj/opt_obj/field_opt".to_string(),
            OpenID4VCICredentialValueDetails {
                value: "oofm".to_string(),
                value_type: "STRING".to_string(),
            },
        ),
    ]);

    assert!(
        map_offered_claims_to_credential_schema(&schema, Uuid::new_v4().into(), &claim_keys)
            .is_err()
    )
}

#[test]
fn test_map_offered_claims_to_credential_schema_opt_object_opt_obj_present_man_root_field_missing_error(
) {
    let schema = generic_schema_object_hell();

    let claim_keys = IndexMap::from([(
        "opt_obj/opt_obj/field_man".to_string(),
        OpenID4VCICredentialValueDetails {
            value: "oofm".to_string(),
            value_type: "STRING".to_string(),
        },
    )]);

    assert!(
        map_offered_claims_to_credential_schema(&schema, Uuid::new_v4().into(), &claim_keys)
            .is_err()
    )
}

#[tokio::test]
async fn test_can_handle_issuance_success_with_custom_url_scheme() {
    let url_scheme = "my-custom-scheme";

    let protocol = setup_protocol(TestInputs {
        params: Some(test_params(url_scheme, "presentation-url-scheme")),
        ..Default::default()
    });

    let test_url = format!("{url_scheme}://?credential_offer_uri=http%3A%2F%2Fbase_url%2Fssi%2Foidc-issuer%2Fv1%2Fc322aa7f-9803-410d-b891-939b279fb965%2Foffer%2Fc322aa7f-9803-410d-b891-939b279fb965");
    assert!(protocol.can_handle(&test_url.parse().unwrap()))
}

#[test]
fn test_can_handle_issuance_fail_with_custom_url_scheme() {
    let url_scheme = "my-custom-scheme";
    let other_url_scheme = "my-different-scheme";

    let protocol = setup_protocol(TestInputs {
        params: Some(test_params(url_scheme, "presentation-url-scheme")),
        ..Default::default()
    });

    let test_url = format!("{other_url_scheme}://?credential_offer_uri=http%3A%2F%2Fbase_url%2Fssi%2Foidc-issuer%2Fv1%2Fc322aa7f-9803-410d-b891-939b279fb965%2Foffer%2Fc322aa7f-9803-410d-b891-939b279fb965");
    assert!(!protocol.can_handle(&test_url.parse().unwrap()))
}

#[tokio::test]
async fn test_can_handle_presentation_success_with_custom_url_scheme() {
    let url_scheme = "my-custom-scheme";

    let protocol = setup_protocol(TestInputs {
        params: Some(test_params("issuance-url-scheme", url_scheme)),
        ..Default::default()
    });

    let test_url = format!("{url_scheme}://?response_type=vp_token&nonce=123&client_id_scheme=redirect_uri&client_id=abc&client_metadata=foo&response_mode=direct_post&response_uri=uri&presentation_definition=def");
    assert!(protocol.can_handle(&test_url.parse().unwrap()))
}

#[test]
fn test_can_handle_presentation_fail_with_custom_url_scheme() {
    let url_scheme = "my-custom-scheme";
    let other_url_scheme = "my-different-scheme";

    let protocol = setup_protocol(TestInputs {
        params: Some(test_params("issuance-url-scheme", url_scheme)),
        ..Default::default()
    });

    let test_url = format!("{other_url_scheme}://?credential_offer_uri=http%3A%2F%2Fbase_url%2Fssi%2Foidc-issuer%2Fv1%2Fc322aa7f-9803-410d-b891-939b279fb965%2Foffer%2Fc322aa7f-9803-410d-b891-939b279fb965");
    assert!(!protocol.can_handle(&test_url.parse().unwrap()))
}

#[tokio::test]
async fn test_generate_share_credentials_custom_scheme() {
    let credential = generic_credential();
    let url_scheme = "my-custom-scheme";
    let protocol = setup_protocol(TestInputs {
        params: Some(test_params(url_scheme, "presentation-url-scheme")),
        ..Default::default()
    });

    let result = protocol
        .issuer_share_credential(&credential, "")
        .await
        .unwrap();
    assert!(result.url.starts_with(url_scheme));
}

#[tokio::test]
async fn test_share_proof_custom_scheme() {
    let url_scheme = "my-custom-scheme";
    let mut formatter_provider = MockCredentialFormatterProvider::new();
    let mut credential_formatter = MockCredentialFormatter::new();
    credential_formatter
        .expect_get_capabilities()
        .returning(FormatterCapabilities::default);
    let arc = Arc::new(credential_formatter);
    formatter_provider
        .expect_get_formatter()
        .returning(move |_| Some(arc.clone()));
    let protocol = setup_protocol(TestInputs {
        formatter_provider,
        params: Some(test_params("issuance-url-scheme", url_scheme)),
        ..Default::default()
    });

    let proof_id = Uuid::new_v4();
    let proof = test_proof(proof_id, "JWT");

    let format_type_mapper: FormatMapper = Arc::new(move |input| Ok(input.to_owned()));

    let type_to_descriptor_mapper: TypeToDescriptorMapper = Arc::new(move |_| Ok(HashMap::new()));

    let key_id = Uuid::new_v4().into();
    let encryption_key_jwk = PublicKeyJwkDTO::Ec(PublicKeyJwkEllipticDataDTO {
        r#use: None,
        kid: None,
        crv: "P-256".to_string(),
        x: "x".to_string(),
        y: None,
    });
    let vp_formats = HashMap::new();

    let ShareResponse { url, .. } = protocol
        .verifier_share_proof(
            &proof,
            format_type_mapper,
            key_id,
            encryption_key_jwk,
            vp_formats,
            type_to_descriptor_mapper,
            ClientIdSchemaType::RedirectUri,
        )
        .await
        .unwrap();
    assert!(url.starts_with(url_scheme));
}

fn test_params(issuance_url_scheme: &str, presentation_url_scheme: &str) -> OpenID4VCParams {
    OpenID4VCParams {
        pre_authorized_code_expires_in: 10,
        token_expires_in: 10,
        credential_offer_by_value: true,
        client_metadata_by_value: false,
        presentation_definition_by_value: false,
        allow_insecure_http_transport: true,
        refresh_expires_in: 1000,
        use_request_uri: false,
        issuance: OpenID4VCIssuanceParams {
            disabled: false,
            url_scheme: issuance_url_scheme.to_string(),
            redirect_uri: OpenID4VCRedirectUriParams {
                disabled: false,
                allowed_schemes: vec!["https".to_string()],
            },
        },
        presentation: OpenID4VCPresentationParams {
            disabled: false,
            url_scheme: presentation_url_scheme.to_string(),
            x509_ca_certificate: None,
            holder: OpenID4VCPresentationHolderParams {
                supported_client_id_schemes: vec![
                    ClientIdSchemaType::RedirectUri,
                    ClientIdSchemaType::VerifierAttestation,
                ],
            },
            verifier: OpenID4VCPresentationVerifierParams {
                default_client_id_schema: ClientIdSchemaType::RedirectUri,
                supported_client_id_schemes: vec![
                    ClientIdSchemaType::RedirectUri,
                    ClientIdSchemaType::VerifierAttestation,
                ],
            },
            redirect_uri: OpenID4VCRedirectUriParams {
                disabled: false,
                allowed_schemes: vec!["https".to_string()],
            },
        },
    }
}
