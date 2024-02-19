use core_server::router::start_server;
use one_core::{
    model::proof::ProofStateEnum,
    provider::transport_protocol::openid4vc::dto::{
        OpenID4VPClientMetadata, OpenID4VPFormat, OpenID4VPPresentationDefinition,
    },
};
use serde_json::{json, Value};
use std::collections::HashMap;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;
use wiremock::http::Method;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::fixtures;
use crate::utils::context::TestContext;
use crate::utils::{self};

#[tokio::test]
async fn test_handle_invitation_endpoint_for_procivis_temp_issuance() {
    // GIVEN
    let (context, _, did, _) = TestContext::new_with_did().await;
    let credential_id = Uuid::new_v4();

    context
        .server_mock
        .ssi_issuance("PROCIVIS_TEMPORARY", credential_id)
        .await;

    // WHEN
    let url = format!(
        "{}/ssi/temporary-issuer/v1/connect?protocol=PROCIVIS_TEMPORARY&credential={credential_id}",
        context.server_mock.uri()
    );
    let resp = context
        .api
        .interactions
        .handle_invitation(did.id, &url)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);

    let resp = resp.json_value().await;
    assert!(resp.get("interactionId").is_some());
}

#[tokio::test]
async fn test_handle_invitation_endpoint_for_procivis_temp_proving() {
    // GIVEN
    let mock_server = MockServer::start().await;
    let config = fixtures::create_config(mock_server.uri(), None);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let organisation2 = fixtures::create_organisation(&db_conn).await;
    let holder_did = fixtures::create_did(&db_conn, &organisation, None).await;
    let verifier_id = fixtures::create_did(&db_conn, &organisation2, None).await;

    let proof_id = Uuid::new_v4();

    Mock::given(method(Method::POST))
        .and(path("/ssi/temporary-verifier/v1/connect"))
        .and(query_param("protocol", "PROCIVIS_TEMPORARY"))
        .and(query_param("proof", proof_id.to_string()))
        .and(query_param("redirect_uri", ""))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "claims": [
                    {
                        "id": "48db4654-01c4-4a43-9df4-300f1f425c40",
                        "createdDate": "2023-11-08T15:46:14.997Z",
                        "lastModified": "2023-11-08T15:46:14.997Z",
                        "key": "Name",
                        "datatype": "STRING",
                        "required": true,
                        "credentialSchema": {
                            "createdDate": "2023-11-08T15:46:14.997Z",
                            "format": "SDJWT",
                            "id": "293d1376-62ea-4b0e-8c16-2dfe4f7ac0bd",
                            "lastModified": "2023-11-08T15:46:14.997Z",
                            "name": "detox-e2e-revocable-12a4212d-9b28-4bb0-9640-23c938f8a8b1",
                            "organisationId": "2476ebaa-0108-413d-aa72-c2a6babd423f",
                            "revocationMethod": "BITSTRINGSTATUSLIST"
                        },
                    }
                ],
                "verifierDid" : verifier_id.did.to_string(),
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    // WHEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());

    let url = format!("{base_url}/api/interaction/v1/handle-invitation");

    let db_con_cloned = db_conn.clone();
    let _handle = tokio::spawn(async move { start_server(listener, config, db_con_cloned).await });

    let resp = utils::client()
        .post(url)
        .bearer_auth("test")
        .json(&json!({
          "didId": holder_did.id,
          "url": format!("{}/ssi/temporary-verifier/v1/connect?protocol=PROCIVIS_TEMPORARY&proof={proof_id}&redirect_uri=", mock_server.uri())
        }))
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 200);

    let resp: Value = resp.json().await.unwrap();
    assert!(resp.get("interactionId").is_some());
    assert_eq!(
        resp.get("proofId").unwrap().as_str(),
        Some(proof_id.to_string().as_str())
    );

    let proof = fixtures::get_proof(&db_conn, &proof_id).await;
    assert_eq!(proof.holder_did.unwrap().id, holder_did.id);
    assert!(proof
        .state
        .unwrap()
        .iter()
        .any(|state| state.state == ProofStateEnum::Pending));

    assert_eq!(
        &proof.interaction.unwrap().id.to_string(),
        resp.get("interactionId").unwrap().as_str().unwrap()
    );
}

#[tokio::test]
async fn test_handle_invitation_endpoint_for_openid4vc_issuance_offer_by_value() {
    let mock_server = MockServer::start().await;
    let (context, _, did, _) = TestContext::new_with_did().await;

    let credential_id = "90eb3e0f-cc34-4994-8093-0bdb3983ef21";
    let credential_issuer = format!("{}/ssi/oidc-issuer/v1/{credential_id}", mock_server.uri());
    let credential_offer = json!({
        "credential_issuer": credential_issuer,
        "credentials": [
            {
                "format": "vc+sd-jwt",
                "credential_definition": {
                    "type": [
                        "VerifiableCredential"
                    ],
                    "credentialSubject": {
                        "field": {
                            "value": "xyy",
                            "value_type": "STRING"
                        }
                    }
                }
            }
        ],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": "78db97c3-dbda-4bb2-a17c-b971ae7d6740"
            }
        }
    });

    Mock::given(method(Method::GET))
        .and(path(format!(
            "/ssi/oidc-issuer/v1/{credential_id}/.well-known/openid-credential-issuer"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "credential_endpoint": format!("{credential_issuer}/credential"),
                "credential_issuer": credential_issuer,
                "credentials_supported": [
                    {
                        "credential_definition": {
                            "type": [
                                "VerifiableCredential"
                            ]
                        },
                        "format": "vc+sd-jwt"
                    }
                ]
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    let token_endpoint = format!("{credential_issuer}/token");

    Mock::given(method(Method::GET))
        .and(path(format!(
            "/ssi/oidc-issuer/v1/{credential_id}/.well-known/openid-configuration"
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

    Mock::given(method(Method::POST))
    .and(path(format!("/ssi/oidc-issuer/v1/{credential_id}/token")))
    .respond_with(ResponseTemplate::new(200).set_body_json(json!(
        {
            "access_token": "4994a63d-d822-4fb9-87bf-6f298247c571.0ss4z9sgtsNYafQKhDeOINLhQIdW8yQE",
            "expires_in": OffsetDateTime::now_utc().unix_timestamp() + 3600,
            "token_type": "bearer"
        }
    )))
    .expect(1)
    .mount(&mock_server).await;

    // WHEN
    let credential_offer = serde_json::to_string(&credential_offer).unwrap();
    let mut credential_offer_url: Url = "openid-credential-offer://".parse().unwrap();
    credential_offer_url
        .query_pairs_mut()
        .append_pair("credential_offer", &credential_offer);

    let resp = context
        .api
        .interactions
        .handle_invitation(did.id, credential_offer_url.as_ref())
        .await;

    // THEN
    assert_eq!(resp.status(), 200);

    let resp = resp.json_value().await;
    assert!(resp.get("interactionId").is_some());
}

#[tokio::test]
async fn test_handle_invitation_endpoint_for_openid4vc_issuance_offer_by_reference() {
    let mock_server = MockServer::start().await;
    let (context, _, did, _) = TestContext::new_with_did().await;

    let credential_id = Uuid::new_v4();
    let credential_schema_id = Uuid::new_v4();
    let credential_issuer = format!(
        "{}/ssi/oidc-issuer/v1/{credential_schema_id}",
        mock_server.uri()
    );
    let credential_offer = json!({
        "credential_issuer": credential_issuer,
        "credentials": [
            {
                "format": "vc+sd-jwt",
                "credential_definition": {
                    "type": [
                        "VerifiableCredential"
                    ],
                    "credentialSubject": {
                        "field": {
                            "value": "xyy",
                            "value_type": "STRING"
                        }
                    }
                }
            }
        ],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": "78db97c3-dbda-4bb2-a17c-b971ae7d6740"
            }
        }
    });

    Mock::given(method(Method::GET))
        .and(path(format!(
            "/ssi/oidc-issuer/v1/{credential_schema_id}/.well-known/openid-credential-issuer"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "credential_endpoint": format!("{credential_issuer}/credential"),
                "credential_issuer": credential_issuer,
                "credentials_supported": [
                    {
                        "credential_definition": {
                            "type": [
                                "VerifiableCredential"
                            ]
                        },
                        "format": "vc+sd-jwt"
                    }
                ]
            }
        )))
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

    Mock::given(method(Method::POST))
    .and(path(format!("/ssi/oidc-issuer/v1/{credential_schema_id}/token")))
    .respond_with(ResponseTemplate::new(200).set_body_json(json!(
        {
            "access_token": "4994a63d-d822-4fb9-87bf-6f298247c571.0ss4z9sgtsNYafQKhDeOINLhQIdW8yQE",
            "expires_in": OffsetDateTime::now_utc().unix_timestamp() + 3600,
            "token_type": "bearer"
        }
    )))
    .expect(1)
    .mount(&mock_server).await;

    Mock::given(method(Method::GET))
        .and(path(format!(
            "/ssi/oidc-issuer/v1/{credential_schema_id}/offer/{credential_id}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(credential_offer))
        .expect(1)
        .mount(&mock_server)
        .await;

    // WHEN
    // let credential_offer = serde_json::to_string(&credential_offer).unwrap();
    let mut credential_offer_url: Url = "openid-credential-offer://".parse().unwrap();
    credential_offer_url.query_pairs_mut().append_pair(
        "credential_offer_uri",
        &format!("{credential_issuer}/offer/{credential_id}"),
    );

    let resp = context
        .api
        .interactions
        .handle_invitation(did.id, credential_offer_url.as_ref())
        .await;

    // THEN
    assert_eq!(resp.status(), 200);

    let resp = resp.json_value().await;
    assert!(resp.get("interactionId").is_some());
}

#[tokio::test]
async fn test_handle_invitation_endpoint_for_openid4vc_proof_by_reference() {
    let mock_server = MockServer::start().await;
    let (context, _, did, _) = TestContext::new_with_did().await;

    let client_metadata = serde_json::to_string(&OpenID4VPClientMetadata {
        vp_formats: HashMap::from([(
            "jwt_vp_json".to_string(),
            OpenID4VPFormat {
                alg: vec!["EdDSA".to_string()],
            },
        )]),
        client_id_scheme: "redirect_uri".to_string(),
    })
    .unwrap();
    let presentation_definition = serde_json::to_string(&OpenID4VPPresentationDefinition {
        id: Default::default(),
        input_descriptors: vec![],
    })
    .unwrap();
    let nonce = Uuid::new_v4().to_string();
    let callback_url = "http://127.0.0.1/callback";
    let client_metadata_uri = format!("{}/client-metadata", mock_server.uri());
    let presentation_definition_uri = format!("{}/presentation-definition", mock_server.uri());
    let query = Url::parse(&format!("openid4vp://?response_type=vp_token&nonce={}&client_id_scheme=redirect_uri&client_id={}&client_metadata_uri={}&response_mode=direct_post&response_uri={}&presentation_definition_uri={}"
                                    , nonce, callback_url, client_metadata_uri, callback_url, presentation_definition_uri)).unwrap().to_string();

    Mock::given(method(Method::GET))
        .and(path("/client-metadata"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(client_metadata, "application/json"))
        .expect(1)
        .mount(&mock_server)
        .await;
    Mock::given(method(Method::GET))
        .and(path("/presentation-definition"))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(presentation_definition, "application/json"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .handle_invitation(did.id, &query)
        .await;
    // THEN
    assert_eq!(resp.status(), 200);

    let resp = resp.json_value().await;
    assert!(resp.get("interactionId").is_some());
}

#[tokio::test]
async fn test_handle_invitation_endpoint_for_openid4vc_proof_by_value() {
    let (context, _, did, _) = TestContext::new_with_did().await;

    let client_metadata = serde_json::to_string(&OpenID4VPClientMetadata {
        vp_formats: HashMap::from([(
            "jwt_vp_json".to_string(),
            OpenID4VPFormat {
                alg: vec!["EdDSA".to_string()],
            },
        )]),
        client_id_scheme: "redirect_uri".to_string(),
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
                                    , nonce, callback_url, client_metadata, callback_url, presentation_definition)).unwrap().to_string();

    // WHEN
    let resp = context
        .api
        .interactions
        .handle_invitation(did.id, &query)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);

    let resp = resp.json_value().await;
    assert!(resp.get("interactionId").is_some());
}
