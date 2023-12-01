use serde_json::{json, Value};
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;
use wiremock::{
    http::Method::{Get, Post},
    matchers::{method, path, query_param},
    Mock, MockServer, ResponseTemplate,
};

use core_server::router::start_server;

use crate::{fixtures, utils};

#[tokio::test]
async fn test_handle_invitation_endpoint_for_procivis_temp_issuance() {
    let mock_server = MockServer::start().await;
    let config = fixtures::create_config(mock_server.uri());
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let did = fixtures::create_did_key(&db_conn, &organisation).await;

    let credential_id = Uuid::new_v4();

    Mock::given(method(Post))
        .and(path("/ssi/temporary-issuer/v1/connect"))
        .and(query_param("protocol", "PROCIVIS_TEMPORARY"))
        .and(query_param("credential", credential_id.to_string()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "claims": [
                    {
                        "schema": {
                            "createdDate": "2023-11-08T15:46:14.997Z",
                            "datatype": "STRING",
                            "id": "48db4654-01c4-4a43-9df4-300f1f425c40",
                            "key": "field",
                            "lastModified": "2023-11-08T15:46:14.997Z",
                            "required": true
                        },
                        "value": "aae"
                    }
                ],
                "createdDate": "2023-11-09T08:39:16.459Z",
                "id": credential_id,
                "issuanceDate": "2023-11-09T08:39:16.459Z",
                "issuerDid": "did:key:z6Mkm1qx9JYefnqDVyyUBovf4Jo97jDxVzPejTeStyrNzyqU",
                "lastModified": "2023-11-09T08:39:16.548Z",
                "revocationDate": null,
                "schema": {
                    "createdDate": "2023-11-08T15:46:14.997Z",
                    "format": "SDJWT",
                    "id": "293d1376-62ea-4b0e-8c16-2dfe4f7ac0bd",
                    "lastModified": "2023-11-08T15:46:14.997Z",
                    "name": "detox-e2e-revocable-12a4212d-9b28-4bb0-9640-23c938f8a8b1",
                    "organisationId": "2476ebaa-0108-413d-aa72-c2a6babd423f",
                    "revocationMethod": "STATUSLIST2021"
                },
                "state": "PENDING"
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());

    let url = format!("{base_url}/api/interaction/v1/handle-invitation");

    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn).await });

    let resp = utils::client()
        .post(url)
        .bearer_auth("test")
        .json(&json!({
          "didId": did.id,
          "url": format!("{}/ssi/temporary-issuer/v1/connect?protocol=PROCIVIS_TEMPORARY&credential={credential_id}", mock_server.uri())
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    let resp: Value = resp.json().await.unwrap();
    assert!(resp.get("interactionId").is_some());
}

#[tokio::test]
async fn test_handle_invitation_endpoint_for_openid4vc_issuance() {
    let mock_server = MockServer::start().await;
    let config = fixtures::create_config(mock_server.uri());
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let did = fixtures::create_did_key(&db_conn, &organisation).await;

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

    Mock::given(method(Get))
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

    Mock::given(method(Get))
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

    Mock::given(method(Post))
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

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url: String = format!("http://{}", listener.local_addr().unwrap());

    let url: String = format!("{base_url}/api/interaction/v1/handle-invitation");

    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn).await });

    let credential_offer = serde_json::to_string(&credential_offer).unwrap();
    let mut credential_offer_url: Url = "openid-credential-offer://".parse().unwrap();
    credential_offer_url
        .query_pairs_mut()
        .append_pair("credential_offer", &credential_offer);

    let resp = utils::client()
        .post(url)
        .bearer_auth("test")
        .json(&json!({
          "didId": did.id,
          "url": credential_offer_url,
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    let resp: Value = resp.json().await.unwrap();
    assert!(resp.get("interactionId").is_some());
}
