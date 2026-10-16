use axum::http::Method;
use one_core::model::interaction::InteractionType;
use serde_json::json;
use similar_asserts::assert_eq;
use uuid::Uuid;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::utils::context::TestContext;
use crate::utils::db_clients::interactions::TestingInteractionParams;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_continue_issuance_endpoint() {
    // given
    let mock_server = MockServer::start().await;
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let interaction_id = Uuid::new_v4().into();
    let authorization_code = "aUtH_CoDe";
    let credential_schema_id = Uuid::new_v4();

    let credential_issuer = format!(
        "{}/ssi/openid4vci/final-1.0/{credential_schema_id}",
        mock_server.uri()
    );

    let interaction_body = json!({
        "request": {
            "organisation_id": organisation.id,
            "protocol": "OPENID4VCI_FINAL1",
            "issuer": credential_issuer,
            "client_id": "clientId",
            "scope": ["scope1"],
        }
    });

    let interaction_body = serde_json::to_vec(&interaction_body).unwrap();

    context
        .db
        .interactions
        .create(
            &organisation,
            InteractionType::Issuance,
            TestingInteractionParams {
                id: Some(interaction_id),
                data: Some(interaction_body),
                ..Default::default()
            },
        )
        .await;

    Mock::given(method(Method::GET))
        .and(path(format!(
            ".well-known/openid-credential-issuer/ssi/openid4vci/final-1.0/{credential_schema_id}"
        )))
        .and(header("Accept", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "credential_endpoint": format!("{credential_issuer}/credential"),
                "credential_issuer": credential_issuer,
                "credential_configurations_supported": {
                    "doctype": {
                          "scope": "scope1",
                          "format": "mso_mdoc",
                              "claims": {
                              "namespace1": {
                                  "string_array": {
                                    "value_type": "string[]",
                                    "mandatory": true
                                  },
                                  "object_array": [
                                  {
                                      "field1": {
                                        "value_type": "string",
                                        "mandatory": true
                                      },
                                      "field 2": {
                                        "value_type": "string",
                                        "mandatory": true
                                      }
                                  }
                                  ]
                              },
                              "namespace2": {
                                  "Field 1": {
                                    "value_type": "string",
                                    "mandatory": true
                                  },
                                  "array": [
                                    {
                                        "N2 field1": {
                                            "value_type": "string",
                                            "mandatory": true
                                        },
                                        "N2 array": {
                                            "value_type": "string[]",
                                            "mandatory": true
                                        }
                                    }
                                ]
                              }
                          },
                          "order": [
                              "namespace1~string_array",
                              "namespace1~object_array",
                              "namespace2~Field 1",
                              "namespace2~array"
                          ],
                          "display": [
                          {
                              "name": "TestNestedHell"
                          }
                          ],
                          "proof_types_supported": {
                            "jwt": {
                              "proof_signing_alg_values_supported": [
                                "ES256",
                                "EdDSA",
                                "EDDSA",
                                "BBS_PLUS",
                                "ML-DSA-65"
                              ]
                            }
                          }
                      }
              }
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    let token_endpoint = format!("{credential_issuer}/token");

    Mock::given(method(Method::GET))
        .and(path(format!(
            ".well-known/oauth-authorization-server/ssi/openid4vci/final-1.0/{credential_schema_id}"
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

    // when
    let resp = context
        .api
        .interactions
        .continue_issuance(format!(
            "https://localhost:3000/some_path?state={interaction_id}&code={authorization_code}"
        ))
        .await;

    // then
    assert_eq!(resp.status(), 200);

    let resp = resp.json_value().await;
    assert!(resp.get("interactionId").is_some());
    assert_eq!(resp["requiresWalletInstanceAttestation"], false);
    resp["keyAlgorithms"].assert_eq_unordered(&[
        "ECDSA".to_string(),
        "EDDSA".to_string(),
        "BBS_PLUS".to_string(),
        "ML_DSA".to_string(),
    ]);
}

#[tokio::test]
async fn test_continue_issuance_endpoint_failed_invalid_authorization_server() {
    // given
    let mock_server = MockServer::start().await;
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let authorization_code = "aUtH_CoDe";
    let credential_schema_id = Uuid::new_v4();

    let credential_issuer = format!(
        "{}/ssi/openid4vci/final-1.0/{credential_schema_id}",
        mock_server.uri()
    );

    let interaction_body = json!({
        "request": {
            "organisation_id": organisation.id,
            "protocol": "OPENID4VCI_FINAL1",
            "issuer": credential_issuer,
            "client_id": "clientId",
            "scope": ["scope"],
            "authorization_server": "https://invalid.com",
        }
    });

    let interaction_body = serde_json::to_vec(&interaction_body).unwrap();

    let interaction_id = context
        .db
        .interactions
        .create(
            &organisation,
            InteractionType::Issuance,
            TestingInteractionParams {
                data: Some(interaction_body),
                ..Default::default()
            },
        )
        .await
        .id;

    Mock::given(method(Method::GET))
        .and(path(format!(
            ".well-known/openid-credential-issuer/ssi/openid4vci/final-1.0/{credential_schema_id}"
        )))
        .and(header("Accept", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "credential_endpoint": format!("{credential_issuer}/credential"),
                "authorization_servers": [
                    "https://authorization.com"
                ],
                "credential_issuer": credential_issuer,
                "credential_configurations_supported": {
                    "doctype": {
                          "scope": "scope",
                          "format": "mso_mdoc",
                              "claims": {
                              "namespace": {
                                  "field": {
                                    "value_type": "string",
                                    "mandatory": true
                                  }
                              }
                          },
                          "display": [
                          {
                              "name": "Test"
                          }
                          ],
                          "proof_types_supported": {
                            "jwt": {
                              "proof_signing_alg_values_supported": [
                                "ES256",
                                "EdDSA"
                              ]
                            }
                          }
                      }
              }
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    // when
    let resp = context
        .api
        .interactions
        .continue_issuance(format!(
            "https://localhost:3000/some_path?state={interaction_id}&code={authorization_code}"
        ))
        .await;

    // then
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0085");
}

#[tokio::test]
async fn test_dpop_bound_authorization_code_flow() {
    // given
    let mock_server = MockServer::start().await;
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let credential_schema_id = Uuid::new_v4();
    let credential_issuer = format!(
        "{}/ssi/openid4vci/final-1.0/{credential_schema_id}",
        mock_server.uri()
    );

    Mock::given(method(Method::GET))
        .and(path(format!(
            ".well-known/oauth-authorization-server/ssi/openid4vci/final-1.0/{credential_schema_id}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": credential_issuer,
            "authorization_endpoint": format!("{credential_issuer}/authorize"),
            "pushed_authorization_request_endpoint": format!("{credential_issuer}/par"),
            "token_endpoint": format!("{credential_issuer}/token"),
            "dpop_signing_alg_values_supported": ["ES256"],
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path(format!(
            "/ssi/openid4vci/final-1.0/{credential_schema_id}/par"
        )))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "request_uri": "urn:ietf:params:oauth:request_uri:test",
            "expires_in": 60,
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::GET))
        .and(path(format!(
            ".well-known/openid-credential-issuer/ssi/openid4vci/final-1.0/{credential_schema_id}"
        )))
        .and(header("Accept", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "credential_endpoint": format!("{credential_issuer}/credential"),
            "credential_issuer": credential_issuer,
            "credential_configurations_supported": {
                "configuration": {
                    "scope": "scope1",
                    "format": "dc+sd-jwt",
                    "vct": "test-vct",
                    "proof_types_supported": {
                        "jwt": {
                            "proof_signing_alg_values_supported": ["ES256"]
                        }
                    }
                }
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // when
    let resp = context
        .api
        .interactions
        .initiate_issuance(
            organisation.id,
            "OPENID4VCI_FINAL1",
            "clientId",
            credential_issuer.to_owned(),
            vec!["scope1".to_string()],
        )
        .await;

    // then
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let url = resp["url"].as_str().unwrap();
    assert!(url.contains("request_uri="));
    assert!(!url.contains("dpop_jkt="));

    // the authorization code is bound to the key via `dpop_jkt`, without a DPoP proof on the
    // pushed authorization request
    let par_request = mock_server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .find(|request| request.url.path().ends_with("/par"))
        .unwrap();
    assert!(!par_request.headers.contains_key("DPoP"));
    let par_params: std::collections::HashMap<String, String> =
        serde_urlencoded::from_bytes(&par_request.body).unwrap();
    let dpop_jkt = par_params.get("dpop_jkt").unwrap();
    // base64url encoded SHA-256 JWK thumbprint
    assert_eq!(dpop_jkt.len(), 43);

    // the interaction id is passed as the `state` of the authorization request
    let initiated_interaction_id: Uuid = par_params.get("state").unwrap().parse().unwrap();
    let initiated_interaction = context
        .db
        .interactions
        .get(initiated_interaction_id)
        .await
        .unwrap();
    let dpop_key = context
        .db
        .keys
        .get(&initiated_interaction.dpop_key.unwrap().id())
        .await;
    assert_eq!(dpop_key.key_type, "ECDSA");

    // when
    let resp = context
        .api
        .interactions
        .continue_issuance(format!(
            "https://localhost:3000/some_path?state={initiated_interaction_id}&code=aUtH_CoDe"
        ))
        .await;

    // then
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    // the token request has to be made with the key the authorization code is bound to
    let continued_interaction = context
        .db
        .interactions
        .get(resp["interactionId"].parse::<Uuid>())
        .await
        .unwrap();
    assert_eq!(continued_interaction.dpop_key.unwrap().id(), dpop_key.id);
    let initiated_interaction = context
        .db
        .interactions
        .get(initiated_interaction_id)
        .await
        .unwrap();
    assert!(initiated_interaction.dpop_key.is_none());
}
