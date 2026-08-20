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
