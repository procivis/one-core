use axum::http::Method;
use one_core::model::credential_schema::WalletStorageTypeEnum;
use serde_json::json;
use similar_asserts::assert_eq;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_continue_issuance_endpoint() {
    // given
    let mock_server = MockServer::start().await;
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let interaction_id = Uuid::new_v4();
    let authorization_code = "aUtH_CoDe";
    let credential_schema_id = Uuid::new_v4();

    let credential_issuer = format!(
        "{}/ssi/openid4vci/draft-13/{credential_schema_id}",
        mock_server.uri()
    );

    let interaction_body = json!({
        "request": {
            "organisation_id": organisation.id,
            "protocol": "OPENID4VCI_DRAFT13",
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
            Some(interaction_id),
            "https://www.procivis.ch",
            &interaction_body,
            &organisation,
        )
        .await;

    Mock::given(method(Method::GET))
        .and(path(format!(
            "/ssi/openid4vci/draft-13/{credential_schema_id}/.well-known/openid-credential-issuer"
        )))
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
                          "wallet_storage_type": "SOFTWARE",
                          "proof_types_supported": {
                            "jwt": {
                              "proof_signing_alg_values_supported": [
                                "ES256",
                                "EdDSA",
                                "EDDSA",
                                "BBS_PLUS",
                                "DILITHIUM"
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
            "/ssi/openid4vci/draft-13/{credential_schema_id}/.well-known/openid-configuration"
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
        .and(path(format!("/ssi/schema/v1/{credential_schema_id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": credential_schema_id,
            "createdDate": "2024-05-16T10:47:48.093Z",
            "lastModified": "2024-05-16T10:47:48.093Z",
            "name": "test",
            "format": "SD_JWT",
            "revocationMethod": "NONE",
            "organisationId": organisation.id,
            "claims": [
              {
                  "id": "73535006-f102-481b-8a23-5a45b912372e",
                  "createdDate": "2024-10-17T10:36:55.019Z",
                  "lastModified": "2024-10-17T10:36:55.019Z",
                  "key": "namespace1",
                  "datatype": "OBJECT",
                  "required": true,
                  "array": false,
                  "claims": [
                  {
                      "id": "e8ab7052-38f7-4cbf-bace-18f94210d5c1",
                      "createdDate": "2024-10-17T10:36:55.019Z",
                      "lastModified": "2024-10-17T10:36:55.019Z",
                      "key": "string_array",
                      "datatype": "STRING",
                      "required": true,
                      "array": true
                  },
                  {
                      "id": "fc29db10-1dc7-4a12-bb0a-df00006f5db3",
                      "createdDate": "2024-10-17T10:36:55.019Z",
                      "lastModified": "2024-10-17T10:36:55.019Z",
                      "key": "object_array",
                      "datatype": "OBJECT",
                      "required": true,
                      "array": true,
                      "claims": [
                      {
                          "id": "9a6de1c5-cdfc-48b3-8dfb-d8380aed7ce8",
                          "createdDate": "2024-10-17T10:36:55.019Z",
                          "lastModified": "2024-10-17T10:36:55.019Z",
                          "key": "field1",
                          "datatype": "STRING",
                          "required": true,
                          "array": false
                      },
                      {
                          "id": "6f39e1c3-120c-409e-b222-cf782ca6a885",
                          "createdDate": "2024-10-17T10:36:55.019Z",
                          "lastModified": "2024-10-17T10:36:55.019Z",
                          "key": "field 2",
                          "datatype": "STRING",
                          "required": true,
                          "array": false
                      }
                      ]
                  }
                  ]
              },
              {
                  "id": "98deb04d-c639-42d3-aa32-3b0ee8b713f0",
                  "createdDate": "2024-10-17T10:36:55.019Z",
                  "lastModified": "2024-10-17T10:36:55.019Z",
                  "key": "namespace2",
                  "datatype": "OBJECT",
                  "required": true,
                  "array": false,
                  "claims": [
                  {
                      "id": "2b7c0489-cc7f-492f-b96f-0b67a08c5bf6",
                      "createdDate": "2024-10-17T10:36:55.019Z",
                      "lastModified": "2024-10-17T10:36:55.019Z",
                      "key": "Field 1",
                      "datatype": "STRING",
                      "required": true,
                      "array": false
                  },
                  {
                      "id": "de19b5b8-6771-4bf3-a5b4-a5f32fa106c2",
                      "createdDate": "2024-10-17T10:36:55.019Z",
                      "lastModified": "2024-10-17T10:36:55.019Z",
                      "key": "array",
                      "datatype": "OBJECT",
                      "required": true,
                      "array": false,
                      "claims": [
                      {
                          "id": "f7f21b90-2591-48bd-b018-2e6e9bf1060d",
                          "createdDate": "2024-10-17T10:36:55.019Z",
                          "lastModified": "2024-10-17T10:36:55.019Z",
                          "key": "N2 field1",
                          "datatype": "STRING",
                          "required": true,
                          "array": false
                      },
                      {
                          "id": "94cc0d00-f1fd-49b0-8567-e345a1cc1051",
                          "createdDate": "2024-10-17T10:36:55.019Z",
                          "lastModified": "2024-10-17T10:36:55.019Z",
                          "key": "N2 array",
                          "datatype": "STRING",
                          "required": true,
                          "array": true
                      }
                      ]
                  }
                  ]
              }
              ],
            "walletStorageType": "SOFTWARE",
            "schemaId": format!("{}/ssi/schema/v1/{credential_schema_id}", mock_server.uri()),
            "schemaType": "ProcivisOneSchema2024",
            "layoutType": "CARD",
        })))
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

    let credential_id = resp["credentialIds"][0].parse();
    let credential = context.db.credentials.get(&credential_id).await;
    assert_eq!(
        credential.schema.unwrap().wallet_storage_type,
        Some(WalletStorageTypeEnum::Software)
    );
}

#[tokio::test]
async fn test_continue_issuance_endpoint_failed_invalid_authorization_server() {
    // given
    let mock_server = MockServer::start().await;
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let authorization_code = "aUtH_CoDe";
    let credential_schema_id = Uuid::new_v4();

    let credential_issuer = format!(
        "{}/ssi/openid4vci/draft-13/{credential_schema_id}",
        mock_server.uri()
    );

    let interaction_body = json!({
        "request": {
            "organisation_id": organisation.id,
            "protocol": "OPENID4VCI_DRAFT13",
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
            None,
            credential_issuer.as_str(),
            &interaction_body,
            &organisation,
        )
        .await
        .id;

    Mock::given(method(Method::GET))
        .and(path(format!(
            "/ssi/openid4vci/draft-13/{credential_schema_id}/.well-known/openid-credential-issuer"
        )))
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
                          "wallet_storage_type": "SOFTWARE",
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

    let token_endpoint = format!("{credential_issuer}/token");

    Mock::given(method(Method::GET))
        .and(path(format!(
            "/ssi/openid4vci/draft-13/{credential_schema_id}/.well-known/openid-configuration"
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
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0085");
}
