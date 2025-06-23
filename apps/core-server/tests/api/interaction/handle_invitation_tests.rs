use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use one_core::model::credential_schema::WalletStorageTypeEnum;
use one_core::model::did::DidType;
use one_core::provider::verification_protocol::openid4vp::model::{
    OpenID4VPAlgs, OpenID4VPClientMetadata, OpenID4VPPresentationDefinition,
    OpenID4VpPresentationFormat,
};
use serde_json::json;
use url::Url;
use uuid::Uuid;
use wiremock::http::Method;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_handle_invitation_endpoint_for_openid4vc_issuance_offer_by_value() {
    let mock_server = MockServer::start().await;
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let credential_schema_id = Uuid::new_v4();
    let credential_issuer = format!(
        "{}/ssi/openid4vci/draft-13/{credential_schema_id}",
        mock_server.uri()
    );
    let issuer_did = "did:key:zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb";
    let credential_offer = json!({
        "credential_issuer": credential_issuer,
        "issuer_did": issuer_did,
        "credential_configuration_ids": [
            "doctype"
        ],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": "78db97c3-dbda-4bb2-a17c-b971ae7d6740"
            }
        },
        "credential_subject": {
            "keys": {
                "namespace1/string_array/0": {"value": "foo", "value_type": "STRING"},
                "namespace1/string_array/1": {"value": "foo", "value_type": "STRING"},
                "namespace1/object_array/0/field1": {"value": "foo", "value_type": "STRING"},
                "namespace1/object_array/0/field 2": {"value": "foo", "value_type": "STRING"},
                "namespace2/Field 1": {"value": "foo", "value_type": "STRING"},
                "namespace2/array/0/N2 field1": {"value": "foo", "value_type": "STRING"},
                "namespace2/array/0/N2 array/0": {"value": "foo", "value_type": "STRING"},
                "namespace2/array/0/N2 array/1": {"value": "foo", "value_type": "STRING"},
            },
            "wallet_storage_type": "SOFTWARE"
        }
    });

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
                          "wallet_storage_type": "SOFTWARE"
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

    // WHEN
    let credential_offer = serde_json::to_string(&credential_offer).unwrap();
    let mut credential_offer_url: Url = "openid-credential-offer://".parse().unwrap();
    credential_offer_url
        .query_pairs_mut()
        .append_pair("credential_offer", &credential_offer);

    let resp = context
        .api
        .interactions
        .handle_invitation(organisation.id, credential_offer_url.as_ref())
        .await;

    // THEN
    assert_eq!(resp.status(), 201);

    let resp = resp.json_value().await;
    assert!(resp.get("interactionId").is_some());

    let credential = context
        .db
        .credentials
        .get(&resp["credentialIds"][0].parse())
        .await;
    assert_eq!(
        credential.schema.unwrap().wallet_storage_type,
        Some(WalletStorageTypeEnum::Software)
    );
    let did = context
        .db
        .dids
        .get_did_by_value(&issuer_did.parse().unwrap())
        .await;
    assert_eq!(did.did_type, DidType::Remote);
}

#[tokio::test]
async fn test_handle_invitation_endpoint_for_openid4vc_issuance_offer_by_value_with_double_layered_nested_claims()
 {
    let mock_server = MockServer::start().await;
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let credential_schema_id = Uuid::new_v4();
    let credential_issuer = format!(
        "{}/ssi/openid4vci/draft-13/{credential_schema_id}",
        mock_server.uri()
    );
    let credential_offer = json!({
        "credential_issuer": credential_issuer,
        "credential_configuration_ids": [
            format!("{}/ssi/schema/v1/{credential_schema_id}", mock_server.uri())
        ],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": "78db97c3-dbda-4bb2-a17c-b971ae7d6740"
            }
        },
        "credential_subject": {
            "keys": {
                "address/location/position/x": {"value": "test_value", "value_type": "STRING"},
            },
            "wallet_storage_type": "SOFTWARE"
        }
    });

    Mock::given(method(Method::GET))
        .and(path(format!(
            "/ssi/openid4vci/draft-13/{credential_schema_id}/.well-known/openid-credential-issuer"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "credential_endpoint": format!("{credential_issuer}/credential"),
                "credential_issuer": credential_issuer,
                "credential_configurations_supported":
                {
                    format!("{}/ssi/schema/v1/{credential_schema_id}", mock_server.uri()): {
                    "wallet_storage_type": "SOFTWARE",
                    "credential_definition": {
                        "type": [
                            "VerifiableCredential"
                        ],
                        "credentialSubject" : {
                            "address": {
                                "location": {
                                    "position": {
                                        "x": {
                                            "value_type": "STRING",
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "format": "vc+sd-jwt",
                }
            }}
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

    let address_claim_schema = json!({
        "id": "545f984b-4fdf-4e26-aba0-61b72d21dbd9",
        "createdDate": "2024-05-16T18:34:34.115Z",
        "lastModified": "2024-05-16T18:34:34.115Z",
        "key": "address",
        "datatype": "OBJECT",
        "required": true,
        "array": false,
        "claims": [{
            "id": "545f984b-4fdf-4e26-aba0-61b72d21dbd9",
            "createdDate": "2024-05-16T18:34:34.115Z",
            "lastModified": "2024-05-16T18:34:34.115Z",
            "key": "location",
            "datatype": "OBJECT",
            "required": true,
            "array": false,
            "claims": [{
                "id": "545f984b-4fdf-4e26-aba0-61b72d21dbd9",
                "createdDate": "2024-05-16T18:34:34.115Z",
                "lastModified": "2024-05-16T18:34:34.115Z",
                "key": "position",
                "datatype": "OBJECT",
                "required": true,
                "array": false,
                "claims": [{
                    "id": "e4f1b7c1-809b-41a1-8f59-a6ee34011480",
                    "createdDate": "2024-05-16T18:34:34.115Z",
                    "lastModified": "2024-05-16T18:34:34.115Z",
                    "key": "x",
                    "datatype": "STRING",
                    "required": true,
                    "array": false
                }],
            }],
        }],
    });

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
            "claims": [address_claim_schema],
            "walletStorageType": "SOFTWARE",
            "schemaId": format!("{}/ssi/schema/v1/{credential_schema_id}", mock_server.uri()),
            "schemaType": "ProcivisOneSchema2024",
            "layoutType": "CARD",
            "allowSuspension": "true"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // WHEN
    let credential_offer = serde_json::to_string(&credential_offer).unwrap();
    let mut credential_offer_url: Url = "openid-credential-offer://".parse().unwrap();
    credential_offer_url
        .query_pairs_mut()
        .append_pair("credential_offer", &credential_offer);

    let resp = context
        .api
        .interactions
        .handle_invitation(organisation.id, credential_offer_url.as_ref())
        .await;

    // THEN
    assert_eq!(resp.status(), 201);

    let resp = resp.json_value().await;
    assert!(resp.get("interactionId").is_some());

    let credential = context
        .db
        .credentials
        .get(&resp["credentialIds"][0].parse())
        .await;
    let claim_schema_keys: Vec<String> = credential
        .schema
        .unwrap()
        .claim_schemas
        .unwrap()
        .iter()
        .map(|claim_schema| claim_schema.schema.key.to_owned())
        .collect();
    assert_eq!(
        vec![
            "address",
            "address/location",
            "address/location/position",
            "address/location/position/x",
        ],
        claim_schema_keys
    );
}

#[tokio::test]
async fn test_handle_invitation_endpoint_for_openid4vc_issuance_offer_by_value_with_optional_object_array_and_required_field()
 {
    let mock_server = MockServer::start().await;
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let credential_schema_id = Uuid::new_v4();
    let credential_issuer = format!(
        "{}/ssi/openid4vci/draft-13/{credential_schema_id}",
        mock_server.uri()
    );
    let credential_offer = json!({
        "credential_issuer": credential_issuer,
        "credential_configuration_ids": [
            format!("{}/ssi/schema/v1/{credential_schema_id}", mock_server.uri())
        ],
        "credential_subject": {
            "keys": {
                "address/field": {"value": "xyy", "value_type": "STRING"},
            },
            "wallet_storage_type": "SOFTWARE"
        },
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": "78db97c3-dbda-4bb2-a17c-b971ae7d6740"
            }
        }
    });

    Mock::given(method(Method::GET))
        .and(path(format!(
            "/ssi/openid4vci/draft-13/{credential_schema_id}/.well-known/openid-credential-issuer"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "credential_endpoint": format!("{credential_issuer}/credential"),
                "credential_issuer": credential_issuer,
                "credential_configurations_supported": {
                    format!("{}/ssi/schema/v1/{credential_schema_id}", mock_server.uri()): {
                    "wallet_storage_type": "SOFTWARE",
                    "credential_definition": {
                        "type": [
                            "VerifiableCredential"
                        ],
                        "credentialSubject" : {
                            "address": {
                                "location": {
                                    "position": {
                                        "x": {
                                            "value_type": "STRING",
                                        }
                                    }
                                }
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

    let address_claim_schema = json!({
        "id": "545f984b-4fdf-4e26-aba0-61b72d21dbd9",
        "createdDate": "2024-05-16T18:34:34.115Z",
        "lastModified": "2024-05-16T18:34:34.115Z",
        "key": "address",
        "datatype": "OBJECT",
        "required": true,
        "array": false,
        "claims": [{
            "id": "6afd9ffc-1fff-442c-980e-b9141b6910d6",
            "createdDate": "2024-05-16T10:47:48.093Z",
            "lastModified": "2024-05-16T10:47:48.093Z",
            "key": "field",
            "datatype": "STRING",
            "required": true,
            "array": false,
        },
        {
            "id": "545f984b-4fdf-4e26-aba0-61b72d21dbd9",
            "createdDate": "2024-05-16T18:34:34.115Z",
            "lastModified": "2024-05-16T18:34:34.115Z",
            "key": "location",
            "datatype": "OBJECT",
            "required": false,
            "array": true,
            "claims": [{
                "id": "545f984b-4fdf-4e26-aba0-61b72d21dbd9",
                "createdDate": "2024-05-16T18:34:34.115Z",
                "lastModified": "2024-05-16T18:34:34.115Z",
                "key": "position",
                "datatype": "OBJECT",
                "required": true,
                "array": false,
                "claims": [{
                    "id": "e4f1b7c1-809b-41a1-8f59-a6ee34011480",
                    "createdDate": "2024-05-16T18:34:34.115Z",
                    "lastModified": "2024-05-16T18:34:34.115Z",
                    "key": "x",
                    "datatype": "STRING",
                    "required": true,
                    "array": false
                }],
            }],
        }],
    });

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
            "claims": [address_claim_schema],
            "walletStorageType": "SOFTWARE",
            "schemaId": format!("{}/ssi/schema/v1/{credential_schema_id}", mock_server.uri()),
            "schemaType": "ProcivisOneSchema2024",
            "layoutType": "CARD",
            "allowSuspension": "true"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // WHEN
    let credential_offer = serde_json::to_string(&credential_offer).unwrap();
    let mut credential_offer_url: Url = "openid-credential-offer://".parse().unwrap();
    credential_offer_url
        .query_pairs_mut()
        .append_pair("credential_offer", &credential_offer);

    let resp = context
        .api
        .interactions
        .handle_invitation(organisation.id, credential_offer_url.as_ref())
        .await;

    // THEN
    assert_eq!(resp.status(), 201);

    let resp = resp.json_value().await;
    assert!(resp.get("interactionId").is_some());

    let credential = context
        .db
        .credentials
        .get(&resp["credentialIds"][0].parse())
        .await;
    let claim_schema_keys: Vec<String> = credential
        .schema
        .unwrap()
        .claim_schemas
        .unwrap()
        .iter()
        .map(|claim_schema| claim_schema.schema.key.to_owned())
        .collect();
    assert_eq!(
        vec![
            "address",
            "address/field",
            "address/location",
            "address/location/position",
            "address/location/position/x"
        ],
        claim_schema_keys
    );
}

#[tokio::test]
async fn test_handle_invitation_endpoint_for_openid4vc_issuance_offer_by_value_with_similar_prefix_keys()
 {
    let mock_server = MockServer::start().await;
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let credential_schema_id = Uuid::new_v4();
    let credential_issuer = format!(
        "{}/ssi/openid4vci/draft-13/{credential_schema_id}",
        mock_server.uri()
    );
    let credential_offer = json!({
        "credential_issuer": credential_issuer,
        "credential_configuration_ids": [
            format!("{}/ssi/schema/v1/{credential_schema_id}", mock_server.uri())
        ],
        "credential_subject": {
            "keys": {
                "address/field": {"value": "xyy", "value_type": "STRING"},
            },
            "wallet_storage_type": "SOFTWARE"
        },
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": "78db97c3-dbda-4bb2-a17c-b971ae7d6740"
            }
        }
    });

    Mock::given(method(Method::GET))
        .and(path(format!(
            "/ssi/openid4vci/draft-13/{credential_schema_id}/.well-known/openid-credential-issuer"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "credential_endpoint": format!("{credential_issuer}/credential"),
                "credential_issuer": credential_issuer,
                "credential_configurations_supported": {
                    format!("{}/ssi/schema/v1/{credential_schema_id}", mock_server.uri()): {
                    "wallet_storage_type": "SOFTWARE",
                    "credential_definition": {
                        "type": [
                            "VerifiableCredential"
                        ],
                        "credentialSubject" : {
                            "address": {
                                "location": {
                                    "position": {
                                        "x": {
                                            "value_type": "STRING",
                                        }
                                    }
                                }
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

    let address_claim_schema = json!({
        "id": "545f984b-4fdf-4e26-aba0-61b72d21dbd9",
        "createdDate": "2024-05-16T18:34:34.115Z",
        "lastModified": "2024-05-16T18:34:34.115Z",
        "key": "address",
        "datatype": "OBJECT",
        "required": true,
        "array": false,
        "claims": [{
            "id": "6afd9ffc-1fff-442c-980e-b9141b6910d6",
            "createdDate": "2024-05-16T10:47:48.093Z",
            "lastModified": "2024-05-16T10:47:48.093Z",
            "key": "field",
            "datatype": "STRING",
            "required": true,
            "array": false,
        },
        {
            "id": "545f984b-4fdf-4e26-aba0-61b72d21dbd9",
            "createdDate": "2024-05-16T18:34:34.115Z",
            "lastModified": "2024-05-16T18:34:34.115Z",
            "key": "field of location",
            "datatype": "OBJECT",
            "required": false,
            "array": true,
            "claims": [{
                "id": "545f984b-4fdf-4e26-aba0-61b72d21dbd9",
                "createdDate": "2024-05-16T18:34:34.115Z",
                "lastModified": "2024-05-16T18:34:34.115Z",
                "key": "position",
                "datatype": "OBJECT",
                "required": true,
                "array": false,
                "claims": [{
                    "id": "e4f1b7c1-809b-41a1-8f59-a6ee34011480",
                    "createdDate": "2024-05-16T18:34:34.115Z",
                    "lastModified": "2024-05-16T18:34:34.115Z",
                    "key": "x",
                    "datatype": "STRING",
                    "required": true,
                    "array": false
                }],
            }],
        }],
    });

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
            "claims": [address_claim_schema],
            "walletStorageType": "SOFTWARE",
            "schemaId": format!("{}/ssi/schema/v1/{credential_schema_id}", mock_server.uri()),
            "schemaType": "ProcivisOneSchema2024",
            "layoutType": "CARD",
            "allowSuspension": "true"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // WHEN
    let credential_offer = serde_json::to_string(&credential_offer).unwrap();
    let mut credential_offer_url: Url = "openid-credential-offer://".parse().unwrap();
    credential_offer_url
        .query_pairs_mut()
        .append_pair("credential_offer", &credential_offer);

    let resp = context
        .api
        .interactions
        .handle_invitation(organisation.id, credential_offer_url.as_ref())
        .await;

    // THEN
    assert_eq!(resp.status(), 201);

    let resp = resp.json_value().await;
    assert!(resp.get("interactionId").is_some());

    let credential = context
        .db
        .credentials
        .get(&resp["credentialIds"][0].parse())
        .await;
    let claim_schema_keys: Vec<String> = credential
        .schema
        .unwrap()
        .claim_schemas
        .unwrap()
        .iter()
        .map(|claim_schema| claim_schema.schema.key.to_owned())
        .collect();
    assert_eq!(
        vec![
            "address",
            "address/field",
            "address/field of location",
            "address/field of location/position",
            "address/field of location/position/x"
        ],
        claim_schema_keys
    );
}

#[tokio::test]
async fn test_handle_invitation_endpoint_for_openid4vc_issuance_offer_by_value_matching_succeeds() {
    let mock_server = MockServer::start().await;
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let new_claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> = vec![(
        Uuid::from_str("48db4654-01c4-4a43-9df4-300f1f425c40").unwrap(),
        "key",
        true,
        "STRING",
        false,
    )];

    let schema_id = Uuid::new_v4();

    let credential_schema = context
        .db
        .credential_schemas
        .create_with_claims(
            &schema_id,
            "MatchedSchema",
            &organisation,
            "NONE",
            &new_claim_schemas,
            "JWT",
            &format!("{}/ssi/schema/v1/{}", &mock_server.uri(), schema_id),
        )
        .await;

    let credential_schema_id = credential_schema.id;
    let credential_issuer = format!(
        "{}/ssi/openid4vci/draft-13/{credential_schema_id}",
        mock_server.uri()
    );
    let credential_offer = json!({
        "credential_issuer": credential_issuer,
        "credential_configuration_ids": [
            format!("{}/ssi/schema/v1/{credential_schema_id}", mock_server.uri())
        ],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": "78db97c3-dbda-4bb2-a17c-b971ae7d6740"
            }
        },
        "credential_subject": {
            "keys": {
                "key": {"value": "foo", "value_type": "STRING"},
            },
            "wallet_storage_type": "SOFTWARE"
        }
    });

    Mock::given(method(Method::GET))
        .and(path(format!(
            "/ssi/openid4vci/draft-13/{credential_schema_id}/.well-known/openid-credential-issuer"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "credential_endpoint": format!("{credential_issuer}/credential"),
                "credential_issuer": credential_issuer,
                "credential_configurations_supported":
                    {
                    format!("{}/ssi/schema/v1/{credential_schema_id}", mock_server.uri()): {
                    "wallet_storage_type": "SOFTWARE",
                        "credential_definition": {
                            "type": [
                                "VerifiableCredential"
                            ],
                            "credentialSubject" : {
                                "key": {
                                    "value_type": "string",
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

    // WHEN
    let credential_offer = serde_json::to_string(&credential_offer).unwrap();
    let mut credential_offer_url: Url = "openid-credential-offer://".parse().unwrap();
    credential_offer_url
        .query_pairs_mut()
        .append_pair("credential_offer", &credential_offer);

    let resp = context
        .api
        .interactions
        .handle_invitation(organisation.id, credential_offer_url.as_ref())
        .await;

    // THEN
    assert_eq!(resp.status(), 201);

    let resp = resp.json_value().await;
    assert!(resp.get("interactionId").is_some());

    let credential = context
        .db
        .credentials
        .get(&resp["credentialIds"][0].parse())
        .await;

    let credential_schema = credential.schema.unwrap();
    assert_eq!(credential_schema.name, "MatchedSchema");
}

#[tokio::test]
async fn test_handle_invitation_endpoint_for_openid4vc_issuance_offer_should_not_match_deleted_schema()
 {
    let mock_server = MockServer::start().await;
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let new_claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> = vec![(
        Uuid::from_str("48db4654-01c4-4a43-9df4-300f1f425c40").unwrap(),
        "key",
        true,
        "STRING",
        false,
    )];

    let credential_schema_id = Uuid::new_v4();
    let deleted_schema_id = Uuid::new_v4();

    let deleted_credential_schema = context
        .db
        .credential_schemas
        .create_with_claims(
            &deleted_schema_id,
            "MatchedSchema",
            &organisation,
            "NONE",
            &new_claim_schemas,
            "JWT",
            &format!(
                "{}/ssi/schema/v1/{}",
                &mock_server.uri(),
                credential_schema_id
            ),
        )
        .await;
    context
        .db
        .credential_schemas
        .delete(&deleted_credential_schema)
        .await;

    let credential_issuer = format!(
        "{}/ssi/openid4vci/draft-13/{credential_schema_id}",
        mock_server.uri()
    );
    let credential_offer = json!({
        "credential_issuer": credential_issuer,
        "credential_configuration_ids": [
            format!("{}/ssi/schema/v1/{credential_schema_id}", mock_server.uri())
        ],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": "78db97c3-dbda-4bb2-a17c-b971ae7d6740"
            }
        },
        "credential_subject": {
            "keys": {
                "key": {"value": "foo", "value_type": "STRING"},
            },
            "wallet_storage_type": "SOFTWARE"
        }
    });

    Mock::given(method(Method::GET))
        .and(path(format!("/ssi/schema/v1/{credential_schema_id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "id": "a170ddf1-17b3-4547-abdd-3f8ee2836747",
                "createdDate": "2005-04-02T21:37:00.000Z",
                "lastModified": "2005-04-02T21:37:00.000Z",
                "name": "MatchedSchema",
                "format": "JWT",
                "revocationMethod": "NONE",
                "organisationId": "bb6c2535-e1d7-4319-b9db-f8949bb50758",
                "claims": [
                    {
                        "id": "48db4654-01c4-4a43-9df4-300f1f425c40",
                        "createdDate": "2005-04-02T21:37:00.000Z",
                        "lastModified": "2005-04-02T21:37:00.000Z",
                        "key": "key",
                        "datatype": "STRING",
                        "required": true,
                        "array": false
                    }
                ],
                "walletStorageType": null,
                "schemaId": format!("{}/ssi/schema/v1/{credential_schema_id}", mock_server.uri()),
                "schemaType": "ProcivisOneSchema2024",
                "importedSourceUrl": "CORE_URL",
                "allowSuspension": true
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::GET))
        .and(path(format!(
            "/ssi/openid4vci/draft-13/{credential_schema_id}/.well-known/openid-credential-issuer"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "credential_endpoint": format!("{credential_issuer}/credential"),
                "credential_issuer": credential_issuer,
                "credential_configurations_supported":
                {
                    format!("{}/ssi/schema/v1/{credential_schema_id}", mock_server.uri()): {
                    "wallet_storage_type": "SOFTWARE",
                    "credential_definition": {
                        "type": [
                            "VerifiableCredential"
                        ],
                        "credentialSubject" : {
                            "field": {
                                "value_type": "string"
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

    // WHEN
    let credential_offer = serde_json::to_string(&credential_offer).unwrap();
    let mut credential_offer_url: Url = "openid-credential-offer://".parse().unwrap();
    credential_offer_url
        .query_pairs_mut()
        .append_pair("credential_offer", &credential_offer);

    let resp = context
        .api
        .interactions
        .handle_invitation(organisation.id, credential_offer_url.as_ref())
        .await;

    // THEN
    assert_eq!(resp.status(), 201);

    let resp = resp.json_value().await;
    assert!(resp.get("interactionId").is_some());

    let credential_schemas = context.db.credential_schemas.list().await;
    assert_eq!(credential_schemas.len(), 1); // the deleted one is _not_ listed

    // the current schema is a newly created one and not the deleted one
    assert_ne!(credential_schemas[0].id, deleted_credential_schema.id);
}

#[tokio::test]
async fn test_handle_invitation_endpoint_for_openid4vc_issuance_offer_by_reference() {
    let mock_server = MockServer::start().await;
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let credential_id = Uuid::new_v4();
    let credential_schema_id = Uuid::new_v4();
    let credential_issuer = format!(
        "{}/ssi/openid4vci/draft-13/{credential_schema_id}",
        mock_server.uri()
    );
    let credential_offer = json!({
        "credential_issuer": credential_issuer,
        "credential_configuration_ids": [
            format!("{}/ssi/schema/v1/{credential_schema_id}", mock_server.uri())
        ],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": "78db97c3-dbda-4bb2-a17c-b971ae7d6740"
            }
        },
        "credential_subject": {
            "keys": {
                "field": {"value": "foo", "value_type": "STRING"},
            },
            "wallet_storage_type": "SOFTWARE"
        }
    });

    Mock::given(method(Method::GET))
        .and(path(format!(
            "/ssi/openid4vci/draft-13/{credential_schema_id}/.well-known/openid-credential-issuer"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "credential_endpoint": format!("{credential_issuer}/credential"),
                "credential_issuer": credential_issuer,
                "credential_configurations_supported":
                {
                    format!("{}/ssi/schema/v1/{credential_schema_id}", mock_server.uri()): {
                    "wallet_storage_type": "SOFTWARE",
                    "credential_definition": {
                        "type": [
                            "VerifiableCredential"
                        ],
                        "credentialSubject" : {
                            "field": {
                                "value_type": "string"
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
        .and(path(format!(
            "/ssi/openid4vci/draft-13/{credential_schema_id}/offer/{credential_id}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(credential_offer))
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
                "id": "6afd9ffc-1fff-442c-980e-b9141b6910d6",
                "createdDate": "2024-05-16T10:47:48.093Z",
                "lastModified": "2024-05-16T10:47:48.093Z",
                "key": "field",
                "datatype": "STRING",
                "array": false,
                "required": true
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
        .handle_invitation(organisation.id, credential_offer_url.as_ref())
        .await;

    // THEN
    assert_eq!(resp.status(), 201);

    let resp = resp.json_value().await;
    assert!(resp.get("interactionId").is_some());

    let credential = context
        .db
        .credentials
        .get(&resp["credentialIds"][0].parse())
        .await;
    assert_eq!(
        credential.schema.unwrap().wallet_storage_type,
        Some(WalletStorageTypeEnum::Software)
    );
}

#[tokio::test]
async fn test_handle_invitation_endpoint_for_openid4vc_proof_by_reference() {
    let mock_server = MockServer::start().await;
    let (context, organistion) = TestContext::new_with_organisation(None).await;

    let client_metadata = serde_json::to_string(&OpenID4VPClientMetadata {
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
        .handle_invitation(organistion.id, &query)
        .await;
    // THEN
    assert_eq!(resp.status(), 201);

    let resp = resp.json_value().await;
    assert!(resp.get("interactionId").is_some());
}

#[tokio::test]
async fn test_handle_invitation_endpoint_for_openid4vc_proof_by_value() {
    let (context, organistion) = TestContext::new_with_organisation(None).await;

    let client_metadata = serde_json::to_string(&OpenID4VPClientMetadata {
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
    let query = Url::parse(&format!("openid4vp://?response_type=vp_token&nonce={}&client_id_scheme=redirect_uri&client_id={}&client_metadata={}&response_mode=direct_post&response_uri={}&presentation_definition={}"
                                    , nonce, callback_url, client_metadata, callback_url, presentation_definition)).unwrap().to_string();

    // WHEN
    let resp = context
        .api
        .interactions
        .handle_invitation(organistion.id, &query)
        .await;

    // THEN
    assert_eq!(resp.status(), 201);

    let resp = resp.json_value().await;
    assert!(resp.get("interactionId").is_some());
}

#[tokio::test]
async fn test_handle_invitation_mdoc() {
    let mock_server = MockServer::start().await;
    let (context, organistion) = TestContext::new_with_organisation(None).await;

    let credential_schema_id = Uuid::new_v4();
    let credential_issuer = format!(
        "{}/ssi/openid4vci/draft-13/{credential_schema_id}",
        mock_server.uri()
    );

    let credential_offer = json!({
        "credential_issuer": credential_issuer,
        "credential_configuration_ids": [
            "custom-doctype"
        ],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": "78db97c3-dbda-4bb2-a17c-b971ae7d6740"
            }
        }
    });

    Mock::given(method(Method::GET))
        .and(path(format!(
            "/ssi/openid4vci/draft-13/{credential_schema_id}/.well-known/openid-credential-issuer"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "credential_endpoint": format!("{credential_issuer}/credential"),
                "credential_issuer": credential_issuer,
                "credential_configurations_supported":
                {
                    "custom-doctype":
                    {
                        "claims": {
                            "first.namespace": {
                                "field": {
                                    "value_type": "string",
                                    "mandatory": true
                                },
                                "string_array": {
                                    "value_type": "string[]"
                                },
                                "object_array": [
                                    {
                                        "field1": {
                                            "value_type": "string",
                                            "mandatory": true
                                        },
                                        "field2": {
                                            "value_type": "string",
                                            "mandatory": false
                                        },
                                    }
                                ]
                            },
                            "company": {
                                "address": {
                                    "streetName": {
                                        "value_type": "string"
                                    },
                                    "streetNumber": {
                                        "value_type": "number"
                                    },
                                    "order": ["streetName", "streetNumber"]
                                }
                            }
                        },
                        "format": "mso_mdoc",
                        "doctype": "custom-doctype",
                        "order": ["first.namespace~field", "company~address"]
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

    // WHEN
    let credential_offer = serde_json::to_string(&credential_offer).unwrap();
    let mut credential_offer_url: Url = "openid-credential-offer://".parse().unwrap();
    credential_offer_url
        .query_pairs_mut()
        .append_pair("credential_offer", &credential_offer);

    let resp = context
        .api
        .interactions
        .handle_invitation(organistion.id, credential_offer_url.as_ref())
        .await;

    // THEN
    assert_eq!(resp.status(), 201);

    let resp = resp.json_value().await;
    assert!(resp.get("interactionId").is_some());

    let credential = context
        .db
        .credentials
        .get(&resp["credentialIds"][0].parse())
        .await;

    let claim_schemas = credential.schema.unwrap().claim_schemas.unwrap();

    let claim_schema_keys: HashSet<&str> = claim_schemas
        .iter()
        .map(|claim_schema| claim_schema.schema.key.as_str())
        .collect();

    assert_eq!(
        HashSet::from([
            "first.namespace",
            "first.namespace/field",
            "first.namespace/string_array",
            "first.namespace/object_array",
            "first.namespace/object_array/field1",
            "first.namespace/object_array/field2",
            "company",
            "company/address",
            "company/address/streetName",
            "company/address/streetNumber",
        ]),
        claim_schema_keys
    );

    let field = claim_schemas
        .iter()
        .find(|schema| schema.schema.key == "first.namespace/field")
        .unwrap();
    assert!(field.required);
    assert!(!field.schema.array);
    assert_eq!(&field.schema.data_type, "STRING");

    let field = claim_schemas
        .iter()
        .find(|schema| schema.schema.key == "first.namespace/string_array")
        .unwrap();
    assert!(!field.required);
    assert!(field.schema.array);
    assert_eq!(&field.schema.data_type, "STRING");

    let field = claim_schemas
        .iter()
        .find(|schema| schema.schema.key == "first.namespace/object_array")
        .unwrap();
    assert!(!field.required);
    assert!(field.schema.array);
    assert_eq!(&field.schema.data_type, "OBJECT");

    let field = claim_schemas
        .iter()
        .find(|schema| schema.schema.key == "first.namespace/object_array/field1")
        .unwrap();
    assert!(field.required);
    assert!(!field.schema.array);
    assert_eq!(&field.schema.data_type, "STRING");

    let field = claim_schemas
        .iter()
        .find(|schema| schema.schema.key == "first.namespace/object_array/field2")
        .unwrap();
    assert!(!field.required);
    assert!(!field.schema.array);
    assert_eq!(&field.schema.data_type, "STRING");
}

#[tokio::test]
async fn test_handle_invitation_endpoint_for_openid4vc_issuance_offer_by_value_tx_code_passed() {
    let mock_server = MockServer::start().await;
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let credential_schema_id = Uuid::new_v4();
    let credential_issuer = format!(
        "{}/ssi/openid4vci/draft-13/{credential_schema_id}",
        mock_server.uri()
    );
    let credential_offer = json!({
        "credential_issuer": credential_issuer,
        "credential_configuration_ids": [
            "doctype"
        ],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": "78db97c3-dbda-4bb2-a17c-b971ae7d6740",
                "tx_code":{"input_mode":"numeric","length":5,"description":"code"}
            }
        },
        "credential_subject": {
            "keys": {
                "namespace2/Field 1": {"value": "foo", "value_type": "STRING"},
            },
            "wallet_storage_type": "SOFTWARE"
        }
    });

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
                          "format": "mso_mdoc",
                              "claims": {
                              "namespace2": {
                                  "Field 1": {
                                    "value_type": "string",
                                    "mandatory": true
                                  }
                              }
                          },
                          "order": [
                              "namespace2~Field 1",
                          ],
                          "display": [
                          {
                              "name": "TestNestedHell"
                          }
                          ],
                          "wallet_storage_type": "SOFTWARE"
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

    // WHEN
    let credential_offer = serde_json::to_string(&credential_offer).unwrap();
    let mut credential_offer_url: Url = "openid-credential-offer://".parse().unwrap();
    credential_offer_url
        .query_pairs_mut()
        .append_pair("credential_offer", &credential_offer);

    let resp = context
        .api
        .interactions
        .handle_invitation(organisation.id, credential_offer_url.as_ref())
        .await;

    // THEN
    assert_eq!(resp.status(), 201);

    let resp = resp.json_value().await;
    assert!(resp.get("interactionId").is_some());

    let code = &resp["txCode"];
    assert_eq!(code["input_mode"], "numeric");
    assert_eq!(code["length"], 5);
    assert_eq!(code["description"], "code");
}

#[tokio::test]
async fn test_handle_invitation_endpoint_for_openid4vc_issuance_offer_by_value_no_subject() {
    let mock_server = MockServer::start().await;
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let credential_schema_id = Uuid::new_v4();
    let credential_issuer = format!(
        "{}/ssi/openid4vci/draft-13/{credential_schema_id}",
        mock_server.uri()
    );
    let credential_offer = json!({
        "credential_issuer": credential_issuer,
        "credential_configuration_ids": [
            "doctype"
        ],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": "78db97c3-dbda-4bb2-a17c-b971ae7d6740"
            }
        },
    });

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
                          "wallet_storage_type": "SOFTWARE"
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
            "format": "SDJWT",
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

    // WHEN
    let credential_offer = serde_json::to_string(&credential_offer).unwrap();
    let mut credential_offer_url: Url = "openid-credential-offer://".parse().unwrap();
    credential_offer_url
        .query_pairs_mut()
        .append_pair("credential_offer", &credential_offer);

    let resp = context
        .api
        .interactions
        .handle_invitation(organisation.id, credential_offer_url.as_ref())
        .await;

    // THEN
    assert_eq!(resp.status(), 201);

    let resp = resp.json_value().await;
    assert!(resp.get("interactionId").is_some());

    let credential = context
        .db
        .credentials
        .get(&resp["credentialIds"][0].parse())
        .await;

    let claims = credential.claims.unwrap();
    assert!(claims.is_empty());
}

#[tokio::test]
async fn test_handle_invitation_external_sd_jwt_vc() {
    let mock_server = MockServer::start().await;
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let credential_schema_id = Uuid::new_v4();
    let credential_issuer = format!(
        "{}/ssi/openid4vci/draft-13/{credential_schema_id}",
        mock_server.uri()
    );

    let vct = format!("{}/education_credential", mock_server.uri());

    let credential_offer = json!({
        "credential_issuer": credential_issuer,
        "credential_configuration_ids": [
            "https://betelgeuse.example.com/education_credential"
        ],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": "78db97c3-dbda-4bb2-a17c-b971ae7d6740",
                "tx_code":{
                    "input_mode": "numeric",
                    "length": 5,
                    "description": "code"
                }
            }
        }
    });

    Mock::given(method(Method::GET))
        .and(path(format!(
            "/ssi/openid4vci/draft-13/{credential_schema_id}/.well-known/openid-credential-issuer"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "credential_endpoint": format!("{credential_issuer}/credential"),
                "credential_issuer": credential_issuer,
                "credential_configurations_supported": {
                    "https://betelgeuse.example.com/education_credential": {
                        "format": "vc+sd-jwt",
                        "display": [
                            {
                              "name": "TestNestedHell",
                              "logo": {
                                    "uri": "https://university.example.edu/public/logo.png",
                                    "alt_text": "a square logo of a university"
                              },
                              "locale": "en-US",
                              "background_color": "#12107c",
                              "text_color": "#FFFFFF"
                            }
                        ],
                        "vct": vct,
                        "claims": {
                            "name": {
                              "display": [
                                {
                                  "name": "The name of the student",
                                  "locale": "en-US"
                                }
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

    // vct endpoint
    Mock::given(method(Method::GET))
        .and(path("/education_credential"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "vct": vct,
            "name": "Betelgeuse Education Credential - Preliminary Version",
            "description": "This is our development version of the education credential. Don't panic.",
            "display": [
              {
                "lang": "en-US",
                "name": "Betelgeuse Education Credential",
                "description": "An education credential for all carbon-based life forms on Betelgeusians",
                "rendering": {
                  "simple": {
                    "logo": {
                      "uri": "https://betelgeuse.example.com/public/education-logo.png",
                      "uri#integrity": "sha256-LmXfh-9cLlJNXN-TsMk-PmKjZ5t0WRL5ca_xGgX3c1V",
                      "alt_text": "Betelgeuse Ministry of Education logo"
                    },
                    "background_color": "#12107c",
                    "text_color": "#FFFFFF"
                  }
                }
              }
            ],
            "claims": [
              {
                "path": ["name"],
                "display": [
                    {
                        "lang": "en-US",
                        "label": "Name",
                        "description": "The name of the student"
                    }
                ]
               }
            ]
          })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // WHEN
    let credential_offer = serde_json::to_string(&credential_offer).unwrap();
    let mut credential_offer_url: Url = "openid-credential-offer://".parse().unwrap();
    credential_offer_url
        .query_pairs_mut()
        .append_pair("credential_offer", &credential_offer);

    let resp = context
        .api
        .interactions
        .handle_invitation(organisation.id, credential_offer_url.as_ref())
        .await;

    // THEN
    assert_eq!(resp.status(), 201);

    let resp = resp.json_value().await;
    assert!(resp.get("interactionId").is_some());

    let resp = context
        .api
        .credentials
        .get(&resp["credentialIds"][0].as_str().unwrap())
        .await;

    assert_eq!(resp.status(), 200);

    let resp = resp.json_value().await;
    assert_eq!("SD_JWT_VC", resp["schema"]["format"]);

    assert_eq!(
        "#12107c",
        resp["schema"]["layoutProperties"]["background"]["color"]
    );
    assert_eq!(
        "https://betelgeuse.example.com/public/education-logo.png",
        resp["schema"]["layoutProperties"]["logo"]["image"]
    );

    assert!(resp["claims"].as_array().unwrap().is_empty());
}
