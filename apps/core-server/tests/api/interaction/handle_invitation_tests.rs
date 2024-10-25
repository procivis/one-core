use std::collections::HashMap;
use std::str::FromStr;

use one_core::model::credential_schema::WalletStorageTypeEnum;
use one_core::provider::exchange_protocol::openid4vc::model::{
    HolderInteractionData, OpenID4VPClientMetadata, OpenID4VPFormat,
    OpenID4VPPresentationDefinition,
};
use serde_json::json;
use time::OffsetDateTime;
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
    let (context, organisation) = TestContext::new_with_organisation().await;

    let credential_schema_id = Uuid::new_v4();
    let credential_issuer = format!(
        "{}/ssi/oidc-issuer/v1/{credential_schema_id}",
        mock_server.uri()
    );
    let credential_offer = json!({
        "credential_issuer": credential_issuer,
        "credentials": [
            {
                "wallet_storage_type": "SOFTWARE",
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
                            ],
                            "credentialSchema": {
                                "id": format!("{}/ssi/schema/v1/{credential_schema_id}", mock_server.uri()),
                                "type": "ProcivisOneSchema2024"
                            }
                        },
                        "format": "vc+sd-jwt",
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

    let test_token = "4994a63d-d822-4fb9-87bf-6f298247c571.0ss4z9sgtsNYafQKhDeOINLhQIdW8yQE";
    Mock::given(method(Method::POST))
        .and(path(format!(
            "/ssi/oidc-issuer/v1/{credential_schema_id}/token"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "access_token": test_token,
                "expires_in": OffsetDateTime::now_utc().unix_timestamp() + 3600,
                "refresh_token": test_token,
                "refresh_token_expires_in": OffsetDateTime::now_utc().unix_timestamp() + 3600,
                "token_type": "bearer"
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
                "id": "6afd9ffc-1fff-442c-980e-b9141b6910d6",
                "createdDate": "2024-05-16T10:47:48.093Z",
                "lastModified": "2024-05-16T10:47:48.093Z",
                "key": "field",
                "datatype": "STRING",
                "required": true,
                "array": false,
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
    assert_eq!(resp.status(), 200);

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

    let interaction: HolderInteractionData =
        serde_json::from_slice(&credential.interaction.unwrap().data.unwrap()).unwrap();
    assert_eq!(interaction.access_token, test_token);
    assert_eq!(interaction.refresh_token, Some(test_token.to_string()));
    assert!(interaction.access_token_expires_at.is_some());
    assert!(interaction.refresh_token_expires_at.is_some());
}

#[tokio::test]
async fn test_handle_invitation_endpoint_for_openid4vc_issuance_offer_by_value_with_double_layered_nested_claims(
) {
    let mock_server = MockServer::start().await;
    let (context, organisation) = TestContext::new_with_organisation().await;

    let credential_schema_id = Uuid::new_v4();
    let credential_issuer = format!(
        "{}/ssi/oidc-issuer/v1/{credential_schema_id}",
        mock_server.uri()
    );
    let credential_offer = json!({
        "credential_issuer": credential_issuer,
        "credentials": [
            {
                "wallet_storage_type": "SOFTWARE",
                "format": "vc+sd-jwt",
                "credential_definition": {
                    "type": [
                        "VerifiableCredential"
                    ],
                    "credentialSubject": {
                        "address/location/position/x": {
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
                            ],
                            "credentialSchema": {
                                "id": format!("{}/ssi/schema/v1/{credential_schema_id}", mock_server.uri()),
                                "type": "ProcivisOneSchema2024"
                            }
                        },
                        "format": "vc+sd-jwt",
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
            "format": "SDJWT",
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
    assert_eq!(resp.status(), 200);

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
async fn test_handle_invitation_endpoint_for_openid4vc_issuance_offer_by_value_with_optional_object_array_and_required_field(
) {
    let mock_server = MockServer::start().await;
    let (context, organisation) = TestContext::new_with_organisation().await;

    let credential_schema_id = Uuid::new_v4();
    let credential_issuer = format!(
        "{}/ssi/oidc-issuer/v1/{credential_schema_id}",
        mock_server.uri()
    );
    let credential_offer = json!({
        "credential_issuer": credential_issuer,
        "credentials": [
            {
                "wallet_storage_type": "SOFTWARE",
                "format": "vc+sd-jwt",
                "credential_definition": {
                    "type": [
                        "VerifiableCredential"
                    ],
                    "credentialSubject": {
                        "address/field": {
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
                            ],
                            "credentialSchema": {
                                "id": format!("{}/ssi/schema/v1/{credential_schema_id}", mock_server.uri()),
                                "type": "ProcivisOneSchema2024"
                            }
                        },
                        "format": "vc+sd-jwt",
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
            "format": "SDJWT",
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
    assert_eq!(resp.status(), 200);

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
async fn test_handle_invitation_endpoint_for_openid4vc_issuance_offer_by_value_with_similar_prefix_keys(
) {
    let mock_server = MockServer::start().await;
    let (context, organisation) = TestContext::new_with_organisation().await;

    let credential_schema_id = Uuid::new_v4();
    let credential_issuer = format!(
        "{}/ssi/oidc-issuer/v1/{credential_schema_id}",
        mock_server.uri()
    );
    let credential_offer = json!({
        "credential_issuer": credential_issuer,
        "credentials": [
            {
                "wallet_storage_type": "SOFTWARE",
                "format": "vc+sd-jwt",
                "credential_definition": {
                    "type": [
                        "VerifiableCredential"
                    ],
                    "credentialSubject": {
                        "address/field": {
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
                            ],
                            "credentialSchema": {
                                "id": format!("{}/ssi/schema/v1/{credential_schema_id}", mock_server.uri()),
                                "type": "ProcivisOneSchema2024"
                            }
                        },
                        "format": "vc+sd-jwt",
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
            "format": "SDJWT",
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
    assert_eq!(resp.status(), 200);

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
    let (context, organisation) = TestContext::new_with_organisation().await;

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
        "{}/ssi/oidc-issuer/v1/{credential_schema_id}",
        mock_server.uri()
    );
    let credential_offer = json!({
        "credential_issuer": credential_issuer,
        "credentials": [
            {
                "wallet_storage_type": "SOFTWARE",
                "format": "vc+sd-jwt",
                "credential_definition": {
                    "type": [
                        "VerifiableCredential"
                    ],
                    "credentialSubject": {
                        "key": {
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
                        "format": "vc+sd-jwt",
                        "display": [{
                            "name": credential_schema.name,
                        }],
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
    assert_eq!(resp.status(), 200);

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
async fn test_handle_invitation_endpoint_for_openid4vc_issuance_offer_by_reference() {
    let mock_server = MockServer::start().await;
    let (context, organisation) = TestContext::new_with_organisation().await;

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
                "wallet_storage_type": "SOFTWARE",
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
                            ],
                            "credentialSchema": {
                                "id": format!("{}/ssi/schema/v1/{credential_schema_id}", mock_server.uri()),
                                "type": "ProcivisOneSchema2024"
                            }
                        },
                        "format": "vc+sd-jwt",
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

    let test_token = "4994a63d-d822-4fb9-87bf-6f298247c571.0ss4z9sgtsNYafQKhDeOINLhQIdW8yQE";
    Mock::given(method(Method::POST))
        .and(path(format!(
            "/ssi/oidc-issuer/v1/{credential_schema_id}/token"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "access_token": test_token,
                "expires_in": OffsetDateTime::now_utc().unix_timestamp() + 3600,
                "refresh_token": test_token,
                "refresh_token_expires_in": OffsetDateTime::now_utc().unix_timestamp() + 3600,
                "token_type": "bearer"
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::GET))
        .and(path(format!(
            "/ssi/oidc-issuer/v1/{credential_schema_id}/offer/{credential_id}"
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
            "format": "SDJWT",
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
    assert_eq!(resp.status(), 200);

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

    let interaction: HolderInteractionData =
        serde_json::from_slice(&credential.interaction.unwrap().data.unwrap()).unwrap();
    assert_eq!(interaction.access_token, test_token);
    assert_eq!(interaction.refresh_token, Some(test_token.to_string()));
    assert!(interaction.access_token_expires_at.is_some());
    assert!(interaction.refresh_token_expires_at.is_some());
}

#[tokio::test]
async fn test_handle_invitation_endpoint_for_openid4vc_proof_by_reference() {
    let mock_server = MockServer::start().await;
    let (context, organistion) = TestContext::new_with_organisation().await;

    let client_metadata = serde_json::to_string(&OpenID4VPClientMetadata {
        jwks: vec![],
        vp_formats: HashMap::from([(
            "jwt_vp_json".to_string(),
            OpenID4VPFormat {
                alg: vec!["EdDSA".to_string()],
            },
        )]),
        client_id_scheme: "redirect_uri".to_string(),
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
    assert_eq!(resp.status(), 200);

    let resp = resp.json_value().await;
    assert!(resp.get("interactionId").is_some());
}

#[tokio::test]
async fn test_handle_invitation_endpoint_for_openid4vc_proof_by_value() {
    let (context, organistion) = TestContext::new_with_organisation().await;

    let client_metadata = serde_json::to_string(&OpenID4VPClientMetadata {
        jwks: vec![],
        vp_formats: HashMap::from([(
            "jwt_vp_json".to_string(),
            OpenID4VPFormat {
                alg: vec!["EdDSA".to_string()],
            },
        )]),
        client_id_scheme: "redirect_uri".to_string(),
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
                                    , nonce, callback_url, client_metadata, callback_url, presentation_definition)).unwrap().to_string();

    // WHEN
    let resp = context
        .api
        .interactions
        .handle_invitation(organistion.id, &query)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);

    let resp = resp.json_value().await;
    assert!(resp.get("interactionId").is_some());
}

#[tokio::test]
async fn test_handle_invitation_mdoc() {
    let mock_server = MockServer::start().await;
    let (context, organistion) = TestContext::new_with_organisation().await;

    let credential_schema_id = Uuid::new_v4();
    let credential_issuer = format!(
        "{}/ssi/oidc-issuer/v1/{credential_schema_id}",
        mock_server.uri()
    );

    let credential_offer = json!({
        "credential_issuer": credential_issuer,
        "credentials": [
            {
                "wallet_storage_type": "SOFTWARE",
                "format": "mso_mdoc",
                "claims": {
                    "company": {
                        "value_type": "OBJECT",
                        "value": {
                            "address": {
                                "value_type": "OBJECT",
                                "value": {
                                    "streetName": {
                                        "value_type": "STRING",
                                        "value": "Deitzingerstrasse 111"
                                    },
                                    "streetNumber": {
                                        "value_type": "NUMBER",
                                        "value": "55"
                                    },
                                }
                            }
                        }
                    },
                    "first.namespace": {
                        "value_type": "OBJECT",
                        "value": {
                            "field": {
                                "value_type": "STRING",
                                "value": "test"
                            }
                        }
                    },
                },
                "doctype": "custom-doctype",
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
                "credentials_supported": [{
                    "claims": {
                        "first.namespace": {
                            "value": {
                                "field": {
                                    "value_type": "STRING"
                                },
                            },
                            "value_type": "OBJECT",
                        },
                        "company": {
                            "value": {
                                "address": {
                                    "value_type": "OBJECT",
                                    "value": {
                                        "streetName": {
                                            "value_type": "STRING"
                                        },
                                        "streetNumber": {
                                            "value_type": "NUMBER"
                                        }
                                    },
                                    "order": ["streetName", "streetNumber"]
                                },
                            },
                            "value_type": "OBJECT",
                        }
                    },
                    "format": "mso_mdoc",
                    "doctype": "custom-doctype",
                    "order": ["first.namespace~field", "company~address"]
                }]
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
    assert_eq!(resp.status(), 200);

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
        .into_iter()
        .map(|claim_schema| claim_schema.schema.key)
        .collect();

    assert_eq!(
        vec![
            "first.namespace".to_string(),
            "first.namespace/field".to_string(),
            "company".to_string(),
            "company/address".to_string(),
            "company/address/streetName".to_string(),
            "company/address/streetNumber".to_string(),
        ],
        claim_schema_keys
    );
}

#[tokio::test]
async fn test_handle_invitation_mdoc_with_optional_root() {
    let mock_server = MockServer::start().await;
    let (context, organistion) = TestContext::new_with_organisation().await;

    let credential_schema_id = Uuid::new_v4();
    let credential_issuer = format!(
        "{}/ssi/oidc-issuer/v1/{credential_schema_id}",
        mock_server.uri()
    );

    let credential_offer = json!({
        "credential_issuer": credential_issuer,
        "credentials": [
            {
                "wallet_storage_type": "SOFTWARE",
                "format": "mso_mdoc",
                "claims": {
                    "company": {
                        "value_type": "OBJECT",
                        "value": {
                            "address": {
                                "value_type": "OBJECT",
                                "value": {
                                    "streetName": {
                                        "value_type": "STRING",
                                        "value": "Deitzingerstrasse 111"
                                    },
                                    "streetNumber": {
                                        "value_type": "NUMBER",
                                        "value": "55"
                                    },
                                }
                            }
                        }
                    }
                },
                "doctype": "custom-doctype",
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
                "credentials_supported": [{
                    "claims": {
                        "first.namespace": {
                            "value": {
                                "field": {
                                    "value_type": "STRING"
                                },
                            },
                            "value_type": "OBJECT",
                            "mandatory": false,
                        },
                        "company": {
                            "value": {
                                "address": {
                                    "value_type": "OBJECT",
                                    "value": {
                                        "streetName": {
                                            "value_type": "STRING"
                                        },
                                        "streetNumber": {
                                            "value_type": "NUMBER"
                                        }
                                    },
                                    "order": ["streetName", "streetNumber"]
                                },
                            },
                            "value_type": "OBJECT",
                        }
                    },
                    "format": "mso_mdoc",
                    "doctype": "custom-doctype",
                    "order": ["first.namespace~field", "company~address"]
                }]
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
    assert_eq!(resp.status(), 200);

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
        .into_iter()
        .map(|claim_schema| claim_schema.schema.key)
        .collect();

    assert_eq!(
        vec![
            "first.namespace".to_string(),
            "first.namespace/field".to_string(),
            "company".to_string(),
            "company/address".to_string(),
            "company/address/streetName".to_string(),
            "company/address/streetNumber".to_string(),
        ],
        claim_schema_keys
    );
}
