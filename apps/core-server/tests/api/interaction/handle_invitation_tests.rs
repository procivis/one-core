use maplit::btreeset;
use one_core::{
    model::{
        credential_schema::{CredentialSchemaType, WalletStorageTypeEnum},
        proof::ProofStateEnum,
    },
    provider::transport_protocol::openid4vc::dto::{
        OpenID4VPClientMetadata, OpenID4VPFormat, OpenID4VPPresentationDefinition,
    },
};
use serde_json::json;
use std::{
    collections::{BTreeSet, HashMap},
    str::FromStr,
};
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;
use wiremock::http::Method;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::utils::{
    context::TestContext, db_clients::credential_schemas::TestingCreateSchemaParams,
    field_match::FieldHelpers,
};

#[tokio::test]
async fn test_handle_invitation_endpoint_for_procivis_temp_issuance() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let credential_id = Uuid::new_v4();
    let credential_schema_id = Uuid::new_v4();

    context
        .server_mock
        .temporary_issuer_connect(
            "PROCIVIS_TEMPORARY",
            credential_id,
            credential_schema_id,
            None,
            json!([
                {
                    "schema": {
                        "createdDate": "2023-11-08T15:46:14.997Z",
                        "datatype": "STRING",
                        "id": "48db4654-01c4-4a43-9df4-300f1f425c40",
                        "key": "firstName",
                        "lastModified": "2023-11-08T15:46:14.997Z",
                        "required": true
                    },
                    "value": "aae"
                }
            ]),
        )
        .await;

    // WHEN
    let url = format!(
        "{}/ssi/temporary-issuer/v1/connect?protocol=PROCIVIS_TEMPORARY&credential={credential_id}",
        context.server_mock.uri()
    );
    let resp = context
        .api
        .interactions
        .handle_invitation(organisation.id, &url)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);

    let stored_credential = context.db.credentials.get(&credential_id.into()).await;

    let schema = stored_credential.schema.unwrap();

    assert_eq!(schema.schema_id, credential_schema_id.to_string());
    assert_eq!(
        schema.schema_type,
        CredentialSchemaType::ProcivisOneSchema2024
    );

    let resp = resp.json_value().await;
    assert!(resp.get("interactionId").is_some());
}

#[tokio::test]
async fn test_handle_invitation_endpoint_for_procivis_temp_issuance_with_nested_claims() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let credential_id = Uuid::new_v4();
    let credential_schema_id = Uuid::new_v4();

    context
        .server_mock
        .temporary_issuer_connect(
            "PROCIVIS_TEMPORARY",
            credential_id,
            credential_schema_id,
            None,
            json!([
                {
                    "schema": {
                        "createdDate": "2023-11-08T15:46:14.997Z",
                        "datatype": "OBJECT",
                        "id": "48db4654-01c4-4a43-9df4-300f1f425c40",
                        "key": "location",
                        "lastModified": "2023-11-08T15:46:14.997Z",
                        "required": true
                    },
                    "value": [
                        {
                            "schema": {
                                "createdDate": "2023-11-08T15:46:14.997Z",
                                "datatype": "OBJECT",
                                "id": "48db4654-01c4-4a43-9df4-300f1f425c41",
                                "key": "coordinates",
                                "lastModified": "2023-11-08T15:46:14.997Z",
                                "required": true
                            },
                            "value": [
                                {
                                    "schema": {
                                        "createdDate": "2023-11-08T15:46:14.997Z",
                                        "datatype": "STRING",
                                        "id": "48db4654-01c4-4a43-9df4-300f1f425c42",
                                        "key": "X",
                                        "lastModified": "2023-11-08T15:46:14.997Z",
                                        "required": true
                                    },
                                    "value": "123"
                                }
                            ]
                        }
                    ]
                }
            ]),
        )
        .await;

    // WHEN
    let url = format!(
        "{}/ssi/temporary-issuer/v1/connect?protocol=PROCIVIS_TEMPORARY&credential={credential_id}",
        context.server_mock.uri()
    );
    let resp = context
        .api
        .interactions
        .handle_invitation(organisation.id, &url)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);

    let stored_credential = context.db.credentials.get(&credential_id.into()).await;

    let schema = stored_credential.schema.unwrap();

    assert_eq!(schema.schema_id, credential_schema_id.to_string());
    assert_eq!(
        schema.schema_type,
        CredentialSchemaType::ProcivisOneSchema2024
    );
    let schema_keys: Vec<String> = schema
        .claim_schemas
        .unwrap()
        .into_iter()
        .map(|schema| schema.schema.key)
        .collect();
    assert_eq!(
        vec!["location", "location/coordinates", "location/coordinates/X"],
        schema_keys
    );

    let resp = resp.json_value().await;
    assert!(resp.get("interactionId").is_some());
}

#[tokio::test]
async fn test_handle_invitation_endpoint_for_procivis_temp_issuance_match_existing_schema_success()
{
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let credential_id = Uuid::new_v4();

    let new_claim_schemas: Vec<(Uuid, &str, bool, &str)> = vec![(
        Uuid::from_str("48db4654-01c4-4a43-9df4-300f1f425c40").unwrap(),
        "firstName",
        true,
        "STRING",
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
            &schema_id.to_string(),
        )
        .await;

    context
        .server_mock
        .temporary_issuer_connect(
            "PROCIVIS_TEMPORARY",
            credential_id,
            credential_schema.id,
            None,
            json!([
                {
                    "schema": {
                        "createdDate": "2023-11-08T15:46:14.997Z",
                        "datatype": "STRING",
                        "id": "48db4654-01c4-4a43-9df4-300f1f425c40",
                        "key": "firstName",
                        "lastModified": "2023-11-08T15:46:14.997Z",
                        "required": true
                    },
                    "value": "aae"
                }
            ]),
        )
        .await;

    // WHEN
    let url = format!(
        "{}/ssi/temporary-issuer/v1/connect?protocol=PROCIVIS_TEMPORARY&credential={credential_id}",
        context.server_mock.uri()
    );
    let resp = context
        .api
        .interactions
        .handle_invitation(organisation.id, &url)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);

    let stored_credential = context.db.credentials.get(&credential_id.into()).await;

    let schema = stored_credential.schema.unwrap();

    assert_eq!(schema.schema_id, credential_schema.id.to_string());
    assert_eq!(
        schema.schema_type,
        CredentialSchemaType::ProcivisOneSchema2024
    );
    assert_eq!(schema.name, "MatchedSchema");

    let resp = resp.json_value().await;
    assert!(resp.get("interactionId").is_some());
}

#[tokio::test]
async fn test_handle_invitation_endpoint_for_procivis_temp_issuance_match_existing_schema_fails() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let credential_id = Uuid::new_v4();

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "MatchedSchema",
            &organisation,
            "NONE",
            TestingCreateSchemaParams {
                ..Default::default()
            },
        )
        .await;

    context
        .server_mock
        .temporary_issuer_connect(
            "PROCIVIS_TEMPORARY",
            credential_id,
            credential_schema.id,
            Some("IncorrectSchemaType"),
            json!([
                {
                    "schema": {
                        "createdDate": "2023-11-08T15:46:14.997Z",
                        "datatype": "STRING",
                        "id": "48db4654-01c4-4a43-9df4-300f1f425c40",
                        "key": "firstName",
                        "lastModified": "2023-11-08T15:46:14.997Z",
                        "required": true
                    },
                    "value": "aae"
                }
            ]),
        )
        .await;

    // WHEN
    let url = format!(
        "{}/ssi/temporary-issuer/v1/connect?protocol=PROCIVIS_TEMPORARY&credential={credential_id}",
        context.server_mock.uri()
    );
    let resp = context
        .api
        .interactions
        .handle_invitation(organisation.id, &url)
        .await;

    // THEN
    assert_eq!(resp.status(), 500);
}

#[tokio::test]
async fn test_handle_invitation_endpoint_for_procivis_temp_proving() {
    // GIVEN
    let mock_server = MockServer::start().await;
    let (context, organisation) = TestContext::new_with_organisation().await;

    let organisation2 = context.db.organisations.create().await;
    let verifier_id = context
        .db
        .dids
        .create(&organisation2, Default::default())
        .await;

    let proof_id = Uuid::new_v4();

    Mock::given(method(Method::POST))
        .and(path("/ssi/temporary-verifier/v1/connect"))
        .and(query_param("protocol", "PROCIVIS_TEMPORARY"))
        .and(query_param("proof", proof_id))
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
                            "revocationMethod": "BITSTRINGSTATUSLIST",
                            "schemaType": "ProcivisOneSchema2024",
                            "schemaId": "293d1376-62ea-4b0e-8c16-2dfe4f7ac0bd"
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
    let resp = context
        .api
        .interactions
        .handle_invitation(organisation.id, &format!("{}/ssi/temporary-verifier/v1/connect?protocol=PROCIVIS_TEMPORARY&proof={proof_id}&redirect_uri=", mock_server.uri()))
        .await;

    // THEN
    assert_eq!(resp.status(), 200);

    let resp = resp.json_value().await;
    assert!(resp.get("interactionId").is_some());
    resp["proofId"].assert_eq(&proof_id);

    let proof = context.db.proofs.get(&proof_id).await;
    assert!(proof
        .state
        .unwrap()
        .iter()
        .any(|state| state.state == ProofStateEnum::Pending));

    resp["interactionId"].assert_eq(&proof.interaction.unwrap().id);
}

#[tokio::test]
async fn test_handle_invitation_endpoint_for_openid4vc_issuance_offer_by_value() {
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

    Mock::given(method(Method::GET))
        .and(path(format!("/ssi/schema/v1/{credential_schema_id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
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
    assert_eq!(
        credential.schema.unwrap().wallet_storage_type,
        Some(WalletStorageTypeEnum::Software)
    )
}

#[tokio::test]
async fn test_handle_invitation_endpoint_for_openid4vc_issuance_offer_by_value_with_double_layered_nested_claims(
) {
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
                            ]
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

    Mock::given(method(Method::GET))
        .and(path(format!("/ssi/schema/v1/{credential_schema_id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
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
        .iter()
        .map(|claim_schema| claim_schema.schema.key.to_owned())
        .collect();
    assert_eq!(
        vec![
            "address/location/position/x",
            "address",
            "address/location",
            "address/location/position",
        ],
        claim_schema_keys
    );
}

#[tokio::test]
async fn test_handle_invitation_endpoint_for_openid4vc_issuance_offer_by_value_matching_succeeds() {
    let mock_server = MockServer::start().await;
    let (context, organisation) = TestContext::new_with_organisation().await;

    let new_claim_schemas: Vec<(Uuid, &str, bool, &str)> = vec![(
        Uuid::from_str("48db4654-01c4-4a43-9df4-300f1f425c40").unwrap(),
        "key",
        true,
        "STRING",
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
                            ]
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
    )
}

#[tokio::test]
async fn test_handle_invitation_endpoint_for_openid4vc_proof_by_reference() {
    let mock_server = MockServer::start().await;
    let (context, organistion) = TestContext::new_with_organisation().await;

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

                "credentials_supported": [
                    {
                        "claims": {
                            "company": {
                                "value_type": "OBJECT",
                            },
                            "address": {
                                "value_type": "OBJECT",
                            },
                            "streetName": {
                                "value_type": "STRING",
                            },
                            "streetNumber": {
                                "value_type": "NUMBER",
                            },
                        },
                        "format": "mso_mdoc",
                        "doctype": "custom-doctype"
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
        .and(path(format!("/ssi/schema/v1/{credential_schema_id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
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
    let claim_schema_keys: BTreeSet<String> = credential
        .schema
        .unwrap()
        .claim_schemas
        .unwrap()
        .into_iter()
        .map(|claim_schema| claim_schema.schema.key)
        .collect();

    assert_eq!(
        btreeset![
            "company/address/streetName".into(),
            "company/address/streetNumber".into(),
            "company".into(),
            "company/address".into(),
        ],
        claim_schema_keys
    );
}
