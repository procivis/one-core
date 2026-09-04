use one_core::model::certificate::CertificateRole;
use one_core::proto::jwt::Jwt;
use serde_json::Value;
use similar_asserts::assert_eq;

use crate::fixtures::{TestingCertIdentifierParams, create_cert_identifier};
use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;

#[tokio::test]
async fn test_oauth_authorization_server_metadata() {
    // GIVEN
    let (context, organisation, _did, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create_with_nested_hell("test_schema", &organisation, Default::default())
        .await;

    // WHEN
    let resp = context
        .api
        .ssi
        .oauth_authorization_server("OPENID4VCI_FINAL1", identifier.id, credential_schema.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    // Get credential issuer metadata to verify authorization_servers field
    let openid_credential_issuer_resp = context
        .api
        .ssi
        .openid_credential_issuer_final1(
            "OPENID4VCI_FINAL1",
            identifier.id,
            credential_schema.id,
            mime::APPLICATION_JSON.into(),
        )
        .await
        .json_value()
        .await;

    // Verify authorization_servers field is missing
    assert_eq!(
        openid_credential_issuer_resp.get("authorization_servers"),
        None
    );

    let issuer = format!(
        "{}/ssi/openid4vci/final-1.0",
        context.config.app.core_base_url
    );

    assert_eq!(
        format!(
            "{issuer}/OPENID4VCI_FINAL1/{}/{}",
            identifier.id, credential_schema.id
        ),
        resp["issuer"]
    );
    assert_eq!(
        format!("{issuer}/{}/token", credential_schema.id),
        resp["token_endpoint"]
    );

    // Check scopes supported (must include "openid" per RFC 8414)
    let scopes = resp["scopes_supported"].as_array().unwrap();
    assert_eq!(scopes.len(), 1);
    assert_eq!(scopes[0], "openid");

    // Check response types supported
    let response_types = resp["response_types_supported"].as_array().unwrap();
    assert_eq!(response_types.len(), 2);
    assert_eq!(response_types[0], "code");

    // Check grant types supported
    let grant_types = resp["grant_types_supported"].as_array().unwrap();
    assert_eq!(grant_types.len(), 2);
    assert_eq!(
        grant_types[0],
        "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    );

    // Check token endpoint auth methods (should be "none")
    let auth_methods = resp["token_endpoint_auth_methods_supported"]
        .as_array()
        .unwrap();
    assert_eq!(auth_methods.len(), 1);
    assert_eq!(auth_methods[0], "none");

    // These fields should also be absent when attest_jwt_client_auth is not supported
    assert!(resp["client_attestation_signing_alg_values_supported"].is_null());
    assert!(resp["client_attestation_pop_signing_alg_values_supported"].is_null());

    // The signed metadata carries the same parameters as claims
    // https://datatracker.ietf.org/doc/html/rfc8414#section-2.1
    let signed_metadata = resp["signed_metadata"].as_str().unwrap();
    let jwt = Jwt::<Value>::decompose_token(signed_metadata).unwrap();

    assert_eq!(jwt.header.r#type.as_deref(), Some("JWT"));
    assert_eq!(jwt.payload.issuer.as_deref(), resp["issuer"].as_str());
    assert_eq!(jwt.payload.custom["issuer"], resp["issuer"]);
    assert_eq!(jwt.payload.custom["token_endpoint"], resp["token_endpoint"]);
    assert_eq!(
        jwt.payload.custom["token_endpoint_auth_methods_supported"],
        resp["token_endpoint_auth_methods_supported"]
    );
    // "A signed_metadata metadata value SHOULD NOT appear as a claim in the JWT"
    assert!(jwt.payload.custom.get("signed_metadata").is_none());

    // and it is cached
    let cache_entry = context
        .db
        .remote_entities
        .get_by_key(&format!(
            "oauth-authorization-server:OPENID4VCI_FINAL1:{}:{}",
            identifier.id, credential_schema.id
        ))
        .await;
    assert_eq!(cache_entry.unwrap().value, signed_metadata.as_bytes());
}

#[tokio::test]
async fn test_oauth_authorization_server_metadata_omits_signed_metadata_without_authentication_key()
{
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let identifier = create_cert_identifier(
        &context,
        &organisation,
        Some(TestingCertIdentifierParams {
            roles: vec![CertificateRole::AssertionMethod],
            ..Default::default()
        }),
        None,
    )
    .await;
    let credential_schema = context
        .db
        .credential_schemas
        .create_with_nested_hell("test_schema", &organisation, Default::default())
        .await;

    // WHEN
    let resp = context
        .api
        .ssi
        .oauth_authorization_server("OPENID4VCI_FINAL1", identifier.id, credential_schema.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert!(resp["signed_metadata"].is_null());
    assert!(!resp["token_endpoint"].is_null());
}

#[tokio::test]
async fn test_oauth_authorization_server_metadata_eudi_compliant() {
    // GIVEN
    let (context, organisation, _did, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create_with_nested_hell(
            "test_schema",
            &organisation,
            TestingCreateSchemaParams {
                requires_wallet_instance_attestation: true,
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .ssi
        .oauth_authorization_server("OPENID4VCI_FINAL1", identifier.id, credential_schema.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    let openid_credential_issuer_resp = context
        .api
        .ssi
        .openid_credential_issuer_final1(
            "OPENID4VCI_FINAL1",
            identifier.id,
            credential_schema.id,
            mime::APPLICATION_JSON.into(),
        )
        .await
        .json_value()
        .await;

    assert_eq!(
        openid_credential_issuer_resp.get("authorization_servers"),
        None
    );

    let issuer = format!(
        "{}/ssi/openid4vci/final-1.0",
        context.config.app.core_base_url
    );

    assert_eq!(
        format!(
            "{issuer}/OPENID4VCI_FINAL1/{}/{}",
            identifier.id, credential_schema.id
        ),
        resp["issuer"]
    );
    assert_eq!(
        format!("{issuer}/{}/token", credential_schema.id),
        resp["token_endpoint"]
    );

    // Check scopes supported (must include "openid" per RFC 8414)
    let scopes = resp["scopes_supported"].as_array().unwrap();
    assert_eq!(scopes.len(), 1);
    assert_eq!(scopes[0], "openid");

    // Check response types supported
    let response_types = resp["response_types_supported"].as_array().unwrap();
    assert_eq!(response_types.len(), 2);
    assert_eq!(response_types[0], "code");

    // Check grant types supported
    let grant_types = resp["grant_types_supported"].as_array().unwrap();
    assert_eq!(grant_types.len(), 2);
    assert_eq!(
        grant_types[0],
        "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    );

    // Check token endpoint auth methods (should include attest_jwt_client_auth for EUDI compliant schemas)
    let auth_methods = resp["token_endpoint_auth_methods_supported"]
        .as_array()
        .unwrap();
    assert_eq!(auth_methods.len(), 1);
    assert_eq!(auth_methods[0], "attest_jwt_client_auth");

    // Per https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-07#section-10.1
    // When attest_jwt_client_auth is supported, these fields MUST be present
    let attestation_algs = resp["client_attestation_signing_alg_values_supported"]
        .as_array()
        .unwrap();
    assert_eq!(attestation_algs.len(), 1);
    assert_eq!(attestation_algs[0], "ES256");

    let attestation_pop_algs = resp["client_attestation_pop_signing_alg_values_supported"]
        .as_array()
        .unwrap();
    assert_eq!(attestation_pop_algs.len(), 1);
    assert_eq!(attestation_pop_algs[0], "ES256");
}

#[tokio::test]
async fn test_oauth_authorization_server_metadata_nonexistent_schema() {
    // GIVEN
    let (context, _organisation, _id, identifier, ..) = TestContext::new_with_did(None).await;
    let nonexistent_id = uuid::Uuid::new_v4();

    // WHEN
    let resp = context
        .api
        .ssi
        .oauth_authorization_server("OPENID4VCI_FINAL1", identifier.id, nonexistent_id)
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
}
