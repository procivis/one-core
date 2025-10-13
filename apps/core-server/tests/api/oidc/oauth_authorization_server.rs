use one_core::model::credential_schema::WalletStorageTypeEnum;
use similar_asserts::assert_eq;

use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;

#[tokio::test]
async fn test_oauth_authorization_server_metadata() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create_with_nested_hell("test_schema", &organisation, "NONE", Default::default())
        .await;

    // WHEN
    let resp = context
        .api
        .ssi
        .oauth_authorization_server(credential_schema.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    // Get credential issuer metadata to verify authorization_servers field
    let openid_credential_issuer_resp = context
        .api
        .ssi
        .openid_credential_issuer_final1(credential_schema.id)
        .await
        .json_value()
        .await;

    // Verify authorization_servers field is present and contains the OAuth authorization server URL
    let authorization_servers = openid_credential_issuer_resp["authorization_servers"]
        .as_array()
        .unwrap();
    assert_eq!(authorization_servers.len(), 1);

    let expected_auth_server_url = format!(
        "{}/.well-known/oauth-authorization-server/ssi/openid4vci/final-1.0/{}",
        context.config.app.core_base_url, credential_schema.id
    );
    assert_eq!(authorization_servers[0], expected_auth_server_url);

    let issuer = format!(
        "{}/ssi/openid4vci/final-1.0",
        context.config.app.core_base_url
    );

    assert_eq!(issuer, resp["issuer"]);
    assert_eq!(
        format!("{issuer}/{}/token", credential_schema.id),
        resp["token_endpoint"]
    );

    // Check response types supported
    let response_types = resp["response_types_supported"].as_array().unwrap();
    assert_eq!(response_types.len(), 1);
    assert_eq!(response_types[0], "code");

    // Check grant types supported
    let grant_types = resp["grant_types_supported"].as_array().unwrap();
    assert_eq!(grant_types.len(), 1);
    assert_eq!(
        grant_types[0],
        "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    );

    // Check token endpoint auth methods (should be absent for non-EUDI compliant schemas)
    let auth_methods = &resp["token_endpoint_auth_methods_supported"];
    assert!(auth_methods.is_null());

    // These fields should also be absent when attest_jwt_client_auth is not supported
    assert!(resp["client_attestation_signing_alg_values_supported"].is_null());
    assert!(resp["client_attestation_pop_signing_alg_values_supported"].is_null());
}

#[tokio::test]
async fn test_oauth_authorization_server_metadata_eudi_compliant() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create_with_nested_hell(
            "test_schema",
            &organisation,
            "NONE",
            TestingCreateSchemaParams {
                wallet_storage_type: Some(WalletStorageTypeEnum::EudiCompliant),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .ssi
        .oauth_authorization_server(credential_schema.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    let openid_credential_issuer_resp = context
        .api
        .ssi
        .openid_credential_issuer_final1(credential_schema.id)
        .await
        .json_value()
        .await;

    assert_eq!(
        openid_credential_issuer_resp["authorization_servers"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        openid_credential_issuer_resp["authorization_servers"]
            .as_array()
            .unwrap()[0],
        format!(
            "{}/.well-known/oauth-authorization-server/ssi/openid4vci/final-1.0/{}",
            context.config.app.core_base_url, credential_schema.id
        )
    );

    let issuer = format!(
        "{}/ssi/openid4vci/final-1.0",
        context.config.app.core_base_url
    );

    assert_eq!(issuer, resp["issuer"]);
    assert_eq!(
        format!("{issuer}/{}/token", credential_schema.id),
        resp["token_endpoint"]
    );

    // Check response types supported
    let response_types = resp["response_types_supported"].as_array().unwrap();
    assert_eq!(response_types.len(), 1);
    assert_eq!(response_types[0], "code");

    // Check grant types supported
    let grant_types = resp["grant_types_supported"].as_array().unwrap();
    assert_eq!(grant_types.len(), 1);
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
    let (context, _) = TestContext::new_with_organisation(None).await;
    let nonexistent_id = uuid::Uuid::new_v4();

    // WHEN
    let resp = context
        .api
        .ssi
        .oauth_authorization_server(nonexistent_id)
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
}
