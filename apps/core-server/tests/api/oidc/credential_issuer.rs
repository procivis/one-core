use crate::utils::context::TestContext;

#[tokio::test]
async fn test_get_credential_issuer_metadata() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE")
        .await;

    // WHEN
    let resp = context
        .api
        .ssi
        .openid_credential_issuer(credential_schema.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    let issuer = format!(
        "{}/ssi/oidc-issuer/v1/{}",
        context.config.app.core_base_url, credential_schema.id
    );
    assert_eq!(issuer, resp["credential_issuer"]);
    assert_eq!(format!("{issuer}/credential"), resp["credential_endpoint"]);

    let credentials = resp["credentials_supported"].as_array().unwrap();
    assert!(!credentials.is_empty());
    assert!(credentials
        .iter()
        .all(|entry| entry["wallet_storage_type"] == "SOFTWARE"));
}
