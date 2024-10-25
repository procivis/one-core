use uuid::Uuid;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_get_credential_issuer_metadata() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
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

#[tokio::test]
async fn test_get_credential_issuer_metadata_for_mdoc() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let new_claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> = vec![
        (Uuid::new_v4(), "root", false, "OBJECT", false),
        (Uuid::new_v4(), "root/str", true, "STRING", false),
        (Uuid::new_v4(), "root/num", true, "NUMBER", false),
        (Uuid::new_v4(), "root/bool", true, "BOOLEAN", false),
    ];

    let credential_schema = context
        .db
        .credential_schemas
        .create_with_claims(
            &Uuid::new_v4(),
            "schema-1",
            &organisation,
            "NONE",
            &new_claim_schemas,
            "MDOC",
            "schema-id",
        )
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
    let claims = &resp["credentials_supported"][0]["claims"];
    let expected_claims = serde_json::json!( {
        "root": {
            "value": {
                "str": {
                    "value_type": "STRING",
                    "mandatory": true,
                    "array": false,
                },
                "num": {
                    "value_type": "NUMBER",
                    "mandatory": true,
                    "array": false,
                },
                "bool": {
                    "value_type": "BOOLEAN",
                    "mandatory": true,
                    "array": false,
                }
            },
            "value_type": "OBJECT",
            "mandatory": false,
            "order": ["str", "num", "bool"],
            "array": false,
        }
    });

    assert_eq!(&expected_claims, claims);
}
