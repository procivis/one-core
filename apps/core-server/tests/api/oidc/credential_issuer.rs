use uuid::Uuid;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_get_credential_issuer_metadata() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create_with_nested_hell("test", &organisation, "NONE", Default::default())
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

    let credentials = resp["credential_configurations_supported"]
        .as_object()
        .unwrap();
    assert!(!credentials.is_empty());
    assert_eq!(
        credentials[&credential_schema.schema_id]["wallet_storage_type"],
        "SOFTWARE"
    );

    let subject =
        &credentials[&credential_schema.schema_id]["credential_definition"]["credentialSubject"];

    assert_eq!(
        &credentials[&credential_schema.schema_id]["credential_definition"]["type"][0],
        "VerifiableCredential"
    );

    assert_eq!(subject["name"]["value_type"], "string");
    assert_eq!(subject["name"]["mandatory"], true);

    assert_eq!(subject["string_array"]["value_type"], "string[]");
    assert_eq!(subject["string_array"]["mandatory"], true);

    assert_eq!(subject["address"]["street"]["value_type"], "string");
    assert_eq!(subject["address"]["street"]["mandatory"], true);

    assert_eq!(
        subject["address"]["coordinates"]["string_array"]["value_type"],
        "string[]"
    );
    assert_eq!(
        subject["address"]["coordinates"]["string_array"]["mandatory"],
        true
    );
    assert_eq!(
        subject["address"]["coordinates"]["x"]["value_type"],
        "number"
    );
    assert_eq!(subject["address"]["coordinates"]["x"]["mandatory"], true);
    assert_eq!(
        subject["address"]["coordinates"]["y"]["value_type"],
        "number"
    );
    assert_eq!(subject["address"]["coordinates"]["y"]["mandatory"], true);

    assert_eq!(
        subject["address"]["coordinates"]["object_array"][0]["field1"]["value_type"],
        "string"
    );
    assert_eq!(
        subject["address"]["coordinates"]["object_array"][0]["field1"]["mandatory"],
        true
    );
    assert_eq!(
        subject["address"]["coordinates"]["object_array"][0]["field2"]["value_type"],
        "string"
    );
    assert_eq!(
        subject["address"]["coordinates"]["object_array"][0]["field2"]["mandatory"],
        true
    );

    assert_eq!(subject["object_array"][0]["field1"]["value_type"], "string");
    assert_eq!(subject["object_array"][0]["field1"]["mandatory"], true);
    assert_eq!(subject["object_array"][0]["field2"]["value_type"], "string");
    assert_eq!(subject["object_array"][0]["field2"]["mandatory"], true);
}

#[tokio::test]
async fn test_get_credential_issuer_metadata_for_mdoc() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
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

    let metadata = &resp["credential_configurations_supported"]["schema-id"];
    let expected_metadata = serde_json::json!({
        "format": "mso_mdoc",
        "claims": {
            "root": {
                "str": {
                    "value_type": "string",
                    "mandatory": true,
                },
                "num": {
                    "value_type": "number",
                    "mandatory": true,
                },
                "bool": {
                    "value_type": "boolean",
                    "mandatory": true,
                }
            }
        },
        "order": ["root~str", "root~num", "root~bool"],
        "doctype": "schema-id",
        "display": [
            {
                "name": "schema-1"
            }
        ]
    });

    assert_eq!(&expected_metadata, metadata);
}
