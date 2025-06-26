use std::collections::HashSet;

use one_core::model::credential_schema::CredentialSchemaType;
use serde_json::{Value, json};
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_get_credential_issuer_metadata_jwt() {
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
        "{}/ssi/openid4vci/draft-13/{}",
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
    assert_eq!(
        &credentials[&credential_schema.schema_id]["credential_definition"]["type"][0],
        "VerifiableCredential"
    );
    let subject =
        &credentials[&credential_schema.schema_id]["credential_definition"]["credentialSubject"];
    assert_expected_claims(subject);
}

#[tokio::test]
async fn test_get_credential_issuer_metadata_sd_jwt() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create_with_nested_hell(
            "test",
            &organisation,
            "NONE",
            TestingCreateSchemaParams {
                format: Some("SD_JWT".to_string()),
                ..Default::default()
            },
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

    let issuer = format!(
        "{}/ssi/openid4vci/draft-13/{}",
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
    assert_eq!(
        &credentials[&credential_schema.schema_id]["credential_definition"]["type"][0],
        "VerifiableCredential"
    );
    let subject =
        &credentials[&credential_schema.schema_id]["credential_definition"]["credentialSubject"];
    assert_expected_claims(subject);
}

#[tokio::test]
async fn test_get_credential_issuer_metadata_sd_jwt_vc() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create_with_nested_hell(
            "test",
            &organisation,
            "NONE",
            TestingCreateSchemaParams {
                format: Some("SD_JWT_VC".to_string()),
                schema_type: Some(CredentialSchemaType::SdJwtVc),
                ..Default::default()
            },
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

    let issuer = format!(
        "{}/ssi/openid4vci/draft-13/{}",
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

    let claims = &credentials[&credential_schema.schema_id]["claims"];
    assert_expected_claims(claims)
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
    let expected_binding_methods =
        HashSet::from(["did:key", "did:web", "did:jwk", "did:ion", "did:tdw", "jwk"]);
    let cryptographic_binding_methods_supported =
        &metadata["cryptographic_binding_methods_supported"]
            .as_array()
            .unwrap()
            .iter()
            .map(|val| val.as_str().unwrap())
            .collect::<HashSet<&str>>();
    assert_eq!(
        *cryptographic_binding_methods_supported,
        expected_binding_methods
    );

    let expected_proof_signing_algs =
        HashSet::from(["BBS_PLUS", "EdDSA", "EDDSA", "CRYDI3", "DILITHIUM", "ES256"]);
    let proof_signing_algs =
        &metadata["proof_types_supported"]["jwt"]["proof_signing_alg_values_supported"]
            .as_array()
            .unwrap()
            .iter()
            .map(|val| val.as_str().unwrap())
            .collect::<HashSet<&str>>();
    assert_eq!(*proof_signing_algs, expected_proof_signing_algs);

    metadata["format"].assert_eq(&json!("mso_mdoc"));
    metadata["doctype"].assert_eq(&json!("schema-id"));
    metadata["order"].assert_eq(&json!(["root~str", "root~num", "root~bool"]));
    metadata["display"].assert_eq(&json!([{ "name": "schema-1" }]));
    metadata["claims"].assert_eq(&json!(
        {
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
        }
    ));
}

fn assert_expected_claims(subject: &Value) {
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
