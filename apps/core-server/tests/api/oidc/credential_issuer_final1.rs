use maplit::hashmap;
use mime::Mime;
use one_core::mapper::x509::pem_chain_into_x5c;
use one_core::model::blob::BlobType;
use one_core::model::certificate::CertificateRole;
use one_core::model::credential_schema::{CredentialSchema, KeyStorageSecurity};
use one_core::model::identifier::Identifier;
use one_core::model::identifier_trust_information::SchemaFormat;
use one_core::proto::jwt::Jwt;
use serde_json::{Value, json};
use similar_asserts::assert_eq;
use time::Duration;
use uuid::Uuid;

use crate::fixtures::{TestingCertIdentifierParams, create_cert_identifier};
use crate::utils::context::TestContext;
use crate::utils::db_clients::blobs::TestingBlobParams;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
use crate::utils::db_clients::identifier_trust_information::TestingIdentifierTrustInformationParams;

#[tokio::test]
async fn test_get_credential_issuer_metadata_json() {
    // GIVEN
    let (context, organisation, identifier, ..) =
        TestContext::new_with_certificate_identifier(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create_with_nested_hell("test_schema", &organisation, Default::default())
        .await;

    // WHEN
    let resp = context
        .api
        .ssi
        .openid_credential_issuer_final1(
            "OPENID4VCI_FINAL1",
            identifier.id,
            credential_schema.id,
            mime::APPLICATION_JSON.into(),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_issuer_metadata(&context, &identifier, &credential_schema, resp).await;
}

#[tokio::test]
async fn test_get_credential_issuer_metadata_wallet_attestation_status_periods() {
    // GIVEN
    let (context, organisation, identifier, ..) =
        TestContext::new_with_certificate_identifier(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create_with_nested_hell(
            "test_schema",
            &organisation,
            TestingCreateSchemaParams {
                key_storage_security: Some(KeyStorageSecurity::Basic),
                preferred_key_storage_attestation_lifetime: Some(Duration::hours(1)),
                preferred_instance_attestation_lifetime: Some(Duration::days(30)),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .ssi
        .openid_credential_issuer_final1(
            "OPENID4VCI_FINAL1",
            identifier.id,
            credential_schema.id,
            mime::APPLICATION_JSON.into(),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["preferred_client_status_period"], 2592000);
    let key_attestations_required = &resp["credential_configurations_supported"]
        [credential_schema.schema_id().await.unwrap()]["proof_types_supported"]["jwt"]["key_attestations_required"];
    assert_eq!(
        key_attestations_required["key_storage"],
        json!(["iso_18045_basic"])
    );
    assert_eq!(
        key_attestations_required["preferred_key_storage_status_period"],
        3600
    );
}

#[tokio::test]
async fn test_get_credential_issuer_metadata_batch_multiformat() {
    // GIVEN
    let (context, organisation, identifier, ..) =
        TestContext::new_with_certificate_identifier(None).await;
    let credential_schema_id = context
        .db
        .credential_schemas
        .create_with_multiformat("test_schema", &organisation, Some(10))
        .await
        .unwrap();

    // WHEN
    let resp = context
        .api
        .ssi
        .openid_credential_issuer_final1(
            "OPENID4VCI_FINAL1",
            identifier.id,
            credential_schema_id,
            mime::APPLICATION_JSON.into(),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["batch_credential_issuance"]["batch_size"], 10);

    let credential_configurations = resp["credential_configurations_supported"]
        .as_object()
        .unwrap();
    assert_eq!(credential_configurations.len(), 2);

    assert_eq!(
        credential_configurations["sd-jwt_vct"]["format"],
        "dc+sd-jwt"
    );
    assert_eq!(credential_configurations["sd-jwt_vct"]["vct"], "sd-jwt_vct");

    assert_eq!(
        credential_configurations["mdoc_doctype"]["format"],
        "mso_mdoc"
    );
    assert_eq!(
        credential_configurations["mdoc_doctype"]["doctype"],
        "mdoc_doctype"
    );
}

#[tokio::test]
async fn test_get_credential_issuer_metadata_jwt_certificate_identifier_with_trust_information() {
    // GIVEN
    let (context, organisation, identifier, certificate, ..) =
        TestContext::new_with_certificate_identifier(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create_with_nested_hell("test_schema", &organisation, Default::default())
        .await;

    // Attach registration certificate blobs via trust_information
    let blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            r#type: Some(BlobType::RegistrationCertificate),
            value: Some("someTestData".as_bytes().to_vec()),
            ..Default::default()
        })
        .await;

    context
        .db
        .identifier_trust_information
        .create(
            identifier.id,
            blob.id,
            TestingIdentifierTrustInformationParams {
                allowed_issuance_types: Some(vec![SchemaFormat {
                    format: "jwt_vc_json".to_string(),
                    schema_id: credential_schema.schema_id().await.unwrap(),
                }]),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .ssi
        .openid_credential_issuer_final1(
            "OPENID4VCI_FINAL1",
            identifier.id,
            credential_schema.id,
            "application/jwt".parse::<Mime>().unwrap().into(),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.text().await;
    assert!(!body.is_empty());
    let jwt = Jwt::<serde_json::Value>::decompose_token(&body).unwrap();

    assert!(jwt.header.x5c.is_some());
    assert_eq!(
        jwt.header.x5c.as_ref().unwrap(),
        &pem_chain_into_x5c(&certificate.chain).unwrap()
    );

    let jwt_payload = jwt.payload.custom;
    let issuer_info = &jwt_payload["issuer_info"][0];

    assert_eq!(issuer_info["format"], "registration_cert");
    assert_eq!(&issuer_info["data"], "someTestData");
    assert!(issuer_info["credential_ids"].is_array());
    assert_eq!(
        issuer_info["credential_ids"][0]
            .as_str()
            .expect("credential_ids should be string"),
        credential_schema.schema_id().await.unwrap()
    );
    assert_issuer_metadata(&context, &identifier, &credential_schema, jwt_payload).await;

    let cache_entry = context
        .db
        .remote_entities
        .get_by_key(&format!(
            "OPENID4VCI_FINAL1:{}:{}",
            identifier.id, credential_schema.id
        ))
        .await;
    assert!(cache_entry.is_some());
    assert_eq!(cache_entry.unwrap().value, body.as_bytes());
}

#[tokio::test]
async fn test_get_credential_issuer_metadata_jwt_with_did_identifier() {
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
        .openid_credential_issuer_final1(
            "OPENID4VCI_FINAL1",
            identifier.id,
            credential_schema.id,
            "application/jwt".parse::<Mime>().unwrap().into(),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.text().await;
    assert!(!body.is_empty());
    let jwt = Jwt::<serde_json::Value>::decompose_token(&body).unwrap();
    assert_issuer_metadata(
        &context,
        &identifier,
        &credential_schema,
        jwt.payload.custom,
    )
    .await;
}

#[tokio::test]
async fn test_get_credential_issuer_metadata_fails_with_invalid_accept_header() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create_with_nested_hell("test_schema", &organisation, Default::default())
        .await;

    // WHEN
    let resp = context
        .api
        .ssi
        .openid_credential_issuer_final1(
            "OPENID4VCI_FINAL1",
            Uuid::new_v4(),
            credential_schema.id,
            mime::APPLICATION_PDF.into(),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 406);
}

#[tokio::test]
async fn test_get_credential_issuer_metadata_fails_with_certificate_invalid_role() {
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
        .openid_credential_issuer_final1(
            "OPENID4VCI_FINAL1",
            identifier.id,
            credential_schema.id,
            "application/jwt".parse::<Mime>().unwrap().into(),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_get_credential_issuer_metadata_with_disclosure_policy() {
    // GIVEN
    let (context, organisation, identifier, ..) =
        TestContext::new_with_certificate_identifier(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test-schema",
            &organisation,
            TestingCreateSchemaParams {
                embedded_disclosure_policy: Some(
                    serde_json::json!({
                        "id": "ID",
                        "policy": "rootOfTrust",
                        "options": {
                            "values": [{
                                "dn": "DN",
                                "serial": "serial"
                            }]
                        },
                        "description": "description",
                        "url": "https://url",
                    })
                    .to_string(),
                ),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .ssi
        .openid_credential_issuer_final1(
            "OPENID4VCI_FINAL1",
            identifier.id,
            credential_schema.id,
            mime::APPLICATION_JSON.into(),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json_value().await;

    assert_eq!(
        body["credential_configurations_supported"]
            [credential_schema.schema_id().await.unwrap().as_str()]["disclosure_policy"],
        serde_json::json!({
            "id": "ID",
            "policy": "rootOfTrust",
            "options": {
                "values": [{
                    "dn": "DN",
                    "serial": "serial"
                }]
            },
            "description": "description",
            "url": "https://url",
        })
    );
}

#[tokio::test]
async fn test_get_credential_issuer_metadata_with_claim_mappings() {
    // GIVEN
    let (context, organisation, identifier, ..) =
        TestContext::new_with_certificate_identifier(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test-schema",
            &organisation,
            TestingCreateSchemaParams {
                claim_mappings: Some(hashmap! {
                    "firstName".to_string() => "firstName_Mapped".to_string(),
                    "isOver18".to_string() => "isOver18_Mapped".to_string()
                }),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .ssi
        .openid_credential_issuer_final1(
            "OPENID4VCI_FINAL1",
            identifier.id,
            credential_schema.id,
            mime::APPLICATION_JSON.into(),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json_value().await;

    let schema_id = credential_schema.schema_id().await.unwrap();
    // layout properties are using mapped paths
    assert_eq!(
        body["credential_configurations_supported"][schema_id.as_str()]["credential_metadata"]["display"]
            [0]["procivis_design"],
        serde_json::json!({
             "primary_attribute": "firstName_Mapped",
             "secondary_attribute": "firstName_Mapped",
             "picture_attribute": "firstName_Mapped",
             "code_attribute": "firstName_Mapped",
             "code_type": "BARCODE",
        })
    );
}

async fn assert_issuer_metadata(
    context: &TestContext,
    identifier: &Identifier,
    credential_schema: &CredentialSchema,
    resp: Value,
) {
    let issuer = format!(
        "{}/ssi/openid4vci/final-1.0/OPENID4VCI_FINAL1/{}/{}",
        context.config.app.core_base_url, identifier.id, credential_schema.id
    );

    assert_eq!(issuer, resp["credential_issuer"]);
    assert!(resp.get("preferred_client_status_period").is_none());
    assert_eq!(
        format!(
            "{}/ssi/openid4vci/final-1.0/{}/credential",
            context.config.app.core_base_url, credential_schema.id
        ),
        resp["credential_endpoint"]
    );
    assert_eq!(
        format!(
            "{}/ssi/openid4vci/final-1.0/OPENID4VCI_FINAL1/nonce",
            context.config.app.core_base_url
        ),
        resp["nonce_endpoint"]
    );

    let credentials = resp["credential_configurations_supported"]
        .as_object()
        .unwrap();
    assert!(!credentials.is_empty());

    // Check the credential format and metadata structure
    assert_eq!(
        credentials[&credential_schema.schema_id().await.unwrap()]["format"],
        "jwt_vc_json"
    );

    // Check display properties are present
    let display = &credentials[&credential_schema.schema_id().await.unwrap()]["credential_metadata"]
        ["display"][0];
    assert_eq!(display["name"], "test_schema");
    assert_eq!(display["locale"], "en");

    // Check claims structure
    let claims = &credentials[&credential_schema.schema_id().await.unwrap()]["credential_metadata"]
        ["claims"];
    assert_expected_claims(claims);
}

fn assert_expected_claims(claims: &Value) {
    let claims_array = claims.as_array().unwrap();
    assert_eq!(claims_array.len(), 14); // Total number of claims including nested ones

    // Helper function to find a claim by path
    let find_claim = |path: Value| -> &Value {
        claims_array
            .iter()
            .find(|claim| claim["path"] == path)
            .unwrap()
    };

    // Check root level claims
    let name_claim = find_claim(json!(["name"]));
    assert_eq!(name_claim["mandatory"], true);
    assert_eq!(name_claim["display"][0]["name"], "name");

    let string_array_claim = find_claim(json!(["string_array"]));
    assert_eq!(string_array_claim["mandatory"], true);
    assert_eq!(string_array_claim["display"][0]["name"], "string_array");

    let object_array_claim = find_claim(json!(["object_array"]));
    assert_eq!(object_array_claim["mandatory"], true);
    assert_eq!(object_array_claim["display"][0]["name"], "object_array");

    let address_claim = find_claim(json!(["address"]));
    assert_eq!(address_claim["mandatory"], true);
    assert_eq!(address_claim["display"][0]["name"], "address");

    // Check nested claims
    let address_street_claim = find_claim(json!(["address", "street"]));
    assert_eq!(address_street_claim["mandatory"], true);
    assert_eq!(address_street_claim["display"][0]["name"], "street");

    let coordinates_claim = find_claim(json!(["address", "coordinates"]));
    assert_eq!(coordinates_claim["mandatory"], true);
    assert_eq!(coordinates_claim["display"][0]["name"], "coordinates");

    let coordinates_x_claim = find_claim(json!(["address", "coordinates", "x"]));
    assert_eq!(coordinates_x_claim["mandatory"], true);
    assert_eq!(coordinates_x_claim["display"][0]["name"], "x");

    let coordinates_y_claim = find_claim(json!(["address", "coordinates", "y"]));
    assert_eq!(coordinates_y_claim["mandatory"], true);
    assert_eq!(coordinates_y_claim["display"][0]["name"], "y");

    // Check array claims
    let nested_string_array_claim = find_claim(json!(["address", "coordinates", "string_array"]));
    assert_eq!(nested_string_array_claim["mandatory"], true);
    assert_eq!(
        nested_string_array_claim["display"][0]["name"],
        "string_array"
    );

    // Check object array claims
    let object_array_field1_claim = find_claim(json!(["object_array", null, "field1"]));
    assert_eq!(object_array_field1_claim["mandatory"], true);
    assert_eq!(object_array_field1_claim["display"][0]["name"], "field1");

    let object_array_field2_claim = find_claim(json!(["object_array", null, "field2"]));
    assert_eq!(object_array_field2_claim["mandatory"], true);
    assert_eq!(object_array_field2_claim["display"][0]["name"], "field2");

    // Check nested object array claims
    let nested_object_array_claim = find_claim(json!(["address", "coordinates", "object_array"]));
    assert_eq!(nested_object_array_claim["mandatory"], true);
    assert_eq!(
        nested_object_array_claim["display"][0]["name"],
        "object_array"
    );

    let nested_object_array_field1_claim = find_claim(json!([
        "address",
        "coordinates",
        "object_array",
        null,
        "field1"
    ]));
    assert_eq!(nested_object_array_field1_claim["mandatory"], true);
    assert_eq!(
        nested_object_array_field1_claim["display"][0]["name"],
        "field1"
    );

    let nested_object_array_field2_claim = find_claim(json!([
        "address",
        "coordinates",
        "object_array",
        null,
        "field2"
    ]));
    assert_eq!(nested_object_array_field2_claim["mandatory"], true);
    assert_eq!(
        nested_object_array_field2_claim["display"][0]["name"],
        "field2"
    );
}
