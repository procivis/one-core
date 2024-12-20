use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use one_core::model::credential::CredentialStateEnum;
use one_core::model::did::{KeyRole, RelatedKey};
use shared_types::KeyId;
use uuid::Uuid;

use crate::fixtures::TestingDidParams;
use crate::utils::context::TestContext;
use crate::utils::db_clients::keys::es256_testing_params;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_create_credential_success() {
    // GIVEN
    let (context, organisation, did, _) = TestContext::new_with_did().await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;
    let claim_id = credential_schema.claim_schemas.clone().unwrap()[0]
        .schema
        .id;
    let claim_id1 = credential_schema.claim_schemas.unwrap()[1].schema.id;

    // WHEN
    let resp = context
        .api
        .credentials
        .create(
            credential_schema.id,
            "OPENID4VC",
            did.id,
            serde_json::json!([
                {
                    "claimId": claim_id.to_string(),
                    "value": "foo",
                    "path": "firstName"
                },
                {
                    "claimId": claim_id1.to_string(),
                    "value": "true",
                    "path": "isOver18"
                }
            ]),
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;

    let credential = context.db.credentials.get(&resp["id"].parse()).await;
    assert_eq!(CredentialStateEnum::Created, credential.state);
    assert_eq!(2, credential.claims.unwrap().len());
    assert_eq!("OPENID4VC", credential.exchange);
}

#[tokio::test]
async fn test_create_credential_with_array_success() {
    // GIVEN
    let (context, organisation, did, _) = TestContext::new_with_did().await;

    let credential_schema = context
        .db
        .credential_schemas
        .create_with_array_claims("test", &organisation, "JWT", Default::default())
        .await;

    let claim_id_root_field = credential_schema
        .claim_schemas
        .clone()
        .unwrap()
        .into_iter()
        .find(|claim| claim.schema.key == "namespace/root_field")
        .unwrap()
        .schema
        .id;

    let claim_id = credential_schema
        .claim_schemas
        .clone()
        .unwrap()
        .into_iter()
        .find(|claim| claim.schema.key == "namespace/root_array/nested/field")
        .unwrap()
        .schema
        .id;

    // WHEN
    let resp = context
        .api
        .credentials
        .create(
            credential_schema.id,
            "OPENID4VC",
            did.id,
            serde_json::json!([
                {
                    "claimId": claim_id_root_field.to_string(),
                    "value": "foo",
                    "path": "namespace/root_field"
                },
                {
                    "claimId": claim_id.to_string(),
                    "value": "foo",
                    "path": "namespace/root_array/0/nested/0/field"
                },
                {
                    "claimId": claim_id.to_string(),
                    "value": "foo",
                    "path": "namespace/root_array/0/nested/0/field"
                },
                {
                    "claimId": claim_id.to_string(),
                    "value": "foo",
                    "path": "namespace/root_array/0/nested/1/field"
                },
                {
                    "claimId": claim_id.to_string(),
                    "value": "foo",
                    "path": "namespace/root_array/1/nested/0/field"
                },
                {
                    "claimId": claim_id.to_string(),
                    "value": "foo",
                    "path": "namespace/root_array/1/nested/1/field"
                }
            ]),
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;

    let resp = context
        .api
        .credentials
        .get(&resp["id"].parse::<String>())
        .await;

    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    let namespace = &resp["claims"][0];
    assert_eq!(namespace["path"], "namespace");

    let root_array = &namespace["value"][0];
    assert_eq!(root_array["path"], "namespace/root_field");

    let root_array = &namespace["value"][1];
    assert_eq!(root_array["path"], "namespace/root_array");

    let item = &root_array["value"][0];
    assert_eq!(item["path"], "namespace/root_array/0");

    let nested = &item["value"][0];
    assert_eq!(nested["path"], "namespace/root_array/0/nested");

    let nested_item = &nested["value"][0];
    assert_eq!(nested_item["path"], "namespace/root_array/0/nested/0");

    let nested_field = &nested_item["value"][0];
    assert_eq!(
        nested_field["path"],
        "namespace/root_array/0/nested/0/field"
    );
    assert_eq!(nested_field["value"], "foo");
}

#[tokio::test]
async fn test_create_credential_success_with_nested_claims() {
    // GIVEN
    let (context, organisation, did, _) = TestContext::new_with_did().await;
    let credential_schema = context
        .db
        .credential_schemas
        .create_with_nested_claims("test schema", &organisation, "NONE", Default::default())
        .await;

    let claim_schemas = credential_schema.claim_schemas.unwrap();

    let street_claim_id = claim_schemas[1].schema.id.to_owned();
    let coordinate_x_claim_id = claim_schemas[3].schema.id.to_owned();
    let coordinate_y_claim_id = claim_schemas[4].schema.id.to_owned();

    // WHEN
    let resp = context
        .api
        .credentials
        .create(
            credential_schema.id,
            "OPENID4VC",
            did.id,
            serde_json::json!([
                {
                    "claimId": street_claim_id.to_string(),
                    "value": "foo",
                    "path": "address/street"
                },
                {
                    "claimId": coordinate_x_claim_id.to_string(),
                    "value": "123",
                    "path": "address/coordinates/x"
                },
                {
                    "claimId": coordinate_y_claim_id.to_string(),
                    "value": "456",
                    "path": "address/coordinates/y"
                },
            ]),
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;

    let credential = context.db.credentials.get(&resp["id"].parse()).await;
    assert_eq!(CredentialStateEnum::Created, credential.state);
    assert_eq!(3, credential.claims.unwrap().len());
    assert_eq!("OPENID4VC", credential.exchange);
}

#[tokio::test]
async fn test_create_credential_with_issuer_key() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

    let key1 = context
        .db
        .keys
        .create(&organisation, es256_testing_params())
        .await;

    let key2 = context
        .db
        .keys
        .create(&organisation, es256_testing_params())
        .await;

    let key3 = context
        .db
        .keys
        .create(&organisation, es256_testing_params())
        .await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;

    let did = context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                keys: Some(vec![
                    RelatedKey {
                        role: KeyRole::AssertionMethod,
                        key: key1,
                    },
                    RelatedKey {
                        role: KeyRole::AssertionMethod,
                        key: key2,
                    },
                    RelatedKey {
                        role: KeyRole::AssertionMethod,
                        key: key3.clone(),
                    },
                ]),
                ..Default::default()
            },
        )
        .await;

    let claim_id = credential_schema.claim_schemas.unwrap()[0].schema.id;

    // WHEN
    let resp = context
        .api
        .credentials
        .create(
            credential_schema.id,
            "OPENID4VC",
            did.id,
            serde_json::json!([
                {
                    "claimId": claim_id.to_string(),
                    "value": "foo",
                    "path": "firstName"
                }
            ]),
            Some(key3.id),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;

    let credential = context.db.credentials.get(&resp["id"].parse()).await;
    assert_eq!(credential.key.unwrap().id, key3.id);
}

#[tokio::test]
async fn test_fail_to_create_credential_invalid_key_role() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

    let key = context
        .db
        .keys
        .create(&organisation, es256_testing_params())
        .await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;

    let did = context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::CapabilityInvocation,
                    key: key.clone(),
                }]),
                ..Default::default()
            },
        )
        .await;

    let claim_id = credential_schema.claim_schemas.unwrap()[0].schema.id;

    // WHEN
    let resp = context
        .api
        .credentials
        .create(
            credential_schema.id,
            "OPENID4VC",
            did.id,
            serde_json::json!([
                {
                    "claimId": claim_id.to_string(),
                    "value": "foo",
                    "path": "firstName"
                }
            ]),
            Some(key.id),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0096", resp.error_code().await);
}

#[tokio::test]
async fn test_fail_to_create_credential_unknown_key_id() {
    // GIVEN
    let (context, organisation, did, _) = TestContext::new_with_did().await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;
    let claim_id = credential_schema.claim_schemas.unwrap()[0].schema.id;

    // WHEN
    let resp = context
        .api
        .credentials
        .create(
            credential_schema.id,
            "OPENID4VC",
            did.id,
            serde_json::json!([
                {
                    "claimId": claim_id.to_string(),
                    "value": "foo",
                    "path": "firstName"
                }
            ]),
            KeyId::from(Uuid::new_v4()),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0096", resp.error_code().await);
}

#[tokio::test]
async fn test_create_credential_with_big_picture_success() {
    // GIVEN
    let (context, organisation, did, _) = TestContext::new_with_did().await;
    let credential_schema = context
        .db
        .credential_schemas
        .create_with_picture_claim("test", &organisation)
        .await;

    let claim_id = credential_schema.claim_schemas.unwrap()[0].schema.id;

    let data = Base64UrlSafeNoPadding::encode_to_string(vec![0; 4 * 1024 * 1024]).unwrap();

    // WHEN
    let resp = context
        .api
        .credentials
        .create(
            credential_schema.id,
            "OPENID4VC",
            did.id,
            serde_json::json!([
                {
                    "claimId": claim_id.to_string(),
                    "value": format!("data:image/png;base64,{data}"),
                    "path": "firstName"
                }
            ]),
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;

    let credential = context.db.credentials.get(&resp["id"].parse()).await;
    assert_eq!(CredentialStateEnum::Created, credential.state);
    assert_eq!(1, credential.claims.unwrap().len());
    assert_eq!("OPENID4VC", credential.exchange);
}

#[tokio::test]
async fn test_create_credential_failed_specified_object_claim() {
    // GIVEN
    let (context, organisation, did, _) = TestContext::new_with_did().await;
    let credential_schema = context
        .db
        .credential_schemas
        .create_with_nested_claims("test schema", &organisation, "NONE", Default::default())
        .await;

    let claim_schemas = credential_schema.claim_schemas.unwrap();

    let object_claim_id = claim_schemas[0].schema.id.to_owned();

    // WHEN
    let resp = context
        .api
        .credentials
        .create(
            credential_schema.id,
            "OPENID4VC",
            did.id,
            serde_json::json!([
                {
                    "claimId": object_claim_id.to_string(),
                    "value": "foo",
                    "path": "address"
                }
            ]),
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0061", resp.error_code().await);
}

#[tokio::test]
async fn test_create_credential_boolean_value_wrong() {
    // GIVEN
    let (context, organisation, did, _) = TestContext::new_with_did().await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;
    let claim_id = credential_schema.claim_schemas.clone().unwrap()[0]
        .schema
        .id;
    let claim_id1 = credential_schema.claim_schemas.unwrap()[1].schema.id;

    // WHEN
    let resp = context
        .api
        .credentials
        .create(
            credential_schema.id,
            "OPENID4VC",
            did.id,
            serde_json::json!([
                {
                    "claimId": claim_id.to_string(),
                    "value": "foo",
                    "path": "firstName"
                },
                {
                    "claimId": claim_id1.to_string(),
                    "value": "test",
                    "path": "isOver18"
                }
            ]),
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0061", resp.error_code().await);
}
