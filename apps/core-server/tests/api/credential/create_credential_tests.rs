use one_core::model::credential::CredentialStateEnum;
use one_core::model::did::{KeyRole, RelatedKey};
use shared_types::KeyId;
use uuid::Uuid;

use crate::fixtures::TestingDidParams;
use crate::utils::field_match::FieldHelpers;
use crate::utils::{context::TestContext, db_clients::keys::es256_testing_params};
use ct_codecs::{Base64UrlSafeNoPadding, Encoder};

#[tokio::test]
async fn test_create_credential_success() {
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
            claim_id,
            "foo",
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;

    let credential = context.db.credentials.get(&resp["id"].parse()).await;
    assert_eq!(
        CredentialStateEnum::Created,
        credential.state.unwrap()[0].state
    );
    assert_eq!(1, credential.claims.unwrap().len());
    assert_eq!("OPENID4VC", credential.transport);
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
            claim_id,
            "foo",
            key3.id,
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
            claim_id,
            "foo",
            key.id,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    let resp = resp.json_value().await;
    assert_eq!(resp["code"], "BR_0096");
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
            claim_id,
            "foo",
            KeyId::from(Uuid::new_v4()),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    let resp = resp.json_value().await;
    assert_eq!(resp["code"], "BR_0096");
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
            claim_id,
            format!("data:image/png;base64,{data}"),
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;

    let credential = context.db.credentials.get(&resp["id"].parse()).await;
    assert_eq!(
        CredentialStateEnum::Created,
        credential.state.unwrap()[0].state
    );
    assert_eq!(1, credential.claims.unwrap().len());
    assert_eq!("OPENID4VC", credential.transport);
}
