use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use futures::future::join_all;
use one_core::model::certificate::CertificateRole;
use one_core::model::credential::{Credential, CredentialStateEnum, CredentialType};
use one_core::model::did::{DidType, KeyRole, RelatedKey};
use one_core::model::identifier::IdentifierType;
use shared_types::CredentialId;
use similar_asserts::assert_eq;
use time::Duration;
use uuid::Uuid;

use crate::fixtures::{TestingDidParams, TestingIdentifierParams};
use crate::utils::api_clients::credential_schemas::{CreateSchemaV2Params, TestClaim};
use crate::utils::api_clients::credentials::CreateCredentialTestParams;
use crate::utils::context::TestContext;
use crate::utils::db_clients::certificates::TestingCertificateParams;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
use crate::utils::db_clients::keys::ecdsa_testing_params;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_create_credential_success() {
    // GIVEN
    let (context, organisation, did, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;
    let claim_id = credential_schema.claim_schemas.as_ref().await.unwrap()[0].id;
    let claim_id1 = credential_schema.claim_schemas.as_ref().await.unwrap()[1].id;

    // WHEN
    let resp = context
        .api
        .credentials
        .create(
            credential_schema.id,
            "OPENID4VCI_FINAL1",
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
            CreateCredentialTestParams {
                issuer_did: Some(did.id.to_string().into()),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;

    let credential = context.db.credentials.get(&resp["id"].parse()).await;
    assert!(matches!(credential, Credential::IssuerSingle { .. }));
    assert_eq!(CredentialStateEnum::Created, credential.common().state);
    assert_eq!(
        2,
        credential
            .claims()
            .unwrap()
            .as_ref()
            .await
            .unwrap()
            .to_owned()
            .len()
    );
    assert_eq!("OPENID4VCI_FINAL1", credential.common().protocol);
    assert_eq!(credential.common().profile, None);
}

#[tokio::test]
async fn test_create_credential_sets_expires_at_from_schema() {
    // GIVEN
    let (context, organisation, did, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            TestingCreateSchemaParams {
                expiration: Some(Duration::days(10)),
                ..Default::default()
            },
        )
        .await;
    let claim_id = credential_schema.claim_schemas.as_ref().await.unwrap()[0].id;

    // WHEN
    let before = one_core::clock::now_utc();
    let resp = context
        .api
        .credentials
        .create(
            credential_schema.id,
            "OPENID4VCI_FINAL1",
            serde_json::json!([
                {
                    "claimId": claim_id.to_string(),
                    "value": "foo",
                    "path": "firstName"
                }
            ]),
            CreateCredentialTestParams {
                issuer_did: Some(did.id.to_string().into()),
                ..Default::default()
            },
        )
        .await;
    let after = one_core::clock::now_utc();

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;

    let credential = context.db.credentials.get(&resp["id"].parse()).await;
    // Compare at the database timestamp's millisecond precision.
    let expires_at = credential
        .common()
        .expires_at
        .unwrap()
        .truncate_to_millisecond();
    assert!(expires_at >= (before + Duration::days(10)).truncate_to_millisecond());
    assert!(expires_at <= (after + Duration::days(10)).truncate_to_millisecond());
}

#[tokio::test]
async fn test_create_credential_no_schema_expiration_no_expiry_in_credential() {
    // GIVEN
    let (context, organisation, did, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            TestingCreateSchemaParams {
                expiration: None,
                ..Default::default()
            },
        )
        .await;
    let claim_id = credential_schema.claim_schemas.as_ref().await.unwrap()[0].id;

    // WHEN
    let resp = context
        .api
        .credentials
        .create(
            credential_schema.id,
            "OPENID4VCI_FINAL1",
            serde_json::json!([
                {
                    "claimId": claim_id.to_string(),
                    "value": "foo",
                    "path": "firstName"
                }
            ]),
            CreateCredentialTestParams {
                issuer_did: Some(did.id.to_string().into()),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;

    let credential = context.db.credentials.get(&resp["id"].parse()).await;
    assert_eq!(credential.common().expires_at, None);
}

#[tokio::test]
async fn test_create_credential_with_array_success() {
    // GIVEN
    let (context, organisation, did, ..) = TestContext::new_with_did(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create_with_array_claims("test", &organisation, Default::default())
        .await;

    let claim_id_root_field = credential_schema
        .claim_schemas
        .as_ref()
        .await
        .unwrap()
        .into_iter()
        .find(|claim| claim.key == "namespace/root_field")
        .unwrap()
        .id;

    let claim_id = credential_schema
        .claim_schemas
        .as_ref()
        .await
        .unwrap()
        .into_iter()
        .find(|claim| claim.key == "namespace/root_array/nested/field")
        .unwrap()
        .id;

    // WHEN
    let resp = context
        .api
        .credentials
        .create(
            credential_schema.id,
            "OPENID4VCI_FINAL1",
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
            CreateCredentialTestParams {
                issuer_did: Some(did.id.to_string().into()),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;

    let credential_id = resp["id"].parse::<String>();
    let resp = context.api.credentials.get(&credential_id).await;

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

    let credential = context
        .db
        .credentials
        .get(&CredentialId::from(credential_id.parse::<Uuid>().unwrap()))
        .await;
    assert_eq!(
        credential.claims().unwrap().as_ref().await.unwrap().len(),
        15
    );
    let expected_claim_paths = [
        "namespace",
        "namespace/root_field",
        "namespace/root_array",
        "namespace/root_array/0",
        "namespace/root_array/1",
        "namespace/root_array/0/nested",
        "namespace/root_array/1/nested",
        "namespace/root_array/0/nested/0",
        "namespace/root_array/0/nested/1",
        "namespace/root_array/1/nested/0",
        "namespace/root_array/1/nested/1",
        "namespace/root_array/0/nested/0/field",
        "namespace/root_array/0/nested/1/field",
        "namespace/root_array/1/nested/0/field",
        "namespace/root_array/1/nested/1/field",
    ];
    for expected_path in expected_claim_paths {
        assert!(
            credential
                .claims()
                .unwrap()
                .as_ref()
                .await
                .unwrap()
                .iter()
                .any(|claim| claim.path == expected_path)
        )
    }
}

#[tokio::test]
async fn test_fail_create_credential_claim_id_not_matching_path() {
    // GIVEN
    let (context, organisation, did, ..) = TestContext::new_with_did(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create_with_array_claims("test", &organisation, Default::default())
        .await;

    let claim_id_root_field = credential_schema
        .claim_schemas
        .as_ref()
        .await
        .unwrap()
        .into_iter()
        .find(|claim| claim.key == "namespace/root_field")
        .unwrap()
        .id;

    // WHEN
    let resp = context
        .api
        .credentials
        .create(
            credential_schema.id,
            "OPENID4VCI_FINAL1",
            serde_json::json!([
                {
                    "claimId": claim_id_root_field.to_string(),
                    "value": "foo",
                    "path": "namespace/root_array/0/nested/0/field"
                }
            ]),
            CreateCredentialTestParams {
                issuer_did: Some(did.id.to_string().into()),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0485", resp.error_code().await);
}

#[tokio::test]
async fn test_create_credential_success_with_nested_claims() {
    // GIVEN
    let (context, organisation, did, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create_with_nested_claims("test schema", &organisation, Default::default())
        .await;

    let claim_schemas = credential_schema.claim_schemas.as_ref().await.unwrap();

    let street_claim_id = claim_schemas[1].id.to_owned();
    let coordinate_x_claim_id = claim_schemas[3].id.to_owned();
    let coordinate_y_claim_id = claim_schemas[4].id.to_owned();

    // WHEN
    let resp = context
        .api
        .credentials
        .create(
            credential_schema.id,
            "OPENID4VCI_FINAL1",
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
            CreateCredentialTestParams {
                issuer_did: Some(did.id.to_string().into()),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;

    let credential = context.db.credentials.get(&resp["id"].parse()).await;
    assert_eq!(CredentialStateEnum::Created, credential.common().state);
    assert_eq!(
        5,
        credential
            .claims()
            .unwrap()
            .as_ref()
            .await
            .unwrap()
            .to_owned()
            .len()
    );
    assert_eq!("OPENID4VCI_FINAL1", credential.common().protocol);
}

#[tokio::test]
async fn test_create_credential_with_issuer_key() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let key1 = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;

    let key2 = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;

    let key3 = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;

    let did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                keys: Some(vec![
                    RelatedKey {
                        role: KeyRole::AssertionMethod,
                        key: key1,
                        reference: "1".to_string(),
                    },
                    RelatedKey {
                        role: KeyRole::AssertionMethod,
                        key: key2,
                        reference: "2".to_string(),
                    },
                    RelatedKey {
                        role: KeyRole::AssertionMethod,
                        key: key3.clone(),
                        reference: "3".to_string(),
                    },
                ]),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let claim_id = credential_schema.claim_schemas.as_ref().await.unwrap()[0].id;

    // WHEN
    let resp = context
        .api
        .credentials
        .create(
            credential_schema.id,
            "OPENID4VCI_FINAL1",
            serde_json::json!([
                {
                    "claimId": claim_id.to_string(),
                    "value": "foo",
                    "path": "firstName"
                }
            ]),
            CreateCredentialTestParams {
                issuer_did: Some(did.id.to_string().into()),
                issuer_key: Some(key3.id.to_string().into()),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;

    let credential = context.db.credentials.get(&resp["id"].parse()).await;
    assert_eq!(credential.key().as_ref().unwrap().id(), key3.id);
}

#[tokio::test]
async fn test_fail_to_create_credential_invalid_key_role() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;

    let did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::CapabilityInvocation,
                    key: key.clone(),
                    reference: "1".to_string(),
                }]),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let claim_id = credential_schema.claim_schemas.as_ref().await.unwrap()[0].id;

    // WHEN
    let resp = context
        .api
        .credentials
        .create(
            credential_schema.id,
            "OPENID4VCI_FINAL1",
            serde_json::json!([
                {
                    "claimId": claim_id.to_string(),
                    "value": "foo",
                    "path": "firstName"
                }
            ]),
            CreateCredentialTestParams {
                issuer_did: Some(did.id.to_string().into()),
                issuer_key: Some(key.id.to_string().into()),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0330");
}

#[tokio::test]
async fn test_fail_to_create_credential_unknown_key_id() {
    // GIVEN
    let (context, organisation, did, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;
    let claim_id = credential_schema.claim_schemas.as_ref().await.unwrap()[0].id;

    // WHEN
    let resp = context
        .api
        .credentials
        .create(
            credential_schema.id,
            "OPENID4VCI_FINAL1",
            serde_json::json!([
                {
                    "claimId": claim_id.to_string(),
                    "value": "foo",
                    "path": "firstName"
                }
            ]),
            CreateCredentialTestParams {
                issuer_did: Some(did.id.to_string().into()),
                issuer_key: Some(Uuid::new_v4().to_string().into()),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0330");
}

#[tokio::test]
async fn test_create_credential_with_certificate_identifier() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;

    let identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                r#type: Some(IdentifierType::Certificate),
                ..Default::default()
            },
        )
        .await;

    let certificate = context
        .db
        .certificates
        .create(
            identifier.id,
            organisation.clone(),
            TestingCertificateParams {
                key: Some(key.clone()),
                roles: Some(vec![CertificateRole::AssertionMethod]),
                ..Default::default()
            },
        )
        .await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;

    let claim_id = credential_schema.claim_schemas.as_ref().await.unwrap()[0].id;

    // WHEN
    let resp = context
        .api
        .credentials
        .create(
            credential_schema.id,
            "OPENID4VCI_FINAL1",
            serde_json::json!([
                {
                    "claimId": claim_id.to_string(),
                    "value": "foo",
                    "path": "firstName"
                }
            ]),
            CreateCredentialTestParams {
                issuer: Some(identifier.id.to_string().into()),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;

    let credential = context.db.credentials.get(&resp["id"].parse()).await;
    assert_eq!(
        credential.issuer_certificate().as_ref().unwrap().id(),
        certificate.id
    );
    assert_eq!(credential.key().as_ref().unwrap().id(), key.id);
}

#[tokio::test]
async fn test_create_credential_with_certificate_selection() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;
    let key2 = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;

    let identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                r#type: Some(IdentifierType::Certificate),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .certificates
        .create(
            identifier.id,
            organisation.clone(),
            TestingCertificateParams {
                key: Some(key2),
                roles: Some(vec![CertificateRole::AssertionMethod]),
                ..Default::default()
            },
        )
        .await;

    let certificate = context
        .db
        .certificates
        .create(
            identifier.id,
            organisation.clone(),
            TestingCertificateParams {
                key: Some(key.clone()),
                roles: Some(vec![CertificateRole::AssertionMethod]),
                ..Default::default()
            },
        )
        .await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;

    let claim_id = credential_schema.claim_schemas.as_ref().await.unwrap()[0].id;

    // WHEN
    let resp = context
        .api
        .credentials
        .create(
            credential_schema.id,
            "OPENID4VCI_FINAL1",
            serde_json::json!([
                {
                    "claimId": claim_id.to_string(),
                    "value": "foo",
                    "path": "firstName"
                }
            ]),
            CreateCredentialTestParams {
                issuer: Some(identifier.id.to_string().into()),
                issuer_certificate: Some(certificate.id.to_string().into()),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;

    let credential = context.db.credentials.get(&resp["id"].parse()).await;
    assert_eq!(
        credential.issuer_certificate().as_ref().unwrap().id(),
        certificate.id
    );
    assert_eq!(credential.key().as_ref().unwrap().id(), key.id);
}

#[tokio::test]
async fn test_create_credential_with_invalid_certificate_id() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;

    let identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                r#type: Some(IdentifierType::Certificate),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .certificates
        .create(
            identifier.id,
            organisation.clone(),
            TestingCertificateParams {
                key: Some(key.clone()),
                ..Default::default()
            },
        )
        .await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;

    let claim_id = credential_schema.claim_schemas.as_ref().await.unwrap()[0].id;

    // WHEN
    let resp = context
        .api
        .credentials
        .create(
            credential_schema.id,
            "OPENID4VCI_FINAL1",
            serde_json::json!([
                {
                    "claimId": claim_id.to_string(),
                    "value": "foo",
                    "path": "firstName"
                }
            ]),
            CreateCredentialTestParams {
                issuer: Some(identifier.id.to_string().into()),
                issuer_certificate: Some(Uuid::new_v4().to_string().into()),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0330")
}

#[tokio::test]
async fn test_create_credential_fail_with_only_certificate_id() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;

    let identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                r#type: Some(IdentifierType::Certificate),
                ..Default::default()
            },
        )
        .await;

    let certificate = context
        .db
        .certificates
        .create(
            identifier.id,
            organisation.clone(),
            TestingCertificateParams {
                key: Some(key.clone()),
                ..Default::default()
            },
        )
        .await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;

    let claim_id = credential_schema.claim_schemas.as_ref().await.unwrap()[0].id;

    // WHEN
    let resp = context
        .api
        .credentials
        .create(
            credential_schema.id,
            "OPENID4VCI_FINAL1",
            serde_json::json!([
                {
                    "claimId": claim_id.to_string(),
                    "value": "foo",
                    "path": "firstName"
                }
            ]),
            CreateCredentialTestParams {
                issuer_certificate: Some(certificate.id.to_string().into()),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0323")
}

#[tokio::test]
async fn test_create_credential_with_big_picture_success() {
    // GIVEN
    let (context, organisation, did, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create_with_picture_claim("test", &organisation)
        .await;

    let claim_id = credential_schema.claim_schemas.as_ref().await.unwrap()[0].id;

    let data = Base64UrlSafeNoPadding::encode_to_string(vec![0; 4 * 1024 * 1024]).unwrap();

    // WHEN
    let resp = context
        .api
        .credentials
        .create(
            credential_schema.id,
            "OPENID4VCI_FINAL1",
            serde_json::json!([
                {
                    "claimId": claim_id.to_string(),
                    "value": format!("data:image/png;base64,{data}"),
                    "path": "firstName"
                }
            ]),
            CreateCredentialTestParams {
                issuer_did: Some(did.id.to_string().into()),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;

    let credential = context.db.credentials.get(&resp["id"].parse()).await;
    assert_eq!(CredentialStateEnum::Created, credential.common().state);
    assert_eq!(
        1,
        credential
            .claims()
            .unwrap()
            .as_ref()
            .await
            .unwrap()
            .to_owned()
            .len()
    );
    assert_eq!("OPENID4VCI_FINAL1", credential.common().protocol);
}

#[tokio::test]
async fn test_create_credential_oversized_body_returns_413() {
    let context = TestContext::new(Some(
        indoc::indoc! {"
            app:
                maxLargeRequestBodyBytes: 1024
        "}
        .to_string(),
    ))
    .await;

    let resp = context
        .api
        .client
        .post(
            "/api/credential/v1",
            serde_json::json!({
                "payload": "x".repeat(2048)
            }),
        )
        .await;

    assert_eq!(resp.status(), 413);
}

#[tokio::test]
async fn test_create_credential_failed_specified_object_claim() {
    // GIVEN
    let (context, organisation, did, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create_with_nested_claims("test schema", &organisation, Default::default())
        .await;

    let claim_schemas = credential_schema.claim_schemas.as_ref().await.unwrap();

    let object_claim_id = claim_schemas[0].id.to_owned();

    // WHEN
    let resp = context
        .api
        .credentials
        .create(
            credential_schema.id,
            "OPENID4VCI_FINAL1",
            serde_json::json!([
                {
                    "claimId": object_claim_id.to_string(),
                    "value": "foo",
                    "path": "address"
                }
            ]),
            CreateCredentialTestParams {
                issuer_did: Some(did.id.to_string().into()),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0061", resp.error_code().await);
}

#[tokio::test]
async fn test_create_credential_boolean_value_wrong() {
    // GIVEN
    let (context, organisation, did, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;
    let claim_id = credential_schema.claim_schemas.as_ref().await.unwrap()[0].id;
    let claim_id1 = credential_schema.claim_schemas.as_ref().await.unwrap()[1].id;

    // WHEN
    let resp = context
        .api
        .credentials
        .create(
            credential_schema.id,
            "OPENID4VCI_FINAL1",
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
            CreateCredentialTestParams {
                issuer_did: Some(did.id.to_string().into()),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0061", resp.error_code().await);
}

#[tokio::test]
async fn test_fail_create_credential_with_empty_value() {
    // GIVEN
    let (context, organisation, did, ..) = TestContext::new_with_did(None).await;

    let claim_id = Uuid::new_v4();

    let new_claim_schema = (claim_id, "root", true, "STRING", false);

    let credential_schema = context
        .db
        .credential_schemas
        .create_with_claims(
            &Uuid::new_v4(),
            "schema-1",
            &organisation,
            &[new_claim_schema],
            "JWT",
            "schema-id",
        )
        .await;

    // WHEN
    let resp_empty_value = context
        .api
        .credentials
        .create(
            credential_schema.id,
            "OPENID4VCI_FINAL1",
            serde_json::json!([{
                "claimId": claim_id.to_string(),
                "value": "",
                "path": "root"
            }]),
            CreateCredentialTestParams {
                issuer_did: Some(did.id.to_string().into()),
                ..Default::default()
            },
        )
        .await;

    let resp_absent_value = context
        .api
        .credentials
        .create(
            credential_schema.id,
            "OPENID4VCI_FINAL1",
            serde_json::json!([{
                "claimId": claim_id.to_string(),
                "path": "root"
            }]),
            CreateCredentialTestParams {
                issuer_did: Some(did.id.to_string().into()),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp_empty_value.status(), 400);
    assert_eq!("BR_0204", resp_empty_value.error_code().await);

    assert_eq!(resp_absent_value.status(), 400);
    assert_eq!("BR_0204", resp_absent_value.error_code().await);
}

#[tokio::test]
async fn test_fail_create_credential_with_empty_array_value() {
    // GIVEN
    let (context, organisation, did, ..) = TestContext::new_with_did(None).await;

    let str_array_claim_id = Uuid::new_v4();
    let new_claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> = vec![
        (Uuid::new_v4(), "root", true, "OBJECT", false),
        (str_array_claim_id, "root/str_array", true, "STRING", true),
    ];

    let credential_schema = context
        .db
        .credential_schemas
        .create_with_claims(
            &Uuid::new_v4(),
            "schema-1",
            &organisation,
            &new_claim_schemas,
            "JWT",
            "schema-id",
        )
        .await;

    // WHEN
    let resp_empty_value = context
        .api
        .credentials
        .create(
            credential_schema.id,
            "OPENID4VCI_FINAL1",
            serde_json::json!([
                {
                    "claimId": str_array_claim_id.to_string(),
                    "value": "",
                    "path": "root/str_array/0"
                },
                {
                    "claimId": str_array_claim_id.to_string(),
                    "value": "present",
                    "path": "root/str_array/1"
                }
            ]),
            CreateCredentialTestParams {
                issuer_did: Some(did.id.to_string().into()),
                ..Default::default()
            },
        )
        .await;

    let resp_absent_value = context
        .api
        .credentials
        .create(
            credential_schema.id,
            "OPENID4VCI_FINAL1",
            serde_json::json!([
                {
                    "claimId": str_array_claim_id.to_string(),
                    "path": "root/str_array/0"
                },
                {
                    "claimId": str_array_claim_id.to_string(),
                    "value": "present",
                    "path": "root/str_array/1"
                }
            ]),
            CreateCredentialTestParams {
                issuer_did: Some(did.id.to_string().into()),
                ..Default::default()
            },
        )
        .await;
    // THEN
    assert_eq!(resp_empty_value.status(), 400);
    assert_eq!("BR_0195", resp_empty_value.error_code().await);

    assert_eq!(resp_absent_value.status(), 400);
    assert_eq!("BR_0195", resp_absent_value.error_code().await);
}

#[tokio::test]
async fn test_fail_create_credential_with_empty_object_value() {
    // GIVEN
    let (context, organisation, did, ..) = TestContext::new_with_did(None).await;

    let name_claim_id = Uuid::new_v4();
    let nested_object_claim_id = Uuid::new_v4();
    let nested_object_name_claim_id = Uuid::new_v4();

    let new_claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> = vec![
        (Uuid::new_v4(), "root", true, "OBJECT", false),
        (name_claim_id, "root/name", false, "STRING", false),
        (
            nested_object_claim_id,
            "root/nested",
            false,
            "OBJECT",
            false,
        ),
        (
            nested_object_name_claim_id,
            "root/nested/name",
            false,
            "STRING",
            false,
        ),
    ];

    let credential_schema = context
        .db
        .credential_schemas
        .create_with_claims(
            &Uuid::new_v4(),
            "schema-1",
            &organisation,
            &new_claim_schemas,
            "JWT",
            "schema-id",
        )
        .await;

    // WHEN
    let resp_empty_value = context
        .api
        .credentials
        .create(
            credential_schema.id,
            "OPENID4VCI_FINAL1",
            serde_json::json!([
                {
                    "claimId": name_claim_id.to_string(),
                    "value": "",
                    "path": "root/name"
                }
            ]),
            CreateCredentialTestParams {
                issuer_did: Some(did.id.to_string().into()),
                ..Default::default()
            },
        )
        .await;

    let resp_absent_value = context
        .api
        .credentials
        .create(
            credential_schema.id,
            "OPENID4VCI_FINAL1",
            serde_json::json!([
                {
                    "claimId": name_claim_id.to_string(),
                    "path": "root/name"
                }
            ]),
            CreateCredentialTestParams {
                issuer_did: Some(did.id.to_string().into()),
                ..Default::default()
            },
        )
        .await;

    let resp_nested_empty_value = context
        .api
        .credentials
        .create(
            credential_schema.id,
            "OPENID4VCI_FINAL1",
            serde_json::json!([
                {
                    "claimId": nested_object_name_claim_id.to_string(),
                    "value": "",
                    "path": "root/nested/name"
                }
            ]),
            CreateCredentialTestParams {
                issuer_did: Some(did.id.to_string().into()),
                ..Default::default()
            },
        )
        .await;

    let resp_nested_absent_value = context
        .api
        .credentials
        .create(
            credential_schema.id,
            "OPENID4VCI_FINAL1",
            serde_json::json!([
                {
                    "claimId": nested_object_name_claim_id.to_string(),
                    "path": "root/nested/name"
                }
            ]),
            CreateCredentialTestParams {
                issuer_did: Some(did.id.to_string().into()),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp_empty_value.status(), 400);
    assert_eq!("BR_0194", resp_empty_value.error_code().await);

    assert_eq!(resp_absent_value.status(), 400);
    assert_eq!("BR_0194", resp_absent_value.error_code().await);

    assert_eq!(resp_nested_empty_value.status(), 400);
    assert_eq!("BR_0194", resp_nested_empty_value.error_code().await);

    assert_eq!(resp_nested_absent_value.status(), 400);
    assert_eq!("BR_0194", resp_nested_absent_value.error_code().await);
}

#[tokio::test]
async fn test_create_credential_success_with_profile() {
    // GIVEN
    let (context, organisation, did, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;
    let claim_id = credential_schema.claim_schemas.as_ref().await.unwrap()[0].id;
    let claim_id1 = credential_schema.claim_schemas.as_ref().await.unwrap()[1].id;

    let test_profile = "test-credential-profile-789";

    // WHEN
    let resp = context
        .api
        .credentials
        .create(
            credential_schema.id,
            "OPENID4VCI_FINAL1",
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
            CreateCredentialTestParams {
                issuer_did: Some(did.id.to_string().into()),
                profile: Some(test_profile),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;

    let credential = context.db.credentials.get(&resp["id"].parse()).await;
    assert_eq!(CredentialStateEnum::Created, credential.common().state);
    assert_eq!(
        2,
        credential
            .claims()
            .unwrap()
            .as_ref()
            .await
            .unwrap()
            .to_owned()
            .len()
    );
    assert_eq!("OPENID4VCI_FINAL1", credential.common().protocol);

    // Verify the profile is correctly stored
    assert_eq!(credential.common().profile.as_ref().unwrap(), test_profile);
}

#[tokio::test]
async fn test_create_credential_success_with_webhook_url() {
    // GIVEN
    let (context, organisation, did, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;
    let claim_id = credential_schema.claim_schemas.as_ref().await.unwrap()[0].id;
    let claim_id1 = credential_schema.claim_schemas.as_ref().await.unwrap()[1].id;

    let webhook_url = "https://webhook.url";

    // WHEN
    let resp = context
        .api
        .credentials
        .create(
            credential_schema.id,
            "OPENID4VCI_FINAL1",
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
            CreateCredentialTestParams {
                issuer_did: Some(did.id.to_string().into()),
                webhook_destination_url: Some(webhook_url),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;

    let credential = context.db.credentials.get(&resp["id"].parse()).await;
    assert_eq!(credential.webhook_url().as_deref().unwrap(), webhook_url);
}

#[tokio::test]
async fn test_create_credential_success_with_multiformat_schema() {
    // GIVEN
    let (context, organisation, did, ..) = TestContext::new_with_did(None).await;

    let flat_claims = vec![TestClaim {
        datatype: "STRING".to_string(),
        key: "firstName".to_string(),
        required: true,
        claims: vec![],
        array: None,
        translations: None,
        mappings: None,
    }];
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "multiformat schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![
                serde_json::json!({ "format": "JWT" }),
                serde_json::json!({ "format": "SD_JWT" }),
            ],
            claims: flat_claims,
            ..Default::default()
        })
        .await;
    assert_eq!(resp.status(), 201);
    let credential_schema_id = resp.json_value().await["id"].parse();
    let credential_schema = context
        .db
        .credential_schemas
        .get(&credential_schema_id)
        .await;
    let claim_id = credential_schema.claim_schemas.as_ref().await.unwrap()[0].id;

    // WHEN
    let resp = context
        .api
        .credentials
        .create(
            credential_schema.id,
            "OPENID4VCI_FINAL1",
            serde_json::json!([
                {
                    "claimId": claim_id.to_string(),
                    "value": "foo",
                    "path": "firstName"
                }
            ]),
            CreateCredentialTestParams {
                issuer_did: Some(did.id.to_string().into()),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;

    let credential = context.db.credentials.get(&resp["id"].parse()).await;
    assert!(matches!(credential, Credential::IssuerBatchParent { .. }));
    assert_eq!(credential.r#type(), CredentialType::BatchParent);
    assert!(credential.format().is_none());
}

#[tokio::test]
async fn test_create_credential_success_with_format_selection() {
    // GIVEN
    let (context, organisation, did, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;
    let claim_id = credential_schema.claim_schemas.as_ref().await.unwrap()[0].id;
    let claim_id1 = credential_schema.claim_schemas.as_ref().await.unwrap()[1].id;

    let format = credential_schema
        .formats
        .as_ref()
        .await
        .unwrap()
        .first()
        .unwrap()
        .format
        .to_owned();

    // WHEN
    let resp = context
        .api
        .credentials
        .create(
            credential_schema.id,
            "OPENID4VCI_FINAL1",
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
            CreateCredentialTestParams {
                issuer_did: Some(did.id.to_string().into()),
                formats: Some(vec![format.clone()]),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;

    let credential = context.db.credentials.get(&resp["id"].parse()).await;
    assert_eq!(
        credential.format().unwrap().as_ref().await.unwrap().format,
        format
    );
}

#[tokio::test]
async fn test_create_credential_failed_wrong_format_selection() {
    // GIVEN
    let (context, organisation, did, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            TestingCreateSchemaParams {
                format: Some("JWT".into()),
                ..Default::default()
            },
        )
        .await;
    let claim_id = credential_schema.claim_schemas.as_ref().await.unwrap()[0].id;
    let claim_id1 = credential_schema.claim_schemas.as_ref().await.unwrap()[1].id;

    // WHEN
    let resp = context
        .api
        .credentials
        .create(
            credential_schema.id,
            "OPENID4VCI_FINAL1",
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
            CreateCredentialTestParams {
                issuer_did: Some(did.id.to_string().into()),
                formats: Some(vec!["MDOC".into()]),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0482", resp.error_code().await);
}

#[tokio::test]
async fn test_create_credential_parallel_no_deadlock() {
    // GIVEN
    let (context, organisation, did, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;
    let claim_id = credential_schema.claim_schemas.as_ref().await.unwrap()[0].id;
    let claim_id1 = credential_schema.claim_schemas.as_ref().await.unwrap()[1].id;
    let issuer_did = did.id.to_string();

    // WHEN — fire many concurrent creates that share the same schema, issuer
    // identifier and key. Without READ COMMITTED on the insert transaction this
    // triggers InnoDB gap-lock deadlocks (1213/40001) on MySQL. See ONE-7015.
    let requests = (0..10).map(|_| {
        context.api.credentials.create(
            credential_schema.id,
            "OPENID4VCI_FINAL1",
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
            CreateCredentialTestParams {
                issuer_did: Some(issuer_did.clone().into()),
                ..Default::default()
            },
        )
    });
    let responses = join_all(requests).await;

    // THEN
    assert!(responses.iter().all(|resp| resp.status() == 201));
}
