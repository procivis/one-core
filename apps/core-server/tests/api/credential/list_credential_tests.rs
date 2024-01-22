use one_core::model::credential::{CredentialRole, CredentialStateEnum};
use time::OffsetDateTime;

use crate::fixtures::TestingCredentialParams;
use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_get_list_credential_success() {
    // GIVEN
    let (context, organisation, did) = TestContext::new_with_did().await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE")
        .await;

    for _ in 1..15 {
        context
            .db
            .credentials
            .create(
                &credential_schema,
                CredentialStateEnum::Accepted,
                &did,
                "PROCIVIS_TEMPORARY",
                TestingCredentialParams::default(),
            )
            .await;
    }

    // WHEN
    let resp = context
        .api
        .credentials
        .list(0, 8, &organisation.id, None, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["totalItems"], 14);
    assert_eq!(resp["totalPages"], 2);
    assert_eq!(resp["values"].as_array().unwrap().len(), 8);
}

#[tokio::test]
async fn test_get_list_credential_deleted_credentials_are_not_returned() {
    // GIVEN
    let (context, organisation, did) = TestContext::new_with_did().await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE")
        .await;

    for _ in 1..15 {
        context
            .db
            .credentials
            .create(
                &credential_schema,
                CredentialStateEnum::Created,
                &did,
                "PROCIVIS_TEMPORARY",
                TestingCredentialParams::default(),
            )
            .await;
    }

    context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Created,
            &did,
            "PROCIVIS_TEMPORARY",
            TestingCredentialParams {
                deleted_at: Some(OffsetDateTime::now_utc()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .credentials
        .list(0, 8, &organisation.id, None, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["totalItems"], 14);
    assert_eq!(resp["totalPages"], 2);
    assert_eq!(resp["values"].as_array().unwrap().len(), 8);
}

#[tokio::test]
async fn test_get_list_credential_filter_by_role() {
    // GIVEN
    let (context, organisation, did) = TestContext::new_with_did().await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE")
        .await;

    for (number, role, role_enum) in [
        (2, "HOLDER", CredentialRole::Holder),
        (3, "ISSUER", CredentialRole::Issuer),
        (4, "VERIFIER", CredentialRole::Verifier),
    ] {
        for _ in 0..number {
            context
                .db
                .credentials
                .create(
                    &credential_schema,
                    CredentialStateEnum::Created,
                    &did,
                    "PROCIVIS_TEMPORARY",
                    TestingCredentialParams {
                        role: Some(role_enum.clone()),
                        ..Default::default()
                    },
                )
                .await;
        }

        // WHEN
        let resp = context
            .api
            .credentials
            .list(0, 10, &organisation.id, Some(role), None)
            .await;

        // THEN
        assert_eq!(resp.status(), 200);
        let credentials = resp.json_value().await;

        assert_eq!(credentials["totalItems"], number);
        assert_eq!(credentials["totalPages"], 1);
        assert_eq!(credentials["values"].as_array().unwrap().len(), number);
        assert!(credentials["values"]
            .as_array()
            .unwrap()
            .iter()
            .all(|credential| { credential["role"] == role }));
    }
}

#[tokio::test]
async fn test_fail_to_get_list_credential_filter_by_invalid_role() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

    // WHEN
    let resp = context
        .api
        .credentials
        .list(0, 10, &organisation.id, Some("foo"), None)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_get_list_credential_filter_by_name() {
    // GIVEN
    let (context, organisation, did) = TestContext::new_with_did().await;
    let credential_schema1 = context
        .db
        .credential_schemas
        .create("test 1", &organisation, "NONE")
        .await;

    let credential_schema2 = context
        .db
        .credential_schemas
        .create("test 2", &organisation, "NONE")
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema1,
            CredentialStateEnum::Created,
            &did,
            "PROCIVIS_TEMPORARY",
            Default::default(),
        )
        .await;

    context
        .db
        .credentials
        .create(
            &credential_schema2,
            CredentialStateEnum::Created,
            &did,
            "PROCIVIS_TEMPORARY",
            Default::default(),
        )
        .await;

    // WHEN
    let resp = context
        .api
        .credentials
        .list(0, 10, &organisation.id, None, Some("test 1"))
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let credentials = resp.json_value().await;

    assert_eq!(credentials["totalItems"], 1);
    assert_eq!(credentials["totalPages"], 1);
    assert_eq!(credentials["values"].as_array().unwrap().len(), 1);
    credentials["values"][0]["id"].assert_eq(&credential.id);
}
