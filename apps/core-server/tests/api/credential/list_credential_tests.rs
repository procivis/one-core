use std::collections::HashSet;

use one_core::model::credential::{CredentialRole, CredentialStateEnum};
use one_core::service::credential::dto::CredentialListIncludeEntityTypeEnum;
use shared_types::CredentialId;
use uuid::Uuid;

use crate::fixtures::TestingCredentialParams;
use crate::utils::api_clients::credentials::Filters;
use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

const CLAIM_NAME: &str = "CLAIM_NAME";
const CLAIM_VALUE: &str = "CLAIM_VALUE";
const CREDENTIAL_SCHEMA_NAME: &str = "CREDENTIAL_SCHEMA_NAME";

#[tokio::test]
async fn test_get_list_credential_success() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;

    for _ in 1..15 {
        context
            .db
            .credentials
            .create(
                &credential_schema,
                CredentialStateEnum::Accepted,
                &identifier,
                "OPENID4VCI_DRAFT13",
                TestingCredentialParams::default(),
            )
            .await;
    }

    // WHEN
    let resp = context
        .api
        .credentials
        .list(0, 8, &organisation.id, None, None, None, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["totalItems"], 14);
    assert_eq!(resp["totalPages"], 2);
    assert_eq!(resp["values"].as_array().unwrap().len(), 8);
    assert!(resp["values"][0]["schema"]["layoutProperties"].is_null());
    assert_eq!(resp["values"][0]["protocol"], "OPENID4VCI_DRAFT13")
}

#[tokio::test]
async fn test_get_list_credential_deleted_credentials_are_not_returned() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;

    for _ in 1..15 {
        context
            .db
            .credentials
            .create(
                &credential_schema,
                CredentialStateEnum::Created,
                &identifier,
                "OPENID4VCI_DRAFT13",
                TestingCredentialParams::default(),
            )
            .await;
    }

    // WHEN
    let resp = context
        .api
        .credentials
        .list(0, 8, &organisation.id, None, None, None, None)
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
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
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
                    &identifier,
                    "OPENID4VCI_DRAFT13",
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
            .list(0, 10, &organisation.id, Some(role), None, None, None)
            .await;

        // THEN
        assert_eq!(resp.status(), 200);
        let credentials = resp.json_value().await;

        assert_eq!(credentials["totalItems"], number);
        assert_eq!(credentials["totalPages"], 1);
        assert_eq!(credentials["values"].as_array().unwrap().len(), number);
        assert!(
            credentials["values"]
                .as_array()
                .unwrap()
                .iter()
                .all(|credential| { credential["role"] == role })
        );
    }
}

#[tokio::test]
async fn test_fail_to_get_list_credential_filter_by_invalid_role() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credentials
        .list(0, 10, &organisation.id, Some("foo"), None, None, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_get_list_credential_filter_by_name() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema1 = context
        .db
        .credential_schemas
        .create("test 1", &organisation, "NONE", Default::default())
        .await;

    let credential_schema2 = context
        .db
        .credential_schemas
        .create("test 2", &organisation, "NONE", Default::default())
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema1,
            CredentialStateEnum::Created,
            &identifier,
            "OPENID4VCI_DRAFT13",
            Default::default(),
        )
        .await;

    context
        .db
        .credentials
        .create(
            &credential_schema2,
            CredentialStateEnum::Created,
            &identifier,
            "OPENID4VCI_DRAFT13",
            Default::default(),
        )
        .await;

    // WHEN
    let resp = context
        .api
        .credentials
        .list(
            0,
            10,
            &organisation.id,
            None,
            Some(Filters {
                name: Some("test 1".to_owned()),
                ..Default::default()
            }),
            None,
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let credentials = resp.json_value().await;

    assert_eq!(credentials["totalItems"], 1);
    assert_eq!(credentials["totalPages"], 1);
    assert_eq!(credentials["values"].as_array().unwrap().len(), 1);
    credentials["values"][0]["id"].assert_eq(&credential.id);
}

#[tokio::test]
async fn test_get_list_credential_filter_by_ids() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;

    let mut credentials = vec![];

    for _ in 1..=5 {
        let credential = context
            .db
            .credentials
            .create(
                &credential_schema,
                CredentialStateEnum::Accepted,
                &identifier,
                "OPENID4VCI_DRAFT13",
                TestingCredentialParams::default(),
            )
            .await;

        credentials.push(credential.id);
    }

    // WHEN
    let credentials = &credentials[..3];
    let resp = context
        .api
        .credentials
        .list(0, 10, &organisation.id, None, None, Some(credentials), None)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let json_resp = resp.json_value().await;

    assert_eq!(json_resp["totalItems"], 3);
    assert_eq!(json_resp["totalPages"], 1);

    let expected_credentials: HashSet<_> =
        HashSet::from_iter(credentials.iter().map(ToOwned::to_owned));

    let credentials: HashSet<CredentialId> = json_resp["values"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["id"].parse())
        .collect();

    assert_eq!(credentials.len(), 3);

    assert_eq!(expected_credentials, credentials);
}

#[tokio::test]
async fn test_get_list_credential_include_layout_properties_success() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;

    for _ in 1..15 {
        context
            .db
            .credentials
            .create(
                &credential_schema,
                CredentialStateEnum::Accepted,
                &identifier,
                "OPENID4VCI_DRAFT13",
                TestingCredentialParams::default(),
            )
            .await;
    }

    // WHEN
    let resp = context
        .api
        .credentials
        .list(
            0,
            8,
            &organisation.id,
            None,
            None,
            None,
            Some(vec![CredentialListIncludeEntityTypeEnum::LayoutProperties]),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["totalItems"], 14);
    assert_eq!(resp["totalPages"], 2);
    assert_eq!(resp["values"].as_array().unwrap().len(), 8);
    assert_eq!(
        resp["values"][0]["schema"]["layoutProperties"]["background"]["color"],
        "#DA2727"
    );
    assert_eq!(
        resp["values"][0]["schema"]["layoutProperties"]["primaryAttribute"],
        "firstName"
    );
    assert_eq!(
        resp["values"][0]["schema"]["layoutProperties"]["secondaryAttribute"],
        "firstName"
    );
    assert_eq!(
        resp["values"][0]["schema"]["layoutProperties"]["logo"]["fontColor"],
        "#DA2727"
    );
}

#[tokio::test]
async fn test_get_list_credential_filter_by_schema_name() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema1 = context
        .db
        .credential_schemas
        .create("test 1", &organisation, "NONE", Default::default())
        .await;

    let credential_schema2 = context
        .db
        .credential_schemas
        .create("test 2", &organisation, "NONE", Default::default())
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema1,
            CredentialStateEnum::Created,
            &identifier,
            "OPENID4VCI_DRAFT13",
            Default::default(),
        )
        .await;

    context
        .db
        .credentials
        .create(
            &credential_schema2,
            CredentialStateEnum::Created,
            &identifier,
            "OPENID4VCI_DRAFT13",
            Default::default(),
        )
        .await;

    // WHEN
    let resp = context
        .api
        .credentials
        .list(
            0,
            10,
            &organisation.id,
            None,
            Some(Filters {
                search_text: Some("test 1".to_owned()),
                search_type: Some(vec![CREDENTIAL_SCHEMA_NAME.into()]),
                ..Default::default()
            }),
            None,
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let credentials = resp.json_value().await;

    assert_eq!(credentials["totalItems"], 1);
    assert_eq!(credentials["totalPages"], 1);
    assert_eq!(credentials["values"].as_array().unwrap().len(), 1);
    credentials["values"][0]["id"].assert_eq(&credential.id);
}

#[tokio::test]
async fn test_get_list_credential_filter_by_claim_name() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;

    let claim_1 = Uuid::new_v4();
    let claim_2 = Uuid::new_v4();

    let credential_schema = context
        .db
        .credential_schemas
        .create_with_claims(
            &Uuid::new_v4(),
            "schema-1",
            &organisation,
            "NONE",
            &[
                (claim_1, "super-name-100", false, "STRING", false),
                (claim_2, "super-name-200", false, "STRING", false),
            ],
            "MDOC",
            "schema-id",
        )
        .await;

    let credential_schema1 = context
        .db
        .credential_schemas
        .create("test 1", &organisation, "NONE", Default::default())
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Offered,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                claims_data: Some(vec![
                    (claim_1, "super-name-100", "extra-value-11"),
                    (claim_2, "super-name-200", "extra-value-22"),
                ]),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Offered,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                claims_data: Some(vec![(claim_2, "super-name-200", "extra-value-22")]),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .credentials
        .create(
            &credential_schema1,
            CredentialStateEnum::Created,
            &identifier,
            "OPENID4VCI_DRAFT13",
            Default::default(),
        )
        .await;

    // WHEN
    let resp = context
        .api
        .credentials
        .list(
            0,
            10,
            &organisation.id,
            None,
            Some(Filters {
                search_text: Some("super-name-100".to_owned()),
                search_type: Some(vec![CLAIM_NAME.into()]),
                ..Default::default()
            }),
            None,
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let credentials = resp.json_value().await;

    assert_eq!(credentials["totalItems"], 1);
    assert_eq!(credentials["totalPages"], 1);
    assert_eq!(credentials["values"].as_array().unwrap().len(), 1);
    credentials["values"][0]["id"].assert_eq(&credential.id);
}

#[tokio::test]
async fn test_get_list_credential_filter_by_claim_value() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;

    let claim_1 = Uuid::new_v4();
    let claim_2 = Uuid::new_v4();

    let credential_schema = context
        .db
        .credential_schemas
        .create_with_claims(
            &Uuid::new_v4(),
            "schema-1",
            &organisation,
            "NONE",
            &[
                (claim_1, "super-name-100", false, "STRING", false),
                (claim_2, "super-name-200", false, "STRING", false),
            ],
            "MDOC",
            "schema-id",
        )
        .await;

    let credential_schema1 = context
        .db
        .credential_schemas
        .create("test 1", &organisation, "NONE", Default::default())
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Offered,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                claims_data: Some(vec![
                    (claim_1, "super-name-100", "extra-value-11"),
                    (claim_2, "super-name-200", "extra-value-22"),
                ]),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Offered,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                claims_data: Some(vec![(claim_2, "super-name-200", "extra-value-33")]),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .credentials
        .create(
            &credential_schema1,
            CredentialStateEnum::Created,
            &identifier,
            "OPENID4VCI_DRAFT13",
            Default::default(),
        )
        .await;

    // WHEN
    let resp = context
        .api
        .credentials
        .list(
            0,
            10,
            &organisation.id,
            None,
            Some(Filters {
                search_text: Some("extra-value-11".to_owned()),
                search_type: Some(vec![CLAIM_VALUE.into()]),
                ..Default::default()
            }),
            None,
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let credentials = resp.json_value().await;

    assert_eq!(credentials["totalItems"], 1);
    assert_eq!(credentials["totalPages"], 1);
    assert_eq!(credentials["values"].as_array().unwrap().len(), 1);
    credentials["values"][0]["id"].assert_eq(&credential.id);
}

#[tokio::test]
async fn test_get_list_credential_filter_by_everything() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;

    let claim_1 = Uuid::new_v4();
    let claim_2 = Uuid::new_v4();

    let credential_schema = context
        .db
        .credential_schemas
        .create_with_claims(
            &Uuid::new_v4(),
            "schema-1",
            &organisation,
            "NONE",
            &[
                (claim_1, "test 2", false, "STRING", false),
                (claim_2, "super-name-200", false, "STRING", false),
            ],
            "MDOC",
            "schema-id",
        )
        .await;

    let credential_schema1 = context
        .db
        .credential_schemas
        .create("test 1", &organisation, "NONE", Default::default())
        .await;

    let credential1 = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Offered,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                claims_data: Some(vec![
                    (claim_1, "test 2", "extra-value-11"),
                    (claim_2, "super-name-200", "extra-value-22"),
                ]),
                ..Default::default()
            },
        )
        .await;

    let credential2 = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Offered,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                claims_data: Some(vec![(claim_2, "super-name-200", "test 3")]),
                ..Default::default()
            },
        )
        .await;

    let credential3 = context
        .db
        .credentials
        .create(
            &credential_schema1,
            CredentialStateEnum::Created,
            &identifier,
            "OPENID4VCI_DRAFT13",
            Default::default(),
        )
        .await;

    // WHEN
    let resp = context
        .api
        .credentials
        .list(
            0,
            10,
            &organisation.id,
            None,
            Some(Filters {
                search_text: Some("test".to_owned()),
                search_type: Some(vec![
                    CLAIM_VALUE.into(),
                    CLAIM_NAME.into(),
                    CREDENTIAL_SCHEMA_NAME.into(),
                ]),
                ..Default::default()
            }),
            None,
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let credentials = resp.json_value().await;

    assert_eq!(credentials["totalItems"], 3);
    assert_eq!(credentials["totalPages"], 1);
    assert_eq!(credentials["values"].as_array().unwrap().len(), 3);
    let ids = credentials["values"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["id"].as_str().unwrap().to_owned())
        .collect::<HashSet<_>>();
    assert_eq!(
        ids,
        HashSet::from_iter([
            credential1.id.to_string(),
            credential2.id.to_string(),
            credential3.id.to_string(),
        ])
    );
}

#[tokio::test]
async fn test_fail_list_credential_both_name_and_search_text_is_present() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credentials
        .list(
            0,
            10,
            &organisation.id,
            None,
            Some(Filters {
                name: Some("foo".into()),
                search_text: Some("foo".into()),
                search_type: Some(vec![CREDENTIAL_SCHEMA_NAME.into()]),
            }),
            None,
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0084", resp.error_code().await);
}
