use one_core::model::claim_schema::ClaimSchema;
use one_core::model::credential::{CredentialStateEnum, CredentialType};
use one_core::model::did::DidType;
use one_core::model::interaction::InteractionType;
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::ecdsa::Ecdsa;
use serde_json::json;
use shared_types::{CredentialId, DidValue};
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::fixtures::interaction::{
    ConfigurationParams, InteractionDataParams, dummy_interaction_data,
};
use crate::fixtures::{TestingCredentialParams, TestingDidParams};
use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
use crate::utils::db_clients::interactions::TestingInteractionParams;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_issuance_reject_subset_of_multi_format_offer() {
    // GIVEN
    let (context, organisation, _, identifier, key) = TestContext::new_with_did(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;
    let notification_endpoint = format!(
        "{}/ssi/openid4vci/final-1.0/{}/notification",
        context.server_mock.uri(),
        credential_schema.id
    );

    let first_credential_id = Uuid::new_v4().into();
    let second_credential_id = Uuid::new_v4().into();
    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams {
            notification_endpoint: Some(notification_endpoint),
            notification_id: Some("first".to_string()),
            additional_configurations: vec![ConfigurationParams {
                credential_configuration_id: "second".to_string(),
                format: "jwt_vc_json".to_string(),
                notification_id: Some("second".to_string()),
                credential_id: Some(second_credential_id),
            }],
            ..Default::default()
        },
    );
    let interaction = context
        .db
        .interactions
        .create(
            &organisation,
            InteractionType::Issuance,
            TestingInteractionParams {
                data: Some(interaction_data),
                ..Default::default()
            },
        )
        .await;
    for credential_id in [first_credential_id, second_credential_id] {
        context
            .db
            .credentials
            .create(
                &credential_schema,
                CredentialStateEnum::Accepted,
                &identifier,
                "OPENID4VCI_FINAL1",
                TestingCredentialParams {
                    id: Some(credential_id),
                    interaction: Some(interaction.to_owned()),
                    key: Some(key.clone()),
                    ..Default::default()
                },
            )
            .await;
    }

    context
        .server_mock
        .ssi_notification_endpoint(credential_schema.id, "second", "123", 1)
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_reject(interaction.id, Some(vec![second_credential_id]))
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
    let first = context.db.credentials.get(&first_credential_id).await;
    assert_eq!(CredentialStateEnum::Accepted, first.common().state);
    let second = context.db.credentials.get(&second_credential_id).await;
    assert_eq!(CredentialStateEnum::Rejected, second.common().state);
}

#[tokio::test]
async fn test_issuance_reject_batch_parent_rejects_its_items() {
    check_reject_batch_parent(false).await;
}

#[tokio::test]
async fn test_issuance_reject_batch_parent_and_item() {
    check_reject_batch_parent(true).await;
}

async fn check_reject_batch_parent(include_item: bool) {
    // GIVEN an accepted batch parent with two items
    let (context, organisation, _, identifier, key) = TestContext::new_with_did(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;
    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams {
            batch_size: Some(2),
            ..Default::default()
        },
    );
    let interaction = context
        .db
        .interactions
        .create(
            &organisation,
            InteractionType::Issuance,
            TestingInteractionParams {
                data: Some(interaction_data),
                ..Default::default()
            },
        )
        .await;
    let parent = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams {
                r#type: Some(CredentialType::BatchParent),
                interaction: Some(interaction.to_owned()),
                key: Some(key.clone()),
                ..Default::default()
            },
        )
        .await;
    let item_ids = [Uuid::new_v4().into(), Uuid::new_v4().into()];
    for item_id in item_ids {
        context
            .db
            .credentials
            .create(
                &credential_schema,
                CredentialStateEnum::Accepted,
                &identifier,
                "OPENID4VCI_FINAL1",
                TestingCredentialParams {
                    id: Some(item_id),
                    r#type: Some(CredentialType::BatchItem),
                    parent_id: Some(parent.common().id),
                    key: Some(key.clone()),
                    ..Default::default()
                },
            )
            .await;
    }

    // WHEN
    let mut selected = vec![parent.common().id];
    if include_item {
        selected.push(item_ids[0]);
    }
    let resp = context
        .api
        .interactions
        .issuance_reject(interaction.id, Some(selected))
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
    let parent = context.db.credentials.get(&parent.common().id).await;
    assert_eq!(CredentialStateEnum::Rejected, parent.common().state);
    for item_id in item_ids {
        let item = context.db.credentials.get(&item_id).await;
        assert_eq!(CredentialStateEnum::Rejected, item.common().state);
    }
}

#[tokio::test]
async fn test_issuance_reject_openid4vci_notification_not_supported_by_issuer() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;

    let interaction_data = dummy_interaction_data(&context, &credential_schema, Default::default());
    let interaction = context
        .db
        .interactions
        .create(
            &organisation,
            InteractionType::Issuance,
            TestingInteractionParams {
                data: Some(interaction_data),
                ..Default::default()
            },
        )
        .await;
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams {
                interaction: Some(interaction.to_owned()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_reject(interaction.id, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
    let credential = context.db.credentials.get(&credential.common().id).await;
    assert_eq!(CredentialStateEnum::Rejected, credential.common().state);
}

#[tokio::test]
async fn test_issuance_reject_openid4vci_with_notification() {
    // GIVEN
    let (context, organisation, _, identifier, key) = TestContext::new_with_did(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams {
            notification_endpoint: Some(format!(
                "{}/ssi/openid4vci/final-1.0/{}/notification",
                context.server_mock.uri(),
                credential_schema.id
            )),
            notification_id: Some("notification_id".to_string()),
            ..Default::default()
        },
    );
    let interaction = context
        .db
        .interactions
        .create(
            &organisation,
            InteractionType::Issuance,
            TestingInteractionParams {
                data: Some(interaction_data),
                ..Default::default()
            },
        )
        .await;
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams {
                interaction: Some(interaction.to_owned()),
                key: Some(key),
                ..Default::default()
            },
        )
        .await;

    context
        .server_mock
        .ssi_notification_endpoint(credential_schema.id, "notification_id", "123", 1)
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_reject(interaction.id, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
    let credential = context.db.credentials.get(&credential.common().id).await;
    assert_eq!(CredentialStateEnum::Rejected, credential.common().state);
}

#[tokio::test]
async fn test_issuance_reject_partial_batch_format() {
    check_batch_item_rejection(1, false, true).await;
}

#[tokio::test]
async fn test_issuance_reject_all_batch_format_items_at_once() {
    check_batch_item_rejection(2, false, true).await;
}

#[tokio::test]
async fn test_issuance_reject_all_batch_format_items_separately() {
    check_batch_item_rejection(2, true, true).await;
}

#[tokio::test]
async fn test_issuance_reject_all_batch_format_items_without_notifications() {
    check_batch_item_rejection(2, false, false).await;
}

async fn check_batch_item_rejection(
    rejected_count: usize,
    separate_requests: bool,
    notifications_supported: bool,
) {
    let (context, organisation, _, identifier, key) = TestContext::new_with_did(Some(
        indoc::indoc! {r#"
            format:
              JWT_SECOND:
                type: "JWT"
                display: "Second JWT"
                order: 301
                params:
                  public:
                    expirationSeconds: 63072000
                    leewaySeconds: 60
                    embedLayoutProperties: true
                    revocationMethod: "BITSTRINGSTATUSLIST"
        "#}
        .to_owned(),
    ))
    .await;
    let issuer_key = Ecdsa.generate_key().unwrap();
    let issuer_did: DidValue = format!(
        "did:key:{}",
        issuer_key.key.public_key_as_multibase().unwrap()
    )
    .parse()
    .unwrap();
    context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                did_type: Some(DidType::Remote),
                did: Some(issuer_did.clone()),
                ..Default::default()
            },
        )
        .await;
    let now = one_core::clock::now_utc();
    let schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            TestingCreateSchemaParams {
                batch_size: Some(2),
                // Both use JWT deliberately: routing must use the exact schema format ID.
                formats: Some(vec![
                    ("JWT".into(), "first".into()),
                    ("JWT_SECOND".into(), "second".into()),
                ]),
                // Include the metadata claims present in the mock's issued JWTs.
                claim_schemas: Some(
                    [
                        ("string", "STRING", false),
                        ("exp", "NUMBER", false),
                        ("iat", "NUMBER", false),
                        ("nbf", "NUMBER", false),
                        ("iss", "STRING", false),
                        ("sub", "STRING", false),
                        ("vc", "OBJECT", false),
                        ("vc/type", "STRING", true),
                    ]
                    .into_iter()
                    .map(|(key, data_type, array)| ClaimSchema {
                        id: Uuid::new_v4().into(),
                        key: key.into(),
                        data_type: data_type.into(),
                        created_date: now,
                        last_modified: now,
                        array,
                        metadata: key != "string",
                        required: key == "string",
                        translations: Default::default(),
                    })
                    .collect(),
                ),
                ..Default::default()
            },
        )
        .await;
    let formats = schema.formats.as_ref().await.unwrap();
    let parent_id: CredentialId = Uuid::new_v4().into();
    let mut data: serde_json::Value = serde_json::from_slice(&dummy_interaction_data(
        &context,
        &schema,
        InteractionDataParams {
            batch_size: Some(2),
            notification_id: Some("first".into()),
            notification_endpoint: notifications_supported.then(|| {
                format!(
                    "{}/ssi/openid4vci/final-1.0/{}/notification",
                    context.server_mock.uri(),
                    schema.id,
                )
            }),
            additional_configurations: vec![ConfigurationParams {
                credential_configuration_id: "second".into(),
                format: "jwt_vc_json".into(),
                notification_id: Some("second".into()),
                credential_id: Some(parent_id),
            }],
            ..Default::default()
        },
    ))
    .unwrap();
    for (configuration, format) in data["credential_configurations"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .zip(formats.iter())
    {
        configuration["credential_id"] = json!(parent_id);
        configuration["credential_schema_format_id"] = json!(format.id);
        configuration["cryptographic_binding_methods_supported"] = json!(["did:key"]);
    }
    let interaction = context
        .db
        .interactions
        .create(
            &organisation,
            InteractionType::Issuance,
            TestingInteractionParams {
                data: Some(serde_json::to_vec(&data).unwrap()),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .credentials
        .create(
            &schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams {
                id: Some(parent_id),
                r#type: Some(CredentialType::BatchParent),
                interaction: Some(interaction.clone()),
                key: Some(key.clone()),
                ..Default::default()
            },
        )
        .await;
    let mut item_ids = vec![vec![], vec![]];
    for (format, ids) in formats.iter().zip(&mut item_ids) {
        for _ in 0..2 {
            let item = context
                .db
                .credentials
                .create(
                    &schema,
                    CredentialStateEnum::Accepted,
                    &identifier,
                    "OPENID4VCI_FINAL1",
                    TestingCredentialParams {
                        r#type: Some(CredentialType::BatchItem),
                        parent_id: Some(parent_id),
                        format: Some(format.clone()),
                        key: Some(key.clone()),
                        ..Default::default()
                    },
                )
                .await;
            ids.push(item.common().id);
        }
    }
    // Another batch of the same format must neither be selectable through this
    // interaction nor prevent this batch's format from being fully rejected.
    let other_parent = context
        .db
        .credentials
        .create(
            &schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams {
                r#type: Some(CredentialType::BatchParent),
                ..Default::default()
            },
        )
        .await;
    let other_item = context
        .db
        .credentials
        .create(
            &schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams {
                r#type: Some(CredentialType::BatchItem),
                parent_id: Some(other_parent.common().id),
                format: Some(formats[0].clone()),
                ..Default::default()
            },
        )
        .await;
    let resp = context
        .api
        .interactions
        .issuance_reject(interaction.id, Some(vec![other_item.common().id]))
        .await;
    assert_eq!(resp.status(), 400);
    assert_eq!(
        context
            .db
            .credentials
            .get(&other_item.common().id)
            .await
            .common()
            .state,
        CredentialStateEnum::Accepted
    );

    let fully_rejected = rejected_count == 2;
    if notifications_supported {
        context
            .server_mock
            .ssi_notification_endpoint(schema.id, "first", "123", u64::from(fully_rejected))
            .await;
        context
            .server_mock
            .ssi_notification_endpoint(schema.id, "second", "123", 0)
            .await;
    }

    let selected = &item_ids[0][..rejected_count];
    for ids in selected.chunks(if separate_requests { 1 } else { selected.len() }) {
        let resp = context
            .api
            .interactions
            .issuance_reject(interaction.id, Some(ids.to_vec()))
            .await;
        assert_eq!(resp.status(), 204);
    }
    let requests = context.server_mock.received_requests().await.unwrap();
    assert_eq!(
        requests.len(),
        usize::from(fully_rejected && notifications_supported)
    );
    if let Some(notification) = requests.first() {
        assert_eq!(
            notification.body_json::<serde_json::Value>().unwrap(),
            json!({
                "notification_id": "first", "event": "credential_deleted",
            })
        );
    }
    assert_eq!(
        context.db.credentials.get(&parent_id).await.common().state,
        CredentialStateEnum::Accepted
    );
    for (index, ids) in item_ids.iter().enumerate() {
        for (item_index, id) in ids.iter().enumerate() {
            assert_eq!(
                context.db.credentials.get(id).await.common().state,
                if index == 0 && item_index < rejected_count {
                    CredentialStateEnum::Rejected
                } else {
                    CredentialStateEnum::Accepted
                }
            );
        }
    }

    let refreshed_formats = if fully_rejected { 1 } else { 2 };
    context
        .server_mock
        .ssi_credential_endpoint_dynamic(
            schema.id,
            "123",
            issuer_key,
            issuer_did,
            None,
            2 * refreshed_formats,
        )
        .await;
    context
        .server_mock
        .ssi_nonce_endpoint("OPENID4VCI_FINAL1", "nonce", 2 * refreshed_formats)
        .await;
    // Repeated refreshes must keep excluding the rejected format and include a partially
    // rejected one, while always refreshing the other format of the same parent.
    for _ in 0..2 {
        let resp = context
            .api
            .interactions
            .issuance_refresh(interaction.id)
            .await;
        assert_eq!(resp.status(), 200);
        let body = resp.json_value().await;
        let ids = body["ids"].as_array().unwrap();
        assert_eq!(ids.len(), 2 * refreshed_formats as usize);
        let mut counts = [0, 0];
        for id in ids {
            let item = context.db.credentials.get(&id.parse()).await;
            assert_eq!(item.parent().as_ref().unwrap().id(), parent_id);
            assert_eq!(item.common().state, CredentialStateEnum::Accepted);
            let format_id = item.format().unwrap().id();
            counts[formats
                .iter()
                .position(|format| format.id == format_id)
                .unwrap()] += 1;
        }
        assert_eq!(counts, [if fully_rejected { 0 } else { 2 }, 2]);
    }
}
