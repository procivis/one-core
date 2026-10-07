use one_core::model::claim_schema::ClaimSchema;
use one_core::model::credential::{Credential, CredentialFilterValue, CredentialStateEnum};
use one_core::model::did::DidType;
use one_core::model::history::HistoryAction;
use one_core::model::interaction::InteractionType;
use one_core::model::list_filter::ListFilterValue;
use one_core::proto::jwt::Jwt;
use one_core::proto::jwt::mapper::{bin_to_b64url_string, string_to_b64url_string};
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::ecdsa::Ecdsa;
use serde_json::json;
use shared_types::{CredentialId, DidValue};
use similar_asserts::assert_eq;
use time::macros::datetime;
use uuid::Uuid;

use super::issuance_accept_tests::{
    AcceptedMultiConfigurationOffer, MultiConfigurationOffer, accept_multi_configuration_offer,
};
use crate::fixtures::TestingDidParams;
use crate::fixtures::interaction::{
    ConfigurationParams, InteractionDataParams, dummy_interaction_data,
};
use crate::fixtures::presentation::w3c_jwt_vc;
use crate::utils::api_clients::histories::QueryParams;
use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
use crate::utils::db_clients::interactions::TestingInteractionParams;
use crate::utils::field_match::FieldHelpers;

#[derive(Default)]
struct RefreshOffer {
    batch_size: Option<u32>,
    fail_on_accept: bool,
    fixed_identifier_expiry: Option<bool>,
    refresh_all_configurations: bool,
}

#[tokio::test]
async fn test_issuance_refresh_without_refresh_token_returns_not_supported() {
    let AcceptedMultiConfigurationOffer {
        context,
        interaction_id,
        response,
        ..
    } = accept_multi_configuration_offer(MultiConfigurationOffer {
        schema_overlap: true,
        ..Default::default()
    })
    .await;

    let credential_ids = response["credentialIds"].as_array().unwrap();
    assert_eq!(credential_ids.len(), 2);
    for id in credential_ids {
        let credential = context.db.credentials.get(&id.parse()).await;
        assert!(matches!(credential, Credential::HolderSingle { .. }));
        assert_eq!(credential.common().state, CredentialStateEnum::Accepted);
        assert_eq!(
            credential.common().interaction.as_ref().unwrap().id(),
            interaction_id
        );
    }
    let interaction = context.db.interactions.get(&interaction_id).await.unwrap();
    let data: serde_json::Value = serde_json::from_slice(&interaction.data.unwrap()).unwrap();
    assert!(data["refresh_token"].is_null());

    let response = context
        .api
        .interactions
        .issuance_refresh(interaction_id)
        .await;

    assert_eq!(response.status(), 400);
    assert_eq!(response.json_value().await["code"], "BR_0452");
    for id in credential_ids {
        let credential = context.db.credentials.get(&id.parse()).await;
        assert_eq!(credential.common().state, CredentialStateEnum::Accepted);
        let history = context
            .db
            .histories
            .get_by_entity_id(&credential.common().id.into())
            .await;
        assert!(
            history
                .values
                .iter()
                .all(|entry| entry.action != HistoryAction::Refreshed)
        );
    }
}

#[tokio::test]
async fn test_issuance_refresh_for_missing_interaction() {
    let (context, _) = TestContext::new_with_organisation(None).await;

    let response = context
        .api
        .interactions
        .issuance_refresh(Uuid::new_v4())
        .await;

    assert_eq!(response.status(), 404);
    assert_eq!(response.json_value().await["code"], "BR_0257");
}

#[tokio::test]
async fn test_issuance_refresh_records_one_history_for_shared_parent() {
    check_issuance_refresh(RefreshOffer {
        batch_size: Some(3),
        refresh_all_configurations: true,
        ..Default::default()
    })
    .await;
}

#[tokio::test]
async fn test_issuance_refresh_skips_configuration_the_issuer_refuses() {
    check_issuance_refresh(RefreshOffer {
        batch_size: Some(2),
        ..Default::default()
    })
    .await;
}

#[tokio::test]
async fn test_issuance_refresh_does_not_retry_configuration_refused_on_accept() {
    check_issuance_refresh(RefreshOffer {
        batch_size: Some(2),
        fail_on_accept: true,
        ..Default::default()
    })
    .await;
}

#[tokio::test]
async fn test_issuance_refresh_without_advertised_batch_support() {
    // Each expiring configuration issues one item and shares a refreshable parent.
    check_issuance_refresh(RefreshOffer::default()).await;
}

#[tokio::test]
async fn test_issuance_refresh_with_fixed_identifier_without_expiry() {
    check_issuance_refresh(RefreshOffer {
        batch_size: Some(3),
        fixed_identifier_expiry: Some(false),
        ..Default::default()
    })
    .await;
}

#[tokio::test]
async fn test_issuance_refresh_with_fixed_identifier_with_expiry() {
    check_issuance_refresh(RefreshOffer {
        batch_size: Some(3),
        fixed_identifier_expiry: Some(true),
        ..Default::default()
    })
    .await;
}

async fn check_issuance_refresh(offer: RefreshOffer) {
    let batch_size = if offer.fixed_identifier_expiry.is_some() {
        1
    } else {
        offer.batch_size.unwrap_or(1)
    };
    let fail_on_accept = offer.fail_on_accept;
    let refresh_supported = offer.fixed_identifier_expiry != Some(false);
    // GIVEN two configurations and a token endpoint that issues a refresh token
    let (context, organisation, holder_did, holder_identifier, holder_key) =
        TestContext::new_with_did(None).await;

    let issuer_key = Ecdsa.generate_key().unwrap();
    let multibase = issuer_key.key.public_key_as_multibase().unwrap();
    let issuer_did: DidValue = format!("did:key:{multibase}").parse().unwrap();
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

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            TestingCreateSchemaParams {
                batch_size: offer.batch_size.map(|size| size.try_into().unwrap()),
                claim_schemas: Some(vec![ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "string".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: datetime!(2024-10-20 12:00 +1),
                    last_modified: datetime!(2024-10-20 12:00 +1),
                    array: false,
                    metadata: false,
                    required: true,
                    translations: Default::default(),
                }]),
                ..Default::default()
            },
        )
        .await;

    let mut interaction_data: serde_json::Value = serde_json::from_slice(&dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams {
            batch_size: offer.batch_size,
            additional_configurations: vec![ConfigurationParams {
                credential_configuration_id: "second".to_string(),
                format: "jwt_vc_json".to_string(),
                notification_id: None,
                credential_id: None,
            }],
            ..Default::default()
        },
    ))
    .unwrap();
    // only issuers that don't support jwk/cose_key binding force the wallet to auto-generate a
    // DID (rather than a bare key) for each proof, which is what our jwt_vc_json credentials
    // (bound via `sub`) need
    for (index, configuration) in interaction_data["credential_configurations"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .enumerate()
    {
        configuration["cryptographic_binding_methods_supported"] = json!(["did:key"]);
        configuration["disclosure_policy"] = json!({
            "id": format!("policy-{index}"),
            "policy": "none",
        });
    }
    let interaction = context
        .db
        .interactions
        .create(
            &organisation,
            InteractionType::Issuance,
            TestingInteractionParams {
                data: Some(serde_json::to_vec(&interaction_data).unwrap()),
                ..Default::default()
            },
        )
        .await;

    context
        .server_mock
        .token_endpoint(credential_schema.id, "123")
        .await;
    let refreshed_configuration_count = if offer.refresh_all_configurations {
        2
    } else {
        1
    };
    let expected_calls = if fail_on_accept { 1 } else { 2 }
        + u64::from(refresh_supported) * refreshed_configuration_count;
    if let Some(expires) = offer.fixed_identifier_expiry {
        let mut token = w3c_jwt_vc(
            &issuer_key,
            "ES256",
            issuer_did,
            holder_did.did.clone(),
            json!({"string": "string"}),
        )
        .await;
        if !expires {
            let mut jwt = Jwt::<serde_json::Value>::decompose_token(&token).unwrap();
            jwt.payload.expires_at = None;
            let unsigned = format!(
                "{}.{}",
                string_to_b64url_string(&serde_json::to_string(&jwt.header).unwrap()).unwrap(),
                string_to_b64url_string(&serde_json::to_string(&jwt.payload).unwrap()).unwrap(),
            );
            let signature = issuer_key.key.sign(unsigned.as_bytes()).await.unwrap();
            token = format!("{unsigned}.{}", bin_to_b64url_string(&signature).unwrap());
        }
        context
            .server_mock
            .ssi_credential_endpoint(credential_schema.id, "123", &[token], expected_calls, None)
            .await;
    } else {
        context
            .server_mock
            .ssi_credential_endpoint_dynamic(
                credential_schema.id,
                "123",
                issuer_key,
                issuer_did,
                None,
                expected_calls,
            )
            .await;
    }
    context
        .server_mock
        .ssi_nonce_endpoint(
            "OPENID4VCI_FINAL1",
            "test-nonce",
            2 + u64::from(refresh_supported) * if fail_on_accept { 1 } else { 2 },
        )
        .await;

    if fail_on_accept {
        context
            .server_mock
            .ssi_credential_endpoint_failure(credential_schema.id, "123", "second")
            .await;
    }

    let resp = context
        .api
        .interactions
        .issuance_accept(
            interaction.id,
            offer.fixed_identifier_expiry.map(|_| holder_did.id),
            None,
            None,
            None,
        )
        .await;
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    if offer.fixed_identifier_expiry == Some(false) {
        let ids = resp["credentialIds"].as_array().unwrap();
        assert_eq!(ids.len(), 2);
        for id in ids {
            let credential = context.db.credentials.get(&id.parse()).await;
            assert!(matches!(credential, Credential::HolderSingle { .. }));
            assert!(credential.common().expires_at.is_none());
            assert!(credential.parent().is_none());
        }
        let response = context
            .api
            .interactions
            .issuance_refresh(interaction.id)
            .await;
        assert_eq!(response.status(), 400);
        assert_eq!(response.json_value().await["code"], "BR_0238");
        return;
    }
    let parents = resp["credentialIds"].as_array().unwrap();
    assert_eq!(parents.len(), 1);
    let first_parent: CredentialId = parents[0].parse();
    assert_eq!(resp["id"], parents[0]);

    // Each configuration's policy belongs to its concrete items, including after refresh.
    let parent = context.db.credentials.get(&first_parent).await;
    assert!(matches!(parent, Credential::HolderBatchParent { .. }));
    let stored = context.db.interactions.get(&interaction.id).await.unwrap();
    let data: serde_json::Value = serde_json::from_slice(stored.data.as_ref().unwrap()).unwrap();
    assert_eq!(data["batch_size"], json!(offer.batch_size));
    assert!(!data["refresh_token"].is_null());
    let items = context
        .db
        .credentials
        .list(CredentialFilterValue::ParentCredential(first_parent).condition())
        .await;
    assert_eq!(
        items.len(),
        batch_size as usize * if fail_on_accept { 1 } else { 2 }
    );
    let mut policy_counts = [0, 0];
    let mut initial_payload_claim_ids = std::collections::HashSet::new();
    for item in &items {
        let claims = item.holder().unwrap().data.claims.as_ref().await.unwrap();
        initial_payload_claim_ids.insert(
            claims
                .iter()
                .find(|claim| claim.path == "string")
                .unwrap()
                .id,
        );
        if let Some(expires) = offer.fixed_identifier_expiry {
            assert_eq!(item.common().expires_at.is_some(), expires);
            assert_eq!(
                item.holder_identifier().as_ref().unwrap().id(),
                holder_identifier.id
            );
        }
        let policy: serde_json::Value = serde_json::from_str(
            item.holder()
                .unwrap()
                .data
                .embedded_disclosure_policy
                .as_ref()
                .unwrap(),
        )
        .unwrap();
        let index = ["policy-0", "policy-1"]
            .into_iter()
            .position(|id| policy["id"] == id)
            .expect("Unexpected policy ID");
        assert_eq!(policy["policy"], "none");
        policy_counts[index] += 1;
    }
    assert_eq!(
        policy_counts,
        [batch_size, if fail_on_accept { 0 } else { batch_size }]
    );
    assert_eq!(initial_payload_claim_ids.len(), 1);

    // the issuer refuses the second configuration on refresh
    if !fail_on_accept && refresh_supported && !offer.refresh_all_configurations {
        context
            .server_mock
            .ssi_credential_endpoint_failure(credential_schema.id, "123", "second")
            .await;
    }
    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_refresh(interaction.id)
        .await;

    let history = context
        .api
        .histories
        .list(
            0,
            5,
            QueryParams {
                organisation_ids: Some(vec![organisation.id]),
                entity_types: Some(vec!["CREDENTIAL".to_string()]),
                entity_ids: Some(vec![first_parent.into()]),
                actions: Some(vec!["REFRESHED".to_string()]),
                show_system_history: Some(false),
                ..Default::default()
            },
        )
        .await;
    assert_eq!(history.status(), 200);
    assert_eq!(
        history.json_value().await["totalItems"],
        u64::from(refresh_supported)
    );

    if !refresh_supported {
        assert_eq!(resp.status(), 400);
        assert_eq!(resp.json_value().await["code"], "BR_0452");
        let unchanged_items = context
            .db
            .credentials
            .list(CredentialFilterValue::ParentCredential(first_parent).condition())
            .await;
        assert_eq!(unchanged_items.len(), items.len());
        return;
    }

    // THEN successful configurations contribute items and share one parent history event.
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let ids = resp["ids"].as_array().unwrap();
    assert_eq!(
        ids.len(),
        batch_size as usize * refreshed_configuration_count as usize
    );
    let mut refreshed_policy_counts = [0, 0];
    for id in ids {
        let item = context.db.credentials.get(&id.parse()).await;
        assert!(matches!(item, Credential::HolderBatchItem { .. }));
        assert_eq!(first_parent, item.parent().unwrap().id());
        let holder = item.holder().unwrap();
        if offer.fixed_identifier_expiry.is_some() {
            let binding = holder.data.binding.as_ref().unwrap();
            assert_eq!(binding.identifier.id(), holder_identifier.id);
            assert_eq!(binding.key.id(), holder_key.id);
        }
        let policy: serde_json::Value =
            serde_json::from_str(holder.data.embedded_disclosure_policy.as_ref().unwrap()).unwrap();
        let index = ["policy-0", "policy-1"]
            .into_iter()
            .position(|id| policy["id"] == id)
            .expect("Unexpected policy ID");
        assert_eq!(policy["policy"], "none");
        refreshed_policy_counts[index] += 1;
        let claims = item.holder().unwrap().data.claims.as_ref().await.unwrap();
        assert!(!claims.is_empty());

        let payload = claims.iter().find(|claim| claim.path == "string").unwrap();
        assert!(initial_payload_claim_ids.contains(&payload.id));
    }
    assert_eq!(
        refreshed_policy_counts,
        [
            batch_size,
            if offer.refresh_all_configurations {
                batch_size
            } else {
                0
            }
        ]
    );
    if !fail_on_accept && !offer.refresh_all_configurations {
        // the refused configuration keeps the items of the accept only
        let refused_items = context
            .db
            .credentials
            .list(CredentialFilterValue::ParentCredential(first_parent).condition())
            .await;
        let refused_ids = refused_items
            .iter()
            .filter(|item| {
                serde_json::from_str::<serde_json::Value>(
                    item.holder()
                        .unwrap()
                        .data
                        .embedded_disclosure_policy
                        .as_ref()
                        .unwrap(),
                )
                .unwrap()["id"]
                    == "policy-1"
            })
            .map(|item| item.common().id)
            .collect::<std::collections::HashSet<_>>();
        let original_ids = items
            .iter()
            .filter(|item| {
                serde_json::from_str::<serde_json::Value>(
                    item.holder()
                        .unwrap()
                        .data
                        .embedded_disclosure_policy
                        .as_ref()
                        .unwrap(),
                )
                .unwrap()["id"]
                    == "policy-1"
            })
            .map(|item| item.common().id)
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(refused_ids, original_ids);
    }
}
