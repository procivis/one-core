use one_core::model::claim_schema::ClaimSchema;
use one_core::model::credential::{CredentialFilterValue, CredentialType};
use one_core::model::did::DidType;
use one_core::model::interaction::InteractionType;
use one_core::model::list_filter::ListFilterValue;
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::ecdsa::Ecdsa;
use serde_json::json;
use shared_types::{CredentialId, DidValue};
use similar_asserts::assert_eq;
use time::macros::datetime;
use uuid::Uuid;

use crate::fixtures::TestingDidParams;
use crate::fixtures::interaction::{
    ConfigurationParams, InteractionDataParams, dummy_interaction_data,
};
use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
use crate::utils::db_clients::interactions::TestingInteractionParams;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_issuance_refresh_skips_configuration_the_issuer_refuses() {
    // GIVEN an accepted batch offer of two configurations
    let (context, organisation) = TestContext::new_with_organisation(None).await;

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
                batch_size: Some(2),
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
            batch_size: Some(2),
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
    for configuration in interaction_data["credential_configurations"]
        .as_array_mut()
        .unwrap()
    {
        configuration["cryptographic_binding_methods_supported"] = json!(["did:key"]);
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
    // two credential requests on accept, one more on refresh
    context
        .server_mock
        .ssi_credential_endpoint_dynamic(credential_schema.id, "123", issuer_key, issuer_did, 3)
        .await;
    context
        .server_mock
        .ssi_nonce_endpoint("OPENID4VCI_FINAL1", "test-nonce", 4)
        .await;

    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, None, None, None, None)
        .await;
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let parents = resp["credentialIds"].as_array().unwrap();
    assert_eq!(parents.len(), 2);
    let first_parent: CredentialId = parents[0].parse();
    let second_parent: CredentialId = parents[1].parse();

    // the issuer refuses the second configuration on refresh
    context
        .server_mock
        .ssi_credential_endpoint_failure(credential_schema.id, "123", "second")
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_refresh(interaction.id)
        .await;

    // THEN the first configuration is refreshed, the second is skipped
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let ids = resp["ids"].as_array().unwrap();
    assert_eq!(ids.len(), 2);
    for id in ids {
        let item = context.db.credentials.get(&id.parse()).await;
        assert_eq!(CredentialType::BatchItem, item.r#type);
        assert_eq!(first_parent, item.parent.unwrap().id());
    }
    // the refused configuration keeps the items of the accept only
    let refused_items = context
        .db
        .credentials
        .list(CredentialFilterValue::ParentCredential(second_parent).condition())
        .await;
    assert_eq!(refused_items.len(), 2);
}
