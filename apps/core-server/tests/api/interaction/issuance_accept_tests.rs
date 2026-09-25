use std::collections::HashSet;
use std::str::FromStr;

use assert2::let_assert;
use one_core::model::claim_schema::ClaimSchema;
use one_core::model::credential::{CredentialFilterValue, CredentialStateEnum, CredentialType};
use one_core::model::credential_schema::KeyStorageSecurity;
use one_core::model::did::{DidType, KeyRole, RelatedKey};
use one_core::model::history::HistoryAction;
use one_core::model::identifier::{IdentifierData, IdentifierType};
use one_core::model::interaction::InteractionType;
use one_core::model::list_filter::ListFilterValue;
use one_core::proto::jwt::Jwt;
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::ecdsa::Ecdsa;
use serde_json::json;
use shared_types::{DidValue, InteractionId};
use similar_asserts::assert_eq;
use time::macros::datetime;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::fixtures::interaction::{
    ConfigurationParams, InteractionDataParams, dummy_interaction_data,
};
use crate::fixtures::presentation::w3c_jwt_vc;
use crate::fixtures::wallet_provider::create_wallet_unit_attestation_issuer_identifier;
use crate::fixtures::{TestingCredentialParams, TestingDidParams, TestingIdentifierParams};
use crate::utils::api_clients::dids::DidFilters;
use crate::utils::api_clients::keys::KeyFilters;
use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
use crate::utils::db_clients::holder_wallet_instance::TestHolderWalletInstanceParams;
use crate::utils::db_clients::interactions::TestingInteractionParams;
use crate::utils::db_clients::keys::ecdsa_testing_params;
use crate::utils::db_clients::managed_instances::TestWalletInstance;
use crate::utils::field_match::FieldHelpers;

async fn random_document() -> String {
    let key = Ecdsa.generate_key().unwrap();
    let multibase = key.key.public_key_as_multibase().unwrap();
    let did: DidValue = format!("did:key:{multibase}").parse().unwrap();
    w3c_jwt_vc(
        &key,
        "ES256",
        did.clone(),
        did.clone(),
        json!({"string":"value"}),
    )
    .await
}

#[tokio::test]
async fn test_issuance_accept_openid4vc() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let issuer_key = Ecdsa.generate_key().unwrap();
    let multibase = issuer_key.key.public_key_as_multibase().unwrap();
    let issuer_did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                did_type: Some(DidType::Remote),
                did: Some(format!("did:key:{multibase}").parse().unwrap()),
                ..Default::default()
            },
        )
        .await;
    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key,
                    reference: "1".to_string(),
                }]),
                did: Some(
                    DidValue::from_str("did:key:zDnaeY6V3KGKLzgK3C2hbb4zMpeVKbrtWhEP4WXUyTAbshioQ")
                        .unwrap(),
                ),
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
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let schema_id = Uuid::new_v4();
    let metadata_schema_id = Uuid::new_v4();

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            TestingCreateSchemaParams {
                claim_schemas: Some(vec![
                    ClaimSchema {
                        id: schema_id.into(),
                        key: "string".to_string(),
                        data_type: "STRING".to_string(),
                        created_date: datetime!(2024-10-20 12:00 +1),
                        last_modified: datetime!(2024-10-20 12:00 +1),
                        array: false,
                        metadata: false,
                        required: true,
                        translations: Default::default(),
                    },
                    ClaimSchema {
                        id: metadata_schema_id.into(),
                        key: "iss".to_string(),
                        data_type: "STRING".to_string(),
                        created_date: datetime!(2024-10-20 12:00 +1),
                        last_modified: datetime!(2024-10-20 12:00 +1),
                        array: false,
                        metadata: true,
                        required: false,
                        translations: Default::default(),
                    },
                ]),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams::default(),
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

    let jwt_credential = w3c_jwt_vc(
        &issuer_key,
        "ES256",
        issuer_did.did.clone(),
        holder_did.did.clone(),
        json!({"string":"string"}),
    )
    .await;

    context
        .server_mock
        .ssi_credential_endpoint(credential_schema.id, "123", &[jwt_credential], 1, None)
        .await;

    context
        .server_mock
        .ssi_nonce_endpoint("OPENID4VCI_FINAL1", "test-nonce", 1)
        .await;

    context
        .server_mock
        .token_endpoint(credential_schema.id, "123")
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, None, None, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert!(resp.get("partiallySuccessful").is_none());

    let credential = context.db.credentials.get(&resp["id"].parse()).await;
    let holder_identifier = credential
        .holder_identifier
        .as_ref()
        .unwrap()
        .as_ref()
        .await
        .unwrap();
    let_assert!(IdentifierData::Did(credential_holder_did) = &holder_identifier.data);
    assert_eq!(holder_did.id, credential_holder_did.id());
    assert_eq!(CredentialStateEnum::Accepted, credential.state);

    let claims = credential.claims.as_ref().await.unwrap().to_owned();
    let iss_claim = claims.iter().find(|claim| claim.path == "iss").unwrap();
    assert_eq!(
        iss_claim.value.as_ref().unwrap(),
        &issuer_did.did.to_string()
    );
    assert_eq!(iss_claim.selectively_disclosable, false);
    assert_eq!(iss_claim.schema.as_ref().await.unwrap().metadata, true);
    let payload_claim = claims.iter().find(|claim| claim.path == "string").unwrap();
    assert_eq!(payload_claim.value.as_ref().unwrap(), "string");
    assert_eq!(payload_claim.selectively_disclosable, false);
    assert_eq!(payload_claim.schema.as_ref().await.unwrap().metadata, false);

    let history = context
        .db
        .histories
        .get_by_entity_id(&credential.id.into())
        .await;
    assert_eq!(history.values.len(), 2); // Accepted + Issued
    let actions = HashSet::from_iter(history.values.iter().map(|value| value.action));
    assert_eq!(
        actions,
        HashSet::from([HistoryAction::Accepted, HistoryAction::Issued])
    );
}

#[derive(Default)]
pub(super) struct MultiConfigurationOffer {
    pub(super) batch_size: Option<u32>,
    pub(super) refresh_token: bool,
    pub(super) schema_overlap: bool,
    pub(super) fail_second: bool,
}

pub(super) struct AcceptedMultiConfigurationOffer {
    pub(super) context: TestContext,
    pub(super) interaction_id: InteractionId,
    pub(super) response: serde_json::Value,
    schema_ids: [shared_types::CredentialSchemaId; 2],
}

/// Issue two configurations with independently selected schemas and token/batch capabilities.
pub(super) async fn accept_multi_configuration_offer(
    offer: MultiConfigurationOffer,
) -> AcceptedMultiConfigurationOffer {
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    use crate::fixtures::jwt::signed_jwt;

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

    let first_schema = context
        .db
        .credential_schemas
        .create("first", &organisation, Default::default())
        .await;
    let second_schema = if offer.schema_overlap {
        first_schema.clone()
    } else {
        context
            .db
            .credential_schemas
            .create("second", &organisation, Default::default())
            .await
    };
    let schema_ids = [first_schema.id, second_schema.id];
    let credential_server = MockServer::start().await;
    let mut interaction_data: serde_json::Value = serde_json::from_slice(&dummy_interaction_data(
        &context,
        &first_schema,
        InteractionDataParams {
            batch_size: offer.batch_size,
            notification_endpoint: Some(format!(
                "{}/ssi/openid4vci/final-1.0/{}/notification",
                context.server_mock.uri(),
                first_schema.id
            )),
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
    interaction_data["credential_endpoint"] =
        json!(format!("{}/credential", credential_server.uri()));
    // Token capabilities are established by the token endpoint, not by prepopulated fixture data.
    interaction_data["refresh_token"] = serde_json::Value::Null;
    interaction_data["refresh_token_expires_at"] = serde_json::Value::Null;
    for (index, configuration) in interaction_data["credential_configurations"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .enumerate()
    {
        configuration["credential_configuration_id"] = json!(["first", "second"][index]);
        configuration["cryptographic_binding_methods_supported"] = json!(["did:key"]);
        configuration["disclosure_policy"] =
            json!({"id": format!("policy-{index}"), "policy": "none"});
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

    for (index, schema_id) in schema_ids.into_iter().enumerate() {
        let configuration_id = ["first", "second"][index];
        let request = Mock::given(method("POST"))
            .and(path("/credential"))
            .and(header("Authorization", "Bearer 123"))
            .and(body_partial_json(
                json!({"credential_configuration_id": configuration_id}),
            ));
        if index == 1 && offer.fail_second {
            request
                .respond_with(
                    ResponseTemplate::new(400)
                        .set_body_json(json!({"error": "invalid_credential_request"})),
                )
                .expect(1)
                .mount(&credential_server)
                .await;
            continue;
        }
        let issuer_key = issuer_key.clone();
        let issuer_did = issuer_did.clone();
        let notification_id = format!("notification-{index}");
        let response_notification_id = notification_id.clone();
        let batch_size = offer.batch_size.unwrap_or(1) as usize;
        request.respond_with(move |request: &Request| {
            let body: serde_json::Value = request.body_json().unwrap();
            let proofs = body["proofs"]["jwt"].as_array().unwrap();
            assert_eq!(proofs.len(), batch_size);
            let credentials: Vec<_> = proofs.iter().map(|proof| {
                let proof = Jwt::<serde_json::Value>::decompose_token(proof.as_str().unwrap()).unwrap();
                let kid = proof.header.key_id.unwrap();
                let holder_did = kid.split('#').next().unwrap();
                let credential = futures::executor::block_on(signed_jwt(
                    &issuer_key, "ES256", None, Some(issuer_did.to_string()), Some(holder_did.to_string()),
                    json!({"vc": {
                        "@context": ["https://www.w3.org/2018/credentials/v1"],
                        "type": ["VerifiableCredential"],
                        "credentialSchema": [{"id": schema_id.to_string(), "type": "JsonSchema"}],
                        "credentialSubject": {"firstName": "John"}
                    }}), None,
                ));
                json!({"credential": credential})
            }).collect();
            ResponseTemplate::new(200).set_body_json(json!({
                "credentials": credentials, "notification_id": response_notification_id
            }))
        }).expect(1).mount(&credential_server).await;
        context
            .server_mock
            .ssi_notification_endpoint(first_schema.id, notification_id, "123", 1)
            .await;
    }
    context
        .server_mock
        .ssi_nonce_endpoint("OPENID4VCI_FINAL1", "test-nonce", 2)
        .await;
    if offer.refresh_token {
        context
            .server_mock
            .token_endpoint(first_schema.id, "123")
            .await;
    } else {
        context
            .server_mock
            .token_endpoint_without_refresh_token(first_schema.id, "123")
            .await;
    }

    let response = context
        .api
        .interactions
        .issuance_accept(interaction.id, None, None, None, None)
        .await;
    assert_eq!(response.status(), 200);
    AcceptedMultiConfigurationOffer {
        context,
        interaction_id: interaction.id,
        response: response.json_value().await,
        schema_ids,
    }
}

#[tokio::test]
async fn test_issuance_accept_no_batch_no_refresh_distinct_schemas_creates_singles() {
    check_multi_configuration_issuance(
        MultiConfigurationOffer::default(),
        CredentialType::Single,
        2,
    )
    .await;
}

#[tokio::test]
async fn test_issuance_accept_no_batch_no_refresh_overlapping_schemas_creates_singles() {
    check_multi_configuration_issuance(
        MultiConfigurationOffer {
            schema_overlap: true,
            ..Default::default()
        },
        CredentialType::Single,
        2,
    )
    .await;
}

#[tokio::test]
async fn test_issuance_accept_batch_no_refresh_distinct_schemas_creates_two_parents() {
    check_multi_configuration_issuance(
        MultiConfigurationOffer {
            batch_size: Some(2),
            ..Default::default()
        },
        CredentialType::BatchParent,
        2,
    )
    .await;
}

#[tokio::test]
async fn test_issuance_accept_batch_no_refresh_overlapping_schemas_creates_one_parent() {
    check_multi_configuration_issuance(
        MultiConfigurationOffer {
            batch_size: Some(2),
            schema_overlap: true,
            ..Default::default()
        },
        CredentialType::BatchParent,
        1,
    )
    .await;
}

#[tokio::test]
async fn test_issuance_accept_no_batch_with_refresh_distinct_schemas_creates_two_parents() {
    check_multi_configuration_issuance(
        MultiConfigurationOffer {
            refresh_token: true,
            ..Default::default()
        },
        CredentialType::BatchParent,
        2,
    )
    .await;
}

#[tokio::test]
async fn test_issuance_accept_no_batch_with_refresh_overlapping_schemas_creates_one_parent() {
    check_multi_configuration_issuance(
        MultiConfigurationOffer {
            refresh_token: true,
            schema_overlap: true,
            ..Default::default()
        },
        CredentialType::BatchParent,
        1,
    )
    .await;
}

async fn check_multi_configuration_issuance(
    offer: MultiConfigurationOffer,
    expected_type: CredentialType,
    expected_main_count: usize,
) {
    let items_per_configuration = offer.batch_size.unwrap_or(1) as usize;
    let refreshable = offer.refresh_token;
    let schema_overlap = offer.schema_overlap;
    let AcceptedMultiConfigurationOffer {
        context,
        interaction_id,
        response,
        schema_ids,
    } = accept_multi_configuration_offer(offer).await;

    assert_eq!(response["partiallySuccessful"], false);
    let main_ids = response["credentialIds"].as_array().unwrap();
    assert_eq!(main_ids.len(), expected_main_count);
    assert_eq!(response["id"], main_ids[0]);
    // The accept response contains every single/parent and never exposes batch item IDs.
    let stored_main_credentials = context
        .db
        .credentials
        .list(
            CredentialFilterValue::Types(vec![CredentialType::Single, CredentialType::BatchParent])
                .condition(),
        )
        .await;
    assert_eq!(stored_main_credentials.len(), expected_main_count);
    assert_eq!(
        stored_main_credentials
            .iter()
            .map(|credential| credential.id)
            .collect::<HashSet<_>>(),
        main_ids.iter().map(|id| id.parse()).collect::<HashSet<_>>()
    );
    let interaction = context.db.interactions.get(&interaction_id).await.unwrap();
    let data: serde_json::Value = serde_json::from_slice(&interaction.data.unwrap()).unwrap();
    assert_eq!(!data["refresh_token"].is_null(), refreshable);
    assert_eq!(data["batch_size"].is_null(), items_per_configuration == 1);
    let configurations = data["credential_configurations"].as_array().unwrap();
    assert_eq!(configurations.len(), 2);

    let mut all_item_ids = HashSet::new();
    for main_id in main_ids {
        let main = context.db.credentials.get(&main_id.parse()).await;
        assert_eq!(main.r#type, expected_type);
        assert_eq!(main.state, CredentialStateEnum::Accepted);
        assert_eq!(main.interaction.as_ref().unwrap().id(), interaction_id);
        assert!(main.parent.is_none());
        let items = context
            .db
            .credentials
            .list(CredentialFilterValue::ParentCredential(main.id).condition())
            .await;
        if expected_type == CredentialType::Single {
            assert!(items.is_empty());
            assert!(main.format.is_some());
            assert!(main.credential_blob_id.is_some());
        } else {
            assert!(main.format.is_none());
            assert!(main.credential_blob_id.is_none());
            assert!(main.embedded_disclosure_policy.is_none());
            assert!(main.claims.as_ref().await.unwrap().is_empty());
            assert_eq!(main.expires_at.is_none(), refreshable);
            assert_eq!(
                items.len(),
                items_per_configuration * if schema_overlap { 2 } else { 1 }
            );
            for item in &items {
                assert_eq!(item.r#type, CredentialType::BatchItem);
                assert_eq!(item.state, CredentialStateEnum::Accepted);
                assert_eq!(item.schema.id(), main.schema.id());
                assert!(item.interaction.is_none());
                assert!(item.credential_blob_id.is_some());
                assert!(
                    !main_ids
                        .iter()
                        .any(|id| id.parse::<shared_types::CredentialId>() == item.id)
                );
                assert!(all_item_ids.insert(item.id));
                let claims = item.claims.as_ref().await.unwrap();

                assert!(claims.iter().any(
                    |claim| claim.path == "firstName" && claim.value.as_deref() == Some("John")
                ));
            }
        }
    }
    assert_eq!(
        all_item_ids.len(),
        if expected_type == CredentialType::Single {
            0
        } else {
            2 * items_per_configuration
        }
    );

    for (index, configuration) in configurations.iter().enumerate() {
        assert_eq!(
            configuration["notification_id"],
            format!("notification-{index}")
        );
        assert!(main_ids.contains(&configuration["credential_id"]));
        let main = context
            .db
            .credentials
            .get(&configuration["credential_id"].parse())
            .await;
        assert_eq!(main.schema.id(), schema_ids[index]);
        let concrete = if expected_type == CredentialType::Single {
            vec![main]
        } else {
            context
                .db
                .credentials
                .list(CredentialFilterValue::ParentCredential(main.id).condition())
                .await
        };
        let policy = json!({"id": format!("policy-{index}"), "policy": "none"});
        let matching: Vec<_> = concrete
            .iter()
            .filter(|item| {
                serde_json::from_str::<serde_json::Value>(
                    item.embedded_disclosure_policy.as_ref().unwrap(),
                )
                .unwrap()
                    == policy
            })
            .collect();
        assert_eq!(matching.len(), items_per_configuration);
        for item in matching {
            assert_eq!(
                configuration["credential_schema_format_id"],
                item.format.as_ref().unwrap().id().to_string()
            );
        }
    }
}

#[tokio::test]
async fn test_issuance_accept_partially_successful() {
    let AcceptedMultiConfigurationOffer {
        context,
        interaction_id,
        response,
        ..
    } = accept_multi_configuration_offer(MultiConfigurationOffer {
        fail_second: true,
        ..Default::default()
    })
    .await;

    assert_eq!(response["partiallySuccessful"], true);
    let credential_ids = response["credentialIds"].as_array().unwrap();
    assert_eq!(credential_ids.len(), 1);
    assert_eq!(response["id"], credential_ids[0]);
    let credential = context.db.credentials.get(&credential_ids[0].parse()).await;
    assert_eq!(credential.r#type, CredentialType::Single);
    assert!(credential.parent.is_none());
    let interaction = context.db.interactions.get(&interaction_id).await.unwrap();
    let data: serde_json::Value = serde_json::from_slice(&interaction.data.unwrap()).unwrap();
    let configurations = data["credential_configurations"].as_array().unwrap();
    assert_eq!(configurations[0]["credential_id"], credential_ids[0]);
    assert_eq!(configurations[1]["credential_id"], serde_json::Value::Null);
}

#[tokio::test]
async fn test_issuance_accept_extracts_expires_at_from_issued_credential() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let issuer_key = Ecdsa.generate_key().unwrap();
    let multibase = issuer_key.key.public_key_as_multibase().unwrap();
    let issuer_did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                did_type: Some(DidType::Remote),
                did: Some(format!("did:key:{multibase}").parse().unwrap()),
                ..Default::default()
            },
        )
        .await;
    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key,
                    reference: "1".to_string(),
                }]),
                did: Some(
                    DidValue::from_str("did:key:zDnaeY6V3KGKLzgK3C2hbb4zMpeVKbrtWhEP4WXUyTAbshioQ")
                        .unwrap(),
                ),
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
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
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

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams::default(),
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

    // `w3c_jwt_vc` (via the shared `signed_jwt` fixture helper) always signs the issued
    // credential with `exp` set to `now + 10 hours` - this is the value the wallet must
    // extract into `Credential.expires_at` when accepting the credential.
    let before = one_core::clock::now_utc();
    let jwt_credential = w3c_jwt_vc(
        &issuer_key,
        "ES256",
        issuer_did.did.clone(),
        holder_did.did.clone(),
        json!({"string":"string"}),
    )
    .await;

    context
        .server_mock
        .ssi_credential_endpoint(credential_schema.id, "123", &[jwt_credential], 1, None)
        .await;
    context
        .server_mock
        .ssi_nonce_endpoint("OPENID4VCI_FINAL1", "test-nonce", 1)
        .await;
    context
        .server_mock
        .token_endpoint(credential_schema.id, "123")
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, None, None, None)
        .await;
    let after = one_core::clock::now_utc();

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let credential_id = resp["id"].parse();

    let credential = context.db.credentials.get(&credential_id).await;
    let expires_at = credential.expires_at.unwrap();
    // the JWT `exp` claim only has whole-second precision, so the round-tripped value can be
    // up to a second below the precise `before + 10h` bound
    assert!(expires_at >= before + Duration::hours(10) - Duration::seconds(1));
    assert!(expires_at <= after + Duration::hours(10));

    // verify it round-trips through the REST API as well
    let resp = context.api.credentials.get(&credential_id).await;
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let returned_expires_at = OffsetDateTime::parse(
        resp["expiresAt"].as_str().unwrap(),
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    assert_eq!(returned_expires_at, expires_at);
}

/// Builds a batch offer (`batch_size: 2`) whose holder-binding proofs are auto-generated
/// `did:key` identifiers, since only auto-generated bindings can produce more than one
/// credential per accept call.
async fn batch_issuance_interaction(
    context: &TestContext,
    organisation: &one_core::model::organisation::Organisation,
    credential_schema: &one_core::model::credential_schema::CredentialSchema,
) -> one_core::model::interaction::Interaction {
    let mut interaction_data: serde_json::Value = serde_json::from_slice(&dummy_interaction_data(
        context,
        credential_schema,
        InteractionDataParams {
            batch_size: Some(2),
            ..Default::default()
        },
    ))
    .unwrap();
    // only issuers that don't support jwk/cose_key binding force the wallet to auto-generate a
    // DID (rather than a bare key) for each proof, which is what our jwt_vc_json credentials
    // (bound via `sub`) need
    interaction_data["credential_configurations"][0]["cryptographic_binding_methods_supported"] =
        json!(["did:key"]);
    let interaction_data = serde_json::to_vec(&interaction_data).unwrap();

    context
        .db
        .interactions
        .create(
            organisation,
            InteractionType::Issuance,
            TestingInteractionParams {
                data: Some(interaction_data),
                ..Default::default()
            },
        )
        .await
}

/// The mocked issuer dynamically signs one credential per proof it receives (see
/// `ssi_credential_endpoint_dynamic`), so this exercises the real `credentials.len() > 1`
/// branch in `holder_process_accepted_credentials` that builds a `BatchParent`.
async fn accept_batch_issuance(
    context: &TestContext,
    organisation: &one_core::model::organisation::Organisation,
    credential_schema: &one_core::model::credential_schema::CredentialSchema,
    issuer_key: &one_core::provider::key_algorithm::model::GeneratedKey,
    issuer_did: &DidValue,
) -> serde_json::Value {
    let interaction = batch_issuance_interaction(context, organisation, credential_schema).await;

    context
        .server_mock
        .ssi_credential_endpoint_dynamic(
            credential_schema.id,
            "123",
            issuer_key.to_owned(),
            issuer_did.to_owned(),
            None,
            1,
        )
        .await;
    context
        .server_mock
        .ssi_nonce_endpoint("OPENID4VCI_FINAL1", "test-nonce", 1)
        .await;

    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, None, None, None, None)
        .await;
    assert_eq!(resp.status(), 200);
    resp.json_value().await
}

#[tokio::test]
async fn test_issuance_accept_batch_with_refresh_token_omits_batch_parent_expires_at() {
    // GIVEN
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

    // `token_endpoint` mock always returns a `refresh_token`, matching an issuer that supports
    // OAuth refresh for the batch
    context
        .server_mock
        .token_endpoint(credential_schema.id, "123")
        .await;

    // WHEN
    let resp = accept_batch_issuance(
        &context,
        &organisation,
        &credential_schema,
        &issuer_key,
        &issuer_did,
    )
    .await;

    // THEN
    let credential = context.db.credentials.get(&resp["id"].parse()).await;
    assert_eq!(CredentialType::BatchParent, credential.r#type);
    assert!(credential.format.is_none());
    // the batch is refreshable via the OAuth refresh token, so the batch_parent's own
    // `expires_at` (which is not a real per-holder expiration) must not be set
    assert_eq!(None, credential.expires_at);

    // each individual batch item still carries its own real expiration (parsed from its
    // signed credential's `exp`), regardless of the parent's refresh-token-governed state
    let batch_items = context
        .db
        .credentials
        .list(CredentialFilterValue::ParentCredential(credential.id).condition())
        .await;
    assert_eq!(2, batch_items.len());
    assert!(credential.claims.as_ref().await.unwrap().is_empty());
    let mut claim_ids = std::collections::HashSet::new();
    for item in batch_items {
        let claims = item.claims.as_ref().await.unwrap();
        assert!(!claims.is_empty());
        let mut has_metadata = false;
        for claim in &claims {
            assert!(claim_ids.insert(claim.id));
            has_metadata |= claim.schema.as_ref().await.unwrap().metadata;
        }
        assert!(has_metadata);
        assert!(claims.iter().any(|claim| claim.path == "string"));
        assert_eq!(CredentialType::BatchItem, item.r#type);
        assert!(item.expires_at.is_some());
    }
}

#[tokio::test]
async fn test_issuance_accept_batch_without_refresh_token_keeps_batch_parent_expires_at() {
    // GIVEN
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

    // no `refresh_token` in the token response: the issuer does not support refreshing this
    // batch, so the batch_parent must fall back to a real per-item expiration
    context
        .server_mock
        .token_endpoint_without_refresh_token(credential_schema.id, "123")
        .await;

    // WHEN
    let before = one_core::clock::now_utc();
    let resp = accept_batch_issuance(
        &context,
        &organisation,
        &credential_schema,
        &issuer_key,
        &issuer_did,
    )
    .await;
    let after = one_core::clock::now_utc();

    // THEN
    let credential = context.db.credentials.get(&resp["id"].parse()).await;
    assert_eq!(CredentialType::BatchParent, credential.r#type);
    assert!(credential.format.is_none());
    // `w3c_jwt_vc` always signs the issued credentials with `exp` set to `now + 10 hours`;
    // the batch_parent should inherit that real value from its first batch item
    let expires_at = credential.expires_at.unwrap();
    assert!(expires_at >= before + Duration::hours(10) - Duration::seconds(1));
    assert!(expires_at <= after + Duration::hours(10));

    // every batch item is individually signed (so their `exp` values can differ by a hair), but
    // the parent's `expires_at` is a literal copy of one specific item's own real value, not
    // just something in the same ballpark - confirm it's an exact match, and that every item
    // still carries its own real expiration regardless of what the parent stores
    let batch_items = context
        .db
        .credentials
        .list(CredentialFilterValue::ParentCredential(credential.id).condition())
        .await;
    assert_eq!(2, batch_items.len());
    for item in &batch_items {
        assert_eq!(CredentialType::BatchItem, item.r#type);
        assert!(item.expires_at.is_some());
    }
    assert!(
        batch_items
            .iter()
            .any(|item| item.expires_at == credential.expires_at)
    );
}

#[tokio::test]
async fn test_issuance_accept_batch_marks_autogenerated_holder_binding_identifiers() {
    // GIVEN
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

    context
        .server_mock
        .token_endpoint(credential_schema.id, "123")
        .await;

    // WHEN
    let resp = accept_batch_issuance(
        &context,
        &organisation,
        &credential_schema,
        &issuer_key,
        &issuer_did,
    )
    .await;

    // THEN
    let credential = context.db.credentials.get(&resp["id"].parse()).await;
    assert_eq!(CredentialType::BatchParent, credential.r#type);
    assert!(credential.format.is_none());

    let batch_items = context
        .db
        .credentials
        .list(CredentialFilterValue::ParentCredential(credential.id).condition())
        .await;
    assert_eq!(2, batch_items.len());

    let mut autogenerated_identifier_ids = HashSet::new();
    for item in &batch_items {
        assert_eq!(CredentialType::BatchItem, item.r#type);

        let holder_identifier = item
            .holder_identifier
            .as_ref()
            .expect("batch item has a holder identifier")
            .as_ref()
            .await
            .unwrap();
        assert!(
            holder_identifier.autogenerated,
            "auto-generated holder-binding identifier for batch item {} must be flagged autogenerated",
            item.id
        );
        autogenerated_identifier_ids.insert(holder_identifier.id);
    }
    // each batch item got its own distinct auto-generated binding identifier, not a shared one
    assert_eq!(2, autogenerated_identifier_ids.len());
}

#[tokio::test]
async fn test_issuance_accept_batch_deletes_unused_autogenerated_holder_binding() {
    // GIVEN a batch offer of two credentials, of which the issuer issues only one
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

    context
        .server_mock
        .token_endpoint(credential_schema.id, "123")
        .await;
    context
        .server_mock
        .ssi_credential_endpoint_dynamic(
            credential_schema.id,
            "123",
            issuer_key,
            issuer_did,
            Some(1),
            1,
        )
        .await;
    context
        .server_mock
        .ssi_nonce_endpoint("OPENID4VCI_FINAL1", "test-nonce", 1)
        .await;
    let interaction = batch_issuance_interaction(&context, &organisation, &credential_schema).await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, None, None, None, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let credential = context.db.credentials.get(&resp["id"].parse()).await;
    let holder_key_id = credential.key.as_ref().unwrap().id();
    let holder_identifier_id = credential.holder_identifier.as_ref().unwrap().id();

    // only the binding of the issued credential remains
    let keys = organisation_keys(&context, &organisation).await;
    assert_eq!(keys["totalItems"], 1);
    keys["values"][0]["id"].assert_eq(&holder_key_id);
    let identifiers = local_identifiers(&context, &organisation).await;
    assert_eq!(identifiers["totalItems"], 1);
    identifiers["values"][0]["id"].assert_eq(&holder_identifier_id);
    let dids = organisation_dids(&context, &organisation).await;
    // the issuer DID and the holder DID of the issued credential
    assert_eq!(dids["totalItems"], 2);
}

#[tokio::test]
async fn test_issuance_accept_batch_deletes_autogenerated_holder_bindings_when_token_request_fails()
{
    // GIVEN a batch offer of two credentials, the issuer rejects the token request
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            TestingCreateSchemaParams {
                batch_size: Some(2),
                ..Default::default()
            },
        )
        .await;
    let interaction = batch_issuance_interaction(&context, &organisation, &credential_schema).await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, None, None, None, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);

    // the bindings generated for the token request are gone
    let keys = organisation_keys(&context, &organisation).await;
    assert_eq!(keys["totalItems"], 0);
    let identifiers = local_identifiers(&context, &organisation).await;
    assert_eq!(identifiers["totalItems"], 0);
    let dids = organisation_dids(&context, &organisation).await;
    assert_eq!(dids["totalItems"], 0);
}

async fn organisation_keys(
    context: &TestContext,
    organisation: &one_core::model::organisation::Organisation,
) -> serde_json::Value {
    context
        .api
        .keys
        .list(KeyFilters {
            page: 0,
            page_size: 10,
            organisation_id: organisation.id,
            name: None,
            key_types: None,
            key_storages: None,
            ids: None,
            is_remote: None,
            created_date_after: None,
            created_date_before: None,
            last_modified_after: None,
            last_modified_before: None,
        })
        .await
        .json_value()
        .await
}

async fn local_identifiers(
    context: &TestContext,
    organisation: &one_core::model::organisation::Organisation,
) -> serde_json::Value {
    context
        .api
        .identifiers
        .list(&organisation.id, Some("isRemote=false".to_string()))
        .await
        .json_value()
        .await
}

async fn organisation_dids(
    context: &TestContext,
    organisation: &one_core::model::organisation::Organisation,
) -> serde_json::Value {
    context
        .api
        .dids
        .list(DidFilters {
            page: 0,
            page_size: 10,
            organisation_id: organisation.id,
            deactivated: None,
            key_algorithms: None,
            key_roles: None,
            did_methods: None,
            key_ids: None,
        })
        .await
        .json_value()
        .await
}

#[tokio::test]
async fn test_issuance_accept_with_new_nested_optional_claims() {
    // GIVEN
    let (context, organisation, holder_did, ..) = TestContext::new_with_did(None).await;
    let issuer_key = Ecdsa.generate_key().unwrap();
    let multibase = issuer_key.key.public_key_as_multibase().unwrap();
    let issuer_did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                did_type: Some(DidType::Remote),
                did: Some(format!("did:key:{multibase}").parse().unwrap()),
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
                schema_id: Some("VerifiableCredential".to_string()),
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

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams::default(),
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

    let jwt_credential = w3c_jwt_vc(
        &issuer_key,
        "ES256",
        issuer_did.did.clone(),
        holder_did.did.clone(),
        json!({
            "string": "string",
            "address": { "city": "Zurich" }
        }),
    )
    .await;

    context
        .server_mock
        .ssi_credential_endpoint(credential_schema.id, "123", &[jwt_credential], 1, None)
        .await;
    context
        .server_mock
        .ssi_nonce_endpoint("OPENID4VCI_FINAL1", "test-nonce", 1)
        .await;
    context
        .server_mock
        .token_endpoint(credential_schema.id, "123")
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, None, None, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    let credential = context.db.credentials.get(&resp["id"].parse()).await;
    assert_eq!(CredentialStateEnum::Accepted, credential.state);

    let claims = credential.claims.as_ref().await.unwrap().to_owned();

    // new nested optional claim (schemas)
    let city_claim = claims
        .iter()
        .find(|claim| claim.path == "address/city")
        .unwrap();
    assert_eq!(city_claim.value.as_ref().unwrap(), "Zurich");
    assert_eq!(
        city_claim.schema.as_ref().await.unwrap().key,
        "address/city"
    );
    let updated_schema = context
        .db
        .credential_schemas
        .get(&credential_schema.id)
        .await;
    let claim_schema_keys: HashSet<String> = updated_schema
        .claim_schemas
        .as_ref()
        .await
        .unwrap()
        .iter()
        .map(|claim_schema| claim_schema.key.clone())
        .collect();
    assert!(claim_schema_keys.contains("address"));
    assert!(claim_schema_keys.contains("address/city"));
}

#[tokio::test]
async fn test_issuance_accept_schema_name_already_exists() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let issuer_key = Ecdsa.generate_key().unwrap();
    let multibase = issuer_key.key.public_key_as_multibase().unwrap();
    let issuer_did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                did_type: Some(DidType::Remote),
                did: Some(format!("did:key:{multibase}").parse().unwrap()),
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
                did: Some(issuer_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(issuer_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;
    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key,
                    reference: "1".to_string(),
                }]),
                did: Some(
                    DidValue::from_str("did:key:zDnaeY6V3KGKLzgK3C2hbb4zMpeVKbrtWhEP4WXUyTAbshioQ")
                        .unwrap(),
                ),
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
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let schema_id = Uuid::new_v4();
    let metadata_schema_id = Uuid::new_v4();

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            TestingCreateSchemaParams {
                claim_schemas: Some(vec![
                    ClaimSchema {
                        id: schema_id.into(),
                        key: "string".to_string(),
                        data_type: "STRING".to_string(),
                        created_date: datetime!(2024-10-20 12:00 +1),
                        last_modified: datetime!(2024-10-20 12:00 +1),
                        array: false,
                        metadata: false,
                        required: true,
                        translations: Default::default(),
                    },
                    ClaimSchema {
                        id: metadata_schema_id.into(),
                        key: "iss".to_string(),
                        data_type: "STRING".to_string(),
                        created_date: datetime!(2024-10-20 12:00 +1),
                        last_modified: datetime!(2024-10-20 12:00 +1),
                        array: false,
                        metadata: true,
                        required: false,
                        translations: Default::default(),
                    },
                ]),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams::default(),
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

    let jwt_credential = w3c_jwt_vc(
        &issuer_key,
        "ES256",
        issuer_did.did.clone(),
        holder_did.did.clone(),
        json!({"string":"string"}),
    )
    .await;

    context
        .server_mock
        .ssi_credential_endpoint(credential_schema.id, "123", &[jwt_credential], 1, None)
        .await;

    context
        .server_mock
        .ssi_nonce_endpoint("OPENID4VCI_FINAL1", "123", 1)
        .await;

    context
        .server_mock
        .token_endpoint(credential_schema.schema_id().await.unwrap(), "123")
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, None, None, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let credential_id = resp.json::<serde_json::Value>().await["id"].parse();
    let credential = context.db.credentials.get(&credential_id).await;
    let credential_schema = credential.schema.as_ref().await.unwrap();

    let history = context
        .db
        .histories
        .get_by_entity_id(&credential.id.into())
        .await;
    assert_eq!(history.values.len(), 2); // Accepted + Issued
    let actions = HashSet::from_iter(history.values.iter().map(|value| value.action));
    assert_eq!(
        actions,
        HashSet::from([HistoryAction::Accepted, HistoryAction::Issued])
    );

    // Assert credential schema has been automatically renamed due to clash with existing schema
    // also named "test".
    assert_ne!(credential_schema.name, "test");
    assert!(credential_schema.name.starts_with("test_"));
}

#[tokio::test]
async fn test_issuance_accept_openid4vc_issuer_invalid_signature() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key,
                    reference: "1".to_string(),
                }]),
                did: Some(
                    DidValue::from_str("did:key:zDnaeY6V3KGKLzgK3C2hbb4zMpeVKbrtWhEP4WXUyTAbshioQ")
                        .unwrap(),
                ),
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
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let schema_id = Uuid::new_v4();

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            TestingCreateSchemaParams {
                claim_schemas: Some(vec![ClaimSchema {
                    id: schema_id.into(),
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

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams::default(),
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

    let document = random_document().await;
    let (jwt_content, _sig) = document.rsplit_once(".").unwrap();
    let document_invalid_sig = format!("{jwt_content}.invalid");

    context
        .server_mock
        .ssi_credential_endpoint(
            credential_schema.id,
            "123",
            &[document_invalid_sig],
            1,
            None,
        )
        .await;

    context
        .server_mock
        .ssi_nonce_endpoint("OPENID4VCI_FINAL1", "test-nonce", 1)
        .await;

    context
        .server_mock
        .token_endpoint(credential_schema.id, "123")
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, None, None, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0173")
}

#[tokio::test]
async fn test_issuance_accept_openid4vc_with_key_id() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let issuer_key = Ecdsa.generate_key().unwrap();
    let multibase = issuer_key.key.public_key_as_multibase().unwrap();
    let issuer_did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                did_type: Some(DidType::Remote),
                did: Some(format!("did:key:{multibase}").parse().unwrap()),
                ..Default::default()
            },
        )
        .await;
    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key: key.clone(),
                    reference: "1".to_string(),
                }]),
                did: Some(
                    DidValue::from_str("did:key:zDnaeY6V3KGKLzgK3C2hbb4zMpeVKbrtWhEP4WXUyTAbshioQ")
                        .unwrap(),
                ),
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
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let schema_id = Uuid::new_v4();

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            TestingCreateSchemaParams {
                claim_schemas: Some(vec![ClaimSchema {
                    id: schema_id.into(),
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

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams::default(),
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

    let jwt_credential = w3c_jwt_vc(
        &issuer_key,
        "ES256",
        issuer_did.did.clone(),
        holder_did.did.clone(),
        json!({"string":"value"}),
    )
    .await;
    context
        .server_mock
        .ssi_credential_endpoint(credential_schema.id, "123", &[jwt_credential], 1, None)
        .await;

    context
        .server_mock
        .ssi_nonce_endpoint("OPENID4VCI_FINAL1", "test-nonce", 1)
        .await;

    context
        .server_mock
        .token_endpoint(credential_schema.id, "123")
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, Some(key.id), None, None)
        .await;

    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let credential = context.db.credentials.get(&resp["id"].parse()).await;
    let holder_identifier = credential
        .holder_identifier
        .as_ref()
        .unwrap()
        .as_ref()
        .await
        .unwrap();
    let_assert!(IdentifierData::Did(credential_holder_did) = &holder_identifier.data);
    assert_eq!(holder_did.id, credential_holder_did.id());
    assert_eq!(key.id, credential.key.unwrap().id());

    assert_eq!(CredentialStateEnum::Accepted, credential.state);
}

#[tokio::test]
async fn test_fail_issuance_accept_openid4vc_unknown_did() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let issuer_did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                did_type: Some(DidType::Remote),
                ..Default::default()
            },
        )
        .await;
    let identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(issuer_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(issuer_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams::default(),
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

    context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
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
        .issuance_accept(
            interaction.id,
            Some(Uuid::new_v4().into()),
            None,
            None,
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
    assert_eq!("BR_0024", resp.error_code().await);
}

#[tokio::test]
async fn test_fail_issuance_accept_openid4vc_unknown_key() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let issuer_did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                did_type: Some(DidType::Remote),
                ..Default::default()
            },
        )
        .await;
    let identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(issuer_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(issuer_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key,
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
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams::default(),
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

    context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
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
        .issuance_accept(
            interaction.id,
            holder_did.id,
            Some(Uuid::new_v4().into()),
            None,
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0330");
}

#[tokio::test]
async fn test_fail_issuance_accept_openid4vc_wrong_key_role() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let issuer_did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                did_type: Some(DidType::Remote),
                ..Default::default()
            },
        )
        .await;
    let identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(issuer_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(issuer_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;
    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
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
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams::default(),
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

    context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
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
        .issuance_accept(interaction.id, holder_did.id, Some(key.id), None, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0330");
}

#[tokio::test]
async fn test_fail_issuance_accept_openid4vc_no_suitable_key_storage() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            TestingCreateSchemaParams {
                key_storage_security: Some(KeyStorageSecurity::EnhancedBasic),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams::default(),
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

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, None, None, None, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0217", resp.error_code().await);
}

#[tokio::test]
async fn test_fail_issuance_accept_openid4vc_no_key_with_auth_role() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let issuer_did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                did_type: Some(DidType::Remote),
                ..Default::default()
            },
        )
        .await;
    let identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(issuer_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(issuer_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
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
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams::default(),
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

    context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
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
        .issuance_accept(interaction.id, holder_did.id, None, None, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0096", resp.error_code().await);
}

#[tokio::test]
async fn test_fail_issuance_accept_openid4vc_wallet_storage_type_not_met() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key: key.clone(),
                    reference: "1".to_string(),
                }]),
                did: Some(
                    DidValue::from_str("did:key:zDnaeY6V3KGKLzgK3C2hbb4zMpeVKbrtWhEP4WXUyTAbshioQ")
                        .unwrap(),
                ),
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
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
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
                key_storage_security: Some(KeyStorageSecurity::High),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams::default(),
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

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, Some(key.id), None, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0310", resp.error_code().await);
}

#[tokio::test]
async fn test_issuance_accept_openid4vc_with_tx_code() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let issuer_key = Ecdsa.generate_key().unwrap();
    let multibase = issuer_key.key.public_key_as_multibase().unwrap();
    let issuer_did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                did_type: Some(DidType::Remote),
                did: Some(format!("did:key:{multibase}").parse().unwrap()),
                ..Default::default()
            },
        )
        .await;
    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key,
                    reference: "1".to_string(),
                }]),
                did: Some(
                    DidValue::from_str("did:key:zDnaeY6V3KGKLzgK3C2hbb4zMpeVKbrtWhEP4WXUyTAbshioQ")
                        .unwrap(),
                ),
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
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let schema_id = Uuid::new_v4();

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            TestingCreateSchemaParams {
                claim_schemas: Some(vec![ClaimSchema {
                    id: schema_id.into(),
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

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams {
            require_tx_code: true,
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

    let jwt_credential = w3c_jwt_vc(
        &issuer_key,
        "ES256",
        issuer_did.did.clone(),
        holder_did.did.clone(),
        json!({"string":"string"}),
    )
    .await;
    context
        .server_mock
        .ssi_credential_endpoint(credential_schema.id, "123", &[jwt_credential], 1, None)
        .await;

    context
        .server_mock
        .ssi_nonce_endpoint("OPENID4VCI_FINAL1", "test-nonce", 1)
        .await;

    let tx_code = "45454";

    context
        .server_mock
        .token_endpoint_tx_code(credential_schema.schema_id().await.unwrap(), "123", tx_code)
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, None, Some(tx_code), None)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let credential = context.db.credentials.get(&resp["id"].parse()).await;
    let holder_identifier = credential
        .holder_identifier
        .as_ref()
        .unwrap()
        .as_ref()
        .await
        .unwrap();
    let_assert!(IdentifierData::Did(credential_holder_did) = &holder_identifier.data);
    assert_eq!(holder_did.id, credential_holder_did.id());

    assert_eq!(CredentialStateEnum::Accepted, credential.state);
}

#[tokio::test]
async fn test_wia_pop_iss_equals_wia_sub() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    create_wallet_unit_attestation_issuer_identifier(&context, &organisation).await;

    let holder_key_params = ecdsa_testing_params();
    let holder_public_jwk = Ecdsa
        .reconstruct_key(holder_key_params.public_key.as_ref().unwrap(), None, None)
        .unwrap()
        .public_key_as_jwk()
        .unwrap();

    let holder_auth_key = context
        .db
        .keys
        .create(&organisation, holder_key_params)
        .await;

    let wallet_unit = context
        .db
        .managed_instances
        .create(
            organisation.clone(),
            TestWalletInstance {
                public_key: Some(holder_public_jwk),
                ..Default::default()
            },
        )
        .await;

    let holder_wallet_unit = context
        .db
        .holder_wallet_units
        .create(
            organisation.clone(),
            Some(holder_auth_key),
            TestHolderWalletInstanceParams {
                provider_url: Some(context.config.app.core_base_url.clone()),
                provider_wallet_unit_id: Some(wallet_unit.id),
                ..Default::default()
            },
        )
        .await;

    let issuer_key = Ecdsa.generate_key().unwrap();
    let multibase = issuer_key.key.public_key_as_multibase().unwrap();
    let issuer_did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                did_type: Some(DidType::Remote),
                did: Some(format!("did:key:{multibase}").parse().unwrap()),
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
                did: Some(issuer_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(issuer_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let holder_did_key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key: holder_did_key,
                    reference: "1".to_string(),
                }]),
                did: Some(
                    DidValue::from_str("did:key:zDnaeY6V3KGKLzgK3C2hbb4zMpeVKbrtWhEP4WXUyTAbshioQ")
                        .unwrap(),
                ),
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
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let schema_id = Uuid::new_v4();
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test_wia_pop",
            &organisation,
            TestingCreateSchemaParams {
                claim_schemas: Some(vec![ClaimSchema {
                    id: schema_id.into(),
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
    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams {
            require_instance_attestation: true,
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

    let jwt_credential = w3c_jwt_vc(
        &issuer_key,
        "ES256",
        issuer_did.did.clone(),
        holder_did.did.clone(),
        json!({"string":"value"}),
    )
    .await;

    context
        .server_mock
        .ssi_credential_endpoint(credential_schema.id, "123", &[jwt_credential], 1, None)
        .await;

    context
        .server_mock
        .ssi_nonce_endpoint("OPENID4VCI_FINAL1", "test-nonce", 1)
        .await;

    context
        .server_mock
        .token_endpoint(credential_schema.id, "123")
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(
            interaction.id,
            holder_did.id,
            None,
            None,
            holder_wallet_unit.id,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);

    let requests = context.server_mock.received_requests().await.unwrap();
    let token_request = requests
        .iter()
        .find(|r| r.url.path().contains("/token"))
        .expect("Token request not found");

    let wia_header = token_request
        .headers
        .get("oauth-client-attestation")
        .expect("OAuth-Client-Attestation header not found");
    let wia_pop_header = token_request
        .headers
        .get("oauth-client-attestation-pop")
        .expect("OAuth-Client-Attestation-PoP header not found");

    let wia =
        Jwt::<()>::decompose_token(wia_header.to_str().unwrap()).expect("Failed to parse WIA JWT");
    let wia_pop = Jwt::<()>::decompose_token(wia_pop_header.to_str().unwrap())
        .expect("Failed to parse WIA PoP JWT");

    assert_eq!(
        wia_pop.payload.issuer, wia.payload.subject,
        "WIA PoP 'iss' must equal WIA 'sub' per OAuth Attestation-Based Client Auth spec section 5.2"
    );

    assert_eq!(
        wia.payload.subject,
        Some("eudiw-abca".to_string()),
        "WIA 'sub' should be wallet_client_id from config"
    );
}

#[tokio::test]
async fn test_issuance_accept_persists_issuer_display_translations_and_logo() {
    use one_core::model::blob::BlobType;
    use one_core::model::localized_text::LocalizedTextField;

    const LOGO_URI: &str = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=";

    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let issuer_key = Ecdsa.generate_key().unwrap();
    let multibase = issuer_key.key.public_key_as_multibase().unwrap();
    let issuer_did: DidValue = format!("did:key:{multibase}").parse().unwrap();

    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key,
                    reference: "1".to_string(),
                }]),
                did: Some(
                    DidValue::from_str("did:key:zDnaeY6V3KGKLzgK3C2hbb4zMpeVKbrtWhEP4WXUyTAbshioQ")
                        .unwrap(),
                ),
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
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams {
            issuer_display: Some(json!([
                { "name": "English issuer", "locale": "en" },
                {
                    "name": "Deutscher Aussteller",
                    "locale": "de",
                    "logo": { "uri": LOGO_URI, "alt_text": "Logo Beschreibung" }
                }
            ])),
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

    let jwt_credential = w3c_jwt_vc(
        &issuer_key,
        "ES256",
        issuer_did.clone(),
        holder_did.did.clone(),
        json!({ "string": "string" }),
    )
    .await;
    context
        .server_mock
        .ssi_credential_endpoint(credential_schema.id, "123", &[jwt_credential], 1, None)
        .await;
    context
        .server_mock
        .ssi_nonce_endpoint("OPENID4VCI_FINAL1", "test-nonce", 1)
        .await;
    context
        .server_mock
        .token_endpoint(credential_schema.id, "123")
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, None, None, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let credential = context.db.credentials.get(&resp["id"].parse()).await;
    let issuer_identifier = credential
        .issuer_identifier
        .as_ref()
        .unwrap()
        .as_ref()
        .await
        .unwrap();

    // localized text rows from the issuer display
    let texts = context.db.localized_text.get(issuer_identifier.id).await;
    let lookup = |field: LocalizedTextField, lang: &str| {
        texts
            .iter()
            .find(|t| t.field == field && t.lang == lang)
            .map(|t| t.value.as_str())
    };
    assert_eq!(
        lookup(LocalizedTextField::Name, "en"),
        Some("English issuer")
    );
    assert_eq!(
        lookup(LocalizedTextField::Name, "de"),
        Some("Deutscher Aussteller")
    );
    assert_eq!(
        lookup(LocalizedTextField::LogoAltText, "de"),
        Some("Logo Beschreibung")
    );

    // logo persisted as an IdentifierLogo blob storing the URI verbatim
    let logo_blob_id = issuer_identifier
        .logo
        .expect("issuer identifier logo should be set");
    let blob = context.db.blobs.get(&logo_blob_id).await.unwrap();
    assert_eq!(blob.r#type, BlobType::IdentifierLogo);
    assert_eq!(blob.value, LOGO_URI.as_bytes());
}

#[tokio::test]
async fn test_issuance_accept_refreshes_display_for_existing_issuer_identifier() {
    use one_core::model::blob::BlobType;
    use one_core::model::localized_text::LocalizedTextField;

    const SMALL_PNG_DATA_URI: &str = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=";

    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let issuer_key = Ecdsa.generate_key().unwrap();
    let multibase = issuer_key.key.public_key_as_multibase().unwrap();
    let issuer_did_value: DidValue = format!("did:key:{multibase}").parse().unwrap();

    // pre-existing issuer DID + identifier (no translations, no logo)
    let issuer_did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                did_type: Some(DidType::Remote),
                did: Some(issuer_did_value.clone()),
                ..Default::default()
            },
        )
        .await;
    let issuer_identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(issuer_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(true),
                ..Default::default()
            },
        )
        .await;

    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key,
                    reference: "1".to_string(),
                }]),
                did: Some(
                    DidValue::from_str("did:key:zDnaeY6V3KGKLzgK3C2hbb4zMpeVKbrtWhEP4WXUyTAbshioQ")
                        .unwrap(),
                ),
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
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams {
            issuer_display: Some(json!([
                {
                    "name": "Deutscher Aussteller",
                    "locale": "de",
                    "logo": { "uri": SMALL_PNG_DATA_URI, "alt_text": "alt" }
                }
            ])),
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

    let jwt_credential = w3c_jwt_vc(
        &issuer_key,
        "ES256",
        issuer_did_value.clone(),
        holder_did.did.clone(),
        json!({ "string": "string" }),
    )
    .await;
    context
        .server_mock
        .ssi_credential_endpoint(credential_schema.id, "123", &[jwt_credential], 1, None)
        .await;
    context
        .server_mock
        .ssi_nonce_endpoint("OPENID4VCI_FINAL1", "test-nonce", 1)
        .await;
    context
        .server_mock
        .token_endpoint(credential_schema.id, "123")
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, None, None, None)
        .await;

    // THEN – the pre-existing identifier is reused and its display is refreshed
    assert_eq!(resp.status(), 200);
    let credential = context
        .db
        .credentials
        .get(&resp.json_value().await["id"].parse())
        .await;
    let used_issuer = credential
        .issuer_identifier
        .as_ref()
        .unwrap()
        .as_ref()
        .await
        .unwrap();
    assert_eq!(used_issuer.id, issuer_identifier.id);

    let texts = context.db.localized_text.get(issuer_identifier.id).await;
    let lookup = |field: LocalizedTextField, lang: &str| {
        texts
            .iter()
            .find(|t| t.field == field && t.lang == lang)
            .map(|t| t.value.as_str())
    };
    assert_eq!(
        lookup(LocalizedTextField::Name, "de"),
        Some("Deutscher Aussteller")
    );
    assert_eq!(lookup(LocalizedTextField::LogoAltText, "de"), Some("alt"));

    let logo_blob_id = used_issuer.logo.expect("issuer logo should now be set");
    let blob = context.db.blobs.get(&logo_blob_id).await.unwrap();
    assert_eq!(blob.r#type, BlobType::IdentifierLogo);
    assert_eq!(blob.value, SMALL_PNG_DATA_URI.as_bytes());
}
