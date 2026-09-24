use assert2::let_assert;
use one_core::clock::now_utc;
use one_core::model::credential::{
    Clearable, Credential, CredentialFilterValue, CredentialRole, CredentialStateEnum,
    CredentialType, UpdateCredentialRequest,
};
use one_core::model::did::{Did, DidType, KeyRole, RelatedKey};
use one_core::model::identifier::{Identifier, IdentifierData, IdentifierType};
use one_core::model::interaction::{Interaction, InteractionType};
use one_core::model::key::Key;
use one_core::model::list_filter::ListFilterValue;
use one_core::model::organisation::Organisation;
use one_core::model::proof::{Proof, ProofStateEnum};
use sea_orm::ExprTrait;
use serde_json::json;
use shared_types::CredentialId;
use similar_asserts::assert_eq;
use uuid::Uuid;
use wiremock::MockBuilder;
use wiremock::matchers::body_string_contains;

use crate::fixtures::{
    ClaimData, TestingCredentialParams, TestingCredentialSchemaParams, TestingDidParams,
    TestingIdentifierParams, TestingKeyParams, create_credential_schema_with_claims,
};
use crate::utils::context::TestContext;
use crate::utils::db_clients::blobs::TestingBlobParams;
use crate::utils::db_clients::proofs::TestingProofParams;
use crate::{fixtures, utils};

#[tokio::test]
async fn test_presentation_submit_endpoint_for_openid4vp_dcql() {
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let (verifier_did, verifier_identifier, credential, interaction, proof) =
        setup_submittable_presentation_dcql(&context, &organisation, &identifier, None).await;

    context
        .server_mock
        .ssi_request_uri_endpoint(Some(|mock_builder: MockBuilder| {
            // Just sample query params as they are too dynamic and contain random ids
            mock_builder
                .and(body_string_contains("state"))
                .and(body_string_contains("53c44733-4f9d-4db2-aa83-afb8e17b500f")) // this is the state
                .and(body_string_contains("vp_token"))
                .and(body_string_contains("input_0"))
        }))
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .presentation_submit_v2(interaction.id, credential.id, &[], &[])
        .await;

    // THEN
    assert_eq!(resp.status(), 204);

    let proof = fixtures::get_proof(&context.db.db_conn, &proof.id).await;
    assert_eq!(proof.state, ProofStateEnum::Accepted);
    assert!(
        proof
            .claims
            .as_ref()
            .await
            .unwrap()
            .iter()
            .any(|c| c.claim.value == Some("test".to_string()))
    );
    let_assert!(
        Identifier {
            data: IdentifierData::Did(proof_verifier_did),
            ..
        } = proof
            .verifier_identifier
            .as_ref()
            .unwrap()
            .as_ref()
            .await
            .unwrap()
            .to_owned()
    );
    assert_eq!(
        proof_verifier_did.as_ref().await.unwrap().did,
        verifier_did.did
    );
    // There is no longer a single holder identifier associated with the proof
    let proof_history = context
        .db
        .histories
        .get_by_entity_id(&proof.id.into())
        .await;
    assert_eq!(
        proof_history
            .values
            .first()
            .as_ref()
            .unwrap()
            .target
            .as_ref()
            .unwrap(),
        &verifier_identifier.id.to_string()
    )
}

#[tokio::test]
async fn test_presentation_submit_endpoint_user_selection_unknown_claim() {
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;

    let (_, _, credential, interaction, _) =
        setup_submittable_presentation_dcql(&context, &organisation, &identifier, None).await;

    // WHEN
    let resp = context
        .api
        .interactions
        .presentation_submit_v2(interaction.id, credential.id, &["unknown_claim"], &[])
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0291")
}

#[tokio::test]
async fn test_presentation_submit_endpoint_user_selection_duplicate_claim() {
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;

    let (_, _, credential, interaction, _) =
        setup_submittable_presentation_dcql(&context, &organisation, &identifier, None).await;

    // WHEN
    let resp = context
        .api
        .interactions
        .presentation_submit_v2(
            interaction.id,
            credential.id,
            &["duplicate", "duplicate"],
            &[],
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0291")
}

#[tokio::test]
async fn test_presentation_submit_endpoint_for_openid4vp_dcql_batch_credential() {
    check_batch_presentation(false, CredentialType::BatchItem).await;
}

#[tokio::test]
async fn test_presentation_submit_endpoint_for_openid4vp_dcql_batch_item_claims() {
    check_batch_presentation(true, CredentialType::BatchItem).await;
}

async fn check_batch_presentation(item_claims: bool, submitted_type: CredentialType) {
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential = setup_batch_credential(&context, &organisation, &identifier, 2).await;
    let (verifier_did, verifier_identifier, credential, interaction, proof) =
        setup_submittable_presentation_dcql(&context, &organisation, &identifier, Some(credential))
            .await;

    if item_claims {
        let claims = credential.claims.as_ref().await.unwrap().to_owned();
        let items = batch_items(&context, credential.id).await;
        for item in items {
            let claims = claims
                .iter()
                .cloned()
                .map(|mut claim| {
                    claim.id = Uuid::new_v4().into();
                    claim.credential_id = item.id;
                    claim
                })
                .collect();
            context
                .db
                .credentials
                .update(
                    item.id,
                    UpdateCredentialRequest {
                        claims: Some(claims),
                        ..Default::default()
                    },
                )
                .await;
        }
        context
            .db
            .credentials
            .update(
                credential.id,
                UpdateCredentialRequest {
                    claims: Some(vec![]),
                    ..Default::default()
                },
            )
            .await;
    }

    context
        .server_mock
        .ssi_request_uri_endpoint(Some(|mock_builder: MockBuilder| {
            // Just sample query params as they are too dynamic and contain random ids
            mock_builder
                .and(body_string_contains("state"))
                .and(body_string_contains("53c44733-4f9d-4db2-aa83-afb8e17b500f")) // this is the state
                .and(body_string_contains("vp_token"))
                .and(body_string_contains("input_0"))
        }))
        .await;

    let selected_id = selected_batch_item(&context, proof.id).await;

    let submitted_id = match submitted_type {
        CredentialType::BatchParent => credential.id,
        CredentialType::BatchItem => selected_id,
        CredentialType::Single => unreachable!(),
    };
    // WHEN
    let resp = context
        .api
        .interactions
        .presentation_submit_v2(interaction.id, submitted_id, &[], &[])
        .await;

    // THEN
    assert_eq!(resp.status(), 204);

    let proof = fixtures::get_proof(&context.db.db_conn, &proof.id).await;
    assert_eq!(proof.state, ProofStateEnum::Accepted);
    assert!(
        proof
            .claims
            .as_ref()
            .await
            .unwrap()
            .iter()
            .any(|c| c.claim.value == Some("test".to_string()))
    );
    let_assert!(
        Identifier {
            data: IdentifierData::Did(proof_verifier_did),
            ..
        } = proof
            .verifier_identifier
            .as_ref()
            .unwrap()
            .as_ref()
            .await
            .unwrap()
            .to_owned()
    );
    assert_eq!(
        proof_verifier_did.as_ref().await.unwrap().did,
        verifier_did.did
    );
    let proof_history = context
        .db
        .histories
        .get_by_entity_id(&proof.id.into())
        .await;
    assert_eq!(
        proof_history
            .values
            .first()
            .as_ref()
            .unwrap()
            .target
            .as_ref()
            .unwrap(),
        &verifier_identifier.id.to_string()
    );

    let items = batch_items(&context, credential.id).await;
    // Only one item consumed
    assert!(items.iter().any(|c| c.consumed_at.is_some()));
    assert!(items.iter().any(|c| c.consumed_at.is_none()));
    let consumed = items.iter().find(|c| c.consumed_at.is_some()).unwrap();
    assert_eq!(consumed.id, selected_id);
    let expected_owner = if item_claims {
        consumed.id
    } else {
        credential.id
    };
    assert!(
        proof
            .claims
            .as_ref()
            .await
            .unwrap()
            .iter()
            .all(|claim| claim.claim.credential_id == expected_owner)
    );
    assert!(
        proof
            .claims
            .as_ref()
            .await
            .unwrap()
            .iter()
            .all(|claim| claim.credential.id() == selected_id)
    );
}

#[tokio::test]
async fn test_presentation_submit_endpoint_for_openid4vp_dcql_batch_parent() {
    check_batch_presentation(true, CredentialType::BatchParent).await;
}

#[tokio::test]
async fn test_presentation_submit_endpoint_for_openid4vp_dcql_batch_consumed() {
    let batch = BatchPresentation::new(2).await;
    batch
        .update_selected(UpdateCredentialRequest {
            consumed_at: Clearable::ForceSet(Some(now_utc())),
            ..Default::default()
        })
        .await;
    batch.assert_rejected(batch.selected_id).await;
}

#[tokio::test]
async fn mixed_format_batch_parent_presents_matching_item() {
    check_mixed_format_batch_submission(CredentialType::BatchParent).await;
}

#[tokio::test]
async fn mixed_format_batch_item_presents_later_expiring_item() {
    check_mixed_format_batch_submission(CredentialType::BatchItem).await;
}

async fn check_mixed_format_batch_submission(submitted_type: CredentialType) {
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let batch = setup_mixed_format_batch(&context, &organisation, &identifier).await;
    // Definition recommends the earliest-expiring JWT item; BBS does not match.
    let (_, _, _, interaction, proof) = setup_submittable_presentation_dcql(
        &context,
        &organisation,
        &identifier,
        Some(batch.parent.clone()),
    )
    .await;
    let definition = context
        .api
        .proofs
        .presentation_definition_v2(proof.id)
        .await;
    assert_eq!(definition.status(), 200);
    let definition = definition.json_value().await;
    let applicable = definition["credentialQueries"]["input_0"]["applicableCredentials"]
        .as_array()
        .unwrap();
    assert_eq!(applicable.len(), 1);
    assert_eq!(
        applicable[0]["id"],
        batch.earliest_expiring_jwt_item.to_string()
    );
    assert_eq!(applicable[0]["parentId"], batch.parent.id.to_string());
    assert_eq!(applicable[0]["type"], "BATCH_ITEM");
    assert_eq!(applicable[0]["format"], "JWT");

    let rejected = context
        .api
        .interactions
        .presentation_submit_v2(interaction.id, batch.bbs_item, &[], &[])
        .await;
    assert_eq!(rejected.status(), 400);
    assert_eq!(rejected.error_code().await, "BR_0291");

    let (submitted_id, presented_id, remaining_id) = match submitted_type {
        CredentialType::BatchParent => (
            batch.parent.id,
            batch.earliest_expiring_jwt_item,
            batch.later_expiring_jwt_item,
        ),
        CredentialType::BatchItem => (
            batch.later_expiring_jwt_item,
            batch.later_expiring_jwt_item,
            batch.earliest_expiring_jwt_item,
        ),
        CredentialType::Single => unreachable!(),
    };
    context
        .server_mock
        .ssi_request_uri_endpoint(None::<fn(MockBuilder) -> MockBuilder>)
        .await;
    let response = context
        .api
        .interactions
        .presentation_submit_v2(interaction.id, submitted_id, &[], &[])
        .await;
    assert_eq!(response.status(), 204);
    let items = batch_items(&context, batch.parent.id).await;
    let consumed_ids: Vec<_> = items
        .into_iter()
        .filter(|item| item.consumed_at.is_some())
        .map(|item| item.id)
        .collect();
    assert_eq!(consumed_ids, vec![presented_id]);
    let (_, _, _, _, next_proof) = setup_submittable_presentation_dcql(
        &context,
        &organisation,
        &identifier,
        Some(batch.parent.clone()),
    )
    .await;
    assert_eq!(
        selected_batch_item(&context, next_proof.id).await,
        remaining_id
    );
}

#[tokio::test]
async fn mixed_format_batch_parent_rejection() {
    for (has_matching_format, error_code) in [(true, "BR_0443"), (false, "BR_0291")] {
        let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
        let batch = setup_mixed_format_batch(&context, &organisation, &identifier).await;
        let bbs_format = context
            .db
            .credentials
            .get(&batch.bbs_item)
            .await
            .format
            .unwrap()
            .id();
        // Consumed JWT items imply exhaustion; consumed BBS items never match this request.
        // In either case, the remaining available BBS item cannot satisfy the JWT request.
        for id in [
            batch.earliest_expiring_jwt_item,
            batch.later_expiring_jwt_item,
        ] {
            context
                .db
                .credentials
                .update(
                    id,
                    UpdateCredentialRequest {
                        consumed_at: Clearable::ForceSet(Some(now_utc())),
                        format: (!has_matching_format).then_some(bbs_format),
                        ..Default::default()
                    },
                )
                .await;
        }
        let (_, _, _, interaction, _) = setup_submittable_presentation_dcql(
            &context,
            &organisation,
            &identifier,
            Some(batch.parent.clone()),
        )
        .await;
        let response = context
            .api
            .interactions
            .presentation_submit_v2(interaction.id, batch.parent.id, &[], &[])
            .await;
        assert_eq!(response.status(), 400);
        assert_eq!(response.error_code().await, error_code);
        assert!(
            context
                .db
                .credentials
                .get(&batch.bbs_item)
                .await
                .consumed_at
                .is_none()
        );
    }
}

#[tokio::test]
async fn two_queries_reuse_the_same_batch_item() {
    check_two_queries_with_inherited_claims(false).await;
}

#[tokio::test]
async fn two_queries_record_different_batch_items_with_inherited_claims() {
    check_two_queries_with_inherited_claims(true).await;
}

async fn check_two_queries_with_inherited_claims(distinct_items: bool) {
    use one_core::model::interaction::UpdateInteractionRequest;
    use one_core::repository::DataRepository;
    use sql_data_provider::DataLayer;

    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let parent = setup_batch_credential(&context, &organisation, &identifier, 2).await;
    let (_, _, _, interaction, proof) = setup_submittable_presentation_dcql(
        &context,
        &organisation,
        &identifier,
        Some(parent.clone()),
    )
    .await;
    let mut data: serde_json::Value =
        serde_json::from_slice(interaction.data.as_ref().unwrap()).unwrap();
    let queries = data["dcql_query"]["credentials"].as_array_mut().unwrap();
    let mut second = queries[0].clone();
    second["id"] = json!("input_1");
    queries.push(second);
    DataLayer::build(context.db.db_conn.clone(), vec![])
        .get_interaction_repository()
        .update_interaction(
            interaction.id,
            UpdateInteractionRequest {
                data: Some(Some(serde_json::to_vec(&data).unwrap())),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    context
        .server_mock
        .ssi_request_uri_endpoint(Some(|builder: MockBuilder| {
            builder
                .and(body_string_contains("input_0"))
                .and(body_string_contains("input_1"))
        }))
        .await;
    let selected_id = selected_batch_item(&context, proof.id).await;
    let second_id = if distinct_items {
        batch_items(&context, parent.id)
            .await
            .into_iter()
            .find(|item| item.id != selected_id)
            .unwrap()
            .id
    } else {
        parent.id
    };
    let response = context
        .api
        .client
        .post(
            "/api/interaction/v2/presentation-submit",
            json!({
                "interactionId": interaction.id,
                "submission": {
                    "input_0": {"credentialId": selected_id},
                    "input_1": {"credentialId": second_id}
                }
            }),
        )
        .await;
    assert_eq!(response.status(), 204);
    let items = batch_items(&context, parent.id).await;
    assert_eq!(items.len(), 2);
    assert_eq!(
        items
            .iter()
            .filter(|item| item.consumed_at.is_some())
            .count(),
        if distinct_items { 2 } else { 1 }
    );
    let proof = context.db.proofs.get(&proof.id).await;
    let claims = proof.claims.as_ref().await.unwrap();
    assert_eq!(claims.len(), if distinct_items { 2 } else { 1 });
    assert!(
        claims
            .iter()
            .all(|entry| entry.claim.credential_id == parent.id)
    );
    let sources: std::collections::HashSet<_> =
        claims.iter().map(|entry| entry.credential.id()).collect();
    let expected = if distinct_items {
        vec![selected_id, second_id]
    } else {
        vec![selected_id]
    };
    assert_eq!(sources, expected.into_iter().collect());
    if distinct_items {
        assert_eq!(claims[0].claim.id, claims[1].claim.id);
    }
    drop(claims);

    let detail = context.api.proofs.get(proof.id).await;
    assert_eq!(detail.status(), 200);
    let detail = detail.json_value().await;
    let inputs = detail["proofInputs"].as_array().unwrap();
    let detail_sources: std::collections::HashSet<_> = inputs
        .iter()
        .map(|input| input["credential"]["id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        detail_sources,
        sources.iter().map(ToString::to_string).collect()
    );
}

struct BatchPresentation {
    context: TestContext,
    parent: Credential,
    items: Vec<Credential>,
    interaction: Interaction,
    proof: Proof,
    selected_id: CredentialId,
}

impl BatchPresentation {
    async fn new(num_items: usize) -> Self {
        let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
        let parent = setup_batch_credential(&context, &organisation, &identifier, num_items).await;
        let (_, _, parent, interaction, proof) =
            setup_submittable_presentation_dcql(&context, &organisation, &identifier, Some(parent))
                .await;
        let selected_id = selected_batch_item(&context, proof.id).await;
        let items = batch_items(&context, parent.id).await;
        assert_eq!(items.len(), num_items);
        Self {
            context,
            parent,
            items,
            interaction,
            proof,
            selected_id,
        }
    }

    async fn update_selected(&self, update: UpdateCredentialRequest) {
        self.context
            .db
            .credentials
            .update(self.selected_id, update)
            .await;
    }

    async fn assert_rejected(&self, credential_id: CredentialId) {
        self.assert_rejected_with_code(credential_id, "BR_0291")
            .await;
    }

    async fn assert_rejected_with_code(&self, credential_id: CredentialId, code: &str) {
        let response = self
            .context
            .api
            .interactions
            .presentation_submit_v2(self.interaction.id, credential_id, &[], &[])
            .await;
        assert_eq!(response.status(), 400);
        assert_eq!(response.error_code().await, code);
        assert_eq!(
            self.context.db.proofs.get(&self.proof.id).await.state,
            ProofStateEnum::Requested
        );
    }

    async fn assert_unconsumed(&self) {
        // Load by saved IDs so deleted items are checked as well.
        for item in &self.items {
            let stored = self.context.db.credentials.get(&item.id).await;
            assert!(stored.consumed_at.is_none());
        }
    }
}

async fn batch_items(context: &TestContext, parent_id: CredentialId) -> Vec<Credential> {
    context
        .db
        .credentials
        .list(CredentialFilterValue::ParentCredential(parent_id).condition())
        .await
}

async fn selected_batch_item(
    context: &TestContext,
    proof_id: shared_types::ProofId,
) -> shared_types::CredentialId {
    let response = context
        .api
        .proofs
        .presentation_definition_v2(proof_id)
        .await;
    assert_eq!(response.status(), 200);
    let definition = response.json_value().await;
    serde_json::from_value(
        definition["credentialQueries"]["input_0"]["applicableCredentials"][0]["id"].clone(),
    )
    .unwrap()
}

struct MixedFormatBatch {
    parent: Credential,
    earliest_expiring_jwt_item: shared_types::CredentialId,
    later_expiring_jwt_item: shared_types::CredentialId,
    bbs_item: shared_types::CredentialId,
}

async fn setup_mixed_format_batch(
    context: &TestContext,
    organisation: &Organisation,
    identifier: &Identifier,
) -> MixedFormatBatch {
    use one_core::model::credential::CredentialType;
    use one_core::model::credential_schema::UpdateCredentialSchemaRequest;
    use one_core::repository::DataRepository;
    use sea_orm::ConnectionTrait;
    use sea_orm::sea_query::{Alias, Expr, Query};
    use sql_data_provider::DataLayer;

    let parent = setup_batch_credential(context, organisation, identifier, 2).await;
    let [earliest_expiring_jwt, later_expiring_jwt]: [Credential; 2] = context
        .db
        .credentials
        .list(CredentialFilterValue::ParentCredential(parent.id).condition())
        .await
        .try_into()
        .unwrap();
    let schema = parent.schema.as_ref().await.unwrap();
    // BBS sorts before JWT in the schema, so using the first schema format would be wrong.
    let mut bbs_format = schema.formats.as_ref().await.unwrap()[0].clone();
    bbs_format.id = Uuid::new_v4().into();
    bbs_format.format = "JSON_LD_BBSPLUS".into();
    bbs_format.ecosystem_schema_id = "other-schema-id".into();
    bbs_format.claim_mappings = Default::default();
    DataLayer::build(context.db.db_conn.clone(), vec![])
        .get_credential_schema_repository()
        .update_credential_schema(
            &schema.id,
            UpdateCredentialSchemaRequest {
                formats: Some(vec![bbs_format.clone()]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let bbs = context
        .db
        .credentials
        .create(
            &schema,
            CredentialStateEnum::Accepted,
            identifier,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams {
                role: Some(CredentialRole::Holder),
                r#type: Some(CredentialType::BatchItem),
                parent_id: Some(parent.id),
                format: Some(bbs_format),
                ..Default::default()
            },
        )
        .await;
    // BBS expires first. Creation order disagrees with expiry order, so selecting
    // the oldest matching item would choose the wrong JWT item.
    let expiry = now_utc() + time::Duration::days(1);
    for (id, seconds) in [
        (bbs.id, -1),
        (earliest_expiring_jwt.id, 0),
        (later_expiring_jwt.id, 1),
    ] {
        context
            .db
            .db_conn
            .execute(
                Query::update()
                    .table(Alias::new("credential"))
                    .value(
                        Alias::new("created_date"),
                        parent.created_date - time::Duration::seconds(seconds),
                    )
                    .value(
                        Alias::new("expires_at"),
                        expiry + time::Duration::seconds(seconds),
                    )
                    .and_where(Expr::col(Alias::new("id")).eq(id.to_string())),
            )
            .await
            .unwrap();
    }
    // The generic batch fixture models legacy storage; new parents have no format.
    context
        .db
        .db_conn
        .execute(
            Query::update()
                .table(Alias::new("credential"))
                .value(Alias::new("format"), Option::<String>::None)
                .and_where(Expr::col(Alias::new("id")).eq(parent.id.to_string())),
        )
        .await
        .unwrap();
    let parent = context.db.credentials.get(&parent.id).await;
    assert!(parent.format.is_none());
    MixedFormatBatch {
        parent,
        earliest_expiring_jwt_item: earliest_expiring_jwt.id,
        later_expiring_jwt_item: later_expiring_jwt.id,
        bbs_item: bbs.id,
    }
}

async fn setup_batch_credential(
    context: &TestContext,
    organisation: &Organisation,
    identifier: &Identifier,
    num_items: usize,
) -> Credential {
    let mut schema = fixtures::create_credential_schema(
        &context.db.db_conn,
        organisation,
        Some(TestingCredentialSchemaParams {
            name: Some("Schema1".to_string()),
            ..Default::default()
        }),
    )
    .await;
    let (key, holder_identifier) = create_holder_identifier(context, organisation).await;
    schema.batch_size = Some(2);

    context
        .db
        .credentials
        .create_batch(
            &schema,
            CredentialStateEnum::Accepted,
            identifier,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams {
                role: Some(CredentialRole::Holder),
                holder_identifier: Some(holder_identifier),
                key: Some(key),
                ..Default::default()
            },
            num_items,
            Some(&context.db.blobs),
        )
        .await
}

async fn setup_submittable_presentation_dcql(
    context: &TestContext,
    organisation: &Organisation,
    issuer_identifier: &Identifier,
    credential: Option<Credential>,
) -> (Did, Identifier, Credential, Interaction, Proof) {
    let client_metadata = json!(
    {
        "jwks": {
            "keys": [{
                "crv": "P-256",
                "kid": "not-a-uuid",
                "kty": "EC",
                "x": "cd_LTtCQnat2XnDElumvgQAM5ZcnUMVTkPig458C1yc",
                "y": "iaQmPUgir80I2XCFqn2_KPqdWH0PxMzCCP8W3uPxlUA",
                "use": "enc"
            }]
        },
        "vp_formats_supported":
        {
            "jwt_vp_json":
            {
                "alg":["EdDSA"]
            },
            "jwt_vc_json":{
                "alg":["EdDSA"]
            },
            "ldp_vp":{
                "proof_type":["DataIntegrityProof"]
            },
            "mso_mdoc":{
                "alg":["EdDSA"]
            },
            "vc+sd-jwt": {
                "kb-jwt_alg_values": ["EdDSA", "ES256"],
                "sd-jwt_alg_values": ["EdDSA", "ES256"]
            }
        }
    });

    let verifier_key = context
        .db
        .keys
        .create(organisation, Default::default())
        .await;
    let verifier_did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                keys: Some(vec![
                    RelatedKey {
                        role: KeyRole::Authentication,
                        key: verifier_key.clone(),
                        reference: "1".to_string(),
                    },
                    RelatedKey {
                        role: KeyRole::AssertionMethod,
                        key: verifier_key.clone(),
                        reference: "1".to_string(),
                    },
                ]),
                ..Default::default()
            },
        )
        .await;
    let verifier_identifier = context
        .db
        .identifiers
        .create(
            organisation,
            TestingIdentifierParams {
                did: Some(verifier_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(verifier_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let credential = if let Some(credential) = credential {
        credential
    } else {
        let (holder_key, holder_identifier) = create_holder_identifier(context, organisation).await;
        let credential_schema = fixtures::create_credential_schema(
            &context.db.db_conn,
            organisation,
            Some(TestingCredentialSchemaParams {
                name: Some("Schema1".to_string()),
                ..Default::default()
            }),
        )
        .await;

        let blob = context
            .db
            .blobs
            .create(TestingBlobParams {
                value: Some("TOKEN".as_bytes().to_vec()),
                ..Default::default()
            })
            .await;

        fixtures::create_credential(
            &context.db.db_conn,
            &credential_schema,
            CredentialStateEnum::Accepted,
            issuer_identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                holder_identifier: Some(holder_identifier),
                key: Some(holder_key),
                role: Some(CredentialRole::Holder),
                credential_blob_id: Some(blob.id),
                ..Default::default()
            },
        )
        .await
    };

    let jwt_schema_id = {
        let schema = credential.schema.as_ref().await.unwrap();
        let formats = schema.formats.as_ref().await.unwrap();
        formats
            .iter()
            .find(|format| format.format == "JWT".into())
            .unwrap()
            .ecosystem_schema_id
            .clone()
    };
    let verifier_url = context.server_mock.uri();
    let interaction = fixtures::create_interaction(
        &context.db.db_conn,
        json!(
            {
                "response_type":"vp_token",
                "state": "53c44733-4f9d-4db2-aa83-afb8e17b500f",
                "nonce":"QnoICmZxqAUZdOlPJRVtbJrrHJRTDwCM",
                "client_id_scheme":"redirect_uri",
                "client_id": format!("{verifier_url}/mock/response"),
                "client_metadata": client_metadata,
                "response_mode":"direct_post",
                "response_uri": format!("{verifier_url}/mock/response"),
                "dcql_query":
                {
                    "credentials" : [
                        {
                            "id": "input_0",
                            "format": "jwt_vc_json",
                            "meta": {
                                "type_values": [[
                                    "https://www.w3.org/2018/credentials#VerifiableCredential",
                                    format!("{jwt_schema_id}#Schema1")
                                ]]
                            },
                            "claims": [
                                {
                                    "path": ["firstName"]
                                }
                            ]
                        }
                    ]
                }
            }
        )
        .to_string()
        .as_bytes(),
        organisation,
        InteractionType::Verification,
    )
    .await;

    let proof = context
        .db
        .proofs
        .create(
            ProofStateEnum::Requested,
            "OPENID4VP_FINAL1",
            TestingProofParams {
                verifier_identifier: Some(verifier_identifier.clone()),
                verifier_key: Some(verifier_key),
                interaction: Some(interaction.clone()),
                ..Default::default()
            },
        )
        .await;
    (
        verifier_did,
        verifier_identifier,
        credential,
        interaction,
        proof,
    )
}

async fn create_holder_identifier(
    context: &TestContext,
    organisation: &Organisation,
) -> (Key, Identifier) {
    let holder_key = fixtures::create_key(
        &context.db.db_conn,
        organisation,
        Some(TestingKeyParams {
            key_type: Some("ECDSA".to_string()),
            storage_type: Some("INTERNAL".to_string()),
            public_key: Some(vec![
                2, 41, 83, 61, 165, 86, 37, 125, 46, 237, 61, 7, 255, 169, 76, 11, 51, 20, 151,
                189, 221, 246, 169, 103, 136, 2, 114, 144, 254, 4, 26, 202, 33,
            ]),
            key_reference: Some(vec![
                214, 40, 173, 242, 210, 229, 35, 49, 245, 164, 136, 170, 0, 0, 0, 0, 0, 0, 0, 32,
                168, 61, 62, 181, 162, 142, 116, 226, 190, 20, 146, 183, 17, 166, 110, 17, 207, 54,
                243, 166, 143, 172, 23, 72, 196, 139, 42, 147, 222, 122, 234, 133, 236, 18, 64,
                113, 85, 218, 233, 136, 236, 48, 86, 184, 249, 54, 210, 76,
            ]),
            ..Default::default()
        }),
    )
    .await;
    let holder_did = fixtures::create_did(
        &context.db.db_conn,
        organisation,
        Some(TestingDidParams {
            did_method: Some("KEY".into()),
            did: Some(
                "did:key:zDnaeTDHP1rEYDFKYtQtH9Yx6Aycyxj7y9PXYDSeDKHnWUFP6"
                    .parse()
                    .unwrap(),
            ),
            keys: Some(vec![RelatedKey {
                role: KeyRole::Authentication,
                key: holder_key.clone(),
                reference: "1".to_string(),
            }]),
            ..Default::default()
        }),
    )
    .await;
    let holder_identifier = context
        .db
        .identifiers
        .create(
            organisation,
            TestingIdentifierParams {
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;
    (holder_key, holder_identifier)
}

#[tokio::test]
async fn test_presentation_submit_endpoint_for_openid4vp_dcql_array_claim() {
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;

    let claim_schema_id = Uuid::new_v4();
    let new_claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> =
        vec![(claim_schema_id, "array_claim", true, "STRING", true)];

    let credential_schema = create_credential_schema_with_claims(
        &context.db.db_conn,
        "Schema1",
        &organisation,
        false,
        &new_claim_schemas,
    )
    .await;

    let holder_key = fixtures::create_key(
        &context.db.db_conn,
        &organisation,
        Some(TestingKeyParams {
            key_type: Some("ECDSA".to_string()),
            storage_type: Some("INTERNAL".to_string()),
            public_key: Some(vec![
                2, 41, 83, 61, 165, 86, 37, 125, 46, 237, 61, 7, 255, 169, 76, 11, 51, 20, 151,
                189, 221, 246, 169, 103, 136, 2, 114, 144, 254, 4, 26, 202, 33,
            ]),
            key_reference: Some(vec![
                214, 40, 173, 242, 210, 229, 35, 49, 245, 164, 136, 170, 0, 0, 0, 0, 0, 0, 0, 32,
                168, 61, 62, 181, 162, 142, 116, 226, 190, 20, 146, 183, 17, 166, 110, 17, 207, 54,
                243, 166, 143, 172, 23, 72, 196, 139, 42, 147, 222, 122, 234, 133, 236, 18, 64,
                113, 85, 218, 233, 136, 236, 48, 86, 184, 249, 54, 210, 76,
            ]),
            ..Default::default()
        }),
    )
    .await;
    let holder_did = fixtures::create_did(
        &context.db.db_conn,
        &organisation,
        Some(TestingDidParams {
            did_method: Some("KEY".into()),
            did: Some(
                "did:key:zDnaeTDHP1rEYDFKYtQtH9Yx6Aycyxj7y9PXYDSeDKHnWUFP6"
                    .parse()
                    .unwrap(),
            ),
            keys: Some(vec![RelatedKey {
                role: KeyRole::Authentication,
                key: holder_key.clone(),
                reference: "1".to_string(),
            }]),
            ..Default::default()
        }),
    )
    .await;
    let holder_identifier = context
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
    let blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some("TOKEN".as_bytes().to_vec()),
            ..Default::default()
        })
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                holder_identifier: Some(holder_identifier.clone()),
                key: Some(holder_key),
                role: Some(CredentialRole::Holder),
                credential_blob_id: Some(blob.id),
                claims_data: Some(vec![
                    ClaimData {
                        schema_id: claim_schema_id.into(),
                        path: "array_claim".to_string(),
                        value: None,
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: claim_schema_id.into(),
                        path: "array_claim/0".to_string(),
                        value: Some("value1".to_string()),
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: claim_schema_id.into(),
                        path: "array_claim/1".to_string(),
                        value: Some("value2".to_string()),
                        selectively_disclosable: false,
                    },
                ]),
                ..Default::default()
            },
        )
        .await;

    let verifier_key = context
        .db
        .keys
        .create(&organisation, Default::default())
        .await;
    let verifier_did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                keys: Some(vec![
                    RelatedKey {
                        role: KeyRole::Authentication,
                        key: verifier_key.clone(),
                        reference: "1".to_string(),
                    },
                    RelatedKey {
                        role: KeyRole::AssertionMethod,
                        key: verifier_key.clone(),
                        reference: "1".to_string(),
                    },
                ]),
                ..Default::default()
            },
        )
        .await;
    let verifier_identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(verifier_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(verifier_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let verifier_url = context.server_mock.uri();
    let interaction_data = json!(
        {
            "response_type": "vp_token",
            "state": "53c44733-4f9d-4db2-aa83-afb8e17b500f",
            "nonce": "QnoICmZxqAUZdOlPJRVtbJrrHJRTDwCM",
            "client_id_scheme": "redirect_uri",
            "client_id": format!("{verifier_url}/mock/response"),
            "client_metadata": {
                "jwks": {
                    "keys": [{
                        "crv": "P-256",
                        "kid": "not-a-uuid",
                        "kty": "EC",
                        "x": "cd_LTtCQnat2XnDElumvgQAM5ZcnUMVTkPig458C1yc",
                        "y": "iaQmPUgir80I2XCFqn2_KPqdWH0PxMzCCP8W3uPxlUA",
                        "use": "enc"
                    }]
                },
                "vp_formats_supported": {
                    "jwt_vp_json": { "alg": ["EdDSA"] },
                    "jwt_vc_json": { "alg": ["EdDSA"] },
                    "ldp_vp": { "proof_type": ["DataIntegrityProof"] },
                    "mso_mdoc": { "alg": ["EdDSA"] },
                    "vc+sd-jwt": {
                        "kb-jwt_alg_values": ["EdDSA", "ES256"],
                        "sd-jwt_alg_values": ["EdDSA", "ES256"]
                    }
                }
            },
            "response_mode": "direct_post",
            "response_uri": format!("{verifier_url}/mock/response"),
            "dcql_query": {
                "credentials": [
                    {
                        "id": "query_0",
                        "format": "jwt_vc_json",
                        "meta": {
                            "type_values": [[credential_schema.id]]
                        },
                        "claims": [
                            {
                                "path": [
                                    "array_claim",
                                    1
                                ]
                            }
                        ]
                    }
                ]
            }
        }
    );

    let interaction = fixtures::create_interaction(
        &context.db.db_conn,
        interaction_data.to_string().as_bytes(),
        &organisation,
        InteractionType::Verification,
    )
    .await;

    let proof = context
        .db
        .proofs
        .create(
            ProofStateEnum::Requested,
            "OPENID4VP_FINAL1",
            TestingProofParams {
                verifier_identifier: Some(verifier_identifier.clone()),
                verifier_key: Some(verifier_key),
                interaction: Some(interaction.clone()),
                ..Default::default()
            },
        )
        .await;

    context
        .server_mock
        .ssi_request_uri_endpoint(Some(|mock_builder: MockBuilder| {
            // Just sample query params as they are too dynamic and contain random ids
            mock_builder
        }))
        .await;

    // WHEN
    let url = format!(
        "{}/api/interaction/v2/presentation-submit",
        context.config.app.core_base_url
    );

    let resp = utils::client()
        .post(url)
        .bearer_auth("test")
        .json(&json!({
          "interactionId": interaction.id,
          "submission": {
            "query_0": {
              "credentialId": credential.id
            }
          }
        }))
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 204);

    let proof = fixtures::get_proof(&context.db.db_conn, &proof.id).await;
    assert_eq!(proof.state, ProofStateEnum::Accepted);
    assert!(
        proof
            .claims
            .as_ref()
            .await
            .unwrap()
            .iter()
            .any(|c| c.claim.value == Some("value2".to_string()))
    );
    let_assert!(
        Identifier {
            data: IdentifierData::Did(proof_verifier_did),
            ..
        } = proof
            .verifier_identifier
            .as_ref()
            .unwrap()
            .as_ref()
            .await
            .unwrap()
            .to_owned()
    );
    assert_eq!(
        proof_verifier_did.as_ref().await.unwrap().did,
        verifier_did.did
    );
    let proof_history = context
        .db
        .histories
        .get_by_entity_id(&proof.id.into())
        .await;
    assert_eq!(
        proof_history
            .values
            .first()
            .as_ref()
            .unwrap()
            .target
            .as_ref()
            .unwrap(),
        &verifier_identifier.id.to_string()
    )
}

#[tokio::test]
async fn batch_item_submission_rejects_item_after_state_change() {
    for state in [
        CredentialStateEnum::Suspended,
        CredentialStateEnum::Revoked,
        CredentialStateEnum::Expired,
    ] {
        let batch = BatchPresentation::new(2).await;
        batch
            .update_selected(UpdateCredentialRequest {
                state: Some(state),
                ..Default::default()
            })
            .await;

        batch.assert_rejected(batch.selected_id).await;
        batch.assert_unconsumed().await;
        // A valid sibling is available, but submission must not substitute it.
        assert_ne!(
            selected_batch_item(&batch.context, batch.proof.id).await,
            batch.selected_id
        );
    }
}

#[tokio::test]
async fn batch_item_submission_rejects_item_after_expiry() {
    let batch = BatchPresentation::new(2).await;
    // Expiry must be checked even before the lifecycle task updates the Accepted state.
    batch
        .update_selected(UpdateCredentialRequest {
            expires_at: Some(now_utc() - time::Duration::seconds(1)),
            ..Default::default()
        })
        .await;

    batch.assert_rejected(batch.selected_id).await;
    batch.assert_unconsumed().await;
}

#[tokio::test]
async fn batch_item_submission_rejects_item_after_batch_deletion() {
    let batch = BatchPresentation::new(2).await;
    let response = batch.context.api.credentials.delete(&batch.parent.id).await;
    assert_eq!(response.status(), 204);
    for credential in std::iter::once(&batch.parent).chain(&batch.items) {
        let stored = batch.context.db.credentials.get(&credential.id).await;
        assert!(stored.deleted_at.is_some());
    }
    let definition = batch
        .context
        .api
        .proofs
        .presentation_definition_v2(batch.proof.id)
        .await;
    assert_eq!(definition.status(), 200);
    assert_eq!(
        definition.json_value().await["credentialQueries"]["input_0"]["failureHint"]["reason"],
        "NO_CREDENTIAL"
    );

    batch.assert_rejected(batch.selected_id).await;
    batch.assert_rejected(batch.parent.id).await;
    batch.assert_unconsumed().await;
}

#[tokio::test]
async fn batch_parent_submission_uses_next_available_item() {
    let batch = BatchPresentation::new(3).await;
    batch
        .update_selected(UpdateCredentialRequest {
            consumed_at: Clearable::ForceSet(Some(now_utc())),
            ..Default::default()
        })
        .await;
    let next_id = selected_batch_item(&batch.context, batch.proof.id).await;
    assert_ne!(next_id, batch.selected_id);
    batch
        .context
        .server_mock
        .ssi_request_uri_endpoint(None::<fn(MockBuilder) -> MockBuilder>)
        .await;

    let response = batch
        .context
        .api
        .interactions
        .presentation_submit_v2(batch.interaction.id, batch.parent.id, &[], &[])
        .await;
    assert_eq!(response.status(), 204);
    for item in batch_items(&batch.context, batch.parent.id).await {
        assert_eq!(
            item.consumed_at.is_some(),
            [batch.selected_id, next_id].contains(&item.id)
        );
    }
    assert_eq!(
        batch.context.db.proofs.get(&batch.proof.id).await.state,
        ProofStateEnum::Accepted
    );
}

#[tokio::test]
async fn batch_parent_submission_rejects_exhausted_batch() {
    let batch = BatchPresentation::new(1).await;
    batch
        .update_selected(UpdateCredentialRequest {
            consumed_at: Clearable::ForceSet(Some(now_utc())),
            ..Default::default()
        })
        .await;
    // Concrete IDs retain their existing invalid-submission error.
    batch.assert_rejected(batch.selected_id).await;
    batch
        .assert_rejected_with_code(batch.parent.id, "BR_0443")
        .await;
}

#[tokio::test]
async fn batch_submission_with_nonmatching_claims_is_invalid() {
    let batch = BatchPresentation::new(2).await;
    // Legacy fixture items read their claims from the parent.
    batch
        .context
        .db
        .credentials
        .update(
            batch.parent.id,
            UpdateCredentialRequest {
                claims: Some(vec![]),
                ..Default::default()
            },
        )
        .await;
    let sibling = batch
        .items
        .iter()
        .find(|item| item.id != batch.selected_id)
        .unwrap();
    batch.assert_rejected(sibling.id).await;
    batch.assert_unconsumed().await;
    batch
        .update_selected(UpdateCredentialRequest {
            consumed_at: Clearable::ForceSet(Some(now_utc())),
            ..Default::default()
        })
        .await;
    batch.assert_rejected(batch.parent.id).await;
}
