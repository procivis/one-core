use assert2::let_assert;
use one_core::clock::now_utc;
use one_core::model::credential::{
    Clearable, Credential, CredentialFilterValue, CredentialRole, CredentialStateEnum,
    UpdateCredentialRequest,
};
use one_core::model::did::{Did, DidType, KeyRole, RelatedKey};
use one_core::model::identifier::{Identifier, IdentifierData, IdentifierType};
use one_core::model::interaction::{Interaction, InteractionType};
use one_core::model::key::Key;
use one_core::model::list_filter::ListFilterValue;
use one_core::model::organisation::Organisation;
use one_core::model::proof::{Proof, ProofStateEnum};
use serde_json::json;
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
    check_batch_presentation(false).await;
}

#[tokio::test]
async fn test_presentation_submit_endpoint_for_openid4vp_dcql_batch_item_claims() {
    check_batch_presentation(true).await;
}

async fn check_batch_presentation(item_claims: bool) {
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential = setup_batch_credential(&context, &organisation, &identifier, 2).await;
    let (verifier_did, verifier_identifier, credential, interaction, proof) =
        setup_submittable_presentation_dcql(&context, &organisation, &identifier, Some(credential))
            .await;

    if item_claims {
        let claims = credential.claims.as_ref().await.unwrap().to_owned();
        let items = context
            .db
            .credentials
            .list(CredentialFilterValue::ParentCredential(credential.id).condition())
            .await;
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

    let items = context
        .db
        .credentials
        .list(CredentialFilterValue::ParentCredential(credential.id).condition())
        .await;
    // Only one item consumed
    assert!(items.iter().any(|c| c.consumed_at.is_some()));
    assert!(items.iter().any(|c| c.consumed_at.is_none()));
    let consumed = items.iter().find(|c| c.consumed_at.is_some()).unwrap();
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
}

#[tokio::test]
async fn test_presentation_submit_endpoint_for_openid4vp_dcql_batch_item() {
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential = setup_batch_credential(&context, &organisation, &identifier, 1).await;
    let (_, _, credential, interaction, _) =
        setup_submittable_presentation_dcql(&context, &organisation, &identifier, Some(credential))
            .await;
    let items = context
        .db
        .credentials
        .list(CredentialFilterValue::ParentCredential(credential.id).condition())
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .presentation_submit_v2(interaction.id, items[0].id, &[], &[])
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0291")
}

#[tokio::test]
async fn test_presentation_submit_endpoint_for_openid4vp_dcql_batch_consumed() {
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential = setup_batch_credential(&context, &organisation, &identifier, 1).await;
    let (_, _, credential, interaction, _) =
        setup_submittable_presentation_dcql(&context, &organisation, &identifier, Some(credential))
            .await;
    let items = context
        .db
        .credentials
        .list(CredentialFilterValue::ParentCredential(credential.id).condition())
        .await;
    context
        .db
        .credentials
        .update(
            items[0].id,
            UpdateCredentialRequest {
                consumed_at: Clearable::ForceSet(Some(now_utc())),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .presentation_submit_v2(interaction.id, credential.id, &[], &[])
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0291")
}

#[tokio::test]
async fn mixed_format_batch_presents_earliest_expiring_matching_item() {
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let batch = setup_mixed_format_batch(&context, &organisation, &identifier).await;
    // The request accepts JWT: skip BBS even though it expires first, and present
    // the JWT item with the earliest expiry through the formatless parent.
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
    assert_eq!(applicable[0]["id"], batch.parent.id.to_string());

    context
        .server_mock
        .ssi_request_uri_endpoint(None::<fn(MockBuilder) -> MockBuilder>)
        .await;
    let response = context
        .api
        .interactions
        .presentation_submit_v2(interaction.id, batch.parent.id, &[], &[])
        .await;
    assert_eq!(response.status(), 204);
    let items = context
        .db
        .credentials
        .list(CredentialFilterValue::ParentCredential(batch.parent.id).condition())
        .await;
    let consumed_ids: Vec<_> = items
        .into_iter()
        .filter(|item| item.consumed_at.is_some())
        .map(|item| item.id)
        .collect();
    // Neither the later-expiring JWT item nor the non-matching BBS item is consumed.
    assert_eq!(consumed_ids, vec![batch.earliest_expiring_jwt_item]);
}

#[tokio::test]
async fn mixed_format_batch_rejects_submission_when_matching_format_is_exhausted() {
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let batch = setup_mixed_format_batch(&context, &organisation, &identifier).await;
    // Exhaust only JWT. An available BBS item cannot satisfy the JWT request.
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
    assert_eq!(response.error_code().await, "BR_0291");
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

#[tokio::test]
async fn two_queries_reuse_the_same_batch_item() {
    use one_core::model::interaction::UpdateInteractionRequest;
    use one_core::repository::DataRepository;
    use sql_data_provider::DataLayer;

    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let parent = setup_batch_credential(&context, &organisation, &identifier, 2).await;
    let (_, _, _, interaction, _) = setup_submittable_presentation_dcql(
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
    let response = context
        .api
        .client
        .post(
            "/api/interaction/v2/presentation-submit",
            json!({
                "interactionId": interaction.id,
                "submission": {
                    "input_0": {"credentialId": parent.id},
                    "input_1": {"credentialId": parent.id}
                }
            }),
        )
        .await;
    assert_eq!(response.status(), 204);
    let items = context
        .db
        .credentials
        .list(CredentialFilterValue::ParentCredential(parent.id).condition())
        .await;
    assert_eq!(items.len(), 2);
    assert_eq!(
        items
            .iter()
            .filter(|item| item.consumed_at.is_some())
            .count(),
        1
    );
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
                context.db.db_conn.get_database_backend().build(
                    &Query::update()
                        .table(Alias::new("credential"))
                        .value(
                            Alias::new("created_date"),
                            parent.created_date - time::Duration::seconds(seconds),
                        )
                        .value(
                            Alias::new("expires_at"),
                            expiry + time::Duration::seconds(seconds),
                        )
                        .and_where(Expr::col(Alias::new("id")).eq(id.to_string()))
                        .to_owned(),
                ),
            )
            .await
            .unwrap();
    }
    // The generic batch fixture models legacy storage; new parents have no format.
    context
        .db
        .db_conn
        .execute(
            context.db.db_conn.get_database_backend().build(
                &Query::update()
                    .table(Alias::new("credential"))
                    .value(Alias::new("format"), Option::<String>::None)
                    .and_where(Expr::col(Alias::new("id")).eq(parent.id.to_string()))
                    .to_owned(),
            ),
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
