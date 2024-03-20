use std::collections::HashSet;

use one_core::model::{
    did::{KeyRole, RelatedKey},
    proof::ProofStateEnum,
};
use serde_json::Value;
use uuid::Uuid;

use crate::{
    fixtures::TestingDidParams,
    utils::{
        context::TestContext,
        db_clients::proof_schemas::{CreateProofClaim, CreateProofInputSchema},
        field_match::FieldHelpers,
    },
};

#[tokio::test]
async fn test_list_proof_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

    let verifier_key = context
        .db
        .keys
        .create(&organisation, Default::default())
        .await;

    let verifier_did = context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: verifier_key.to_owned(),
                }]),
                ..Default::default()
            },
        )
        .await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;

    let claim_schema = &credential_schema.claim_schemas.as_ref().unwrap()[0].schema;

    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "proof-schema-name",
            &organisation,
            CreateProofInputSchema {
                claims: vec![CreateProofClaim {
                    id: claim_schema.id,
                    key: &claim_schema.key,
                    required: true,
                    data_type: &claim_schema.data_type,
                }],
                credential_schema: &credential_schema,
                validity_constraint: None,
            },
        )
        .await;

    let mut proofs = HashSet::new();

    for _ in 1..15 {
        let proof = context
            .db
            .proofs
            .create(
                None,
                &verifier_did,
                None,
                Some(&proof_schema),
                ProofStateEnum::Requested,
                "OPENID4VC",
                None,
                verifier_key.to_owned(),
            )
            .await;

        proofs.insert(proof.id);
    }

    // WHEN
    let resp = context.api.proofs.list(0, 10, &organisation.id, None).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp: Value = resp.json_value().await;

    assert_eq!(resp["totalItems"], 14);
    assert_eq!(resp["totalPages"], 2);
    assert_eq!(resp["values"].as_array().unwrap().len(), 10);
}

#[tokio::test]
async fn test_list_proofs_by_ids() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

    let verifier_key = context
        .db
        .keys
        .create(&organisation, Default::default())
        .await;

    let verifier_did = context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: verifier_key.to_owned(),
                }]),
                ..Default::default()
            },
        )
        .await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;

    let claim_schema = &credential_schema.claim_schemas.as_ref().unwrap()[0].schema;

    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "proof-schema-name",
            &organisation,
            CreateProofInputSchema {
                claims: vec![CreateProofClaim {
                    id: claim_schema.id,
                    key: &claim_schema.key,
                    required: true,
                    data_type: &claim_schema.data_type,
                }],
                credential_schema: &credential_schema,
                validity_constraint: None,
            },
        )
        .await;

    let mut proofs = HashSet::new();

    for _ in 1..5 {
        let proof = context
            .db
            .proofs
            .create(
                None,
                &verifier_did,
                None,
                Some(&proof_schema),
                ProofStateEnum::Requested,
                "OPENID4VC",
                None,
                verifier_key.to_owned(),
            )
            .await;

        proofs.insert(proof.id);
    }

    // WHEN
    let resp = context
        .api
        .proofs
        .list(0, 10, &organisation.id, proofs.iter())
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp: Value = resp.json_value().await;

    assert_eq!(resp["totalItems"], 4);
    assert_eq!(resp["totalPages"], 1);

    let result_proofs: HashSet<Uuid> = resp["values"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["id"].parse())
        .collect();

    assert_eq!(result_proofs.len(), 4);

    assert_eq!(proofs, result_proofs);
}
