use std::collections::HashSet;

use one_core::model::did::{KeyRole, RelatedKey};
use one_core::model::proof::ProofStateEnum;
use shared_types::ProofId;

use crate::fixtures::TestingDidParams;
use crate::utils::api_clients::proofs::ProofFilters;
use crate::utils::context::TestContext;
use crate::utils::db_clients::proof_schemas::{CreateProofClaim, CreateProofInputSchema};
use crate::utils::field_match::FieldHelpers;

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
            vec![CreateProofInputSchema {
                claims: vec![CreateProofClaim {
                    id: claim_schema.id,
                    key: &claim_schema.key,
                    required: true,
                    data_type: &claim_schema.data_type,
                    array: false,
                }],
                credential_schema: &credential_schema,
                validity_constraint: None,
            }],
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
    let resp = context
        .api
        .proofs
        .list(0, 10, &organisation.id, Default::default())
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

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
            vec![CreateProofInputSchema {
                claims: vec![CreateProofClaim {
                    id: claim_schema.id,
                    key: &claim_schema.key,
                    required: true,
                    data_type: &claim_schema.data_type,
                    array: false,
                }],
                credential_schema: &credential_schema,
                validity_constraint: None,
            }],
        )
        .await;

    let mut proofs = vec![];

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

        proofs.push(proof.id);
    }

    // WHEN
    let resp = context
        .api
        .proofs
        .list(
            0,
            10,
            &organisation.id,
            ProofFilters {
                ids: Some(&proofs),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["totalItems"], 4);
    assert_eq!(resp["totalPages"], 1);

    let result_proofs: HashSet<ProofId> = resp["values"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["id"].parse())
        .collect();
    assert_eq!(result_proofs.len(), 4);
    assert_eq!(HashSet::from_iter(proofs), result_proofs);
}

#[tokio::test]
async fn test_list_proofs_by_name() {
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

    let proof_schema1 = context
        .db
        .proof_schemas
        .create(
            "proof-schema-name",
            &organisation,
            vec![CreateProofInputSchema {
                claims: vec![CreateProofClaim {
                    id: claim_schema.id,
                    key: &claim_schema.key,
                    required: true,
                    data_type: &claim_schema.data_type,
                    array: false,
                }],
                credential_schema: &credential_schema,
                validity_constraint: None,
            }],
        )
        .await;

    let proof_schema2 = context
        .db
        .proof_schemas
        .create(
            "other-schema",
            &organisation,
            vec![CreateProofInputSchema {
                claims: vec![CreateProofClaim {
                    id: claim_schema.id,
                    key: &claim_schema.key,
                    required: true,
                    data_type: &claim_schema.data_type,
                    array: false,
                }],
                credential_schema: &credential_schema,
                validity_constraint: None,
            }],
        )
        .await;

    let mut proofs = vec![];

    for _ in 1..5 {
        let proof = context
            .db
            .proofs
            .create(
                None,
                &verifier_did,
                None,
                Some(&proof_schema1),
                ProofStateEnum::Requested,
                "OPENID4VC",
                None,
                verifier_key.to_owned(),
            )
            .await;

        proofs.push(proof.id);
    }

    context
        .db
        .proofs
        .create(
            None,
            &verifier_did,
            None,
            Some(&proof_schema2),
            ProofStateEnum::Requested,
            "OPENID4VC",
            None,
            verifier_key.to_owned(),
        )
        .await;

    // WHEN
    let resp = context
        .api
        .proofs
        .list(
            0,
            10,
            &organisation.id,
            ProofFilters {
                name: Some(&proof_schema1.name),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["totalItems"], 4);
    assert_eq!(resp["totalPages"], 1);

    let result_proofs: HashSet<ProofId> = resp["values"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["id"].parse())
        .collect();
    assert_eq!(result_proofs.len(), 4);
    assert_eq!(HashSet::from_iter(proofs), result_proofs);
}

#[tokio::test]
async fn test_list_proofs_by_schema_ids() {
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

    let proof_schema1 = context
        .db
        .proof_schemas
        .create(
            "proof-schema-name",
            &organisation,
            vec![CreateProofInputSchema {
                claims: vec![CreateProofClaim {
                    id: claim_schema.id,
                    key: &claim_schema.key,
                    required: true,
                    data_type: &claim_schema.data_type,
                    array: false,
                }],
                credential_schema: &credential_schema,
                validity_constraint: None,
            }],
        )
        .await;

    let proof_schema2 = context
        .db
        .proof_schemas
        .create(
            "other-schema",
            &organisation,
            vec![CreateProofInputSchema {
                claims: vec![CreateProofClaim {
                    id: claim_schema.id,
                    key: &claim_schema.key,
                    required: true,
                    data_type: &claim_schema.data_type,
                    array: false,
                }],
                credential_schema: &credential_schema,
                validity_constraint: None,
            }],
        )
        .await;

    let mut proofs = vec![];

    for _ in 1..5 {
        let proof = context
            .db
            .proofs
            .create(
                None,
                &verifier_did,
                None,
                Some(&proof_schema1),
                ProofStateEnum::Requested,
                "OPENID4VC",
                None,
                verifier_key.to_owned(),
            )
            .await;

        proofs.push(proof.id);
    }

    context
        .db
        .proofs
        .create(
            None,
            &verifier_did,
            None,
            Some(&proof_schema2),
            ProofStateEnum::Requested,
            "OPENID4VC",
            None,
            verifier_key.to_owned(),
        )
        .await;

    // WHEN
    let resp = context
        .api
        .proofs
        .list(
            0,
            10,
            &organisation.id,
            ProofFilters {
                proof_schema_ids: Some(&[proof_schema1.id]),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["totalItems"], 4);
    assert_eq!(resp["totalPages"], 1);

    let result_proofs: HashSet<ProofId> = resp["values"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["id"].parse())
        .collect();
    assert_eq!(result_proofs.len(), 4);
    assert_eq!(HashSet::from_iter(proofs), result_proofs);
}

#[tokio::test]
async fn test_list_proofs_by_state() {
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
            vec![CreateProofInputSchema {
                claims: vec![CreateProofClaim {
                    id: claim_schema.id,
                    key: &claim_schema.key,
                    required: true,
                    data_type: &claim_schema.data_type,
                    array: false,
                }],
                credential_schema: &credential_schema,
                validity_constraint: None,
            }],
        )
        .await;

    let mut proofs = vec![];

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

        proofs.push(proof.id);
    }

    context
        .db
        .proofs
        .create(
            None,
            &verifier_did,
            None,
            Some(&proof_schema),
            ProofStateEnum::Error,
            "OPENID4VC",
            None,
            verifier_key.to_owned(),
        )
        .await;

    // WHEN
    let resp = context
        .api
        .proofs
        .list(
            0,
            10,
            &organisation.id,
            ProofFilters {
                proof_states: Some(&[ProofStateEnum::Requested]),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["totalItems"], 4);
    assert_eq!(resp["totalPages"], 1);

    let result_proofs: HashSet<ProofId> = resp["values"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["id"].parse())
        .collect();
    assert_eq!(result_proofs.len(), 4);
    assert_eq!(HashSet::from_iter(proofs), result_proofs);
}

#[tokio::test]
async fn test_list_proof_with_retain_date() {
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
            vec![CreateProofInputSchema {
                claims: vec![CreateProofClaim {
                    id: claim_schema.id,
                    key: &claim_schema.key,
                    required: true,
                    data_type: &claim_schema.data_type,
                    array: false,
                }],
                credential_schema: &credential_schema,
                validity_constraint: None,
            }],
        )
        .await;

    context
        .db
        .proofs
        .create(
            None,
            &verifier_did,
            None,
            Some(&proof_schema),
            ProofStateEnum::Accepted,
            "OPENID4VC",
            None,
            verifier_key.to_owned(),
        )
        .await;

    // WHEN
    let resp = context
        .api
        .proofs
        .list(0, 10, &organisation.id, Default::default())
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["totalItems"], 1);
    assert_eq!(resp["totalPages"], 1);
    assert_eq!(resp["values"].as_array().unwrap().len(), 1);
    assert!(resp["values"]
        .as_array()
        .unwrap()
        .iter()
        .all(|proof| !proof["retainUntilDate"].is_null()))
}
