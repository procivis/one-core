use std::collections::HashSet;

use one_core::model::did::{DidType, KeyRole, RelatedKey};
use one_core::model::identifier::IdentifierType;
use one_core::model::proof::{ProofRole, ProofStateEnum};
use shared_types::ProofId;

use crate::fixtures::{create_organisation, TestingDidParams, TestingIdentifierParams};
use crate::utils::api_clients::proofs::ProofFilters;
use crate::utils::context::TestContext;
use crate::utils::db_clients::proof_schemas::{CreateProofClaim, CreateProofInputSchema};
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_list_proof_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let verifier_key = context
        .db
        .keys
        .create(&organisation, Default::default())
        .await;

    let verifier_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: verifier_key.to_owned(),
                }]),
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
                &verifier_identifier,
                None,
                None,
                Some(&proof_schema),
                ProofStateEnum::Requested,
                "OPENID4VP_DRAFT20",
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
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let verifier_key = context
        .db
        .keys
        .create(&organisation, Default::default())
        .await;

    let verifier_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: verifier_key.to_owned(),
                }]),
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
                &verifier_identifier,
                None,
                None,
                Some(&proof_schema),
                ProofStateEnum::Requested,
                "OPENID4VP_DRAFT20",
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
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let verifier_key = context
        .db
        .keys
        .create(&organisation, Default::default())
        .await;

    let verifier_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: verifier_key.to_owned(),
                }]),
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
                &verifier_identifier,
                None,
                None,
                Some(&proof_schema1),
                ProofStateEnum::Requested,
                "OPENID4VP_DRAFT20",
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
            &verifier_identifier,
            None,
            None,
            Some(&proof_schema2),
            ProofStateEnum::Requested,
            "OPENID4VP_DRAFT20",
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
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let verifier_key = context
        .db
        .keys
        .create(&organisation, Default::default())
        .await;

    let verifier_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: verifier_key.to_owned(),
                }]),
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
                &verifier_identifier,
                None,
                None,
                Some(&proof_schema1),
                ProofStateEnum::Requested,
                "OPENID4VP_DRAFT20",
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
            &verifier_identifier,
            None,
            None,
            Some(&proof_schema2),
            ProofStateEnum::Requested,
            "OPENID4VP_DRAFT20",
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
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let verifier_key = context
        .db
        .keys
        .create(&organisation, Default::default())
        .await;

    let verifier_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: verifier_key.to_owned(),
                }]),
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
                &verifier_identifier,
                None,
                None,
                Some(&proof_schema),
                ProofStateEnum::Requested,
                "OPENID4VP_DRAFT20",
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
            &verifier_identifier,
            None,
            None,
            Some(&proof_schema),
            ProofStateEnum::Error,
            "OPENID4VP_DRAFT20",
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
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let verifier_key = context
        .db
        .keys
        .create(&organisation, Default::default())
        .await;

    let verifier_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: verifier_key.to_owned(),
                }]),
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
            &verifier_identifier,
            None,
            None,
            Some(&proof_schema),
            ProofStateEnum::Accepted,
            "OPENID4VP_DRAFT20",
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

#[tokio::test]
async fn test_list_proofs_with_org_by_interaction() {
    // GIVEN
    let (context, organisation, did, identifier, key) = TestContext::new_with_did(None).await;

    let interaction = context
        .db
        .interactions
        .create(None, "https://example.com", &[], &organisation)
        .await;

    let mut proofs = vec![];
    for _ in 1..5 {
        let proof = context
            .db
            .proofs
            .create(
                None,
                &did,
                &identifier,
                None,
                None,
                None,
                ProofStateEnum::Requested,
                "OPENID4VP_DRAFT20",
                Some(&interaction),
                key.clone(),
            )
            .await;

        proofs.push(proof.id);
    }

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;

    let claim_schema = &credential_schema.claim_schemas.as_ref().unwrap()[0].schema;

    let different_org = create_organisation(&context.db.db_conn).await;
    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "proof-schema-name",
            &different_org,
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
            &did,
            &identifier,
            None,
            None,
            Some(&proof_schema),
            ProofStateEnum::Error,
            "OPENID4VP_DRAFT20",
            None,
            key,
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
async fn test_list_proofs_by_role() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let verifier_key = context
        .db
        .keys
        .create(&organisation, Default::default())
        .await;

    let verifier_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: verifier_key.to_owned(),
                }]),
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
                &verifier_identifier,
                None,
                None,
                Some(&proof_schema),
                ProofStateEnum::Requested,
                "OPENID4VP_DRAFT20",
                None,
                verifier_key.to_owned(),
            )
            .await;

        proofs.push(proof.id);
    }
    let interaction = context
        .db
        .interactions
        .create(None, "https://example.com", &[], &organisation)
        .await;
    let holder_proof = context
        .db
        .proofs
        .create(
            None,
            &verifier_did,
            &verifier_identifier,
            None,
            None,
            None,
            ProofStateEnum::Error,
            "OPENID4VP_DRAFT20",
            Some(&interaction),
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
                proof_roles: Some(&[ProofRole::Verifier]),
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

    let resp = context
        .api
        .proofs
        .list(
            0,
            10,
            &organisation.id,
            ProofFilters {
                proof_roles: Some(&[ProofRole::Holder]),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["totalItems"], 1);
    assert_eq!(resp["totalPages"], 1);

    let result_proof = resp["values"].as_array().unwrap().first().cloned().unwrap();
    assert_eq!(result_proof["id"].parse::<ProofId>(), holder_proof.id);
    assert_eq!(
        result_proof["role"],
        holder_proof.role.to_string().to_ascii_uppercase()
    );
}
