use std::collections::HashSet;
use std::str::FromStr;

use one_core::model::claim_schema::ClaimSchema;
use one_core::model::credential::{CredentialRole, CredentialStateEnum};
use one_core::model::did::{DidType, KeyRole, RelatedKey};
use one_core::model::history::{HistoryAction, HistoryEntityType};
use one_core::model::identifier::IdentifierType;
use one_core::model::interaction::InteractionType;
use one_core::model::proof::ProofStateEnum;
use serde_json::json;
use serde_json_path::JsonPath;
use similar_asserts::assert_eq;
use sql_data_provider::test_utilities::get_dummy_date;
use uuid::Uuid;
use validator::ValidateLength;

use crate::fixtures::{
    ClaimData, TestingCredentialParams, TestingDidParams, TestingIdentifierParams,
    key_to_claim_schema_id,
};
use crate::utils::api_clients::proofs::CreateProofTestParams;
use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
use crate::utils::db_clients::histories::TestingHistoryParams;
use crate::utils::db_clients::proof_schemas::{CreateProofClaim, CreateProofInputSchema};
use crate::utils::db_clients::proofs::TestingProofParams;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_get_proof_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create_with_nested_claims("test", &organisation, Default::default())
        .await;

    // Select a root claim.
    let claim_schema = &credential_schema.claim_schemas.as_ref().await.unwrap()[0];

    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "test",
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
            }],
        )
        .await;

    let verifier_key = context
        .db
        .keys
        .create(&organisation, Default::default())
        .await;

    let did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: verifier_key.to_owned(),
                    reference: "1".to_string(),
                }]),
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
                did: Some(did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let proof = context
        .db
        .proofs
        .create(
            ProofStateEnum::Created,
            "OPENID4VP_FINAL1",
            TestingProofParams {
                verifier_identifier: Some(identifier),
                verifier_key: Some(verifier_key),
                proof_schema: Some(proof_schema.clone()),
                engagement: Some("NFC".to_string()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.proofs.get(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp["id"].assert_eq(&proof.id);
    resp["organisationId"].assert_eq(&organisation.id);
    resp["transport"].assert_eq(&"HTTP".to_string());
    resp["schema"]["id"].assert_eq(&proof_schema.id);
    resp["role"].assert_eq(&proof.role.to_string().to_ascii_uppercase());
    resp["engagement"].assert_eq(&proof.engagement);
    assert_eq!(resp["proofInputs"].as_array().unwrap().len(), 1);
    assert_eq!(
        resp["proofInputs"][0]["claims"].as_array().unwrap().len(),
        1
    );
    let claim_item = &resp["proofInputs"][0]["claims"][0];
    claim_item["schema"]["id"].assert_eq(&claim_schema.id);
    assert_eq!(claim_item["value"].as_array().length(), Some(2));
}

#[tokio::test]
async fn test_get_proof_detached_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create_with_nested_claims("test", &organisation, Default::default())
        .await;

    //Select 2nd claim - a nested object
    let claim_schema = &credential_schema.claim_schemas.as_ref().await.unwrap()[2];

    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "test",
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
            }],
        )
        .await;

    let verifier_key = context
        .db
        .keys
        .create(&organisation, Default::default())
        .await;

    let did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: verifier_key.to_owned(),
                    reference: "1".to_string(),
                }]),
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
                did: Some(did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let proof = context
        .db
        .proofs
        .create(
            ProofStateEnum::Created,
            "OPENID4VP_FINAL1",
            TestingProofParams {
                verifier_identifier: Some(identifier),
                verifier_key: Some(verifier_key),
                proof_schema: Some(proof_schema.clone()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.proofs.get(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp["id"].assert_eq(&proof.id);
    resp["organisationId"].assert_eq(&organisation.id);
    resp["schema"]["id"].assert_eq(&proof_schema.id);

    assert_eq!(resp["proofInputs"].as_array().unwrap().len(), 1);
    //Both nested claims are there and the object claim is properly nested.
    assert_eq!(
        resp["proofInputs"][0]["claims"][0]["value"][0]["value"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let claim_item = &resp["proofInputs"][0]["claims"][0]["value"][0];
    claim_item["schema"]["id"].assert_eq(&claim_schema.id);
    assert_eq!(
        claim_item["schema"]["key"].as_str(),
        Some("address/coordinates")
    );
}

#[tokio::test]
async fn test_get_proof_with_nested_claims() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create_with_nested_claims("test", &organisation, Default::default())
        .await;

    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "test",
            &organisation,
            vec![CreateProofInputSchema {
                claims: credential_schema
                    .claim_schemas
                    .as_ref()
                    .await
                    .unwrap()
                    .iter()
                    .map(|item| CreateProofClaim {
                        id: item.id,
                        key: &item.key,
                        required: true,
                        data_type: &item.data_type,
                        array: false,
                    })
                    .collect(),
                credential_schema: &credential_schema,
            }],
        )
        .await;

    let verifier_key = context
        .db
        .keys
        .create(&organisation, Default::default())
        .await;

    let did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: verifier_key.to_owned(),
                    reference: "1".to_string(),
                }]),
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
                did: Some(did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let proof = context
        .db
        .proofs
        .create(
            ProofStateEnum::Created,
            "OPENID4VP_FINAL1",
            TestingProofParams {
                verifier_identifier: Some(identifier),
                verifier_key: Some(verifier_key),
                proof_schema: Some(proof_schema.clone()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.proofs.get(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp["id"].assert_eq(&proof.id);
    resp["organisationId"].assert_eq(&organisation.id);
    resp["schema"]["id"].assert_eq(&proof_schema.id);

    assert_eq!(resp["proofInputs"].as_array().unwrap().len(), 1);

    let root_claims = resp["proofInputs"][0]["claims"].as_array().unwrap();
    assert_eq!(root_claims.len(), 1);

    let address_claims = root_claims[0]["value"].as_array().unwrap();
    assert_eq!(address_claims.len(), 2);

    let coordinates_claims = address_claims[1]["value"].as_array().unwrap();
    assert_eq!(coordinates_claims.len(), 2);
}

#[tokio::test]
async fn test_get_proof_with_empty_array() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create_with_array_claims("test", &organisation, Default::default())
        .await;

    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "test",
            &organisation,
            vec![CreateProofInputSchema {
                claims: credential_schema
                    .claim_schemas
                    .as_ref()
                    .await
                    .unwrap()
                    .iter()
                    .map(|item| CreateProofClaim {
                        id: item.id,
                        key: &item.key,
                        required: true,
                        data_type: &item.data_type,
                        array: item.array,
                    })
                    .collect(),
                credential_schema: &credential_schema,
            }],
        )
        .await;

    let verifier_key = context
        .db
        .keys
        .create(&organisation, Default::default())
        .await;

    let did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: verifier_key.to_owned(),
                    reference: "1".to_string(),
                }]),
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
                did: Some(did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let proof = context
        .db
        .proofs
        .create(
            ProofStateEnum::Created,
            "OPENID4VP_FINAL1",
            TestingProofParams {
                verifier_identifier: Some(identifier),
                verifier_key: Some(verifier_key),
                proof_schema: Some(proof_schema.clone()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.proofs.get(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp["id"].assert_eq(&proof.id);
    resp["organisationId"].assert_eq(&organisation.id);
    resp["schema"]["id"].assert_eq(&proof_schema.id);

    assert_eq!(resp["proofInputs"].as_array().unwrap().len(), 1);
    assert_eq!(
        resp["proofInputs"][0]["claims"][0]["value"][1]["path"],
        "namespace/root_array"
    );
    assert!(resp["proofInputs"][0]["claims"][0]["value"][1]["value"].is_null());
}

#[tokio::test]
async fn test_get_proof_with_array() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create_with_array_claims("test", &organisation, Default::default())
        .await;

    let array_claim_id = key_to_claim_schema_id("namespace/root_array", &credential_schema).await;
    let nested_obj_claim_id =
        key_to_claim_schema_id("namespace/root_array/nested", &credential_schema).await;
    let nested_field_claim_id =
        key_to_claim_schema_id("namespace/root_array/nested/field", &credential_schema).await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                role: Some(CredentialRole::Verifier),
                claims_data: Some(vec![
                    ClaimData {
                        schema_id: nested_obj_claim_id,
                        path: "namespace/root_array/0/nested/0".to_string(),
                        value: None,
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: nested_obj_claim_id,
                        path: "namespace/root_array/0/nested".to_string(),
                        value: None,
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: nested_obj_claim_id,
                        path: "namespace/root_array/1/nested/1".to_string(),
                        value: None,
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: nested_obj_claim_id,
                        path: "namespace/root_array/1/nested".to_string(),
                        value: None,
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: array_claim_id,
                        path: "namespace/root_array/0".to_string(),
                        value: None,
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: array_claim_id,
                        path: "namespace/root_array/1".to_string(),
                        value: None,
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: array_claim_id,
                        path: "namespace/root_array".to_string(),
                        value: None,
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: nested_field_claim_id,
                        path: "namespace/root_array/0/nested/0/field".to_string(),
                        value: Some("foo1".to_string()),
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: nested_field_claim_id,
                        path: "namespace/root_array/0/nested/1/field".to_string(),
                        value: Some("foo2".to_string()),
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: nested_field_claim_id,
                        path: "namespace/root_array/1/nested/0/field".to_string(),
                        value: Some("foo3".to_string()),
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: nested_field_claim_id,
                        path: "namespace/root_array/1/nested/1/field".to_string(),
                        value: Some("foo4".to_string()),
                        selectively_disclosable: false,
                    },
                ]),
                ..Default::default()
            },
        )
        .await;

    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "test",
            &organisation,
            vec![CreateProofInputSchema {
                claims: credential_schema
                    .claim_schemas
                    .as_ref()
                    .await
                    .unwrap()
                    .iter()
                    .map(|item| CreateProofClaim {
                        id: item.id,
                        key: &item.key,
                        required: true,
                        data_type: &item.data_type,
                        array: item.array,
                    })
                    .collect(),
                credential_schema: &credential_schema,
            }],
        )
        .await;

    let verifier_key = context
        .db
        .keys
        .create(&organisation, Default::default())
        .await;

    let did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: verifier_key.to_owned(),
                    reference: "1".to_string(),
                }]),
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
                did: Some(did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let proof = context
        .db
        .proofs
        .create(
            ProofStateEnum::Created,
            "OPENID4VP_FINAL1",
            TestingProofParams {
                verifier_identifier: Some(identifier),
                verifier_key: Some(verifier_key),
                proof_schema: Some(proof_schema.clone()),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .proofs
        .set_proof_claims(
            &proof.id,
            credential.common().id,
            credential
                .claims()
                .unwrap()
                .as_ref()
                .await
                .unwrap()
                .to_owned(),
        )
        .await;

    // WHEN
    let resp = context.api.proofs.get(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp["id"].assert_eq(&proof.id);
    resp["organisationId"].assert_eq(&organisation.id);
    resp["schema"]["id"].assert_eq(&proof_schema.id);

    assert_eq!(resp["proofInputs"].as_array().unwrap().len(), 1);

    let namespace = &resp["proofInputs"][0]["claims"][0];
    assert_eq!(namespace["path"], "namespace");

    // all nested values
    let path = JsonPath::parse(
        "$.proofInputs[0].claims[0].value[*].value[*].value[*].value[*].value[*].value",
    )
    .unwrap();

    let values: HashSet<&str> = path
        .query(&resp)
        .all()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    assert_eq!(values.len(), 4);

    assert_eq!(values, HashSet::from_iter(["foo1", "foo2", "foo3", "foo4"]));
}

#[tokio::test]
async fn test_get_proof_with_nested_claims_and_root_field() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create_with_nested_claims_and_root_field("test", &organisation, Default::default())
        .await;

    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "test",
            &organisation,
            vec![CreateProofInputSchema {
                claims: credential_schema
                    .claim_schemas
                    .as_ref()
                    .await
                    .unwrap()
                    .iter()
                    .map(|item| CreateProofClaim {
                        id: item.id,
                        key: &item.key,
                        required: true,
                        data_type: &item.data_type,
                        array: false,
                    })
                    .collect(),
                credential_schema: &credential_schema,
            }],
        )
        .await;

    let verifier_key = context
        .db
        .keys
        .create(&organisation, Default::default())
        .await;

    let did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: verifier_key.to_owned(),
                    reference: "1".to_string(),
                }]),
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
                did: Some(did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let proof = context
        .db
        .proofs
        .create(
            ProofStateEnum::Created,
            "OPENID4VP_FINAL1",
            TestingProofParams {
                verifier_identifier: Some(identifier),
                verifier_key: Some(verifier_key),
                proof_schema: Some(proof_schema.clone()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.proofs.get(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp["id"].assert_eq(&proof.id);
    resp["organisationId"].assert_eq(&organisation.id);
    resp["schema"]["id"].assert_eq(&proof_schema.id);

    assert_eq!(resp["proofInputs"].as_array().unwrap().len(), 1);

    let root_claims = resp["proofInputs"][0]["claims"].as_array().unwrap();
    assert_eq!(root_claims.len(), 2);

    let name_claims = &root_claims[0];
    assert_eq!(name_claims["schema"]["key"], "name");

    let address_claims = root_claims[1]["value"].as_array().unwrap();
    assert_eq!(address_claims.len(), 2);

    let coordinates_claims = address_claims[1]["value"].as_array().unwrap();
    assert_eq!(coordinates_claims.len(), 2);
}

#[tokio::test]
async fn test_get_proof_with_nested_optional_inputs() {
    // GIVEN
    let (context, organisation, _, identifier, verifier_key) =
        TestContext::new_with_did(None).await;

    let root_claim = ClaimSchema {
        array: false,
        id: Uuid::new_v4().into(),
        key: "root".to_string(),
        data_type: "STRING".to_string(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        metadata: false,
        required: true,
        translations: Default::default(),
    };
    let obj_claim = ClaimSchema {
        array: false,
        id: Uuid::new_v4().into(),
        key: "obj".to_string(),
        data_type: "OBJECT".to_string(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        metadata: false,
        required: true,
        translations: Default::default(),
    };
    let nested_claim = ClaimSchema {
        array: false,
        id: Uuid::new_v4().into(),
        key: "obj/nested".to_string(),
        data_type: "STRING".to_string(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        metadata: false,
        required: true,
        translations: Default::default(),
    };
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            TestingCreateSchemaParams {
                claim_schemas: Some(vec![
                    obj_claim.clone(),
                    nested_claim.clone(),
                    root_claim.clone(),
                ]),
                ..Default::default()
            },
        )
        .await;

    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "test",
            &organisation,
            vec![CreateProofInputSchema {
                claims: vec![
                    CreateProofClaim {
                        id: root_claim.id,
                        key: &root_claim.key,
                        required: true,
                        data_type: &root_claim.data_type,
                        array: false,
                    },
                    CreateProofClaim {
                        id: nested_claim.id,
                        key: &nested_claim.key,
                        required: false,
                        data_type: &nested_claim.data_type,
                        array: false,
                    },
                ],
                credential_schema: &credential_schema,
            }],
        )
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Created,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                role: Some(CredentialRole::Verifier),
                claims_data: Some(vec![
                    ClaimData {
                        schema_id: root_claim.id,
                        path: root_claim.key.to_owned(),
                        value: Some("root".to_string()),
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: nested_claim.id,
                        path: nested_claim.key.to_owned(),
                        value: Some("nested".to_string()),
                        selectively_disclosable: false,
                    },
                ]),
                ..Default::default()
            },
        )
        .await;

    let proof = context
        .db
        .proofs
        .create(
            ProofStateEnum::Created,
            "OPENID4VP_FINAL1",
            TestingProofParams {
                verifier_identifier: Some(identifier),
                verifier_key: Some(verifier_key),
                proof_schema: Some(proof_schema.clone()),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .proofs
        .set_proof_claims(
            &proof.id,
            credential.common().id,
            credential
                .claims()
                .unwrap()
                .as_ref()
                .await
                .unwrap()
                .to_owned(),
        )
        .await;

    // WHEN
    let resp = context.api.proofs.get(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp["id"].assert_eq(&proof.id);
    resp["organisationId"].assert_eq(&organisation.id);
    resp["schema"]["id"].assert_eq(&proof_schema.id);

    assert_eq!(resp["proofInputs"].as_array().unwrap().len(), 1);

    let root_claims = resp["proofInputs"][0]["claims"].as_array().unwrap();
    assert_eq!(root_claims.len(), 2);

    let root_input = root_claims
        .iter()
        .find(|claim| claim["path"] == "root")
        .unwrap();
    assert_eq!(root_input["schema"]["required"], true);

    let obj_input = root_claims
        .iter()
        .find(|claim| claim["path"] == "obj")
        .unwrap();
    assert_eq!(obj_input["schema"]["required"], false);
}

#[tokio::test]
async fn test_get_proof_with_credentials() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;

    let claim_schema = &credential_schema.claim_schemas.as_ref().await.unwrap()[0];

    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "test",
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
            }],
        )
        .await;

    let verifier_key = context
        .db
        .keys
        .create(&organisation, Default::default())
        .await;

    let did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: verifier_key.to_owned(),
                    reference: "1".to_string(),
                }]),
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
                did: Some(did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Created,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                role: Some(CredentialRole::Verifier),
                ecosystem: Some("EUDI".into()),
                ..Default::default()
            },
        )
        .await;

    let proof = context
        .db
        .proofs
        .create(
            ProofStateEnum::Created,
            "OPENID4VP_FINAL1",
            TestingProofParams {
                verifier_identifier: Some(identifier),
                verifier_key: Some(verifier_key),
                proof_schema: Some(proof_schema),
                ecosystem: Some("EUDI".into()),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .proofs
        .set_proof_claims(
            &proof.id,
            credential.common().id,
            credential
                .claims()
                .unwrap()
                .as_ref()
                .await
                .unwrap()
                .to_owned(),
        )
        .await;

    // WHEN
    let resp = context.api.proofs.get(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    resp["id"].assert_eq(&proof.id);
    assert!(resp["profile"].is_null());

    assert_eq!(resp["proofInputs"].as_array().unwrap().len(), 1);
    resp["proofInputs"][0]["credential"]["id"].assert_eq(&credential.common().id);
    assert!(resp["proofInputs"][0]["credential"]["role"].is_string());
    assert!(resp["proofInputs"][0]["credential"]["profile"].is_null());
    resp["proofInputs"][0]["credential"]["trustInformation"]["result"]
        .assert_eq(&"TRUSTED".to_string());
}

#[tokio::test]
async fn test_get_proof_with_deleted_credential() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;

    let claim_schema = &credential_schema.claim_schemas.as_ref().await.unwrap()[0];

    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "test",
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
            }],
        )
        .await;

    let verifier_key = context
        .db
        .keys
        .create(&organisation, Default::default())
        .await;

    let did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: verifier_key.to_owned(),
                    reference: "1".to_string(),
                }]),
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
                did: Some(did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Created,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                role: Some(CredentialRole::Verifier),
                deleted_at: Some(get_dummy_date()),
                ..Default::default()
            },
        )
        .await;

    let proof = context
        .db
        .proofs
        .create(
            ProofStateEnum::Created,
            "OPENID4VP_FINAL1",
            TestingProofParams {
                verifier_identifier: Some(identifier),
                verifier_key: Some(verifier_key),
                proof_schema: Some(proof_schema),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .proofs
        .set_proof_claims(
            &proof.id,
            credential.common().id,
            credential
                .claims()
                .unwrap()
                .as_ref()
                .await
                .unwrap()
                .to_owned(),
        )
        .await;

    // WHEN
    let resp = context.api.proofs.get(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    resp["id"].assert_eq(&proof.id);
    assert_eq!(resp["proofInputs"].as_array().unwrap().len(), 1);
    resp["proofInputs"][0]["credential"]["id"].assert_eq(&credential.common().id);
}

#[tokio::test]
async fn test_get_proof_as_holder_success() {
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
            organisation.clone(),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: verifier_key.to_owned(),
                    reference: "1".to_string(),
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
    let interaction = context
        .db
        .interactions
        .create(
            &organisation,
            InteractionType::Verification,
            Default::default(),
        )
        .await;

    let proof = context
        .db
        .proofs
        .create(
            ProofStateEnum::Created,
            "OPENID4VP_FINAL1",
            TestingProofParams {
                verifier_identifier: Some(verifier_identifier),
                verifier_key: Some(verifier_key),
                interaction: Some(interaction),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.proofs.get(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    resp["id"].assert_eq(&proof.id);
    resp["organisationId"].assert_eq(&organisation.id);
    assert!(resp["schema"].as_object().is_none());
    assert_eq!(resp["proofInputs"].as_array().unwrap().len(), 0);
    resp["trustInformation"]["result"].assert_eq(&"UNTRUSTED".to_string());
}

#[tokio::test]
async fn test_get_proof_with_retain_date() {
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
            organisation.clone(),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: verifier_key.to_owned(),
                    reference: "1".to_string(),
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
        .create("test", &organisation, Default::default())
        .await;

    let claim_schema = &credential_schema.claim_schemas.as_ref().await.unwrap()[0];

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
            }],
        )
        .await;

    let proof = context
        .db
        .proofs
        .create(
            ProofStateEnum::Accepted,
            "OPENID4VP_FINAL1",
            TestingProofParams {
                verifier_identifier: Some(verifier_identifier),
                verifier_key: Some(verifier_key),
                proof_schema: Some(proof_schema),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .histories
        .create(
            &organisation,
            TestingHistoryParams {
                action: Some(HistoryAction::Accepted),
                created_date: Some(get_dummy_date()),
                entity_id: Some(proof.id.into()),
                entity_type: Some(HistoryEntityType::Proof),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.proofs.get(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert!(!resp["retainUntilDate"].is_null())
}

#[tokio::test]
async fn test_get_proof_with_deleted_claims() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;

    let claim_schema = &credential_schema.claim_schemas.as_ref().await.unwrap()[0];

    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "test",
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
            }],
        )
        .await;

    let verifier_key = context
        .db
        .keys
        .create(&organisation, Default::default())
        .await;

    let did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: verifier_key.to_owned(),
                    reference: "1".to_string(),
                }]),
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
                did: Some(did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Created,
            &identifier,
            "OPENID4VCI_DRAFT13",
            Default::default(),
        )
        .await;

    let proof = context
        .db
        .proofs
        .create(
            ProofStateEnum::Accepted,
            "OPENID4VP_FINAL1",
            TestingProofParams {
                verifier_identifier: Some(identifier),
                verifier_key: Some(verifier_key),
                proof_schema: Some(proof_schema),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .proofs
        .set_proof_claims(
            &proof.id,
            credential.common().id,
            credential
                .claims()
                .unwrap()
                .as_ref()
                .await
                .unwrap()
                .to_owned(),
        )
        .await;

    context
        .db
        .histories
        .create(
            &organisation,
            TestingHistoryParams {
                action: Some(HistoryAction::Accepted),
                created_date: Some(get_dummy_date()),
                entity_id: Some(proof.id.into()),
                entity_type: Some(HistoryEntityType::Proof),
                ..Default::default()
            },
        )
        .await;

    let resp = context.api.tasks.run("RETAIN_PROOF_CHECK").await;
    assert_eq!(resp.status(), 200);

    // WHEN
    let resp = context.api.proofs.get(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert!(!resp["claimsRemovedAt"].is_null())
}

#[tokio::test]
async fn test_get_proof_with_verifier_and_issuer_certificates() {
    // GIVEN
    let (context, organisation, identifier, certificate, key) =
        TestContext::new_with_certificate_identifier(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create_with_nested_claims("test", &organisation, Default::default())
        .await;

    // Select a root claim.
    let claim_schema = &credential_schema.claim_schemas.as_ref().await.unwrap()[0];

    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "test",
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
            }],
        )
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Created,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                role: Some(CredentialRole::Verifier),
                ..Default::default()
            },
        )
        .await;

    let proof = context
        .db
        .proofs
        .create(
            ProofStateEnum::Created,
            "OPENID4VP_FINAL1",
            TestingProofParams {
                verifier_identifier: Some(identifier),
                verifier_key: Some(key),
                proof_schema: Some(proof_schema.clone()),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .proofs
        .set_proof_claims(
            &proof.id,
            credential.common().id,
            credential
                .claims()
                .unwrap()
                .as_ref()
                .await
                .unwrap()
                .to_owned(),
        )
        .await;

    // WHEN
    let resp = context.api.proofs.get(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp["id"].assert_eq(&proof.id);
    resp["organisationId"].assert_eq(&organisation.id);
    resp["transport"].assert_eq(&"HTTP".to_string());
    resp["schema"]["id"].assert_eq(&proof_schema.id);
    resp["role"].assert_eq(&proof.role.to_string().to_ascii_uppercase());

    assert_eq!(resp["proofInputs"].as_array().unwrap().len(), 1);
    assert_eq!(
        resp["proofInputs"][0]["claims"].as_array().unwrap().len(),
        1
    );
    let claim_item = &resp["proofInputs"][0]["claims"][0];
    claim_item["schema"]["id"].assert_eq(&claim_schema.id);
    assert_eq!(claim_item["value"].as_array().length(), Some(2));

    assert_eq!(
        resp["verifierCertificate"]["id"],
        certificate.id.to_string()
    );
    assert_eq!(resp["verifierCertificate"]["name"], certificate.name);
    assert_eq!(
        resp["proofInputs"][0]["credential"]["issuerCertificate"]["id"],
        certificate.id.to_string()
    );
    assert_eq!(
        resp["proofInputs"][0]["credential"]["issuerCertificate"]["name"],
        certificate.name
    );
}

#[tokio::test]
async fn test_get_proof_with_credentials_returns_profiles() {
    // GIVEN
    let test_profile = "test-credential-profile";
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;

    let claim_schema = &credential_schema.claim_schemas.as_ref().await.unwrap()[0];

    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "test",
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
            }],
        )
        .await;

    let verifier_key = context
        .db
        .keys
        .create(&organisation, Default::default())
        .await;

    let did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: verifier_key.to_owned(),
                    reference: "1".to_string(),
                }]),
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
                did: Some(did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Created,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                role: Some(CredentialRole::Verifier),
                ..Default::default()
            },
        )
        .await;

    let proof = context
        .db
        .proofs
        .create(
            ProofStateEnum::Created,
            "OPENID4VP_FINAL1",
            TestingProofParams {
                verifier_identifier: Some(identifier),
                verifier_key: Some(verifier_key),
                proof_schema: Some(proof_schema),
                profile: Some(test_profile.to_string()),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .proofs
        .set_proof_claims(
            &proof.id,
            credential.common().id,
            credential
                .claims()
                .unwrap()
                .as_ref()
                .await
                .unwrap()
                .to_owned(),
        )
        .await;

    // WHEN
    let resp = context.api.proofs.get(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    resp["id"].assert_eq(&proof.id);
    assert_eq!(resp["profile"], test_profile);

    assert_eq!(resp["proofInputs"].as_array().unwrap().len(), 1);
    resp["proofInputs"][0]["credential"]["id"].assert_eq(&credential.common().id);
    assert!(resp["proofInputs"][0]["credential"]["role"].is_string());
    assert!(resp["proofInputs"][0]["credential"]["profile"].is_null());
}

#[tokio::test]
async fn test_get_proof_with_transaction_data() {
    // GIVEN
    let (context, organisation, did, ..) = TestContext::new_with_did(None).await;
    let claim_schemas: Vec<_> = vec![
        (
            Uuid::from_str("48db4654-01c4-4a43-9df4-300f1f425c40").unwrap(),
            "namespace",
            true,
            "OBJECT",
            false,
        ),
        (
            Uuid::from_str("48db4654-01c4-4a43-9df4-300f1f425c41").unwrap(),
            "namespace/name",
            true,
            "STRING",
            false,
        ),
    ];
    let credential_schema = context
        .db
        .credential_schemas
        .create_with_claims(
            &Uuid::new_v4(),
            "test",
            &organisation,
            &claim_schemas,
            "MDOC",
            "org.iso.18013.5.1.mDL",
        )
        .await;
    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "test",
            &organisation,
            vec![CreateProofInputSchema::from((
                &claim_schemas[..],
                &credential_schema,
            ))],
        )
        .await;

    let tx_data = json!({
      "numSignatures": 2,
      "signatureQualifier": "eu_eidas_qes",
      "documentInfos": [],
      "hashAlgorithmOID": "2.16.840.1.101.3.4.2.1"
    });
    let resp = context
        .api
        .proofs
        .create(CreateProofTestParams {
            proof_schema_id: proof_schema.id.to_string().into(),
            protocol: "OPENID4VP_FINAL1".into(),
            verifier_did: did.id.to_string().into(),
            transaction_data: Some(json!([{
                "type": "QES_APPROVAL",
                "credentialSchemaIds": [credential_schema.id.to_string()],
                "data": tx_data}])),
            ..Default::default()
        })
        .await;
    assert_eq!(resp.status(), 201);
    let proof_id = resp.json_value().await["id"].as_str().unwrap().to_string();

    // WHEN
    let resp = context.api.proofs.get(&proof_id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let transaction_data = resp["transactionData"].as_array().unwrap();
    assert_eq!(transaction_data.len(), 1);
    assert_eq!(transaction_data[0]["type"], json!("QES_APPROVAL"));
    transaction_data[0]["credentialSchemaIds"][0].assert_eq(&credential_schema.id);
    assert_eq!(transaction_data[0]["data"], tx_data);
}
