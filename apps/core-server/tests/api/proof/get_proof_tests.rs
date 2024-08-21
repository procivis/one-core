use one_core::model::{
    credential::CredentialStateEnum,
    did::{KeyRole, RelatedKey},
    proof::ProofStateEnum,
};
use validator::ValidateLength;

use crate::{
    fixtures::TestingDidParams,
    utils::{
        context::TestContext,
        db_clients::proof_schemas::{CreateProofClaim, CreateProofInputSchema},
        field_match::FieldHelpers,
    },
};

#[tokio::test]
async fn test_get_proof_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

    let credential_schema = context
        .db
        .credential_schemas
        .create_with_nested_claims("test", &organisation, "NONE", Default::default())
        .await;

    // Select a root claim.
    let claim_schema = &credential_schema.claim_schemas.get().await.unwrap()[0].schema;

    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "test",
            &organisation,
            CreateProofInputSchema {
                claims: vec![CreateProofClaim {
                    id: claim_schema.id,
                    key: &claim_schema.key,
                    required: true,
                    data_type: &claim_schema.data_type,
                    array: false,
                }],
                credential_schema: &credential_schema,
                validity_constraint: None,
            },
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

    let proof = context
        .db
        .proofs
        .create(
            None,
            &did,
            None,
            Some(&proof_schema),
            ProofStateEnum::Created,
            "OPENID4VC",
            None,
            verifier_key,
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
    let (context, organisation) = TestContext::new_with_organisation().await;

    let credential_schema = context
        .db
        .credential_schemas
        .create_with_nested_claims("test", &organisation, "NONE", Default::default())
        .await;

    //Select 2nd claim - a nested object
    let claim_schema = &credential_schema.claim_schemas.get().await.unwrap()[2].schema;

    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "test",
            &organisation,
            CreateProofInputSchema {
                claims: vec![CreateProofClaim {
                    id: claim_schema.id,
                    key: &claim_schema.key,
                    required: true,
                    data_type: &claim_schema.data_type,
                    array: false,
                }],
                credential_schema: &credential_schema,
                validity_constraint: None,
            },
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

    let proof = context
        .db
        .proofs
        .create(
            None,
            &did,
            None,
            Some(&proof_schema),
            ProofStateEnum::Created,
            "OPENID4VC",
            None,
            verifier_key,
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
    assert_eq!(claim_item["schema"]["key"].as_str(), Some("coordinates"));
}

#[tokio::test]
async fn test_get_proof_with_nested_claims() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

    let credential_schema = context
        .db
        .credential_schemas
        .create_with_nested_claims("test", &organisation, "NONE", Default::default())
        .await;

    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "test",
            &organisation,
            CreateProofInputSchema {
                claims: credential_schema
                    .claim_schemas
                    .get()
                    .await
                    .unwrap()
                    .iter()
                    .map(|item| CreateProofClaim {
                        id: item.schema.id,
                        key: &item.schema.key,
                        required: true,
                        data_type: &item.schema.data_type,
                        array: false,
                    })
                    .collect(),
                credential_schema: &credential_schema,
                validity_constraint: None,
            },
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

    let proof = context
        .db
        .proofs
        .create(
            None,
            &did,
            None,
            Some(&proof_schema),
            ProofStateEnum::Created,
            "OPENID4VC",
            None,
            verifier_key,
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
async fn test_get_proof_with_nested_claims_and_root_field() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

    let credential_schema = context
        .db
        .credential_schemas
        .create_with_nested_claims_and_root_field("test", &organisation, "NONE", Default::default())
        .await;

    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "test",
            &organisation,
            CreateProofInputSchema {
                claims: credential_schema
                    .claim_schemas
                    .get()
                    .await
                    .unwrap()
                    .iter()
                    .map(|item| CreateProofClaim {
                        id: item.schema.id,
                        key: &item.schema.key,
                        required: true,
                        data_type: &item.schema.data_type,
                        array: false,
                    })
                    .collect(),
                credential_schema: &credential_schema,
                validity_constraint: None,
            },
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

    let proof = context
        .db
        .proofs
        .create(
            None,
            &did,
            None,
            Some(&proof_schema),
            ProofStateEnum::Created,
            "OPENID4VC",
            None,
            verifier_key,
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
async fn test_get_proof_with_credentials() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;

    let claim_schema = &credential_schema.claim_schemas.get().await.unwrap()[0].schema;

    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "test",
            &organisation,
            CreateProofInputSchema {
                claims: vec![CreateProofClaim {
                    id: claim_schema.id,
                    key: &claim_schema.key,
                    required: true,
                    data_type: &claim_schema.data_type,
                    array: false,
                }],
                credential_schema: &credential_schema,
                validity_constraint: None,
            },
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

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Created,
            &did,
            "PROCIVIS_TEMPORARY",
            Default::default(),
        )
        .await;

    let proof = context
        .db
        .proofs
        .create(
            None,
            &did,
            None,
            Some(&proof_schema),
            ProofStateEnum::Created,
            "OPENID4VC",
            None,
            verifier_key,
        )
        .await;

    context
        .db
        .proofs
        .set_proof_claims(&proof.id, credential.claims.unwrap())
        .await;

    // WHEN
    let resp = context.api.proofs.get(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    resp["id"].assert_eq(&proof.id);

    assert_eq!(resp["proofInputs"].as_array().unwrap().len(), 1);
    resp["proofInputs"][0]["credential"]["id"].assert_eq(&credential.id);
    assert!(resp["proofInputs"][0]["credential"]["role"].is_string());
}

#[tokio::test]
async fn test_get_proof_as_holder_success() {
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
    let holder_did = context
        .db
        .dids
        .create(&organisation, Default::default())
        .await;

    let proof = context
        .db
        .proofs
        .create(
            None,
            &verifier_did,
            Some(&holder_did),
            None, // Proof schema is empty on holder side
            ProofStateEnum::Created,
            "OPENID4VC",
            None,
            verifier_key,
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
}
