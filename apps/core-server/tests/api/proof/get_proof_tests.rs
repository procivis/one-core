use one_core::model::{credential::CredentialStateEnum, proof::ProofStateEnum};

use crate::utils::{context::TestContext, field_match::FieldHelpers};

#[tokio::test]
async fn test_get_proof_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE")
        .await;

    let claim_schema = &credential_schema.claim_schemas.as_ref().unwrap()[0].schema;

    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "test",
            &organisation,
            &[(
                claim_schema.id,
                &claim_schema.key,
                true,
                &claim_schema.data_type,
            )],
        )
        .await;

    let did = context
        .db
        .dids
        .create(&organisation, Default::default())
        .await;

    let proof = context
        .db
        .proofs
        .create(
            &did,
            None,
            Some(&proof_schema),
            ProofStateEnum::Created,
            "OPENID4VC",
            None,
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

    assert_eq!(resp["claims"].as_array().unwrap().len(), 1);
    let claim_item = &resp["claims"][0];
    claim_item["schema"]["id"].assert_eq(&claim_schema.id);
    assert!(claim_item["value"].is_null());
}

#[tokio::test]
async fn test_get_proof_with_credentials() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE")
        .await;

    let claim_schema = &credential_schema.claim_schemas.as_ref().unwrap()[0].schema;

    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "test",
            &organisation,
            &[(
                claim_schema.id,
                &claim_schema.key,
                true,
                &claim_schema.data_type,
            )],
        )
        .await;

    let did = context
        .db
        .dids
        .create(&organisation, Default::default())
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
            &did,
            None,
            Some(&proof_schema),
            ProofStateEnum::Created,
            "OPENID4VC",
            None,
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
    assert_eq!(resp["credentials"].as_array().unwrap().len(), 1);
    resp["credentials"][0]["id"].assert_eq(&credential.id);
    assert!(resp["credentials"][0]["role"].is_string());
}

#[tokio::test]
async fn test_get_proof_as_holder_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

    let verifier_did = context
        .db
        .dids
        .create(&organisation, Default::default())
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
            &verifier_did,
            Some(&holder_did),
            None, // Proof schema is empty on holder side
            ProofStateEnum::Created,
            "OPENID4VC",
            None,
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
    assert_eq!(resp["claims"].as_array().unwrap().len(), 0);
}
