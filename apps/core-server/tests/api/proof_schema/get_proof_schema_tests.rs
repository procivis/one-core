use serde_json::Value;
use validator::ValidateLength;

use crate::{
    fixtures,
    utils::{
        self,
        context::TestContext,
        db_clients::proof_schemas::{CreateProofClaim, CreateProofInputSchema},
        server::run_server,
    },
};

#[tokio::test]
async fn test_get_proof_schema_success() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url, None);
    let db_conn = fixtures::create_db(&config).await;

    let organisation = fixtures::create_organisation(&db_conn).await;

    let credential_schema =
        fixtures::create_credential_schema(&db_conn, "test", &organisation, "NONE").await;
    let claim_schema = credential_schema
        .claim_schemas
        .as_ref()
        .unwrap()
        .first()
        .unwrap()
        .schema
        .to_owned();

    let proof_schema = fixtures::create_proof_schema(
        &db_conn,
        "test",
        &organisation,
        &[CreateProofInputSchema {
            claims: vec![CreateProofClaim {
                id: claim_schema.id,
                key: &claim_schema.key,
                required: true,
                data_type: &claim_schema.data_type,
            }],
            credential_schema: &credential_schema,
            validity_constraint: Some(10),
        }],
    )
    .await;

    // WHEN
    let _handle = run_server(listener, config, &db_conn);
    let url = format!("{base_url}/api/proof-schema/v1/{}", proof_schema.id);
    let resp = utils::client()
        .get(url)
        .bearer_auth("test")
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 200);
    let resp: Value = resp.json().await.unwrap();
    assert_eq!(resp["id"].as_str().unwrap(), proof_schema.id.to_string());
    assert_eq!(
        resp["organisationId"].as_str().unwrap(),
        organisation.id.to_string()
    );
    assert_eq!(resp["name"].as_str().unwrap(), "test");
    assert_eq!(resp["proofInputSchemas"].as_array().unwrap().len(), 1);

    let claim_schema_item = &resp["proofInputSchemas"][0]["claimSchemas"][0];
    assert_eq!(
        claim_schema_item["id"].as_str().unwrap(),
        claim_schema.id.to_string()
    );
    assert_eq!(claim_schema_item["key"].as_str().unwrap(), claim_schema.key);
    assert_eq!(
        claim_schema_item["dataType"].as_str().unwrap(),
        claim_schema.data_type
    );
    assert!(claim_schema_item["required"].as_bool().unwrap());
    assert_eq!(
        resp["proofInputSchemas"][0]["validityConstraint"]
            .as_i64()
            .unwrap(),
        10
    );
}

#[tokio::test]
async fn test_succeed_to_fetch_claims_just_root_object() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

    let credential_schema = context
        .db
        .credential_schemas
        .create_with_nested_claims("test", &organisation, "NONE", Default::default())
        .await;

    let root_claim = credential_schema
        .claim_schemas
        .as_ref()
        .unwrap()
        // We only put a root component in proof schema
        .first()
        .unwrap();

    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "Test",
            &organisation,
            CreateProofInputSchema {
                claims: vec![CreateProofClaim {
                    id: root_claim.schema.id,
                    key: &root_claim.schema.key,
                    required: true,
                    data_type: &root_claim.schema.data_type,
                }],
                credential_schema: &credential_schema,
                validity_constraint: Some(10),
            },
        )
        .await;

    // WHEN
    let resp = context.api.proof_schemas.get(proof_schema.id).await;

    // THEN
    let resp = resp.json::<Value>().await;

    // Response contains all
    assert_eq!(
        resp["proofInputSchemas"][0]["claimSchemas"][0]["claims"]
            .as_array()
            .length(),
        Some(2)
    );
    assert_eq!(
        resp["proofInputSchemas"][0]["claimSchemas"][0]["claims"][1]["claims"]
            .as_array()
            .length(),
        Some(2)
    );
}

#[tokio::test]
async fn test_succeed_to_fetch_claims_nested_root_object() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

    let credential_schema = context
        .db
        .credential_schemas
        .create_with_nested_claims("test", &organisation, "NONE", Default::default())
        .await;

    let root_claim = credential_schema
        .claim_schemas
        .as_ref()
        .unwrap()
        // We only put a nested (coordinates) root component in proof schema
        .iter()
        .nth(2)
        .unwrap();

    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "Test",
            &organisation,
            CreateProofInputSchema {
                claims: vec![CreateProofClaim {
                    id: root_claim.schema.id,
                    key: &root_claim.schema.key,
                    required: true,
                    data_type: &root_claim.schema.data_type,
                }],
                credential_schema: &credential_schema,
                validity_constraint: Some(10),
            },
        )
        .await;

    // WHEN
    let resp = context.api.proof_schemas.get(proof_schema.id).await;

    // THEN
    let resp = resp.json::<Value>().await;

    // Response contains root component with just one claim (coordinates)
    assert_eq!(
        resp["proofInputSchemas"][0]["claimSchemas"][0]["claims"]
            .as_array()
            .length(),
        Some(1)
    );
    // Coordinates contain both claims (x, y)
    assert_eq!(
        resp["proofInputSchemas"][0]["claimSchemas"][0]["claims"][0]["claims"]
            .as_array()
            .length(),
        Some(2)
    );
}
