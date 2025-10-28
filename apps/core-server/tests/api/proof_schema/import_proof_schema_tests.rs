use std::collections::HashSet;

use one_core::model::claim_schema::ClaimSchema;
use one_core::model::credential_schema::CredentialSchemaClaim;
use serde_json::json;
use shared_types::ProofSchemaId;
use similar_asserts::assert_eq;
use sql_data_provider::test_utilities::get_dummy_date;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;

#[tokio::test]
async fn test_import_proof_schema_ok() {
    let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();

    let (context, source_organisation) = TestContext::new_with_organisation(None).await;
    let original_credential_schema_id = Uuid::new_v4().into();
    let original_credential_schema = context
        .db
        .credential_schemas
        .create(
            "test-credential-schema",
            &source_organisation,
            "NONE",
            TestingCreateSchemaParams {
                id: Some(original_credential_schema_id),
                imported_source_url: Some(format!(
                    "{}/ssi/schema/v1/{}",
                    context.server_mock.uri(),
                    original_credential_schema_id
                )),
                allow_suspension: Some(false),
                ..Default::default()
            },
        )
        .await;

    let mut claim_schemas = original_credential_schema.claim_schemas.clone().unwrap();

    context
        .server_mock
        .ssi_credential_schema_endpoint(
            original_credential_schema_id,
            json!({
              "createdDate": now,
              "lastModified": now,
              "format": original_credential_schema.format,
              "id": original_credential_schema_id,
              "importedSourceUrl": original_credential_schema.imported_source_url,
              "name": original_credential_schema.name,
              "organisationId": source_organisation.id,
              "revocationMethod": original_credential_schema.revocation_method,
              "schemaId": original_credential_schema.schema_id,
              "walletStorageType": original_credential_schema.wallet_storage_type,
              "allowSuspension": original_credential_schema.allow_suspension,
              "claims": claim_schemas.iter().map(|schema| json!({
                  "array": schema.schema.array,
                  "createdDate": now,
                  "lastModified": now,
                  "datatype": schema.schema.data_type,
                  "id": schema.schema.id,
                  "key": schema.schema.key,
                  "required": schema.required
              })).collect::<Vec<_>>()
            }),
        )
        .await;

    let requested_claim_schema = claim_schemas.swap_remove(0);

    let target_organisation = context.db.organisations.create().await;

    let old_proof_schema_id: ProofSchemaId = Uuid::new_v4().into();

    let proof_schema = json!({
        "id": old_proof_schema_id,
        "createdDate": now,
        "lastModified": now,
        "name": "test-proof-schema",
        "organisationId": Uuid::new_v4(),
        "importedSourceUrl": "test",
        "expireDuration": 1000,
        "proofInputSchemas": [
            {
                "claimSchemas": [{
                    "id": Uuid::new_v4(),
                    "requested": true,
                    "required": true,
                    "key": requested_claim_schema.schema.key,
                    "dataType": requested_claim_schema.schema.data_type,
                    "array": false,
                }],
                "credentialSchema": {
                    "id": Uuid::new_v4(),
                    "createdDate": now,
                    "lastModified": now,
                    "importedSourceUrl": original_credential_schema.imported_source_url,
                    "name": original_credential_schema.name,
                    "format": original_credential_schema.format,
                    "revocationMethod": original_credential_schema.format,
                    "walletStorageType": original_credential_schema.wallet_storage_type,
                    "schemaId": original_credential_schema.schema_id,
                }
            }
        ]
    });

    let resp = context
        .api
        .proof_schemas
        .import(proof_schema, target_organisation.id)
        .await;

    assert_eq!(201, resp.status());

    let proof_schema_id = resp.json_value().await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    assert_ne!(old_proof_schema_id, proof_schema_id);

    let proof_schema = context.db.proof_schemas.get(&proof_schema_id).await;
    assert_eq!("test-proof-schema", &proof_schema.name);

    let proof_schema = context.db.proof_schemas.get(&proof_schema.id).await;

    let proof_input_schemas = proof_schema.input_schemas.as_ref().unwrap();
    assert_eq!(1, proof_input_schemas.len());

    let credential_schema = proof_input_schemas[0].credential_schema.as_ref().unwrap();
    assert_eq!("test-credential-schema", credential_schema.name);

    let claims = proof_input_schemas[0].claim_schemas.as_ref().unwrap();
    assert_eq!(1, claims.len());
    assert_eq!(requested_claim_schema.schema.key, claims[0].schema.key);
}

#[tokio::test]
async fn test_import_proof_schema_fails_deactivated_organisation() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    context.db.organisations.deactivate(&organisation.id).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test-credential-schema",
            &organisation,
            "NONE",
            Default::default(),
        )
        .await;

    let mut claim_schemas = credential_schema.claim_schemas.clone().unwrap();
    let requested_claim_schema = claim_schemas.swap_remove(0);

    let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
    let proof_schema = json!({
        "id": Uuid::new_v4(),
        "createdDate": now,
        "lastModified": now,
        "name": "test-proof-schema",
        "importedSourceUrl": "TEST",
        "organisationId": organisation.id,
        "expireDuration": 1000,
        "proofInputSchemas": [
            {
                "claimSchemas": [{
                    "id": requested_claim_schema.schema.id,
                    "requested": true,
                    "required": requested_claim_schema.required,
                    "key": requested_claim_schema.schema.key,
                    "dataType": requested_claim_schema.schema.data_type,
                    "claims": [],
                    "array": false,
                }],
                "credentialSchema": {
                    "id": credential_schema.id,
                    "createdDate": now,
                    "lastModified": now,
                    "importedSourceUrl": "invalid_should_not_be_needed",
                    "name": credential_schema.name,
                    "format": credential_schema.format,
                    "revocationMethod": credential_schema.format,
                    "walletStorageType": credential_schema.wallet_storage_type,
                    "schemaId": credential_schema.schema_id,
                }
            }
        ]
    });

    // WHEN
    let resp = context
        .api
        .proof_schemas
        .import(proof_schema, organisation.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0241", resp.error_code().await);
}

#[tokio::test]
async fn test_import_proof_schema_for_existing_credential_schema() {
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let old_proof_schema_id: ProofSchemaId = Uuid::new_v4().into();
    let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();

    let original_credential_schema = context
        .db
        .credential_schemas
        .create(
            "test-credential-schema",
            &organisation,
            "NONE",
            Default::default(),
        )
        .await;

    let mut claim_schemas = original_credential_schema.claim_schemas.clone().unwrap();
    assert_eq!(2, claim_schemas.len());

    let requested_claim_schema = claim_schemas.swap_remove(0);

    let proof_schema = json!({
        "id": old_proof_schema_id,
        "createdDate": now,
        "lastModified": now,
        "name": "test-proof-schema",
        "importedSourceUrl": "TEST",
        "organisationId": Uuid::new_v4(),
        "expireDuration": 1000,
        "proofInputSchemas": [
            {
                "claimSchemas": [{
                    "id": requested_claim_schema.schema.id,
                    "requested": true,
                    "required": requested_claim_schema.required,
                    "key": requested_claim_schema.schema.key,
                    "dataType": requested_claim_schema.schema.data_type,
                    "claims": [],
                    "array": false,
                }],
                "credentialSchema": {
                    "id": original_credential_schema.id,
                    "createdDate": now,
                    "lastModified": now,
                    "importedSourceUrl": "invalid_should_not_be_needed",
                    "name": original_credential_schema.name,
                    "format": original_credential_schema.format,
                    "revocationMethod": original_credential_schema.format,
                    "walletStorageType": original_credential_schema.wallet_storage_type,
                    "schemaId": original_credential_schema.schema_id,
                }
            }
        ]
    });
    let resp = context
        .api
        .proof_schemas
        .import(proof_schema, organisation.id)
        .await;

    assert_eq!(201, resp.status());

    let proof_schema_id = resp.json_value().await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    assert_ne!(old_proof_schema_id, proof_schema_id);

    let proof_schema = context.db.proof_schemas.get(&proof_schema_id).await;
    assert_eq!("test-proof-schema", &proof_schema.name);

    let proof_schema = context.db.proof_schemas.get(&proof_schema.id).await;

    let proof_input_schemas = proof_schema.input_schemas.as_ref().unwrap();
    assert_eq!(1, proof_input_schemas.len());

    let credential_schema = proof_input_schemas[0].credential_schema.as_ref().unwrap();
    assert_eq!("test-credential-schema", credential_schema.name);

    let claim_schemas: HashSet<_> = credential_schema
        .claim_schemas
        .as_ref()
        .unwrap()
        .iter()
        .map(|c| c.schema.key.as_str())
        .collect();
    assert_eq!(
        original_credential_schema.claim_schemas.unwrap().len(),
        claim_schemas.len()
    );

    let claims = proof_input_schemas[0].claim_schemas.as_ref().unwrap();
    assert_eq!(1, claims.len());
    assert_eq!(requested_claim_schema.schema.key, claims[0].schema.key);
}

#[tokio::test]
async fn test_import_proof_schema_nested_array() {
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let old_proof_schema_id: ProofSchemaId = Uuid::new_v4().into();
    let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();

    let root_object_array_claim = CredentialSchemaClaim {
        schema: ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "root".to_string(),
            data_type: "OBJECT".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            array: true,
            metadata: false,
        },
        required: true,
    };

    let original_credential_schema = context
        .db
        .credential_schemas
        .create(
            "test-credential-schema",
            &organisation,
            "NONE",
            TestingCreateSchemaParams {
                claim_schemas: Some(vec![
                    root_object_array_claim.clone(),
                    CredentialSchemaClaim {
                        schema: ClaimSchema {
                            id: Uuid::new_v4().into(),
                            key: "root/field".to_string(),
                            data_type: "STRING".to_string(),
                            created_date: get_dummy_date(),
                            last_modified: get_dummy_date(),
                            array: false,
                            metadata: false,
                        },
                        required: true,
                    },
                ]),
                ..Default::default()
            },
        )
        .await;

    let requested_claim_schema = root_object_array_claim;

    let proof_schema = json!({
        "id": old_proof_schema_id,
        "createdDate": now,
        "lastModified": now,
        "name": "test-proof-schema",
        "importedSourceUrl": "TEST",
        "organisationId": Uuid::new_v4(),
        "expireDuration": 1000,
        "proofInputSchemas": [
            {
                "claimSchemas": [{
                    "id": requested_claim_schema.schema.id,
                    "requested": true,
                    "required": requested_claim_schema.required,
                    "key": requested_claim_schema.schema.key,
                    "dataType": requested_claim_schema.schema.data_type,
                    "claims": [{
                        "id": "06155d27-ea07-4be4-b5e3-c057c741d959",
                        "requested": false,
                        "required": true,
                        "key": "field",
                        "dataType": "STRING",
                        "array": false
                    }],
                    "array": true,
                }],
                "credentialSchema": {
                    "id": original_credential_schema.id,
                    "createdDate": now,
                    "lastModified": now,
                    "importedSourceUrl": "invalid_should_not_be_needed",
                    "name": original_credential_schema.name,
                    "format": original_credential_schema.format,
                    "revocationMethod": original_credential_schema.format,
                    "walletStorageType": original_credential_schema.wallet_storage_type,
                    "schemaId": original_credential_schema.schema_id,
                }
            }
        ]
    });
    let resp = context
        .api
        .proof_schemas
        .import(proof_schema, organisation.id)
        .await;

    assert_eq!(201, resp.status());

    let proof_schema_id = resp.json_value().await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    assert_ne!(old_proof_schema_id, proof_schema_id);

    let proof_schema = context.db.proof_schemas.get(&proof_schema_id).await;
    assert_eq!("test-proof-schema", &proof_schema.name);

    let proof_schema = context.db.proof_schemas.get(&proof_schema.id).await;

    let proof_input_schemas = proof_schema.input_schemas.as_ref().unwrap();
    assert_eq!(1, proof_input_schemas.len());

    let credential_schema = proof_input_schemas[0].credential_schema.as_ref().unwrap();
    assert_eq!("test-credential-schema", credential_schema.name);

    let claim_schemas: HashSet<_> = credential_schema
        .claim_schemas
        .as_ref()
        .unwrap()
        .iter()
        .map(|c| c.schema.key.as_str())
        .collect();
    assert_eq!(
        original_credential_schema.claim_schemas.unwrap().len(),
        claim_schemas.len()
    );

    let claims = proof_input_schemas[0].claim_schemas.as_ref().unwrap();
    assert_eq!(1, claims.len());
    assert_eq!(requested_claim_schema.schema.key, claims[0].schema.key);
}
