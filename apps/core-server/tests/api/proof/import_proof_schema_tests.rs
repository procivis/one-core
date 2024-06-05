use serde_json::json;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use uuid::Uuid;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_import_proof_schema_ok() {
    let (context, organisation) = TestContext::new_with_organisation().await;

    let proof_schema_id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();

    context
        .server_mock
        .get_proof_schema(
            proof_schema_id,
            json!({
                "id": proof_schema_id,
                "createdDate": now,
                "lastModified": now,
                "name": "test-proof-schema",
                "organisationId": Uuid::new_v4(),
                "expireDuration": 1000,
                "proofInputSchemas": [
                    {
                        "claimSchemas": [{
                            "id": Uuid::new_v4(),
                            "required": true,
                            "key": "root/name",
                            "dataType": "STRING",
                            "claims": []
                        },
                        {
                            "id": Uuid::new_v4(),
                            "required": true,
                            "key": "root/age",
                            "dataType": "NUMBER",
                            "claims": []
                        }],
                        "credentialSchema": {
                            "id": Uuid::new_v4(),
                            "createdDate": now,
                            "lastModified": now,
                            "name": "test-credential-schema",
                            "format": "MDOC",
                            "revocationMethod": "NONE",
                            "walletStorageType": "HARDWARE",
                            "schemaId": "iso-org-test123",
                            "schemaType": "ProcivisOneSchema2024",
                        }
                    }
                ]
            }),
        )
        .await;

    let import_url = format!(
        "{}/ssi/proof-schema/v1/{proof_schema_id}",
        context.server_mock.uri()
    );
    let resp = context
        .api
        .proof_schemas
        .import(&import_url, organisation.id)
        .await;

    assert_eq!(204, resp.status());

    let proof_schemas = context.db.proof_schemas.get_all(&organisation.id).await;
    assert_eq!("test-proof-schema", &proof_schemas[0].name);

    let proof_schema = context.db.proof_schemas.get(&proof_schemas[0].id).await;

    let proof_input_schemas = proof_schema.input_schemas.as_ref().unwrap();
    assert_eq!(1, proof_input_schemas.len());

    let credential_schema = proof_input_schemas[0].credential_schema.as_ref().unwrap();
    assert_eq!("test-credential-schema", credential_schema.name);

    let claims = proof_input_schemas[0].claim_schemas.as_ref().unwrap();
    assert_eq!(2, claims.len());
    assert_eq!("root/name", &claims[0].schema.key);
    assert_eq!("root/age", &claims[1].schema.key);
}
