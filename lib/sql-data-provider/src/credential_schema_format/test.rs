use std::sync::Arc;

use one_core::model::credential_schema_format::CredentialSchemaFormat;
use one_core::model::credential_schema_format_claim_schema::CredentialSchemaFormatClaimSchema;
use one_core::model::relation::RelatedVec;
use one_core::repository::credential_schema_format_repository::CredentialSchemaFormatRepository;
use shared_types::{ClaimSchemaId, CredentialSchemaFormatClaimSchemaId, CredentialSchemaFormatId};
use similar_asserts::assert_eq;
use uuid::Uuid;

use super::CredentialSchemaFormatProvider;
use crate::test_utilities::*;
use crate::transaction_context::TransactionManagerImpl;

#[tokio::test]
async fn test_create_and_get_credential_schema_format() {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;
    let tx_manager = TransactionManagerImpl::new(db.clone());

    let organisation_id = insert_organisation_to_database(&db, None).await.unwrap();
    let credential_schema_id =
        insert_credential_schema_to_database(&db, None, organisation_id, "schema-a", false, None)
            .await
            .unwrap();

    let claim_schema_id: ClaimSchemaId = Uuid::new_v4().into();
    let claim_input = ProofInput {
        credential_schema_id,
        claims: &vec![ClaimInsertInfo {
            id: claim_schema_id,
            key: "first_name".to_string(),
            required: true,
            order: 0,
            datatype: "STRING",
            array: false,
            metadata: false,
        }],
    };
    insert_many_claims_schema_to_database(&db, &claim_input)
        .await
        .unwrap();

    let provider: Arc<dyn CredentialSchemaFormatRepository> =
        Arc::new(CredentialSchemaFormatProvider { db: tx_manager });

    let format_id: CredentialSchemaFormatId = Uuid::new_v4().into();
    let mapping_id: CredentialSchemaFormatClaimSchemaId = Uuid::new_v4().into();
    let now = get_dummy_date();

    let format = CredentialSchemaFormat {
        id: format_id,
        created_date: now,
        last_modified: now,
        credential_schema_id,
        format: "SD_JWT_VC".into(),
        ecosystem_schema_id: "https://example.com/schemas/example".to_string(),
        claim_mappings: RelatedVec::from(vec![CredentialSchemaFormatClaimSchema {
            id: mapping_id,
            created_date: now,
            last_modified: now,
            credential_schema_format_id: format_id,
            claim_schema_id,
            technical_key: "given_name".to_string(),
            namespace: None,
        }]),
    };

    let returned_id = provider
        .create_credential_schema_format(format)
        .await
        .expect("create should succeed");
    assert_eq!(returned_id, format_id);

    let fetched = provider
        .get_credential_schema_format(&format_id)
        .await
        .expect("get should succeed");
    assert_eq!(fetched.id, format_id);
    assert_eq!(
        fetched.ecosystem_schema_id,
        "https://example.com/schemas/example"
    );

    let mappings = fetched.claim_mappings.as_ref().await.unwrap();
    assert_eq!(mappings.len(), 1);
    assert_eq!(mappings[0].technical_key, "given_name");
    assert_eq!(mappings[0].namespace, None);

    let listed = provider
        .list_by_credential_schema_id(&credential_schema_id)
        .await
        .expect("list should succeed");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, format_id);
}

#[tokio::test]
async fn test_unique_credential_schema_id_format() {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;
    let tx_manager = TransactionManagerImpl::new(db.clone());

    let organisation_id = insert_organisation_to_database(&db, None).await.unwrap();
    let credential_schema_id =
        insert_credential_schema_to_database(&db, None, organisation_id, "schema-a", false, None)
            .await
            .unwrap();

    insert_credential_schema_with_revocation_to_database(&db, credential_schema_id, "JWT")
        .await
        .unwrap();

    let provider: Arc<dyn CredentialSchemaFormatRepository> =
        Arc::new(CredentialSchemaFormatProvider { db: tx_manager });

    let now = get_dummy_date();
    let format_a = CredentialSchemaFormat {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        credential_schema_id,
        format: "SD_JWT_VC".into(),
        ecosystem_schema_id: "https://example.com/schemas/a".to_string(),
        claim_mappings: RelatedVec::from(vec![]),
    };

    let format_b = CredentialSchemaFormat {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        credential_schema_id,
        format: "SD_JWT_VC".into(), // duplicate (credential_schema_id, format)
        ecosystem_schema_id: "https://example.com/schemas/b".to_string(),
        claim_mappings: RelatedVec::from(vec![]),
    };

    provider
        .create_credential_schema_format(format_a)
        .await
        .expect("first insert should succeed");

    let result = provider.create_credential_schema_format(format_b).await;
    assert!(
        result.is_err(),
        "duplicate (credential_schema_id, format) should be blocked"
    );
}

#[tokio::test]
async fn test_unique_format_claim_schema_mapping() {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;
    let tx_manager = TransactionManagerImpl::new(db.clone());

    let organisation_id = insert_organisation_to_database(&db, None).await.unwrap();
    let credential_schema_id =
        insert_credential_schema_to_database(&db, None, organisation_id, "schema-a", false, None)
            .await
            .unwrap();

    insert_credential_schema_with_revocation_to_database(&db, credential_schema_id, "JWT")
        .await
        .unwrap();

    let claim_schema_id: ClaimSchemaId = Uuid::new_v4().into();
    insert_many_claims_schema_to_database(
        &db,
        &ProofInput {
            credential_schema_id,
            claims: &vec![ClaimInsertInfo {
                id: claim_schema_id,
                key: "first_name".to_string(),
                required: true,
                order: 0,
                datatype: "STRING",
                array: false,
                metadata: false,
            }],
        },
    )
    .await
    .unwrap();

    let provider: Arc<dyn CredentialSchemaFormatRepository> =
        Arc::new(CredentialSchemaFormatProvider { db: tx_manager });

    let now = get_dummy_date();
    let format_id: CredentialSchemaFormatId = Uuid::new_v4().into();
    let mapping = |id: CredentialSchemaFormatClaimSchemaId| CredentialSchemaFormatClaimSchema {
        id,
        created_date: now,
        last_modified: now,
        credential_schema_format_id: format_id,
        claim_schema_id,
        technical_key: "given_name".to_string(),
        namespace: None,
    };

    let result = provider
        .create_credential_schema_format(CredentialSchemaFormat {
            id: format_id,
            created_date: now,
            last_modified: now,
            credential_schema_id,
            format: "SD_JWT_VC".into(),
            ecosystem_schema_id: "https://example.com/schemas/example".to_string(),
            claim_mappings: RelatedVec::from(vec![
                mapping(Uuid::new_v4().into()),
                mapping(Uuid::new_v4().into()),
            ]),
        })
        .await;

    assert!(
        result.is_err(),
        "duplicate (credential_schema_format_id, claim_schema_id) should be blocked"
    );
}
