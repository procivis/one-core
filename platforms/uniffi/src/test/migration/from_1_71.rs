use similar_asserts::assert_eq;

use crate::binding::credential_schema::CredentialSchemaListQueryBindingDTO;
use crate::binding::proof_schema::ListProofSchemasFiltersBindingDTO;
use crate::test::TestContext;

#[tokio::test]
async fn test_unpack_real_backup_1_71() {
    let TestContext { core, data_dir } = TestContext::create().await;

    const VERIFIER_1_71_BACKUP: &[u8] = include_bytes!("verifier_1.71_backup.zip");
    let file_path = data_dir.create_file(VERIFIER_1_71_BACKUP);
    let metadata = core
        .unpack_backup("test".to_string(), file_path)
        .await
        .unwrap();

    assert_eq!(metadata.db_version, "m20260206_032338_waa_to_wia");
    assert_eq!(
        metadata.db_hash,
        "8377da000399b3b9495827eb3f0a11893aa0e0862f209f5fc4101b6ab17552c8"
    );

    let credential_schemas = core
        .list_credential_schemas(CredentialSchemaListQueryBindingDTO {
            page: 0,
            page_size: 10,
            sort: None,
            sort_direction: None,
            organisation_id: "11111111-2222-3333-a444-ffffffffffff".to_string(),
            name: None,
            exact: None,
            ids: None,
            schema_id: None,
            formats: None,
            include: None,
            created_date_after: None,
            created_date_before: None,
            last_modified_after: None,
            last_modified_before: None,
        })
        .await
        .unwrap();

    assert_eq!(credential_schemas.total_items, 1);
    let credential_schema = credential_schemas.values[0].to_owned();
    assert_eq!(credential_schema.id, "fd030cd9-d799-4954-a227-26dad898f487");
    assert_eq!(credential_schema.name, "sdjwt-none");

    let proof_schemas = core
        .list_proof_schemas(ListProofSchemasFiltersBindingDTO {
            page: 0,
            page_size: 10,
            sort: None,
            sort_direction: None,
            organisation_id: "11111111-2222-3333-a444-ffffffffffff".to_string(),
            name: None,
            exact: None,
            ids: None,
            formats: None,
            created_date_after: None,
            created_date_before: None,
            last_modified_after: None,
            last_modified_before: None,
        })
        .await
        .unwrap();
    assert_eq!(proof_schemas.total_items, 0);
}
