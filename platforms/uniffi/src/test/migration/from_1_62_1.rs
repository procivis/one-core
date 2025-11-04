use similar_asserts::assert_eq;

use crate::binding::credential::{CredentialListQueryBindingDTO, CredentialStateBindingEnum};
use crate::test::TestContext;

#[tokio::test]
async fn test_unpack_real_backup_1_62_1() {
    let TestContext { core, data_dir } = TestContext::create().await;

    const WALLET_1_62_1_BACKUP: &[u8] = include_bytes!("wallet_1.62.1_backup.zip");
    let file_path = data_dir.create_file(WALLET_1_62_1_BACKUP);
    let metadata = core
        .unpack_backup("test".to_string(), file_path)
        .await
        .unwrap();

    assert_eq!(
        metadata.db_version,
        "m20250922_102649_adds_user_column_to_history"
    );
    assert_eq!(
        metadata.db_hash,
        "485f6386d3f26b8dd92fa069a774fb4ae3e44e30235676e3b74e400a110f9857"
    );

    let credentials = core
        .get_credentials(CredentialListQueryBindingDTO {
            page: 0,
            page_size: 10,
            sort: None,
            sort_direction: None,
            organisation_id: "11111111-2222-3333-a444-ffffffffffff".to_string(),
            name: None,
            profiles: None,
            search_text: None,
            search_type: None,
            exact: None,
            roles: None,
            ids: None,
            states: None,
            include: None,
            credential_schema_ids: None,
            created_date_after: None,
            created_date_before: None,
            last_modified_after: None,
            last_modified_before: None,
            issuance_date_after: None,
            issuance_date_before: None,
            revocation_date_after: None,
            revocation_date_before: None,
        })
        .await
        .unwrap();

    assert_eq!(credentials.total_items, 1);
    let credential = credentials.values[0].to_owned();
    assert_eq!(credential.id, "e6d61ad8-30a5-4df3-bcb5-67e4f296b1f6");
    assert_eq!(credential.state, CredentialStateBindingEnum::Accepted);
}
