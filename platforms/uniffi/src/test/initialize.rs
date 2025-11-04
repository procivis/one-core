use std::fs;

use similar_asserts::assert_eq;

use super::{TempDirContext, TestContext, TestContextWithOrganisation, initialize_core};
use crate::binding::did::DidRequestKeysBindingDTO;
use crate::binding::identifier::{
    CreateIdentifierDidRequestBindingDTO, CreateIdentifierRequestBindingDTO,
};
use crate::binding::key::KeyRequestBindingDTO;

#[tokio::test]
async fn test_initialize_core() {
    let data_dir = TempDirContext::new();
    initialize_core(data_dir.path()).await;
}

#[tokio::test]
async fn test_uninitialize_core_dont_delete_data() {
    let TestContextWithOrganisation {
        core,
        data_dir,
        organisation_id,
    } = TestContextWithOrganisation::create().await;

    let key_id = core
        .generate_key(KeyRequestBindingDTO {
            organisation_id: organisation_id.to_owned(),
            key_type: "ECDSA".to_string(),
            key_params: Default::default(),
            name: "test-key".to_string(),
            storage_type: "INTERNAL".to_string(),
            storage_params: Default::default(),
        })
        .await
        .unwrap();

    let identifier_id = core
        .create_identifier(CreateIdentifierRequestBindingDTO {
            organisation_id,
            name: "test-identifier".to_string(),
            key_id: None,
            did: Some(CreateIdentifierDidRequestBindingDTO {
                name: Some("test-did".to_string()),
                method: "KEY".to_string(),
                keys: DidRequestKeysBindingDTO {
                    authentication: vec![key_id.to_owned()],
                    assertion_method: vec![key_id.to_owned()],
                    key_agreement: vec![key_id.to_owned()],
                    capability_invocation: vec![key_id.to_owned()],
                    capability_delegation: vec![key_id],
                },
                params: Default::default(),
            }),
            certificates: None,
        })
        .await
        .unwrap();

    core.uninitialize(false).await.unwrap();

    let dir_content = fs::read_dir(data_dir.path()).unwrap();
    assert_eq!(dir_content.into_iter().count(), 1);

    let reinitialized_core = initialize_core(data_dir.path()).await;

    reinitialized_core
        .get_identifier(identifier_id)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_uninitialize_core_delete_data() {
    let TestContext { core, data_dir } = TestContext::create().await;

    core.uninitialize(true).await.unwrap();

    let dir_content = fs::read_dir(data_dir.path()).unwrap();
    assert_eq!(dir_content.into_iter().count(), 0);
}
